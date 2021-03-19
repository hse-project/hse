/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE /* for pthread_getname_np() */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/log2.h>
#include <hse_util/table.h>
#include <hse_util/cds_list.h>
#include <hse_util/bonsai_tree.h>

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0snr_set.h>
#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>
#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/rparam_debug_flags.h>

#include "c0sk_internal.h"
#include "c0_ingest_work.h"

merr_t
c0sk_initialize_concurrency_control(struct c0sk_impl *c0sk)
{
    atomic_set(&c0sk->c0sk_ingest_ldr, 0);
    atomic64_set(&c0sk->c0sk_ingest_gen, 0);
    mutex_init_adaptive(&c0sk->c0sk_kvms_mutex);
    mutex_init(&c0sk->c0sk_sync_mutex);
    cv_init(&c0sk->c0sk_kvms_cv, "c0sk_kvms_cv");

    c0sk->c0sk_mtx_pool = mtx_pool_create(c0sk->c0sk_kvdb_rp->c0_mutex_pool_sz);
    if (!c0sk->c0sk_mtx_pool) {
        cv_destroy(&c0sk->c0sk_kvms_cv);
        mutex_destroy(&c0sk->c0sk_kvms_mutex);
        mutex_destroy(&c0sk->c0sk_sync_mutex);
        return merr(ev(ENOMEM));
    }

    return 0;
}

merr_t
c0sk_free_concurrency_control(struct c0sk_impl *c0sk)
{
    if (c0sk->c0sk_mtx_pool) {
        mtx_pool_destroy(c0sk->c0sk_mtx_pool);
        cv_destroy(&c0sk->c0sk_kvms_cv);
        mutex_destroy(&c0sk->c0sk_sync_mutex);
        mutex_destroy(&c0sk->c0sk_kvms_mutex);
    }

    return 0;
}

/* Update c0sk's throttle sensor based on:
 * - the aggregate size of c0 kvms,
 * - the number of c0 kvms, and
 * - the configured high water mark.
 *
 * The general idea is to limit the amount of RAM that c0sk is holding in kvms
 * pending ingest.  The sensor setting becomes more aggressive as the pending
 * ingest size grows above the high water mark.
 *
 * The general flow is that for any given kvms c0sk_install_c0kvms() adds
 * the estimated 'old' kvms size to c0sk_kvmultisets_sz.  After ingestion,
 * c0sk_release_multiset() subtracts the original estimated size from
 * c0sk_kvmultisets_sz, for a net gain of zero wrt any given kvms.
 *
 * Additionally, we factor in a small fixed amount for each pending kvms
 * (currently roughly .1% of the high water mark per pending kvms).  This
 * allows throttling to engage in the presence of numerous small kvms whose
 * aggregate usage would otherwise never eclipse the high water mark.
 *
 * See 'struct throttle_sensor' for guidelines on setting sensor values.

 * [HSE_REVISIT] This function here may be redundant once the new
 * c0sk throttler c0sk_ingest_throttle_adjust() controls throttling
 * based on outstanding bytes to be ingested. Will be removed later
 * if this function is indeed redundant.
 */
int
c0sk_adjust_throttling(struct c0sk_impl *self)
{
    const struct kvdb_rparams *rp = self->c0sk_kvdb_rp;

    size_t new, old, sz;
    size_t lwm, hwm;

    if (!self->c0sk_sensor || !rp->throttle_c0_hi_th)
        return 0;

    lwm = 1ul << 30;
    hwm = max_t(size_t, lwm, rp->throttle_c0_hi_th * 1024 * 1024);

    /* Current size is based on current pending kvms RAM usage plus
     * a fixed amount per pending kvms.
     */
    sz = self->c0sk_kvmultisets_sz;
    sz += (rp->throttle_c0_hi_th * self->c0sk_kvmultisets_cnt / 64) << 20;

    old = throttle_sensor_get(self->c0sk_sensor);
    new = 0;

    if (sz > lwm) {
        new = THROTTLE_SENSOR_SCALE * sz / hwm;
        new = min_t(size_t, new, THROTTLE_SENSOR_SCALE * 2);

        /* Ease off the throttle to ameliorate stop-n-go behavior...
         */
        if (new < old)
            new = (new + old * 7) / 8;
    }

    throttle_sensor_set(self->c0sk_sensor, new);

    perfc_rec_sample(&self->c0sk_pc_ingest, PERFC_DI_C0SKING_THRSR, new);

    if (self->c0sk_kvdb_rp->throttle_debug & THROTTLE_DEBUG_SENSOR_C0SK)
        hse_log(HSE_NOTICE "%s: kvms_cnt %d, kvms_sz_MiB %zu, sensor: %zu -> %zu",
                __func__, self->c0sk_kvmultisets_cnt,
                self->c0sk_kvmultisets_sz >> 20,
                old, new);

    return new;
}

/**
 * c0sk_rsvd_sn_set() - called when a new kvms is activated
 * @c0sk:   c0sk handle
 * @kvms:   handle to kvms being activated
 *
 * This function is invoked when activating a new KVMS. At this point, there
 * could be older threads still updating the old KVMS.
 * But there is at most one thread that
 * can update seqno - prefix delete. Reserve a seqno for this possibility.
 *
 * Regardless, we always reserve a seqno in case we're here on behalf of a
 * txn flush.
 */
static void
c0sk_rsvd_sn_set(struct c0sk_impl *c0sk, struct c0_kvmultiset *kvms)
{
    unsigned int inc = 2;
    u64          res;

    /* flush from txcommit context; reverve seqno for txn. */

    res = (inc - 1) + atomic64_fetch_add_rel(inc, c0sk->c0sk_kvdb_seq);

    c0kvms_rsvd_sn_set(kvms, res);
}

bool
c0sk_install_c0kvms(struct c0sk_impl *self, struct c0_kvmultiset *old, struct c0_kvmultiset *new)
{
    struct c0_kvmultiset *first;
    size_t                used = 0;

    /* set old kvms seqno to kvdb's seqno before freezing it. */
    if (old) {
        c0kvms_seqno_set(old, atomic64_read_acq(self->c0sk_kvdb_seq));
        used = c0kvms_used_get(old);
    }

    mutex_lock(&self->c0sk_kvms_mutex);
    first = c0sk_get_first_c0kvms(&self->c0sk_handle);
    if (first == old) {
        atomic64_set(&self->c0sk_ingest_gen, c0kvms_gen_update(new));
        cds_list_add_rcu(&new->c0ms_link, &self->c0sk_kvmultisets);

        c0sk_rsvd_sn_set(self, new);

        self->c0sk_kvmultisets_sz += used;
        self->c0sk_kvmultisets_cnt += 1;
        c0sk_adjust_throttling(self);
    }
    mutex_unlock(&self->c0sk_kvms_mutex);

    perfc_set(&self->c0sk_pc_ingest, PERFC_BA_C0SKING_QLEN, self->c0sk_kvmultisets_cnt);

    perfc_set(&self->c0sk_pc_ingest, PERFC_BA_C0SKING_WIDTH, self->c0sk_ingest_width);

    return (first == old);
}

static void
signal_waiters(struct c0sk_impl *c0sk, u64 gen)
{
    struct c0sk_waiter *p;

    /* Awaken all threads waiting on the given c0kvms generation.
     */
    mutex_lock(&c0sk->c0sk_sync_mutex);
    list_for_each_entry (p, &c0sk->c0sk_sync_waiters, c0skw_link) {
        if (gen >= p->c0skw_gen)
            cv_broadcast(&p->c0skw_cv);
    }
    mutex_unlock(&c0sk->c0sk_sync_mutex);
}

static inline void
c0sk_kvmultiset_ingest_completion(struct c0sk_impl *c0sk, struct c0_kvmultiset *multiset)
{
    u64 gen = c0kvms_gen_read(multiset);

    c0kvms_ingested(multiset);
    c0sk_release_multiset(c0sk, multiset);
    signal_waiters(c0sk, gen);
}

/* Compare seqno with the correct previous seqno - ptomb or other
 *
 *  1 : seqno > prev
 * -1 : seqno < prev
 *  0 : seqno == prev
 */
static HSE_ALWAYS_INLINE int
seq_prev_cmp(void *valp, u64 seq, u64 seq_prev, u64 pt_seq_prev)
{
    u64 ref_prev;

    ref_prev = HSE_CORE_IS_PTOMB(valp) ? pt_seq_prev : seq_prev;

    if (seq < ref_prev)
        return -1;
    else if (seq > ref_prev)
        return 1;

    return 0;
}

/**
 * c0sk_builder_add() - spill the given key and values from c0 to cn
 * @bldr:       the kvset builder into which to spill the data
 * @bkv:        key data object
 * @val:        head of list of values sorted by seqno
 * @sorted:     count of potentially misordered values
 * @ingestid:   ingest id
 *
 * The input list of values is sorted by seqno (highest seqno to lowest
 * seqno from head to tail).  If unsorted is not zero, then it is a count
 * of the number of values in the list that might be out of sequence.  In
 * practice, even if unsorted is not zero the list might well be sorted due
 * to the caller having fixed a detcted misorder but being unable to verify
 * the correct order of the entire list.
 */
static merr_t
c0sk_builder_add(
    struct kvset_builder *bldr,
    struct c0_kvmultiset *kvms,
    struct bonsai_kv *    bkv,
    struct bonsai_val *   head,
    u32                   unsorted)
{
    struct bonsai_val *val, *next;
    u64                seqno_prev, pt_seqno_prev;
    u64                seqno;
    merr_t             err;

    assert(bldr && bkv && head);

    seqno = 0;

    /* [HSE_REVISIT] It should be rare that the list contains more than
     * a few items, and even more rare that we need to actually sort
     * the list.  However, should we find a recurrent case to the contrary
     * we'll need either a better sort or a better approach...
     */
    while (unsorted > 0) {
        struct bonsai_val **tailp, **prevp;

        seqno_prev = U64_MAX;
        pt_seqno_prev = U64_MAX;
        tailp = &head;
        prevp = NULL;
        unsorted = 0;

        for (val = head; val; val = next) {
            int rc;

            next = val->bv_free;

            seqnoref_to_seqno(val->bv_seqnoref, &seqno);

            rc = seq_prev_cmp(val->bv_valuep, seqno, seqno_prev, pt_seqno_prev);
            if (rc > 0) {
                *tailp = val->bv_free;
                val->bv_free = *prevp;
                *prevp = val;
                prevp = &val->bv_free;

                ++unsorted;
                continue;
            }

            prevp = tailp;
            tailp = &val->bv_free;
            if (HSE_CORE_IS_PTOMB(val->bv_valuep))
                pt_seqno_prev = seqno;
            else
                seqno_prev = seqno;
        }

        if (unsorted > 0)
            hse_log(HSE_WARNING "%s: %p unsorted %u", __func__, bkv->bkv_key, unsorted);
    }

    seqno_prev = U64_MAX;
    pt_seqno_prev = U64_MAX;

    for (val = head; val; val = next) {
        int rc;

        next = val->bv_free;
        val->bv_free = NULL;

        seqnoref_to_seqno(val->bv_seqnoref, &seqno);

        rc = seq_prev_cmp(val->bv_valuep, seqno, seqno_prev, pt_seqno_prev);

        if (rc == 0)
            continue; /* dup */

        assert(val == head || rc <= 0);

        if (HSE_CORE_IS_PTOMB(val->bv_valuep))
            pt_seqno_prev = seqno;
        else
            seqno_prev = seqno;

        err = kvset_builder_add_val(
            bldr,
            seqno,
            bonsai_val_vlen(val) ? val->bv_value : val->bv_valuep,
            bonsai_val_ulen(val),
            bonsai_val_clen(val));

        if (ev(err))
            return err;
    }

    {
        struct key_obj ko;

        key2kobj(&ko, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));
        err = kvset_builder_add_key(bldr, &ko);
    }

    return err;
}

static void
c0sk_ingest_rec_perfc(struct perfc_set *perfc, u32 sidx, u64 cycles)
{
    if (!PERFC_ISON(perfc))
        return;

    cycles = (perfc_lat_start(perfc) - cycles) / (1000 * 1000);

    perfc_rec_sample(perfc, sidx, cycles);
}

void
c0sk_ingest_worker(struct work_struct *work)
{
    struct bin_heap2 *minheap HSE_ALIGNED(64);
    struct bonsai_kv *        bkv_prev;
    struct bonsai_kv *        bkv;
    struct kvset_builder *    bldr;
    struct kvset_builder **   bldrs;
    struct bonsai_val *       val_head;
    struct bonsai_val **      val_tailp;
    struct bonsai_val **      val_prevp;
    struct bonsai_val *       val;
    u64                       seqno;
    u16                       unsorted;
    s16                       debug;
    u16                       skidx_prev;
    u16                       skidx;
    merr_t                    err;
    struct cn *               cn;
    u64                       go = 0;

    /* Maintain separate ptomb seqno prev to distinguish b/w a key and a
     * ptomb from different KVMSes that have the same seqno.
     */
    u64 seqno_prev, pt_seqno_prev;

    struct c0_ingest_work *ingest;
    struct kvset_mblocks * mblocks;
    struct c0_kvmultiset * kvms;
    struct c0sk_impl *     c0sk;
    u32                    iterc;
    int                    i;
    struct kvset_mblocks **mbv;
    bool                   do_cn_ingest = false;
    u64                    ingestid;

    ingest = container_of(work, struct c0_ingest_work, c0iw_work);

    minheap = ingest->c0iw_minheap;
    bldrs = ingest->c0iw_bldrs;
    mblocks = ingest->c0iw_mblocks;
    iterc = ingest->c0iw_iterc;
    kvms = ingest->c0iw_c0kvms;
    mbv = ingest->c0iw_mbv;

    val_tailp = &val_head;
    val_prevp = NULL;
    val_head = NULL;

    c0sk = c0sk_h2r(ingest->c0iw_c0);
    debug = c0sk->c0sk_kvdb_rp->c0_debug & C0_DEBUG_INGSPILL;
    ingestid = CNDB_DFLT_INGESTID;
    err = 0;

    /* [HSE_REVISIT]
     * Abort all active transactions for now until LC is implemented.
     */
    c0kvms_abort_active(kvms);

    assert(c0sk->c0sk_kvdb_health);

    if (debug)
        ingest->t0 = get_time_ns();

    if (ev(iterc == 0))
        goto exit_err;

    if (c0sk->c0sk_kvdb_rp->c0_diag_mode)
        goto exit_err;

    while (HSE_UNLIKELY((c0sk->c0sk_kvdb_rp->c0_debug & C0_DEBUG_ACCUMULATE) && !c0sk->c0sk_syncing))
        cpu_relax();

    /* ingests do not stop on block deletion failures. */
    err = kvdb_health_check(
        c0sk->c0sk_kvdb_health, KVDB_HEALTH_FLAG_ALL & ~KVDB_HEALTH_FLAG_DELBLKFAIL);
    if (ev(err))
        goto exit_err;

    go = perfc_lat_start(&c0sk->c0sk_pc_ingest);

    /* this logic error cannot result in WA, not kvdb_health recordable */
    err = bin_heap2_prepare(minheap, iterc, ingest->c0iw_sourcev + HSE_C0_KVSET_ITER_MAX - iterc);
    if (ev(err))
        goto exit_err;

    if (debug)
        ingest->t3 = get_time_ns();

    seqno_prev = U64_MAX;
    pt_seqno_prev = U64_MAX;
    bkv_prev = NULL;
    skidx_prev = -1;
    unsorted = 0;
    bldr = NULL;
    seqno = 0;

    ingestid = c0kvms_rsvd_sn_get(kvms);

    /*
     */
    if (ingestid == HSE_SQNREF_INVALID)
        ingestid = CNDB_DFLT_INGESTID;

    /* Due to how sourcev[] is constructed by c0sk_coalesce(), the bin
     * heap returns identicals keys in order of youngest to oldest
     * disambiguated by skidx.
     *
     * [HSE_REVISIT]
     *   Get the ikvdb horizon sequence number and use it to discard
     *   values that need not be ingested.
     *
     *   Divide all values for a given key into two groups based on
     *   the KVDB's current horizon sequence number, HS.  The "newer"
     *   group consists of all values with seqno > HS, and the "older"
     *   group consists of all values with seqno <= HS.  The output kvset
     *   must contain all values in the newer group and only the newest
     *   value from the older group (i.e., the one with the largest
     *   sequence number).
     */
    while (bin_heap2_pop(minheap, (void **)&bkv)) {
        bool have_val = false;

        skidx = key_immediate_index(&bkv->bkv_key_imm);

        if (val_head && (bn_kv_cmp(bkv, bkv_prev) || skidx != skidx_prev)) {
            *val_tailp = NULL;

            err = c0sk_builder_add(bldr, kvms, bkv_prev, val_head, unsorted);
            if (ev(err))
                goto health_err;

            seqno_prev = U64_MAX;
            pt_seqno_prev = U64_MAX;
            val_tailp = &val_head;
            val_prevp = NULL;
            val_head = NULL;
            unsorted = 0;
        }

        bkv_prev = bkv;

        /* Append values from the current key to the list of values
         * from previous identical keys.  Swap adjacent values that
         * are out-of-order (in practice this is almost always
         * sufficient to keep the entire list sorted by seqno).
         */
        for (val = bkv->bkv_values; val; val = val->bv_next) {
            enum hse_seqno_state state;
            int                  rc;

            state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);
            assert(state == HSE_SQNREF_STATE_DEFINED || state == HSE_SQNREF_STATE_ABORTED);

            rc = seq_prev_cmp(val->bv_valuep, seqno, seqno_prev, pt_seqno_prev);

            if (state != HSE_SQNREF_STATE_DEFINED || rc == 0)
                continue;

            assert(seqno < U64_MAX);

            have_val = true;

            assert(!HSE_CORE_IS_PTOMB(val->bv_valuep) || (bkv->bkv_flags & BKV_FLAG_PTOMB));

            /* Insert value as penultimate if seqno is out-of-order.
             */
            if (rc > 0) {
                /* [HSE_REVISIT] Need to choose the right
                 * penultimate position when current key is
                 * non-ptomb and last key was a ptomb. Or vice
                 * versa.
                 * i.e. ptomb must be inserted before last
                 * ptomb and non-ptomb must be inserted before
                 * last non-ptomb instead of always inserting
                 * at previous position.
                 */
                val->bv_free = *val_prevp;
                *val_prevp = val;
                val_prevp = &val->bv_free;

                ++unsorted;
                continue;
            }

            /* Otherwise, append value to the tail of the list.
             */
            val_prevp = val_tailp;
            *val_tailp = val;
            val_tailp = &val->bv_free;

            if (HSE_CORE_IS_PTOMB(val->bv_valuep))
                pt_seqno_prev = seqno;
            else
                seqno_prev = seqno;
        }

        if (have_val && skidx != skidx_prev) {
            skidx_prev = skidx;
            bldr = bldrs[skidx];
            if (!bldr) {
                cn = c0sk->c0sk_cnv[skidx];
                assert(cn);
                err = kvset_builder_create(
                    &bldr,
                    cn,
                    cn_get_ingest_perfc(c0sk->c0sk_cnv[skidx]),
                    get_time_ns(),
                    KVSET_BUILDER_FLAGS_INGEST);
                if (ev(err))
                    goto health_err;

                kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_ROOT);

                bldrs[skidx] = bldr;
            }
        }
    }

    if (val_head) {
        *val_tailp = NULL;

        err = c0sk_builder_add(bldr, kvms, bkv_prev, val_head, unsorted);
        if (ev(err))
            goto health_err;

        val_head = NULL;
    }

    if (debug)
        ingest->t4 = get_time_ns();

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        if (bldrs[i] == 0)
            continue;

        mbv[i] = &mblocks[i];
        err = kvset_builder_get_mblocks(bldrs[i], &mblocks[i]);
        if (ev(err))
            goto health_err;
    }

    if (debug)
        ingest->t5 = get_time_ns();

    do_cn_ingest = !c0sk->c0sk_kvdb_rp->read_only;

health_err:
    if (err)
        kvdb_health_error(c0sk->c0sk_kvdb_health, err);

exit_err:
    if (err) {
        *val_tailp = NULL;

        while ((val = val_head)) {
            val_head = val->bv_free;
            val->bv_free = NULL;
        }
    }

    mutex_lock(&c0sk->c0sk_kvms_mutex);
    while (1) {
        if (kvms == c0sk_get_last_c0kvms(&c0sk->c0sk_handle))
            break;

        cv_wait(&c0sk->c0sk_kvms_cv, &c0sk->c0sk_kvms_mutex);
    }
    mutex_unlock(&c0sk->c0sk_kvms_mutex);

    if (do_cn_ingest) {

        c0sk_ingest_rec_perfc(&c0sk->c0sk_pc_ingest, PERFC_DI_C0SKING_PREP, go);

        go = perfc_lat_start(&c0sk->c0sk_pc_ingest);

        err = cn_ingestv(c0sk->c0sk_cnv, mbv, ingestid, HSE_KVS_COUNT_MAX);

        c0sk_ingest_rec_perfc(&c0sk->c0sk_pc_ingest, PERFC_DI_C0SKING_FIN, go);
        if (ev(err))
            kvdb_health_error(c0sk->c0sk_kvdb_health, err);
    }

    if (debug)
        ingest->t6 = get_time_ns();

    if (ev(err))
        hse_elog(HSE_ERR "c0 ingest failed on %p: @@e", err, kvms);

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        if (bldrs[i] == 0)
            continue;

        kvset_mblocks_destroy(&mblocks[i]);
        kvset_builder_destroy(bldrs[i]);

        bldrs[i] = NULL;
    }

    if (debug) {
        ingest->t7 = get_time_ns();

        ingest->gen = c0kvms_gen_read(kvms);
        ingest->gencur = c0kvms_gen_current(kvms);
    }

    c0sk_kvmultiset_ingest_completion(c0sk, kvms);
}

/**
 * c0sk_ingest_worker_start() - start c0 ingest of given ingest work
 * @self:       ptr to c0sk
 * @ingest:     ptr to ingest work buffer
 *
 * Enqueue the list of ingest buffers...
 */
static void
c0sk_ingest_worker_start(struct c0sk_impl *self, struct c0_ingest_work *ingest)
{
    struct c0_ingest_work *next;

    while (ingest) {
        next = ingest->c0iw_next;

        ingest->c0iw_tenqueued = get_time_ns();
        INIT_WORK(&ingest->c0iw_work, c0sk_ingest_worker);
        queue_work(self->c0sk_wq_ingest, &ingest->c0iw_work);

        ingest = next;
    }
}

/**
 * c0sk_coalesce() - combine several small kvms into one large ingest
 * @self:       ptr to c0sk
 * @kvms:       ptr to kvms to coalesce
 *
 * c0sk_coalesce() attempts to aggregate multiple kvms into a single ingest
 * work buffer in effort to avoid small cn ingest operations.  This is
 * accomplished by delaying a given kvms and then combining subsequently
 * generated kvms to the kvms that was originally delayed.  Eventually
 * the originally delayed kvms becomes full, its guard timer expires, or
 * a kvms arrives that must not be delayed.  At this point, the entire
 * batch of delayed kvms must be spilled (i.e., sent off the c0 ingest
 * worker to be persisted and delivered to cn), thereby allowing the
 * coalescing mechanism to restart with the arrival of the next kvms.
 *
 * Each kvms has an ingest delay parameter which dictates the maximum
 * amount of time a finalized kvms may stay in the coalesing state before
 * it must be persisted.  kvms that are full or "synced" have a delay
 * of zero so that they will be spilled immediately.
 */
static void
c0sk_coalesce(struct c0sk_impl *self, struct c0_kvmultiset *kvms)
{
    struct c0_ingest_work *new, *old;
    u64 delay;
    u64 used;
    u64 hwm;

    new = c0kvms_ingest_work_prepare(kvms, self);
    used = c0kvms_used_get(kvms);
    hwm = self->c0sk_kvdb_rp->c0_coalesce_sz * 1024 * 1024;
    hwm = (hwm * 80) / 100;

    if (!hwm || self->c0sk_closing)
        delay = 0;
    else
        delay = c0kvms_ingest_delay_get(kvms);

    old = self->c0sk_coalesce_head;
    if (old) {
        u32 oiterc = old->c0iw_iterc;
        u32 niterc = new->c0iw_iterc;

        if (oiterc + niterc < HSE_C0_KVSET_ITER_MAX) {
            struct c0_kvset_iterator *iterv;
            struct element_source **  sourcev;

            memcpy(
                old->c0iw_sourcev + HSE_C0_KVSET_ITER_MAX - (oiterc + niterc),
                new->c0iw_sourcev + HSE_C0_KVSET_ITER_MAX - niterc,
                sizeof(*sourcev) * niterc);

            memcpy(
                old->c0iw_iterv + HSE_C0_KVSET_ITER_MAX - (oiterc + niterc),
                new->c0iw_iterv + HSE_C0_KVSET_ITER_MAX - niterc,
                sizeof(*iterv) * niterc);

            old->c0iw_iterc += niterc;
            assert(old->c0iw_iterc < HSE_C0_KVSET_ITER_MAX);

            new->c0iw_iterc = 0;
            *old->c0iw_tailp = new;
            old->c0iw_tailp = new->c0iw_tailp;

            old->c0iw_coalscedkvms[old->c0iw_coalescec] = kvms;
            old->c0iw_coalescec++;

            self->c0sk_coalesce_sz += used;
            self->c0sk_coalesce_cnt += 1;

            /* [HSE_REVISIT] For now, don't let coalesce list
             * get too big (size and length).
             */
            if (self->c0sk_coalesce_sz >= hwm || self->c0sk_coalesce_cnt > 16)
                delay = 0;

            if (old->c0iw_iterc >= HSE_C0_KVSET_ITER_MAX * 75 / 100)
                delay = 0;

            if (delay > 0)
                return;

            hse_log(
                HSE_DEBUG "c0sk_coalesce c0sk_coalesce_sz %ld "
                          "hwm %ld c0sk_coalesce_cnt %ld "
                          "c0iw_iterc %ld iter_max %d",
                (long)self->c0sk_coalesce_sz,
                (long)hwm,
                (long)self->c0sk_coalesce_cnt,
                (long)old->c0iw_iterc,
                HSE_C0_KVSET_ITER_MAX);

            new = NULL;
        }

        assert(!old || old->c0iw_iterc < HSE_C0_KVSET_ITER_MAX);
        c0sk_ingest_worker_start(self, old);
        self->c0sk_coalesce_head = NULL;
        self->c0sk_coalesce_sz = 0;
        self->c0sk_coalesce_cnt = 0;
    } else {
        new->c0iw_coalscedkvms[0] = kvms;
        new->c0iw_coalescec = 1;
    }

    if (delay > 0 && used < hwm) {
        self->c0sk_coalesce_head = new;
        self->c0sk_coalesce_sz = used;
        self->c0sk_coalesce_cnt = 1;
        return;
    }

    assert(!new || new->c0iw_iterc < HSE_C0_KVSET_ITER_MAX);
    c0sk_ingest_worker_start(self, new);

    assert(!self->c0sk_coalesce_head);
    assert(self->c0sk_coalesce_sz == 0);
    assert(self->c0sk_coalesce_cnt == 0);
}

/**
 * c0sk_rcu_sync_cb() - process the RCU pending queue after current grace period
 * @work:   ptr to work struct embedded in c0sk_impl.
 *
 * c0sk_rcu_sync_cb() is the asynchronous completion handler for work
 * initiated by c0sk_rcu_sync().  Its purpose is to decouple callers of
 * c0sk_rcu_sync() from having to wait in-band for the end of the current
 * RCU grace period, and also to batch work for more efficent post
 * processing.
 *
 * c0sk_rcu_sync_cb() moves the requests from the c0sk pending queue to a
 * local pending queue, waits until the end of the current RCU grace period,
 * then processes each kvmultiset on the local pending queue.
 *
 * kvmultisets in the finalized state are simply discarded (they likely
 * arrived here via c0sk_release_multiset()).  kvmultisets that are not
 * in the finalized state require ingest processing, and hence are put
 * on the ingest work queue.
 *
 * This callback reschedules itself ad nauseum until the c0sk pending
 * queue is empty.
 */
static void
c0sk_rcu_sync_cb(struct work_struct *work)
{
    struct c0_kvmultiset *kvms, *next;
    struct list_head      pending, done;
    struct c0sk_impl *    self;
    bool                  more;

    self = container_of(work, struct c0sk_impl, c0sk_rcu_work);

    INIT_LIST_HEAD(&pending);
    INIT_LIST_HEAD(&done);

    mutex_lock(&self->c0sk_kvms_mutex);
    list_splice_tail(&self->c0sk_rcu_pending, &pending);
    INIT_LIST_HEAD(&self->c0sk_rcu_pending);
    mutex_unlock(&self->c0sk_kvms_mutex);

    synchronize_rcu();

    list_for_each_entry_safe (kvms, next, &pending, c0ms_rcu) {
        if (c0kvms_is_finalized(kvms)) {
            list_add_tail(&kvms->c0ms_rcu, &done);
            continue;
        }

        c0kvms_finalize(kvms, self->c0sk_wq_maint);
        c0sk_coalesce(self, kvms);
    }

    mutex_lock(&self->c0sk_kvms_mutex);
    more = !list_empty(&self->c0sk_rcu_pending);
    self->c0sk_rcu_active = more;
    mutex_unlock(&self->c0sk_kvms_mutex);

    if (more)
        queue_work(self->c0sk_wq_maint, work);

    list_for_each_entry_safe (kvms, next, &done, c0ms_rcu)
        c0kvms_putref(kvms);
}

/**
 * c0sk_rcu_sync() - start ingest processing of a kvms
 * @self:      the owning c0sk
 * @c0kvms:    the kvms to ingest
 *
 * c0sk_rcu_sync() enqueues %c0kvms onto the c0sk pending ingest queue
 * for asynchronous batch ingest processing.  If the batch processor is
 * not already running it is started.
 *
 * Note that requests on the pending queue are in strict FIFO ordering.
 *
 * c0sk_rcu_sync() will wait asynchronously (via c0sk_rcu_sync_cb()) for all
 * updaters currently in the bonsai tree to exit their RCU read-side critical
 * sections. After the current RCU grace period, c0sk_rcu_sync_cb() will put
 * the %c0kvms on to the c0 ingest work queue for further ingest processing.
 */
static void
c0sk_rcu_sync(struct c0sk_impl *self, struct c0_kvmultiset *c0kvms, bool start)
{
    mutex_lock(&self->c0sk_kvms_mutex);
    start = (start || !list_empty(&c0kvms->c0ms_rcu)) && !self->c0sk_rcu_active;
    list_add_tail(&c0kvms->c0ms_rcu, &self->c0sk_rcu_pending);
    if (start)
        self->c0sk_rcu_active = start;
    mutex_unlock(&self->c0sk_kvms_mutex);

    if (start) {
        INIT_WORK(&self->c0sk_rcu_work, c0sk_rcu_sync_cb);
        queue_work(self->c0sk_wq_maint, &self->c0sk_rcu_work);
    }
}

/*
 * NB: do NOT define MTF_MOCK_IMPL_, so all callers can be usurped.
 * The pragmas allow for proper compilation when IMPL is not defined.
 */

#pragma push_macro("c0sk_release_multiset")
#undef c0sk_release_multiset

void
c0sk_release_multiset(struct c0sk_impl *self, struct c0_kvmultiset *multiset)
{
    struct c0_kvmultiset *p;
    size_t                used;
    u64                   gen;

    used = c0kvms_used_get(multiset);
    gen = c0kvms_gen_read(multiset);

    mutex_lock(&self->c0sk_kvms_mutex);
    assert(self->c0sk_release_gen < gen);
    self->c0sk_release_gen = gen;

    cds_list_for_each_entry_reverse(p, &self->c0sk_kvmultisets, c0ms_link)
    {
        if (p == multiset) {
            cds_list_del_rcu(&p->c0ms_link);
            self->c0sk_kvmultisets_sz -= used;
            self->c0sk_kvmultisets_cnt -= 1;
            c0sk_adjust_throttling(self);
            cv_broadcast(&self->c0sk_kvms_cv);
            break;
        }
    }
    mutex_unlock(&self->c0sk_kvms_mutex);

    perfc_set(&self->c0sk_pc_ingest, PERFC_BA_C0SKING_QLEN, self->c0sk_kvmultisets_cnt);

    /* We must wait (via c0sk_rcu_sync()) for all threads iterating over
     * c0sk_kvmultisets (e.g., c0sk_get()) to exit their read-side critical
     * sections before we release (and likely destroy) the multiset.
     */
    c0sk_rcu_sync(self, multiset, self->c0sk_closing);
}

#pragma pop_macro("c0sk_release_multiset")

/**
 * c0sk_ingest_boost() - return %true if ingest boost is required
 * @self:       ptr to c0sk_impl
 *
 * It is desirable to boost the ingest process if the caller is a mongod
 * replication worker thread.
 */
static bool
c0sk_ingest_boost(struct c0sk_impl *self)
{
    struct kvdb_rparams *rp = self->c0sk_kvdb_rp;
    char                 namebuf[16];
    int                  rc;

    if (rp->throttle_relax) {
        rc = pthread_getname_np(pthread_self(), namebuf, sizeof(namebuf));

        if (!rc && 0 == strncmp(namebuf, "repl wr", 7))
            return true;
    }

    return (rp->throttle_relax > 1);
}

/**
 * conc2width() - choose a kvms width based on given concurrency
 * @conc:   estimated number of threads issuing put/get/del requests
 *
 * The idea being that the width should always be larger than the
 * given concurrency.
 */
static uint
conc2width(struct c0sk_impl *self, uint conc)
{
    static u8 cwtab[] = {
        8, 8, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68,
    };

    conc = min_t(uint, conc, NELEM(cwtab) - 1);

    return cwtab[conc];
}

/**
 * c0sk_ingest_tune() - dynamically tune c0sk for next ingest buffer size
 * @self:       ptr to c0sk_impl
 * @usage:      usage statistics of most recently ingested kvms
 */
static void
c0sk_ingest_tune(struct c0sk_impl *self, struct c0_usage *usage)
{
    struct kvdb_rparams *rp = self->c0sk_kvdb_rp;

    size_t oldsz, newsz, pct_used, pct_diff;
    uint width, width_max;

    width_max = HSE_C0_INGEST_WIDTH_MAX;
    oldsz = pct_used = pct_diff = 0;

    /* A mongod replica node requires a maximally provisioned
     * kvms with throttling disabled in order to mitigate lag.
     */
    if (c0sk_ingest_boost(self)) {
        rp->throttle_disable |= 0x80u;
        self->c0sk_boost = 4;
    }
    else if (self->c0sk_boost > 0) {
        rp->throttle_disable |= 0x80u;
        self->c0sk_boost--;
    }
    else {
        width_max = self->c0sk_ingest_width_max;
        rp->throttle_disable &= ~0x80u;
    }

    /* Determine the ingest width hint for the next ingest based on
     * the number of threads waiting for this ingest to complete.
     */
    width = rp->c0_ingest_width;
    if (width == 0) {
        width = conc2width(self, self->c0sk_ingest_conc);
        width = min_t(uint, width, width_max);

        if (width < self->c0sk_ingest_width)
            width = (width + self->c0sk_ingest_width * 15) / 16;
    }

    /* Adjust the cheap size for the next ingest such that the aggregate
     * ingest buffer size is roughly consistent irrespective of width.
     * If the last buffer was underutilized then adjust the settings
     * to achieve something close to 95% utilization.
     */
    newsz = rp->c0_heap_sz;
    if (newsz == 0) {
        size_t diff = usage->u_used_max - usage->u_used_min;
        size_t used = usage->u_alloc - usage->u_free;

        pct_diff = diff * 100 * usage->u_count / usage->u_alloc;
        pct_used = used * 100 / usage->u_alloc + 1;

        oldsz = self->c0sk_cheap_sz / 1048576;
        newsz = HSE_C0_INGEST_SZ_MAX / width;

        if (pct_diff > 15 && pct_used < 85) {
            pct_diff = min_t(size_t, pct_diff, 99);
            newsz = newsz * 115 / (100 - pct_diff);
            newsz = (newsz + oldsz * 3) / 4;

            width = width * (100 - pct_diff) / 115;
        } else {
            newsz = (newsz + oldsz * 3) / 4;
            newsz = newsz * pct_used / 100;
        }
    }

    if (width * newsz > HSE_C0_INGEST_SZ_MAX)
        width = HSE_C0_INGEST_SZ_MAX / newsz;

    newsz *= 1048576;
    newsz = min_t(size_t, newsz, HSE_C0_CHEAP_SZ_MAX);
    newsz = max_t(size_t, newsz, HSE_C0_CHEAP_SZ_MIN);

    width = min_t(uint, width, width_max);
    width = max_t(uint, width, HSE_C0_INGEST_WIDTH_MIN);

    self->c0sk_ingest_width = width;
    self->c0sk_cheap_sz = newsz;

    if (rp->c0_debug & C0_DEBUG_INGTUNE)
        hse_log(HSE_NOTICE
                "%s: used %zu%% diff %zu%%, %zu -> %zu (%zu) width %u/%u/%u, conc %u, boost %u, keys %lu",
                __func__, pct_used, pct_diff,
                oldsz, newsz / 1048576ul, (width * newsz) / 1048576ul,
                width, width_max, self->c0sk_ingest_width_max,
                self->c0sk_ingest_conc, self->c0sk_boost,
                usage->u_keys);
}

BullseyeCoverageSaveOff

merr_t
c0sk_queue_ingest(struct c0sk_impl *self, struct c0_kvmultiset *old, struct c0_kvmultiset *new)
{
    struct mtx_node *   node;
    struct c0_usage     usage = { 0 };

    bool   leader, created;
    u64    cycles;
    uint   conc;
    merr_t err;

genchk:
    if (c0kvms_gen_read(old) < atomic64_read(&self->c0sk_ingest_gen))
        return new ? merr(EAGAIN) : 0;

    cycles = get_cycles(); /* Use TSC as an RNG */

    if (c0kvms_is_ingesting(old)) {
        conc = atomic_read(&self->c0sk_ingest_ldr);

        /* If there are already a sufficient number of waiters
         * for tuning purposes then poll until old is ingested
         * or the leader resigns.
         */
        if (conc2width(self, conc) >= self->c0sk_ingest_width_max) {
            struct timespec req = { .tv_nsec = 100 };

            if (cycles % 64 < 8)
                nanosleep(&req, NULL);
            else
                cpu_relax();

            goto genchk;
        }
    }

    c0kvms_ingesting(old);

    node = mtx_pool_lock(self->c0sk_mtx_pool, cycles >> 1);

    conc = atomic_inc_return(&self->c0sk_ingest_ldr);
    leader = (conc == 1);

    if (!leader && conc2width(self, conc - 1) < self->c0sk_ingest_width_max)
        mtx_pool_wait(node);
    mtx_pool_unlock(node);

    if (!leader)
        goto genchk;

    created = false;
    err = 0;

    if (c0kvms_gen_read(old) < atomic64_read(&self->c0sk_ingest_gen)) {
        err = new ? merr(EAGAIN) : 0;
        goto resign;
    }

    /* Sample and save the current usage of old for tuning and
     * throttling.  It may not be 100% accurate, but should be
     * close enough to the finalized result.
     */
    c0kvms_usage(old, &usage);
    c0kvms_used_set(old, usage.u_alloc - usage.u_free);

    if (ev(new)) {
        /* do nothing */
    } else {
        c0sk_ingest_tune(self, &usage);

        err = c0kvms_create(
            self->c0sk_ingest_width,
            self->c0sk_cheap_sz,
            self->c0sk_kvdb_rp->c0_ingest_delay,
            self->c0sk_kvdb_seq,
            &new);

        created = !err;
    }

    if (new) {
        if (c0sk_install_c0kvms(self, old, new)) {
            c0sk_rcu_sync(self, old, true);
        } else {
            if (created)
                c0kvms_putref(new);
            err = merr(EAGAIN);
            created = false;
            ev(1);
        }
    }

    /* Resign as leader and awaken all waiters...
     */
resign:
    mtx_pool_lock_all(self->c0sk_mtx_pool);
    if (created)
        self->c0sk_ingest_conc = atomic_read(&self->c0sk_ingest_ldr);
    atomic_set(&self->c0sk_ingest_ldr, 0);
    mtx_pool_unlock_all(self->c0sk_mtx_pool, true);

    if (leader && usage.u_keyb)
        perfc_rec_sample(
            &self->c0sk_pc_ingest, PERFC_DI_C0SKING_KVMSDSIZE, (usage.u_keyb + usage.u_valb) >> 10);
    return err;
}

BullseyeCoverageRestore

/*
 * Flush the present kvmultiset (queue it for ingest).
 * For sync(), we need to know when this c0kvms has been ingested.
 */
merr_t
c0sk_flush_current_multiset(struct c0sk_impl *self, struct c0_kvmultiset *new, u64 *genp)
{
    struct c0_kvmultiset *old;
    merr_t                err;

again:
    rcu_read_lock();

    old = c0sk_get_first_c0kvms(&self->c0sk_handle);
    if (old)
        c0kvms_getref(old);

    rcu_read_unlock();

    if (ev(!old))
        return merr(ENXIO);

    if (genp) {
        *genp = c0kvms_gen_read(old);
        c0kvms_ingest_delay_set(old, 0);

        /* Caller intends to wait on this flush to be persisted.  To ameliorate
         * the generation of small kvsets we linger around a bit in hopes of
         * piggybacking upon a naturally occuring flush.  This works well if
         * the ingest rate is high.  If the ingest rate is low it simply
         * serves to limit the sync frequency to roughly dur_intvl_ms.
         */
        if (!self->c0sk_closing && !new) {
            long waitmax = self->c0sk_kvdb_rp->dur_intvl_ms / 2;
            long delay = min_t(long, waitmax / 10 + 1, 100);

#if 1
            char namebuf[16];
            int rc;

            rc = pthread_getname_np(pthread_self(), namebuf, sizeof(namebuf));

            /* [HSE_REVISIT] Restrict mongod to syncing no more than once
             * every ten seconds as syncing more frequently generates tiny
             * kvsets that wreak havoc on cn (e.g., capped kvs' can grow
             * spectacularly long...)
             * Remove this once the new WAL is in place.
             */
            if (!rc && 0 == strncmp(namebuf, "KVDBJou.Flusher", 15)) {
                if (c0kvms_ctime(old) + NSEC_PER_SEC * 10 > get_time_ns()) {
                    c0kvms_putref(old);
                    return EAGAIN;
                }
            }
#endif

            while ((waitmax -= delay) > 0) {
                struct c0_kvmultiset *cur;

                usleep(delay * 1000);

                rcu_read_lock();
                cur = c0sk_get_first_c0kvms(&self->c0sk_handle);
                rcu_read_unlock();

                if (cur != old) {
                    c0kvms_putref(old);
                    return 0;
                }
            }
        }
    }

    err = c0sk_queue_ingest(self, old, new);

    c0kvms_putref(old);

    if (new && merr_errno(err) == EAGAIN)
        goto again;

    return ev(err);
}

/*
 * Client applications of c0sk have three entry points: put, delete, and get.
 * Both put and del modify the contents of c0sk - i.e., they are writers.
 * To reduce the amount of complex code both put and del are funneled through
 * a common function, c0sk_putdel().
 */
merr_t
c0sk_putdel(
    struct c0sk_impl *       self,
    u32                      skidx,
    enum c0sk_op             op,
    const struct kvs_ktuple *kt,
    const struct kvs_vtuple *vt,
    uintptr_t                seqnoref)
{
    merr_t err;
    bool is_txn = (seqnoref != HSE_SQNREF_SINGLE);

    while (1) {
        struct c0_kvmultiset   *dst;
        struct c0_kvset        *kvs;
        bool                    first_entry = false;
        uintptr_t              *entry = NULL;
        uintptr_t              *priv = (uintptr_t *)seqnoref;
        u64                     dst_gen;

        rcu_read_lock();
        dst = c0sk_get_first_c0kvms(&self->c0sk_handle);
        if (ev(!dst, HSE_WARNING)) {
            rcu_read_unlock();
            return merr(EINVAL);
        }

        if (ev(c0kvms_should_ingest(dst))) {
            err = merr(ENOMEM);
            goto unlock;
        }

        if (is_txn) {
            u64 curr_gen = c0snr_get_cgen(priv);

            dst_gen = c0kvms_gen_read(dst);
            first_entry = (curr_gen != dst_gen);

            if (first_entry) {
                /* This is the first put for the given txn.
                 * Although C0SNRs can be reused as transactions abort/commit, a C0SNR
                 * within a KVMS is associated with at most one transaction.
                 * Within the context of the put, the C0SNR cannot be reused.
                 * It can only be freed at transaction commit/abort.
                 * The transaction put is still ongoing and prevents any other activity
                 * within the same transaction including commits/aborts.
                 */
                entry = c0kvms_c0snr_alloc(dst);
                if (ev(!entry)) {
                    err = merr(ENOMEM);
                    goto unlock;
                }
            }
        }

        kvs = c0kvms_get_hashed_c0kvset(dst, kt->kt_hash);

        if (op == C0SK_OP_PUT) {
            err = c0kvs_put(kvs, skidx, kt, vt, seqnoref);
        } else if (op == C0SK_OP_DEL) {
            err = c0kvs_del(kvs, skidx, kt, seqnoref);
        } else {
            assert(op == C0SK_OP_PREFIX_DEL);

            /* Ignore hashed kvset. Use ptomb kvset. */
            kvs = c0kvms_ptomb_c0kvset_get(dst);
            err = c0kvs_prefix_del(kvs, skidx, kt, seqnoref);
        }

        assert(!c0kvms_is_finalized(dst)); /* See c0kvs_putdel() */

        if (first_entry) {
            assert(entry);
            if (!err) {
                /*
                 * Acquire a ref on the C0SNR. This prevents it from being
                 * freed/reused by another transaction. It is released at
                 * the time of KVMS destroy.
                 */
                *entry = seqnoref;
                c0snr_getref(priv, dst_gen);
            } else {
                *entry = 0;
            }
        }

    unlock:
        if (merr_errno(err) == ENOMEM)
            c0kvms_getref(dst);

        rcu_read_unlock();

        if (merr_errno(err) != ENOMEM)
            break;

        c0sk_queue_ingest(self, dst, NULL);
        c0kvms_putref(dst);
    }

    return err;
}

#if HSE_MOCKING
#include "c0sk_internal_ut_impl.i"
#endif /* HSE_MOCKING */
