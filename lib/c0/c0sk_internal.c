/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/log2.h>
#include <hse_util/table.h>
#include <hse_util/xrand.h>
#include <hse_util/cds_list.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/bkv_collection.h>

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0snr_set.h>
#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/lc.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>
#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/rparam_debug_flags.h>
#include <hse_ikvdb/kvdb_ctxn.h>

#include "c0sk_internal.h"
#include "c0_ingest_work.h"

/* The c0sk throttle is used to try and prevent a large backlog of finalized
 * c0kvms waiting to be spilled, as a large backlog is a good indicator that
 * there are currently insufficient resources (i.e., cpu and media bandwidth)
 * available to quickly process and write the k/v tuples to media.
 *
 * See 'struct throttle_sensor' for guidelines on setting sensor values.
 */
int
c0sk_adjust_throttling(struct c0sk_impl *self)
{
    const struct kvdb_rparams *rp = self->c0sk_kvdb_rp;
    int finlat, hwm, new;

    if (!self->c0sk_sensor)
        return 0;

    /* Use the ingest finish latency (i.e., the running average time it takes
     * to process and write k/v tuples to media) to adjust the hwm to try and
     * maintain a max backlog of between 2.9 and 5.2 c0kvms (based upon the
     * default value of throttle_c0_hi_th=3.5).
     */
    finlat = atomic_read(&self->c0sk_ingest_finlat);
    hwm = finlat / 1000;
    if (hwm > 23)
        hwm = 23;

    hwm = rp->throttle_c0_hi_th + (17 - hwm);

    new = (self->c0sk_kvmultisets_cnt * THROTTLE_SENSOR_SCALE * 10) / hwm;

    throttle_sensor_set(self->c0sk_sensor, new);

    return new;
}

static uint64_t
c0sk_txhorizon_get(struct c0sk_impl *c0sk)
{
    struct ikvdb *ikvdb;

    if (!c0sk->c0sk_cb)
        return CNDB_INVAL_HORIZON;

    ikvdb = c0sk->c0sk_cb->kc_cbarg;

    return ikvdb_txn_horizon(ikvdb);
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

    if (HSE_UNLIKELY(atomic_read(&c0sk->c0sk_replaying) > 0))
        return;

    /* flush from txcommit context; reverve seqno for txn. */

    res = (inc - 1) + atomic64_fetch_add_rel(inc, c0sk->c0sk_kvdb_seq);

    c0kvms_rsvd_sn_set(kvms, res);
}

bool
c0sk_install_c0kvms(struct c0sk_impl *self, struct c0_kvmultiset *old, struct c0_kvmultiset *new)
{
    struct c0_kvmultiset *first;

    /* Set old kvms seqno to kvdb's seqno + 1 before freezing it.
     * The increment is necessary since this is also used as the upper bound by the
     * ingest thread.
     */
    if (old) {
        u64 seqno;

        c0kvms_txhorizon_set(old, c0sk_txhorizon_get(self));

        seqno = (HSE_UNLIKELY(atomic_read(&self->c0sk_replaying) > 0)) ?
            atomic64_read(self->c0sk_kvdb_seq) : atomic64_inc_acq(self->c0sk_kvdb_seq);
        c0kvms_seqno_set(old, seqno);
    }

    mutex_lock(&self->c0sk_kvms_mutex);
    first = c0sk_get_first_c0kvms(&self->c0sk_handle);
    if (first == old) {
        c0kvms_gen_update(new);

        cds_list_add_rcu(&new->c0ms_link, &self->c0sk_kvmultisets);

        c0sk_rsvd_sn_set(self, new);

        self->c0sk_kvmultisets_cnt += 1;
        c0sk_adjust_throttling(self);
    }
    mutex_unlock(&self->c0sk_kvms_mutex);

    perfc_set(&self->c0sk_pc_ingest, PERFC_BA_C0SKING_QLEN, self->c0sk_kvmultisets_cnt);
    perfc_set(&self->c0sk_pc_ingest, PERFC_BA_C0SKING_WIDTH, self->c0sk_ingest_width);

    return (first == old);
}

static void
c0sk_signal_waiters(struct c0sk_impl *c0sk, u64 gen)
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

/* Compare seqno with the correct previous seqno - ptomb or other
 *
 *  1 : seqno > prev
 * -1 : seqno < prev
 *  0 : seqno == prev
 */
static HSE_ALWAYS_INLINE int
seq_prev_cmp(void *valp, u64 seq, u64 seq_prev, u64 pt_seq_prev)
{
    u64 prev;

    prev = HSE_CORE_IS_PTOMB(valp) ? pt_seq_prev : seq_prev;

    if (seq == prev)
        return 0;

    return seq < prev ? -1 : 1;
}

static void
c0sk_bkv_sort_vals(struct bonsai_kv *bkv, struct bonsai_val **val_head)
{
    struct bonsai_val *val, *next;
    u64                seqno_prev, pt_seqno_prev;
    u64                seqno;
    u32                unsorted;

    seqno = 0;

    /* [HSE_REVISIT] It should be rare that the list contains more than
     * a few items, and even more rare that we need to actually sort
     * the list.  However, should we find a recurrent case to the contrary
     * we'll need either a better sort or a better approach...
     */
    do {
        struct bonsai_val **tailp, **prevp;

        seqno_prev = U64_MAX;
        pt_seqno_prev = U64_MAX;
        tailp = val_head;
        prevp = NULL;
        unsorted = 0;

        for (val = *val_head; val; val = next) {
            enum hse_seqno_state state HSE_MAYBE_UNUSED;
            int                        rc;

            next = val->bv_priv;
            state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);
            assert(state != HSE_SQNREF_STATE_ABORTED);

            rc = seq_prev_cmp(val->bv_value, seqno, seqno_prev, pt_seqno_prev);
            if (rc > 0) {
                *tailp = val->bv_priv;
                val->bv_priv = *prevp;
                *prevp = val;
                prevp = &val->bv_priv;

                ++unsorted;
                continue;
            }

            prevp = tailp;
            tailp = &val->bv_priv;
            if (HSE_CORE_IS_PTOMB(val->bv_value))
                pt_seqno_prev = seqno;
            else
                seqno_prev = seqno;
        }

        if (unsorted > 0)
            hse_log(HSE_WARNING "%s: %p unsorted %u", __func__, bkv->bkv_key, unsorted);
    } while (unsorted > 0);
}

/**
 * c0sk_cningest_cb() - Callback function for bkv_collection. Called once for every pair of
 *                      key and its value list.
 *
 * @rock:  Context - ingest worker object
 * @bkv:   Key
 * @vlist: List of values
 */
static merr_t
c0sk_cningest_cb(void *rock, struct bonsai_kv *bkv, struct bonsai_val *vlist)
{
    struct c0_ingest_work *ingest = rock;
    struct bonsai_val *    val;
    merr_t                 err;
    u64                    seqno_prev, pt_seqno_prev;
    struct key_obj         ko;

    u16                    skidx = key_immediate_index(&bkv->bkv_key_imm);
    struct c0sk_impl *     c0sk = c0sk_h2r(ingest->c0iw_c0sk);
    struct cn *            cn = c0sk->c0sk_cnv[skidx];
    struct kvset_builder **kvbldrs = ingest->c0iw_bldrs;
    struct kvset_builder * bldr = kvbldrs[skidx];

    assert(bkv);
    assert(vlist);

    if (!bldr) {
        assert(cn);
        err = kvset_builder_create(&bldr, cn, cn_get_ingest_perfc(cn), get_time_ns());
        if (ev(err))
            return err;

        kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_ROOT);
        kvbldrs[skidx] = bldr;
    }

    c0sk_bkv_sort_vals(bkv, &vlist);

    seqno_prev = U64_MAX;
    pt_seqno_prev = U64_MAX;

    for (val = vlist; val; val = val->bv_priv) {
        enum hse_seqno_state state HSE_MAYBE_UNUSED;
        int                        rc;
        u64                        seqno = 0;

        state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);
        assert(state == HSE_SQNREF_STATE_DEFINED);

        assert(seqno >= lc_ingest_seqno_get(c0sk->c0sk_lc));
        rc = seq_prev_cmp(val->bv_value, seqno, seqno_prev, pt_seqno_prev);
        if (rc == 0)
            continue; /* dup */

        assert(val == vlist || rc < 0);

        if (HSE_CORE_IS_PTOMB(val->bv_value))
            pt_seqno_prev = seqno;
        else
            seqno_prev = seqno;

        err = kvset_builder_add_val(
            bldr, seqno, val->bv_value, bonsai_val_ulen(val), bonsai_val_clen(val));

        if (ev(err))
            return err;
    }

    key2kobj(&ko, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));
    err = kvset_builder_add_key(bldr, &ko);
    if (ev(err))
        return err;

    return 0;
}

static void
c0sk_ingest_rec_perfc(struct perfc_set *perfc, u32 sidx, u64 cycles)
{
    if (!PERFC_ISON(perfc))
        return;

    cycles = (perfc_lat_start(perfc) - cycles) / (1000 * 1000);

    perfc_rec_sample(perfc, sidx, cycles);
}

static void
c0sk_cningest_walcb(
    struct c0sk_impl *c0sk,
    u64               seqno,
    u64               gen,
    u64               txhorizon,
    bool              post_ingest)
{
    struct ikvdb *ikvdb;

    if (!c0sk->c0sk_cb || !c0sk->c0sk_cb->kc_cningest_cb)
        return;

    ikvdb = c0sk->c0sk_cb->kc_cbarg;
    c0sk->c0sk_cb->kc_cningest_cb(ikvdb, seqno, gen, txhorizon, post_ingest);
}

/* Initial number of entries in cn ingest's bkv_collection.
 */
#define CN_INGEST_BKV_CNT (4UL << 20)

static merr_t
c0sk_merge_loop(
    struct bin_heap2 *     minheap,
    u64                    min_seqno,
    u64                    max_seqno,
    u64                    kvms_gen,
    struct bkv_collection *cn_list,
    struct lc_builder *    lc_list)
{
    struct bonsai_kv *  bkv, *bkv_prev;
    struct bonsai_val * cn_val_head, *lc_val_head;
    struct bonsai_val **cn_val_tailp, **lc_val_tailp;
    u16                 skidx_prev;
    merr_t              err = 0;

    /* Init value ptrs for cn ingest list and lc. */
    cn_val_tailp = &cn_val_head;
    cn_val_head = NULL;
    lc_val_tailp = &lc_val_head;
    lc_val_head = NULL;

    skidx_prev = -1;
    bkv_prev = NULL;

    while (bin_heap2_pop(minheap, (void **)&bkv)) {
        struct bonsai_val *val;
        bool               from_lc = bkv->bkv_flags & BKV_FLAG_FROM_LC;
        u16                skidx = key_immediate_index(&bkv->bkv_key_imm);

        if ((lc_val_head || cn_val_head) && ((bn_kv_cmp(bkv, bkv_prev) || skidx != skidx_prev))) {
            /* Close out val lists */
            *cn_val_tailp = NULL;
            *lc_val_tailp = NULL;

            if (lc_val_head) {
                assert(lc_list);
                err = lc_builder_add(lc_list, bkv_prev, lc_val_head);
                if (ev(err))
                    return err;
            }

            if (cn_val_head) {
                err = bkv_collection_add(cn_list, bkv_prev, cn_val_head);
                if (ev(err))
                    return err;
            }

            cn_val_tailp = &cn_val_head;
            cn_val_head = NULL;
            lc_val_tailp = &lc_val_head;
            lc_val_head = NULL;
        }

        bkv_prev = bkv;

        /* Append values from the current key to the list of values from previous identical keys.
         * Swap adjacent values that are out-of-order (in practice this is almost always sufficient
         * to keep the entire list sorted by seqno).
         */
        rcu_read_lock();
        for (val = rcu_dereference(bkv->bkv_values); val; val = rcu_dereference(val->bv_next)) {
            enum hse_seqno_state state;
            bool                 add_to_lc = true;
            bool                 seqno_in_view;
            bool                 all_txn_entries;
            u64                  seqno = 0;

            state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);
            assert(seqno < U64_MAX);

            if (state == HSE_SQNREF_STATE_ABORTED)
                continue;

            /* If this val has an ordinal seqno (i.e. non-txn val), its seqno must not exceed max_seqno.
             */
            assert(HSE_SQNREF_INDIRECT_P(val->bv_seqnoref) || seqno <= max_seqno);
            if (state == HSE_SQNREF_STATE_DEFINED && seqno < min_seqno) {
                assert(from_lc);
                continue; /* Not garbage collected yet. Ignore. */
            }

            seqno_in_view = state == HSE_SQNREF_STATE_DEFINED && seqno <= max_seqno;
            all_txn_entries = HSE_SQNREF_INDIRECT_P(val->bv_seqnoref) &&
                              kvms_gen >= c0snr_get_cgen((uintptr_t *)val->bv_seqnoref);

            /* In addition to being within this ingest's view, a kv-tuple must also satisfy one of
             * the following criteria to be eligible for ingest to cn:
             *   1. it's a non-txn entry, or
             *   2. it's a txn entry and all entries from the txn are available for ingest.
             */
            if (seqno_in_view && (HSE_SQNREF_ORDNL_P(val->bv_seqnoref) || all_txn_entries))
                add_to_lc = false;

            assert(!HSE_CORE_IS_PTOMB(val->bv_value) || (bkv->bkv_flags & BKV_FLAG_PTOMB));

            if (add_to_lc) {
                if (from_lc)
                    continue; /* don't add to LC again */

                *lc_val_tailp = val;
                lc_val_tailp = &val->bv_priv;
                continue;
            }

            *cn_val_tailp = val;
            cn_val_tailp = &val->bv_priv;
        }
        rcu_read_unlock();

        if (skidx != skidx_prev)
            skidx_prev = skidx;
    }

    if (lc_val_head) {
        *lc_val_tailp = NULL;

        assert(lc_list);
        err = lc_builder_add(lc_list, bkv_prev, lc_val_head);
        if (ev(err))
            return err;
    }

    if (cn_val_head) {
        *cn_val_tailp = NULL;

        err = bkv_collection_add(cn_list, bkv_prev, cn_val_head);
        if (ev(err))
            return err;
    }

    hse_log(
        HSE_DEBUG "%s: (%lu) Entries added: cn %lu lc %lu",
        __func__,
        pthread_self(),
        bkv_collection_count(cn_list),
        lc_list ? bkv_collection_count((void *)lc_list) : 0);

    return 0;
}

static void
c0sk_ingest_serialize_wait(struct c0_ingest_work *ingest)
{
    struct c0sk_impl *c0sk = c0sk_h2r(ingest->c0iw_c0sk);

    mutex_lock(&c0sk->c0sk_kvms_mutex);
    while (1) {
        u64 me = ingest->c0iw_ingest_order;
        u64 next = atomic64_read_acq(&c0sk->c0sk_ingest_order_next);

        if (me == next)
            break;

        cv_timedwait(&c0sk->c0sk_kvms_cv, &c0sk->c0sk_kvms_mutex, 1000);
    }
    mutex_unlock(&c0sk->c0sk_kvms_mutex);
}

/**
 * c0sk_ingest_worker() - Ingest worker thread
 *
 * @work: work object
 *
 * This thread reads kv-tuples from the KVMS and from LC. For each kv-tuple, the thread either
 * adds it to LC or ingests it into cn (except entries from aborted txns, which are discarded).
 * Unlike the KVMS, LC is a common structure that is used by all ingest threads. So entries added
 * to LC by ingest[n] will have to be considered for ingest by ingest[n+1]. For this reason part
 * of this operation must be serialized in the order in which ingests were enqueued.
 *
 * The ingest operation broadly consists of 4 stages:
 *
 *  1. Iterate over kv-pairs in the KVMS and add them to one of 2 lists: cn_list[0] and lc_list.
 *     Entries in cn_list[0] will be ingested into cn and entries in lc_list will be added to lc.
 *  2. Iterate over kv-pairs in LC and add them to cn_list[1] if they are ready for ingest.
 *  3. Update LC with the entries in lc_list.
 *  4. Merge cn_list[0] and cn_list[1] and add the resulting list of kv-pairs to cn using kvset
 *     builders.
 *
 * For all ingests, steps 2 and 3 need to be performed in ingest queuing order.
 */
void
c0sk_ingest_worker(struct work_struct *work)
{
    struct c0_ingest_work *ingest = container_of(work, struct c0_ingest_work, c0iw_work);
    struct c0sk_impl *     c0sk = c0sk_h2r(ingest->c0iw_c0sk);
    struct lc *            lc = c0sk_lc_get(ingest->c0iw_c0sk);
    struct kvset_mblocks * mblocks = ingest->c0iw_mblocks;
    struct kvset_mblocks **mbv = ingest->c0iw_mbv;
    struct c0_kvmultiset * kvms = ingest->c0iw_c0kvms;

    struct bin_heap2 *     kvms_minheap, *lc_minheap;
    struct bkv_collection *cn_list[2] = { 0 };
    struct lc_builder *    lc_list = { 0 };
    u64                    kvms_gen = c0kvms_gen_read(kvms);
    u64                    txhorizon = c0kvms_txhorizon_get(kvms);
    int                    i;
    u64                    go = 0;
    bool                   released = false;
    bool                   debug = c0sk->c0sk_kvdb_rp->c0_debug & C0_DEBUG_INGSPILL;
    bool                   accumulate = c0sk->c0sk_kvdb_rp->c0_debug & C0_DEBUG_ACCUMULATE;
    merr_t                 err = 0;

    /* Ingest everything in the range [min_seq, max_seq]. */
    u64 min_seq = ingest->c0iw_ingest_min_seqno;
    u64 max_seq = ingest->c0iw_ingest_max_seqno;

    assert(min_seq >= lc_ingest_seqno_get(lc));

    kvms_minheap = &ingest->c0iw_kvms_minheap;
    lc_minheap = &ingest->c0iw_lc_minheap;

    assert(c0sk->c0sk_kvdb_health);

    if (c0sk->c0sk_kvdb_rp->c0_diag_mode)
        goto exit_err;

    while (HSE_UNLIKELY(accumulate && !c0sk->c0sk_syncing))
        cpu_relax();

    /* ingests do not stop on block deletion failures. */
    err = kvdb_health_check(
        c0sk->c0sk_kvdb_health, KVDB_HEALTH_FLAG_ALL & ~KVDB_HEALTH_FLAG_DELBLKFAIL);
    if (ev(err))
        goto exit_err;

    go = perfc_lat_start(&c0sk->c0sk_pc_ingest);

    if (debug)
        ingest->t0 = get_time_ns();

    for (i = 0; i < 2; i++) {
        err = bkv_collection_create(&cn_list[i], CN_INGEST_BKV_CNT, &c0sk_cningest_cb, ingest);
        if (ev(err))
            goto exit_err;
    }

    err = lc_builder_create(lc, &lc_list);
    if (ev(err))
        goto exit_err;

    err = bin_heap2_prepare(kvms_minheap, ingest->c0iw_kvms_iterc, ingest->c0iw_kvms_sourcev);
    if (ev(err))
        goto exit_err;

    if (debug)
        ingest->t3 = get_time_ns();

    /* Ensure that all committed txns up to min_seq have finished.
     * TODO: Doesn't finalization make this unnecessary?
     */
    kvdb_ctxn_set_wait_commits(c0sk->c0sk_ctxn_set, 0);

    err = c0sk_merge_loop(kvms_minheap, min_seq, max_seq, kvms_gen, cn_list[0], lc_list);
    if (ev(err))
        goto health_err;

    if (debug)
        ingest->t4 = get_time_ns();

    /* Wait for older ingests to finish this sequential part */
    c0sk_ingest_serialize_wait(ingest);
    assert(atomic_inc_return(&c0sk->c0sk_ingest_serialized_cnt) == 1);

    c0sk_cningest_walcb(c0sk, max_seq, kvms_gen, txhorizon, false);

    /* Prepare LC's binheap in serialized section i.e. only after older ingests have updated LC.
     * A call to prepare moves the iterator forward and positions it at the first valid bkv (see
     * bonsai_ingest_iter_next() for the definition of a 'valid bkv').
     *
     * If LC's binheap is prepared before this sequential section, the binheap will be positioned
     * at the first bkv that was valid at the time. So any entry added to LC (by an older ingest
     * thread) that appears before this first entry would be missed.
     */
    err = bin_heap2_prepare(lc_minheap, ingest->c0iw_lc_iterc, ingest->c0iw_lc_sourcev);
    if (!err) {
        err = c0sk_merge_loop(lc_minheap, min_seq, max_seq, kvms_gen, cn_list[1], NULL);
        if (!err) {
            ingest->t5 = get_time_ns();

            /* Update lc with entries from kvms and lc */
            err = lc_builder_finish(lc_list);
        }
    }

    assert(atomic_dec_return(&c0sk->c0sk_ingest_serialized_cnt) == 0);

    if (ev(err))
        goto health_err;

    atomic64_inc_acq(&c0sk->c0sk_ingest_order_next); /* Move the ingest order forward */

    mutex_lock(&c0sk->c0sk_kvms_mutex);
    cv_broadcast(&c0sk->c0sk_kvms_cv); /* Wake up newer ingest threads */
    mutex_unlock(&c0sk->c0sk_kvms_mutex);
    released = true;

    ingest->t6 = get_time_ns();

    err = bkv_collection_finish_pair(cn_list[0], cn_list[1]);
    if (ev(err))
        goto health_err;

    ingest->t7 = get_time_ns();

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        if (ingest->c0iw_bldrs[i] == 0)
            continue;

        mbv[i] = &mblocks[i];
        err = kvset_builder_get_mblocks(ingest->c0iw_bldrs[i], &mblocks[i]);
        if (ev(err))
            goto health_err;
    }

health_err:
    if (err)
        kvdb_health_error(c0sk->c0sk_kvdb_health, err);

exit_err:
    if (!released) {
        atomic64_inc_acq(&c0sk->c0sk_ingest_order_next); /* Move the ingest order forward */

        mutex_lock(&c0sk->c0sk_kvms_mutex);
        cv_broadcast(&c0sk->c0sk_kvms_cv); /* Wake up newer ingest threads */
        mutex_unlock(&c0sk->c0sk_kvms_mutex);
        released = true;
    }

    if (lc_list)
        lc_builder_destroy(lc_list);

    for (i = 0; i < 2; i++) {
        if (cn_list[i])
            bkv_collection_destroy(cn_list[i]);
    }

    if (debug)
        ingest->t8 = get_time_ns();

    /* Updating cn must be a sequential operation */
    mutex_lock(&c0sk->c0sk_kvms_mutex);
    while (1) {
        if (kvms == c0sk_get_last_c0kvms(&c0sk->c0sk_handle))
            break;

        cv_wait(&c0sk->c0sk_kvms_cv, &c0sk->c0sk_kvms_mutex);
    }
    mutex_unlock(&c0sk->c0sk_kvms_mutex);

    if (HSE_LIKELY(!c0sk->c0sk_kvdb_rp->read_only)) {
        u64 cn_min = 0, cn_max = 0;

        c0sk_ingest_rec_perfc(&c0sk->c0sk_pc_ingest, PERFC_DI_C0SKING_PREP, go);

        go = perfc_lat_start(&c0sk->c0sk_pc_ingest);

        err = cn_ingestv(c0sk->c0sk_cnv, mbv, HSE_KVS_COUNT_MAX, kvms_gen,
                         txhorizon, &cn_min, &cn_max);

        c0sk_ingest_rec_perfc(&c0sk->c0sk_pc_ingest, PERFC_DI_C0SKING_FIN, go);

        if (ev(err))
            kvdb_health_error(c0sk->c0sk_kvdb_health, err);

        c0sk_cningest_walcb(c0sk, max_seq, kvms_gen, txhorizon, true);

        if (!err) {
            if (debug && cn_min && cn_max)
                hse_log(
                    HSE_DEBUG "c0_ingest minseq: c0sk %lu cn %lu; maxseq: c0sk %lu cn %lu",
                    min_seq,
                    cn_min,
                    max_seq,
                    cn_max);

            assert(!cn_min || cn_min >= min_seq);
            assert(!cn_max || cn_max <= max_seq);
        }
    }

    if (debug)
        ingest->t9 = get_time_ns();

    if (err) {
        hse_elog(HSE_ERR "c0 ingest failed on %p: @@e", err, kvms);
    } else {
        int finlat;

        lc_ingest_seqno_set(lc, max_seq);

        /* Compute a running average of the finish latency (weighted more
         * heavily on previous result) for use in adjusting the throttle.
         */
        finlat = atomic_read(&c0sk->c0sk_ingest_finlat);
        finlat = ((ingest->t7 - ingest->t6) / 1000000 + finlat * 2) / 3;
        atomic_set(&c0sk->c0sk_ingest_finlat, finlat);
    }

    /* Releasing mblocks could take several seconds on slow or very busy
     * media, so we release the kvms before we start teardown to allow
     * any kvms waiting on us to run concurrently with our teardown.
     */
    c0kvms_getref(kvms);
    c0kvms_ingested(kvms);
    c0sk_release_multiset(c0sk, kvms);
    c0sk_signal_waiters(c0sk, kvms_gen);

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        if (ingest->c0iw_bldrs[i] == 0)
            continue;

        kvset_mblocks_destroy(&mblocks[i]);
        kvset_builder_destroy(ingest->c0iw_bldrs[i]);

        ingest->c0iw_bldrs[i] = NULL;
    }

    if (debug) {
        ingest->t10 = get_time_ns();

        ingest->gen = kvms_gen;
        ingest->gencur = c0kvms_gen_current();
    }

    c0kvms_putref(kvms);
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
    ingest->c0iw_tenqueued = get_time_ns();
    INIT_WORK(&ingest->c0iw_work, c0sk_ingest_worker);
    queue_work(self->c0sk_wq_ingest, &ingest->c0iw_work);
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
        struct c0_ingest_work *w;

        if (c0kvms_is_finalized(kvms)) {
            list_add_tail(&kvms->c0ms_rcu, &done);
            continue;
        }

        c0kvms_finalize(kvms, self->c0sk_wq_maint);

        w = c0kvms_ingest_work_prepare(kvms, &self->c0sk_handle);
        c0sk_ingest_worker_start(self, w);
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
    u64                   gen;

    gen = c0kvms_gen_read(multiset);

    mutex_lock(&self->c0sk_kvms_mutex);
    assert(self->c0sk_release_gen < gen);
    self->c0sk_release_gen = gen;

    cds_list_for_each_entry_reverse(p, &self->c0sk_kvmultisets, c0ms_link)
    {
        if (p == multiset) {
            cds_list_del_rcu(&p->c0ms_link);
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
 * c0sk_ingest_tune() - adjust tuning for next ingest buffer
 * @self: ptr to c0sk_impl
 */
static void
c0sk_ingest_tune(struct c0sk_impl *self)
{
    struct kvdb_rparams *rp = self->c0sk_kvdb_rp;
    uint width;

    width = min_t(uint, self->c0sk_ingest_width_max * 2, HSE_C0_INGEST_WIDTH_MAX);

    /* A mongod replica node requires a maximally provisioned
     * kvms with throttling disabled in order to mitigate lag.
     */
    if (c0sk_ingest_boost(self)) {
        rp->throttle_disable |= 0x80u;
        self->c0sk_boost = 4;
    } else if (self->c0sk_boost > 0) {
        rp->throttle_disable |= 0x80u;
        self->c0sk_boost--;
    } else {
        width = self->c0sk_ingest_width_max;
        rp->throttle_disable &= ~0x80u;
    }

    self->c0sk_ingest_width = width;
}

/* GCOV_EXCL_START */

static HSE_ALWAYS_INLINE void
c0sk_ingestref_get(struct c0sk_impl *self, bool is_txn, void **cookiep)
{
    atomic_t *ptr = NULL;

    if (!is_txn) {
        uint node = hse_cpu2node(raw_smp_processor_id());

        ptr = &self->c0sk_ingest_refv[node % NELEM(self->c0sk_ingest_refv)].refcnt;

        atomic_inc(ptr);
    }

    *cookiep = ptr;
}

static HSE_ALWAYS_INLINE void
c0sk_ingestref_put(struct c0sk_impl *self, void *cookie)
{
    if (cookie)
        atomic_dec((atomic_t *)cookie);
}

static HSE_ALWAYS_INLINE void
c0sk_ingestref_wait(struct c0sk_impl *self)
{
    while (1) {
        uint bits = 0, i;

        for (i = 0; i < NELEM(self->c0sk_ingest_refv); ++i)
            bits |= atomic_read(&self->c0sk_ingest_refv[i].refcnt);

        if (bits == 0)
            return;

        cpu_relax();
    }
}

merr_t
c0sk_queue_ingest(struct c0sk_impl *self, struct c0_kvmultiset *old)
{
    struct c0_kvmultiset *new;
    merr_t err;

    c0kvms_ingesting(old);

    while (1) {
        const struct timespec req = { .tv_nsec = 1000 };

        if (c0kvms_gen_read(old) < atomic64_read(&self->c0sk_ingest_gen))
            return 0;

        if (atomic_inc_return(&self->c0sk_ingest_ldrcnt) == 1)
            break; /* ingest leader */

        nanosleep(&req, NULL);
    }

    err = 0;

    if (c0kvms_gen_read(old) < atomic64_read(&self->c0sk_ingest_gen))
        goto resign;

    c0sk_ingest_tune(self);

    err = c0kvms_create(self->c0sk_ingest_width, self->c0sk_kvdb_seq, &self->c0sk_stash, &new);
    if (!err) {
        c0kvms_getref(new);

        /* Wait for all active non-txn put/del threads to complete or abort to
         * ensure that all seqnos minted for the new kvms are larger than all
         * seqnos minted for the old kvms.  It would suffice to simply call
         * synchronize_rcu() here, but it is often too slow.
         */
        c0sk_ingestref_wait(self);

        if (c0sk_install_c0kvms(self, old, new)) {
            atomic64_set(&self->c0sk_ingest_gen, c0kvms_gen_read(new));
            c0sk_rcu_sync(self, old, true);
        } else {
            c0kvms_putref(new);
            err = merr(EAGAIN);
            ev(1);
        }

        c0kvms_putref(new);
    }

  resign:
    while (!atomic_cas(&self->c0sk_ingest_ldrcnt, atomic_read(&self->c0sk_ingest_ldrcnt), 0))
        continue;

    return err;
}

/* GCOV_EXCL_STOP */

/*
 * Sync the present kvmultiset (queue it for ingest).
 * For sync(), we need to know when this c0kvms has been ingested.
 */
merr_t
c0sk_flush_current_multiset(struct c0sk_impl *self, u64 *genp)
{
    struct c0_kvmultiset *old;
    merr_t                err;

    rcu_read_lock();

    old = c0sk_get_first_c0kvms(&self->c0sk_handle);
    if (old)
        c0kvms_getref(old);

    rcu_read_unlock();

    if (ev(!old))
        return merr(ENXIO);

    if (genp) {
        *genp = c0kvms_gen_read(old);

        /* Caller intends to wait on this flush to be persisted.  To ameliorate
         * the generation of small kvsets we linger around a bit in hopes of
         * piggybacking upon a naturally occuring flush.  This works well if
         * the ingest rate is high.  If the ingest rate is low it simply
         * serves to limit the sync frequency to roughly dur_intvl_ms.
         */
        if (!self->c0sk_closing) {
            long waitmax = self->c0sk_kvdb_rp->dur_intvl_ms / 2;
            long delay = min_t(long, waitmax / 10 + 1, 100);

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

    err = c0sk_queue_ingest(self, old);

    c0kvms_putref(old);

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
    struct kvs_ktuple       *kt,
    const struct kvs_vtuple *vt,
    uintptr_t                seqnoref)
{
    uintptr_t *priv = (uintptr_t *)seqnoref;
    bool       is_txn = (!HSE_SQNREF_SINGLE_P(seqnoref) && !HSE_SQNREF_ORDNL_P(seqnoref));
    u64        dst_gen = 0;
    merr_t     err;

    while (1) {
        struct c0_kvmultiset *dst;
        struct c0_kvset *     kvs;
        uintptr_t *           entry = NULL;
        void                 *cookie = NULL;

        rcu_read_lock();
        dst = c0sk_get_first_c0kvms(&self->c0sk_handle);
        if (ev(!dst, HSE_WARNING)) {
            rcu_read_unlock();
            return merr(EINVAL);
        }

        /* Non-txn mutations must synchronize with c0sk_queue_ingest()
         * to ensure correct seqno ordering across a kvms switch.
         */
        c0sk_ingestref_get(self, is_txn, &cookie);

        if (c0kvms_should_ingest(dst) && atomic_read(&self->c0sk_replaying) == 0) {
            err = merr(ENOMEM);
            goto unlock;
        }

        dst_gen = c0kvms_gen_read(dst);
        if (is_txn) {
            u64 curr_gen = c0snr_get_cgen(priv);

            if (curr_gen != dst_gen) {
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

        if (entry) {
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
        c0sk_ingestref_put(self, cookie);

        if (merr_errno(err) == ENOMEM)
            c0kvms_getref(dst);

        rcu_read_unlock();

        if (merr_errno(err) != ENOMEM)
            break;

        c0sk_queue_ingest(self, dst);
        c0kvms_putref(dst);
    }

    kt->kt_dgen = dst_gen;

    return err;
}

#if HSE_MOCKING
#include "c0sk_internal_ut_impl.i"
#endif /* HSE_MOCKING */
