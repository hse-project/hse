/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/cds_list.h>
#include <hse_util/bonsai_tree.h>

#define MTF_MOCK_IMPL_c0skm

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0skm.h>
#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/rparam_debug_flags.h>
#include <hse_ikvdb/kvset_builder.h>

#include "c0sk_internal.h"
#include "c0skm_internal.h"
#include "c0_kvmsm.h"

#define MSEC_TO_NSEC(x) ((x)*1000UL * 1000)
#define NSEC_TO_MSEC(x) ((x) / MSEC_TO_NSEC(1))
#define C0_MUT_KVMS_MIN 8
#define C1_INGEST_PCT(x, y) (((x) * (y)) / 100)

merr_t
c0skm_open(struct c0sk *handle, struct kvdb_rparams *rp, struct c1 *c1h, const char *mpname)
{
    struct c0sk_impl *    self;
    struct c0sk_mutation *c0skm;
    struct c0skm_work *   work;
    struct c1_config_info info;

    self = c0sk_h2r(handle);

    if (!c1h || rp->read_only) {
        self->c0sk_mhandle = NULL;
        return 0;
    }

    /* Since c1 is enabled update the current active kvms to track
     * mutations. Any new kvms created after the current active one
     * will automatically have mutation enabled, due to the non-null
     * mutation handle in c0sk.
     */
    c0sk_enable_mutation(handle);

    c1_config_info(c1h, &info);
    if (!info.c1_denabled)
        return 0;

    assert(!rp->dur_throttle_enable || rp->dur_throttle_lo_th > 0);
    assert(!rp->dur_throttle_enable || rp->dur_throttle_lo_th <= 90);
    assert(!rp->dur_throttle_enable || rp->dur_throttle_hi_th <= 150);
    assert(!rp->dur_throttle_enable || rp->dur_throttle_lo_th < rp->dur_throttle_hi_th);

    c0skm = alloc_aligned(sizeof(*c0skm), __alignof(*c0skm), GFP_KERNEL);
    if (!c0skm)
        return merr(ev(ENOMEM));

    memset(c0skm, 0, sizeof(*c0skm));

    c0skm->c0skm_wq_mut = alloc_workqueue("hse_c0skm", 0, 2);
    if (!c0skm->c0skm_wq_mut) {
        free_aligned(c0skm);
        return merr(ev(ENOMEM));
    }

    /* Setup the timer sync, app sync and flush work */
    work = &c0skm->c0skm_tsyncw;
    work->c0skmw_it = C0SKM_TSYNC;
    work->c0skmw_sync = true;
    INIT_WORK(&work->c0skmw_ws, c0skm_ingest_worker);
    work->c0skmw_mut = c0skm;

    work = &c0skm->c0skm_syncw;
    work->c0skmw_it = C0SKM_SYNC;
    INIT_WORK(&work->c0skmw_ws, c0skm_ingest_worker);
    work->c0skmw_mut = c0skm;

    work = &c0skm->c0skm_flushw;
    work->c0skmw_it = C0SKM_FLUSH;
    work->c0skmw_sync = false;
    INIT_WORK(&work->c0skmw_ws, c0skm_ingest_worker);
    work->c0skmw_mut = c0skm;

    c0skm->c0skm_dtime = info.c1_dtime; /* in ms */
    c0skm->c0skm_dsize = info.c1_dsize; /* in bytes */

    atomic64_set(&c0skm->c0skm_mutgen, 1);
    atomic64_set(&c0skm->c0skm_err, 0);
    atomic_set(&c0skm->c0skm_flushing, 0);
    atomic_set(&c0skm->c0skm_syncing, 0);
    atomic_set(&c0skm->c0skm_closing, 0);
    atomic_set(&c0skm->c0skm_tsyncing, 0);
    atomic64_set(&c0skm->c0skm_ingest_start, 0);
    atomic64_set(&c0skm->c0skm_ingest_end, 0);
    atomic64_set(&c0skm->c0skm_ingest_sz, 0);
    atomic64_set(&c0skm->c0skm_tseqno, 0);

    INIT_LIST_HEAD(&c0skm->c0skm_sync_waiters);
    mutex_init(&c0skm->c0skm_sync_mutex);

    c0skm->c0skm_c1h = c1h;
    c0skm->c0skm_c0skh = self;

    self->c0sk_mhandle = c0skm;

    c0skm_perfc_alloc(c0skm, mpname);

    /* Start the timer thread */
    work = &c0skm->c0skm_timerw;
    work->c0skmw_it = C0SKM_TIMER;
    INIT_WORK(&work->c0skmw_ws, c0skm_timer_worker);
    work->c0skmw_mut = c0skm;
    work->c0skmw_rp = rp;
    queue_work(c0skm->c0skm_wq_mut, &work->c0skmw_ws);

    return 0;
}

void
c0skm_close(struct c0sk *handle)
{
    struct c0sk_impl *    self;
    struct c0sk_mutation *c0skm;

    self = c0sk_h2r(handle);
    c0skm = self->c0sk_mhandle;

    if (ev(!c0skm))
        return;

    /* This notifies the timer thread to stop and the worker thread
     * to process all pending work synchronously.
     */
    atomic_set(&c0skm->c0skm_closing, 1);

    /* Flush the pending work items */
    flush_workqueue(c0skm->c0skm_wq_mut);
    destroy_workqueue(c0skm->c0skm_wq_mut);

    mutex_destroy(&c0skm->c0skm_sync_mutex);

    c0skm_perfc_free(c0skm);

    free(c0skm->c0skm_c0kvmsv);
    free_aligned(c0skm);

    self->c0sk_mhandle = NULL;
}

/* Implements external sync request (hse_kvdb_sync) */
merr_t
c0skm_sync(struct c0sk *handle)
{
    struct c0sk_waiter    waiter = {};
    struct c0sk_impl *    self;
    struct c0sk_mutation *c0skm;
    struct c0skm_work *   work;

    u64 start;

    if (!handle)
        return merr(ev(EINVAL));

    self = c0sk_h2r(handle);

    if (self->c0sk_kvdb_rp->read_only)
        return 0;

    c0skm = self->c0sk_mhandle;
    if (!c0skm)
        return 0;

    start = perfc_lat_start(&c0skm->c0skm_pcset_op);

    work = &c0skm->c0skm_syncw;

    cv_init(&waiter.c0skw_cv, __func__);

    mutex_lock(&c0skm->c0skm_sync_mutex);
    waiter.c0skw_gen = atomic64_read(&c0skm->c0skm_mutgen);

    /*
     * If sync is already in progress:
     *      Set sync pending to true.
     * else:
     *      Set syncing to indicate that a sync is now in progress.
     *      Queue a new sync work.
     * Wait for KV mutations in the current mutation gen. to be persisted.
     */
    if (atomic_cmpxchg(&c0skm->c0skm_syncing, 0, 1) == 0)
        queue_work(c0skm->c0skm_wq_mut, &work->c0skmw_ws);
    else
        c0skm->c0skm_syncpend = true;

    list_add_tail(&waiter.c0skw_link, &c0skm->c0skm_sync_waiters);
    while (waiter.c0skw_gen > c0skm->c0skm_syncgen && waiter.c0skw_err == 0)
        cv_wait(&waiter.c0skw_cv, &c0skm->c0skm_sync_mutex);

    list_del(&waiter.c0skw_link);
    mutex_unlock(&c0skm->c0skm_sync_mutex);

    cv_destroy(&waiter.c0skw_cv);

    perfc_rec_lat(&c0skm->c0skm_pcset_op, PERFC_LT_C0SKM_SYNC, start);
    perfc_inc(&c0skm->c0skm_pcset_op, PERFC_RA_C0SKM_SYNC);

    return waiter.c0skw_err;
}

/* Implements external flush request (hse_kvdb_flush) */
merr_t
c0skm_flush(struct c0sk *handle)
{
    u64                   start;
    struct c0sk_impl *    self;
    struct c0sk_mutation *c0skm;
    struct c0skm_work *   flushw;

    if (!handle)
        return merr(ev(EINVAL));

    self = c0sk_h2r(handle);

    if (self->c0sk_kvdb_rp->read_only)
        return 0;

    c0skm = self->c0sk_mhandle;
    if (!c0skm)
        return 0;

    start = perfc_lat_start(&c0skm->c0skm_pcset_op);

    flushw = &c0skm->c0skm_flushw;

    /* If either kvdb/timer sync in progress, return. */
    if ((atomic_read(&c0skm->c0skm_syncing) > 0) || (atomic_read(&c0skm->c0skm_tsyncing) > 0))
        goto exit;

    /* If kvdb_flush in progress, return. */
    if (atomic_cmpxchg(&c0skm->c0skm_flushing, 0, 1) > 0)
        goto exit;

    /* Queue the flush work */
    queue_work(c0skm->c0skm_wq_mut, &flushw->c0skmw_ws);

exit:
    perfc_rec_lat(&c0skm->c0skm_pcset_op, PERFC_LT_C0SKM_FLUSH, start);
    perfc_inc(&c0skm->c0skm_pcset_op, PERFC_RA_C0SKM_FLUSH);

    return 0;
}

void
c0skm_set_tseqno(struct c0sk *handle, u64 seqno)
{
    struct c0sk_mutation *c0skm;
    struct c0sk_impl *    self;
    bool                  swapped;
    u64                   old;

    if (!handle)
        return;

    self = c0sk_h2r(handle);

    c0skm = self->c0sk_mhandle;
    if (!c0skm)
        return; /* c1 is disabled */

    /* The new seqno must always be greater than the current
     * seqno.  See kvdb_ctxn_commit() which ensures it.
     */
    old = atomic64_read(&c0skm->c0skm_tseqno);

    if (ev(old >= seqno)) {
        assert(seqno > old);
        return;
    }

    /* It's a grievous error if there is more than one thread
     * executing in this function at any given time.
     */
    swapped = atomic64_cas(&c0skm->c0skm_tseqno, old, seqno);

    if (ev(!swapped)) {
        assert(swapped);
    }
}

u64
c0skm_get_cnid(struct c0sk_mutation *c0skm, u32 skidx)
{
    assert(skidx < HSE_KVS_COUNT_MAX);

    if (!c0skm)
        return 0;

    return c0skm->c0skm_cnid[skidx];
}

void
c0skm_skidx_register(struct c0sk_impl *self, u32 skidx, struct cn *cn)
{
    struct c0sk_mutation *c0skm;

    u64 cnid;

    assert(skidx < HSE_KVS_COUNT_MAX);

    c0skm = self->c0sk_mhandle;
    if (ev(!c0skm))
        return;

    cnid = cn_get_cnid(cn);
    assert(c0skm->c0skm_cnid[skidx] == 0);
    c0skm->c0skm_cnid[skidx] = cnid;
}

void
c0skm_skidx_deregister(struct c0sk_impl *self, u32 skidx)
{
    struct c0sk_mutation *c0skm;

    assert(skidx < HSE_KVS_COUNT_MAX);

    c0skm = self->c0sk_mhandle;
    if (ev(!c0skm))
        return;

    c0skm->c0skm_cnid[skidx] = 0;
}

static void
c0skm_get_kvsize(struct c0sk_mutation *c0skm, size_t *sz_out)
{
    struct c0sk_impl *    self;
    struct c0_kvmultiset *c0kvms;
    struct c0kvmsm_info   info = {};
    struct c0kvmsm_info   txinfo = {};
    bool                  first = 1;
    u64                   size = 0;

    self = c0skm->c0skm_c0skh;

    rcu_read_lock();
    cds_list_for_each_entry_rcu(c0kvms, &self->c0sk_kvmultisets, c0ms_link)
    {
        if (first) {
            c0kvmsm_get_info(c0kvms, &info, &txinfo, true);
            first = 0;
            size += info.c0ms_kvbytes + txinfo.c0ms_kvbytes;
        } else {
            if (c0kvms_is_ingested(c0kvms) ||
                (c0kvms_is_finalized(c0kvms) && !c0kvms_is_mutating(c0kvms)))
                break;

            size += c0kvms_mut_sz_get(c0kvms);
        }
    }
    rcu_read_unlock();

    if (sz_out)
        *sz_out = size;
}

static bool
c0skm_has_txpend(struct c0sk_mutation *c0skm)
{
    struct c0sk_impl *    self;
    struct c0_kvmultiset *c0kvms;

    bool found = false;

    self = c0skm->c0skm_c0skh;

    rcu_read_lock();
    c0kvms = c0sk_get_first_c0kvms(&self->c0sk_handle);
    if (c0kvms)
        found = c0kvmsm_has_txpend(c0kvms);
    rcu_read_unlock();

    return found;
}

static void
c0skm_signal_waiters(struct c0sk_mutation *c0skm, u64 gen, merr_t err)
{
    struct c0sk_waiter *p;

    /* Awaken all threads waiting on the given mutation generation. */
    list_for_each_entry (p, &c0skm->c0skm_sync_waiters, c0skw_link) {
        if (gen >= p->c0skw_gen) {
            p->c0skw_err = err;
            cv_broadcast(&p->c0skw_cv);
        }
    }
}

static merr_t
c0skm_ingest(struct c0sk_mutation *c0skm, u8 itype, u64 *gen)
{
    struct c1 *            c1h;
    struct c0sk_impl *     self;
    struct c0_kvmultiset * c0kvms;
    struct c0_kvmultiset **c0kvmsv;
    struct kvdb_rparams *  rp;

    merr_t err;
    u64    tseqno;
    u64    fgen;
    u64    lgen;
    u64    old_gen;
    u64    go = 0;
    u64    sz;
    u32    nkvms;
    u32    kvmsid;
    bool * final;
    int    i;

    struct c0kvmsm_info info = {};
    struct c0kvmsm_info txinfo = {};

    u64 cnt = 0;
    u64 tstart = c0skm_reqtime_get(c0skm);

    rp = c0skm->c0skm_c0skh->c0sk_kvdb_rp;
    assert(rp);

    fgen = 0;
    lgen = 0;
    c1h = c0skm->c0skm_c1h;
    self = c0skm->c0skm_c0skh;

    /* Determine the number of KVMSes that needs to be ingested. */
    rcu_read_lock();
    c0kvms = c0sk_get_first_c0kvms(&self->c0sk_handle);
    if (c0kvms)
        fgen = c0kvms_gen_read(c0kvms);

    c0kvms = c0sk_get_last_c0kvms(&self->c0sk_handle);
    if (c0kvms)
        lgen = c0kvms_gen_read(c0kvms);
    rcu_read_unlock();
    assert(fgen >= lgen);

    /* C0_MUT_KVMS_MIN is to accommodate the newer kvmses that could
     * get added between fetching the generation range above and reverse
     * scanning the list below.
     */
    nkvms = (fgen - lgen + 1) + C0_MUT_KVMS_MIN;
    sz = nkvms * (sizeof(*c0kvmsv) + sizeof(*final));
    sz = roundup(sz, SMP_CACHE_BYTES);

    if (ev(sz > c0skm->c0skm_c0kvmsv_sz)) {
        c0kvmsv = malloc(sz);
        if (ev(!c0kvmsv))
            return merr(ENOMEM);

        free(c0skm->c0skm_c0kvmsv);
        c0skm->c0skm_c0kvmsv = c0kvmsv;
        c0skm->c0skm_c0kvmsv_sz = sz;
    }

    c0kvmsv = c0skm->c0skm_c0kvmsv;

    final = (void *)(c0kvmsv + nkvms);
    kvmsid = 0;

    rcu_read_lock();
    cds_list_for_each_entry_reverse(c0kvms, &self->c0sk_kvmultisets, c0ms_link)
    {
        /* Exceeded the max. no. of KVMSes that can be tracked
         * simultaneously.
         */
        if (ev(kvmsid > nkvms - 1))
            break;

        final[kvmsid] = false;

        if (!c0kvms_is_tracked(c0kvms))
            continue;

        if (c0kvms_is_ingested(c0kvms)) {
            perfc_inc(&c0skm->c0skm_pcset_op, PERFC_BA_C0SKM_KVMSS);
            continue; /* mutations already persisted in cN */
        }

        /* This to prevent a tight race where the current kvms is
         * in finalized state while the previous one wasn't at the
         * time when its status was checked. If this condition is hit,
         * don't proceed with ingesting the current AND any younger
         * kvmses. This is to avoid out-of-order-seqno ingests into c1.
         */
        if (ev(kvmsid > 1 && c0kvms_is_finalized(c0kvms) && !final[kvmsid - 1]))
            break;

        /* If this kvms is finalized, then the last set of mutations
         * will be processed in this iteration. Also, if there are any
         * mutations in the tx pending list, wait for the outstanding
         * ctxn commits to finish. This kvms can be safely ignored in
         * the next iteration.
         */
        if (c0kvms_is_finalized(c0kvms)) {
            if (!c0kvms_is_mutating(c0kvms)) {
                perfc_inc(&c0skm->c0skm_pcset_op, PERFC_BA_C0SKM_KVMSS);
                continue;
            }

            c0kvms_priv_wait(c0kvms);
            final[kvmsid] = true;
            perfc_inc(&c0skm->c0skm_pcset_op, PERFC_BA_C0SKM_KVMSF);
        }

        /* Take a reference on this kvms. This reference holds onto
         * the cursor heaps until all the KV mutations from the
         * current gen. is async. written to the c1 mlogs.
         */
        c0kvms_getref(c0kvms);

        c0kvmsv[kvmsid++] = c0kvms;
    }
    rcu_read_unlock();

    perfc_add(&c0skm->c0skm_pcset_op, PERFC_RA_C0SKM_KVMSP, kvmsid);

    /* Reset the request arrival time to 0.
     * The first put/del request that follows records its arrival time.
     */
    c0skm_reqtime_reset(c0skm);

    /* Max. seqno to be used for transaction mutations. */
    tseqno = atomic64_read(&c0skm->c0skm_tseqno);

    /* Increase the mutation gen. and store the old gen. Post c1
     * ingest, all mutations corresponding to this old gen. would
     * have been persisted. Any sync threads waiting on this old gen.
     * will be woken up.
     */
    old_gen = atomic64_fetch_add(1, &c0skm->c0skm_mutgen);

    /* Switch the mutation list for all the KVMSes, from newest to
     * oldest
     */
    for (i = kvmsid - 1; i >= 0; i--)
        c0kvmsm_switch(c0kvmsv[i]);

    /* Push mutations in temporal order, i.e., from the oldest to
     * newest kvms.
     */
    for (i = 0; i < kvmsid; i++) {
        /* Check again whether this KVMS is ingested. */
        if (c0kvms_is_ingested(c0kvmsv[i]))
            continue;

        go = perfc_lat_start(&c0skm->c0skm_pcset_op);
        err = c0kvmsm_ingest(
            c0kvmsv[i], c0skm, c1h, old_gen, tseqno, itype, final[i], &info, &txinfo);
        perfc_rec_lat(&c0skm->c0skm_pcset_op, PERFC_LT_C0SKM_KVMSI, go);
        if (ev(err)) {
            while (++i < kvmsid) {
                c0kvmsm_reset_mlist(c0kvmsv[i], 0);
                c0kvms_putref(c0kvmsv[i]);
            }
            return err;
        }
        cnt++;
    }

    if (cnt && itype == C1_INGEST_SYNC) {
        sz = txinfo.c0ms_kvbytes + info.c0ms_kvbytes;

        atomic64_set(&c0skm->c0skm_ingest_sz, sz);

        if (unlikely(rp->throttle_debug & THROTTLE_DEBUG_SENSOR_C1)) {
            u64 time = get_time_ns();

            hse_slog(
                HSE_NOTICE,
                HSE_SLOG_START("c1_ingest"),
                HSE_SLOG_FIELD("timestamp_ns", "%lu", (ulong)time),
                HSE_SLOG_FIELD("size_b", "%lu", (ulong)sz),
                HSE_SLOG_FIELD("interval_ns", "%lu", (ulong)time - tstart),
                HSE_SLOG_END);
        }
    }

    if (gen)
        *gen = old_gen;

    return 0;
}

static bool
c0skm_should_ingest(struct c0sk_mutation *c0skm, u64 reqtime, u64 deadline_sz, u64 acc_sz)
{
    u64 ingsz;

    /* If no request has arrived in the current interval but there are
     * pending transaction mutations from previous intervals, ingest
     * immediately (don't wait until a request arrives). If a request has
     * arrived, it'll be ingested after the sleep interval, if any.
     */
    if (reqtime == 0 && c0skm_has_txpend(c0skm))
        return true;

    /* The mutation size cannot exceed beyond the max.
     * size that c1 mlogs can hold.
     */
    ingsz = c1_ingest_space_threshold(c0skm->c0skm_c1h);
    if (ingsz > 0 && acc_sz > ingsz)
        return true;

    /*
     * Ingest if the mutation size exceeds the deadline for
     * durability size guarantee.
     */
    if (deadline_sz > 0 && acc_sz >= deadline_sz)
        return true;

    return false;
}

static bool
c0skm_should_skip_tsync(struct c0sk_mutation *c0skm)
{
    /* If a kvdb_sync is in progress, skip TSYNC. */
    if (atomic_read(&c0skm->c0skm_syncing) > 0) {
        perfc_inc(&c0skm->c0skm_pcset_op, PERFC_RA_C0SKM_TSYNCS);

        return true;
    }

    return false;
}

/*
 * The timer thread routine periodically syncs the KV mutations.
 * The sync interval is dpct of the configured durability time.
 * The sync logic ensures that the durability guarantee is met for all
 * KV mutations in a generation.
 */
void
c0skm_timer_worker(struct work_struct *work)
{
    struct c0skm_work *   timerw;
    struct c0skm_work *   tsyncw;
    struct c0sk_mutation *c0skm;
    struct timespec       req = { 0 };

    u64    dtime_ns, lwm_ns, deadline_ns;
    size_t dsize_b, lwm_b, deadline_b;
    u64    last_end = 0, maxwait_ns = 0;
    uint   pct;

    timerw = container_of(work, struct c0skm_work, c0skmw_ws);
    c0skm = timerw->c0skmw_mut;

    assert(timerw->c0skmw_it == C0SKM_TIMER);

    tsyncw = &c0skm->c0skm_tsyncw;
    dtime_ns = MSEC_TO_NSEC(c0skm->c0skm_dtime); /* in ns */
    dsize_b = c0skm->c0skm_dsize;                /* in bytes */
    lwm_ns = timerw->c0skmw_rp->dur_throttle_lo_th * dtime_ns / 100;
    lwm_b = timerw->c0skmw_rp->dur_throttle_lo_th * dsize_b / 100;
    pct = timerw->c0skmw_rp->dur_delay_pct;
    deadline_ns = C1_INGEST_PCT(dtime_ns, pct);
    deadline_b = C1_INGEST_PCT(dsize_b, pct);
    maxwait_ns = min_t(u64, timerw->c0skmw_rp->throttle_update_ns, deadline_ns);

    while (true) {
        bool   check = true;
        u64    reqtime, start, end;
        u64    intvl = 0;
        u64    lag = 0, now = 0;
        size_t sz = 0;

        /* Default retry interval of 1ms. */
        req.tv_nsec = MSEC_TO_NSEC(1);

        /* kvdb close in progress, bail out. */
        if (atomic_read(&c0skm->c0skm_closing) > 0)
            break;

        if (atomic64_read(&c0skm->c0skm_err) != 0)
            break;

        /* Fetch the latest ingest start time */
        start = atomic64_read(&c0skm->c0skm_ingest_start);

        /* Read the ingest start time before the end time. */
        smp_rmb();

        /* Fetch the latest ingest end time */
        end = atomic64_read(&c0skm->c0skm_ingest_end);

        /* Get the mutation size */
        c0skm_get_kvsize(c0skm, &sz);

        /* Fetch the arrival time of the first put/del request*/
        reqtime = c0skm_reqtime_get(c0skm);

        now = get_time_ns();

        if (end >= start) {
            if (end != last_end) {
                /* A c1 ingest completed. Update the sensors. */
                u64 lsize;

                lsize = atomic64_read(&c0skm->c0skm_ingest_sz);

                c0skm_dtime_throttle_set_sensor(c0skm, end - start);
                c0skm_dsize_throttle_set_sensor(c0skm, lsize);

                last_end = end;
                check = false;
            } else {
                /* Note time of oldest request. */
                start = reqtime ? reqtime : now;
            }
        }

        /*
         * Update the durability sensors when the time elapsed since
         * oldest request/start of c1 ingest exceeds the dtime low
         * watermark or if the accumulated size exceeds the dsize
         * low watermark. Update them if there's no work to be done.
         */
        if (check) {
            u64 elapsed = now - start;

            if (elapsed >= lwm_ns)
                c0skm_dtime_throttle_set_sensor(c0skm, elapsed);

            if (sz >= lwm_b)
                c0skm_dsize_throttle_set_sensor(c0skm, sz);

            /* Nothing to ingest. */
            if (reqtime == 0)
                c0skm_dtime_throttle_set_sensor(c0skm, 0);

            if (sz == 0)
                c0skm_dsize_throttle_set_sensor(c0skm, 0);
        }

        if (reqtime != 0)
            lag = now - reqtime;

        if (lag < deadline_ns) {
            intvl = max_t(u64, deadline_ns - lag, MSEC_TO_NSEC(1));
            intvl = min_t(u64, intvl, maxwait_ns);
        }

        /*
         * If the oldest request hasn't met the durability interval
         * deadline and the accumulated ingest size hasn't met the
         * durability size deadline, wait for a minimum of 1 ms
         * and a maximum of maxwait_ns before checking again.
         */
        if (intvl && !c0skm_should_ingest(c0skm, reqtime, deadline_b, sz)) {
            req.tv_nsec = intvl;
            nanosleep(&req, 0);
            continue;
        }

        /* Skip if there is an ongoing sync. */
        if (c0skm_should_skip_tsync(c0skm)) {
            nanosleep(&req, 0);
            continue;
        }

        perfc_rec_sample(&c0skm->c0skm_pcset_op, PERFC_DI_C0SKM_TSYNCD, lag);
        perfc_inc(&c0skm->c0skm_pcset_op, PERFC_RA_C0SKM_TSYNCI);

        if (atomic_cmpxchg(&c0skm->c0skm_tsyncing, 0, 1) == 0) {
            queue_work(c0skm->c0skm_wq_mut, &tsyncw->c0skmw_ws);
            perfc_inc(&c0skm->c0skm_pcset_op, PERFC_RA_C0SKM_TSYNCE);
            continue;
        }

        nanosleep(&req, 0);
    }
}

static inline void
c0skm_tsync_or_flush_reset(struct c0sk_mutation *c0skm, bool tsync)
{
    if (tsync)
        atomic_set(&c0skm->c0skm_tsyncing, 0);
    else
        atomic_set(&c0skm->c0skm_flushing, 0);
}

static void
c0skm_tsync_or_flush_work(struct c0sk_mutation *c0skm, enum c0skm_ingest_type itype)
{
    struct c0sk_impl *c0sk;

    merr_t err;
    bool   tsync;
    u64    start = c0skm_reqtime_get(c0skm);

    if (unlikely(!start))
        start = get_time_ns();

    c0sk = c0skm->c0skm_c0skh;
    tsync = (itype == C0SKM_TSYNC) ? true : false;

    /* Check one final time for kvdb_sync(). */
    if (atomic_read(&c0skm->c0skm_syncing) > 0) {
        c0skm_tsync_or_flush_reset(c0skm, tsync);
        return;
    }

    if (tsync)
        atomic64_set(&c0skm->c0skm_ingest_start, start);

    /* Ensure ingest start time is visible before updating end. */
    smp_wmb();

    err = c0skm_ingest(c0skm, tsync ? C1_INGEST_SYNC : C1_INGEST_FLUSH, NULL);
    if (ev(err)) {
        atomic64_set(&c0skm->c0skm_err, err);
        kvdb_health_error(c0sk->c0sk_kvdb_health, err);
    } else {
        perfc_dis_record(&c0skm->c0skm_pcset_op, PERFC_DI_C0SKM_INGEST, get_time_ns() - start);
    }

    if (tsync)
        atomic64_set(&c0skm->c0skm_ingest_end, get_time_ns());

    c0skm_tsync_or_flush_reset(c0skm, tsync);
}

static void
c0skm_sync_work(struct c0sk_mutation *c0skm)
{
    struct c0sk_impl *c0sk;

    u64    gen;
    merr_t err;
    bool   restart;

    restart = false;
    c0sk = c0skm->c0skm_c0skh;
    gen = atomic64_read(&c0skm->c0skm_mutgen);
    err = atomic64_read(&c0skm->c0skm_err);

    if (!err) {
        u64 start = c0skm_reqtime_get(c0skm);

        if (unlikely(!start))
            start = get_time_ns();

        atomic64_set(&c0skm->c0skm_ingest_start, start);

        /* Ensure ingest start time is visible before updating end. */
        smp_wmb();

        err = c0skm_ingest(c0skm, C1_INGEST_SYNC, &gen);
        if (!ev(err))
            perfc_dis_record(&c0skm->c0skm_pcset_op, PERFC_DI_C0SKM_INGEST, get_time_ns() - start);

        atomic64_set(&c0skm->c0skm_ingest_end, get_time_ns());
    }

    if (ev(err)) {
        atomic64_set(&c0skm->c0skm_err, err);
        kvdb_health_error(c0sk->c0sk_kvdb_health, err);
    }

    /* Signal the sync waiters. Those waiting on c0skm_syncgen
     * leaves.
     */
    mutex_lock(&c0skm->c0skm_sync_mutex);
    c0skm->c0skm_syncgen = gen;
    c0skm_signal_waiters(c0skm, gen, err);

    /* If there are pending sync requests from the application,
     * process them by queueing a sync work.
     */
    if (c0skm->c0skm_syncpend) {
        c0skm->c0skm_syncpend = false;
        restart = true;
    } else {
        atomic_set(&c0skm->c0skm_syncing, 0);
    }
    mutex_unlock(&c0skm->c0skm_sync_mutex);

    if (restart) {
        struct c0skm_work *syncw;

        syncw = &c0skm->c0skm_syncw;
        queue_work(c0skm->c0skm_wq_mut, &syncw->c0skmw_ws);
    }
}

/*
 * Worker thread which pushes mutations to c1. This thread handles the
 * following:
 *     1. Sync request from the timer thread.
 *     2. Sync request from the app. thread.
 *     3. Flush request from the app. thread.
 */
void
c0skm_ingest_worker(struct work_struct *work)
{
    struct c0skm_work *    ingestw;
    struct c0sk_mutation * c0skm;
    enum c0skm_ingest_type itype;

    merr_t err;

    ingestw = container_of(work, struct c0skm_work, c0skmw_ws);
    c0skm = ingestw->c0skmw_mut;
    itype = ingestw->c0skmw_it;

    err = atomic64_read(&c0skm->c0skm_err);
    if (ev(err != 0 && itype != C0SKM_SYNC))
        return;

    /* If a close is in progress, synchronously push the mutations */
    if (atomic_read(&c0skm->c0skm_closing) > 0)
        itype = C0SKM_SYNC;

    switch (itype) {

        case C0SKM_TSYNC:
        case C0SKM_FLUSH:
            c0skm_tsync_or_flush_work(c0skm, itype);
            break;

        case C0SKM_SYNC:
            c0skm_sync_work(c0skm);
            break;

        default:
            hse_log(HSE_ERR "Work type %u not recognized", itype);
            break;
    }
}

merr_t
c0skm_bldr_get(struct c0sk *handle, u64 gen, struct kvset_builder ***bldrout)
{
    *bldrout = NULL;

    return 0;
}

void
c0skm_bldr_put(struct c0sk *handle, u64 gen, u64 c0vlen, u64 c1vlen)
{
    struct c0sk_mutation *c0skm;
    struct c0sk_impl *    self;
    u64                   vratio;

    self = c0sk_h2r(handle);
    c0skm = self->c0sk_mhandle;

    if (ev(!c0skm))
        return;

    if (!(c1vlen + c0vlen))
        return;

    vratio = (c1vlen * 100) / (c1vlen + c0vlen);

    perfc_rec_sample(&c0skm->c0skm_pcset_op, PERFC_DI_C0SKM_VBLDRT, vratio);
}

void
c0skm_dtime_throttle_sensor(struct c0sk *handle, struct throttle_sensor *sensor)
{
    struct c0sk_mutation *c0skm;
    struct c0sk_impl *    self;

    if (ev(!handle))
        return;

    self = c0sk_h2r(handle);
    c0skm = self->c0sk_mhandle;

    if (ev(!c0skm))
        return;

    c0skm->c0skm_dtime_sensor = sensor;
}

void
c0skm_dtime_throttle_set_sensor(struct c0sk_mutation *c0skm, u64 stime)
{
    struct throttle_sensor *sensor;
    struct kvdb_rparams *   rp;
    u64                     dtime;
    u64                     svalue = 0;
    u64                     hwm, lwm;

    sensor = c0skm->c0skm_dtime_sensor;
    if (ev(!sensor))
        return;

    rp = c0skm->c0skm_c0skh->c0sk_kvdb_rp;
    assert(rp);

    if (!rp->dur_throttle_enable)
        return;

    dtime = MSEC_TO_NSEC(c0skm->c0skm_dtime);
    lwm = rp->dur_throttle_lo_th * dtime / 100;
    hwm = rp->dur_throttle_hi_th * dtime / 100;

    if (lwm == 0 || lwm >= hwm)
        return;

    if (stime < lwm) {
        svalue = THROTTLE_SENSOR_SCALE * stime / lwm;
    } else if (stime < hwm) {
        svalue = THROTTLE_SENSOR_SCALE +
                 (stime - lwm) * (2 * THROTTLE_SENSOR_SCALE - THROTTLE_SENSOR_SCALE) / (hwm - lwm);
    } else {
        svalue = 2 * THROTTLE_SENSOR_SCALE;
    }

    perfc_rec_sample(&c0skm->c0skm_pcset_kv, PERFC_DI_C0SKM_DTIME, stime);

    throttle_sensor_set(sensor, (int)svalue);
}

void
c0skm_dsize_throttle_sensor(struct c0sk *handle, struct throttle_sensor *sensor)
{
    struct c0sk_mutation *c0skm;
    struct c0sk_impl *    self;

    if (ev(!handle))
        return;

    self = c0sk_h2r(handle);
    c0skm = self->c0sk_mhandle;

    if (ev(!c0skm))
        return;

    c0skm->c0skm_dsize_sensor = sensor;
}

void
c0skm_dsize_throttle_set_sensor(struct c0sk_mutation *c0skm, u64 ssize)
{
    struct throttle_sensor *sensor;
    struct kvdb_rparams *   rp;
    u64                     dsize;
    u64                     svalue = 0;
    u64                     hwm, lwm;

    sensor = c0skm->c0skm_dsize_sensor;
    if (ev(!sensor))
        return;

    rp = c0skm->c0skm_c0skh->c0sk_kvdb_rp;
    assert(rp);

    if (!rp->dur_throttle_enable)
        return;

    dsize = c0skm->c0skm_dsize;
    lwm = rp->dur_throttle_lo_th * dsize / 100;
    hwm = rp->dur_throttle_hi_th * dsize / 100;

    if (lwm == 0 || lwm >= hwm)
        return;

    if (ssize < lwm) {
        svalue = THROTTLE_SENSOR_SCALE * ssize / lwm;
    } else if (ssize < hwm) {
        svalue = THROTTLE_SENSOR_SCALE +
                 (ssize - lwm) * (2 * THROTTLE_SENSOR_SCALE - THROTTLE_SENSOR_SCALE) / (hwm - lwm);
    } else {
        svalue = 2 * THROTTLE_SENSOR_SCALE;
    }

    perfc_rec_sample(&c0skm->c0skm_pcset_kv, PERFC_DI_C0SKM_DSIZE, ssize);

    throttle_sensor_set(sensor, (int)svalue);
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c0skm_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
