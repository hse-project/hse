/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/timing.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/condvar.h>
#include <hse_util/bin_heap.h>
#include <hse_util/table.h>
#include <hse_util/string.h>
#include <hse_util/fmt.h>
#include <hse_util/keycmp.h>

#include <hse_util/rcu.h>
#include <hse_util/cds_list.h>
#include <hse_util/bonsai_tree.h>

#define MTF_MOCK_IMPL_c0sk

#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/rparam_debug_flags.h>

#include "c0sk_internal.h"
#include "c0_cursor.h"

void
c0sk_perfc_alloc(struct c0sk_impl *self)
{
    if (perfc_ctrseti_alloc(
            COMPNAME,
            self->c0sk_kvdbhome,
            c0sk_perfc_op,
            PERFC_EN_C0SKOP,
            "set",
            &self->c0sk_pc_op))
        hse_log(HSE_ERR "cannot alloc c0sk op perf counters");

    if (perfc_ctrseti_alloc(
            COMPNAME,
            self->c0sk_kvdbhome,
            c0sk_perfc_ingest,
            PERFC_EN_C0SKING,
            "set",
            &self->c0sk_pc_ingest))
        hse_log(HSE_ERR "cannot alloc c0sk ingest perf counters");
}

/**
 * c0sk_perfc_free() - Free perfc counter sets for this c0sk instance.
 * @self:
 */
static void
c0sk_perfc_free(struct c0sk_impl *self)
{
    perfc_ctrseti_free(&self->c0sk_pc_op);
    perfc_ctrseti_free(&self->c0sk_pc_ingest);
}

/*
 * ============================================================================
 *
 * Component Summary:
 * ------------------
 *
 * The c0 component represents the portion of the log-structured merge (LSM)
 * tree that resides in memory.
 *
 * The c0 component maintains its data as a list of generations, each of which
 * is a c0_kvmultiset. Each c0_kvmultiset is in turn a vector of c0_kvset
 * structures. As c0 processes put and delete requests with varying key
 * values, its in memory size grows. At some point a threshold criteria is
 * reached (space and/or time) and the current contents of c0 will be migrated
 * to cN. Since the migration may take some time there may be several
 * generations of c0 present at any one time, although a busy system should
 * have only N on average where N is the # of concurrent c0-to-cN ingests that
 * can be in flight. The case of N=1 is expected to be normal.
 *
 * While the on-flash or on-disk portions of the LSM tree are handled via
 * pseudo B-tree structures, it is believed that a traditional balanced binary
 * tree is more appropriate as a log-time accessible in-memory structure. The
 * c0 component uses something called a Bonsai tree (see c0_kvset for usage)
 * for this purpose. A principal design complexity for c0 is the management
 * of concurrency for overlapping put/get/del/scan activity while enabling a
 * high level of performance.
 *
 * ============================================================================
 */

/*
 * ============================================================================
 *
 * Concurrency Model:
 * ------------------
 *
 * The c0 subsystem has a moderately complex concurrency model which is
 * described here. The implementation of the model is split between this
 * source file and c0sk_internal.c.
 *
 * There are two scenarios in which concurrency must be controlled:
 *
 *     (1) Multi-threaded access to a single c0 instance in the form of
 *         queries and insertions
 *
 *     (2) Dealing with the need to cause an ingest to cN to occur while
 *         multiple threads are accessing a given c0
 *
 *     Scenario 1:
 *     -----------
 *
 *     The first scenario uses a collection of individual "c0 KV sets" to
 *     reduce write contention as well as an RCU strategy to allow readers
 *     access to the data even while it is being updated. Which individual c0
 *     KV set a given query or insertion is directed to is determined by a
 *     hash of that operation's key data.
 *
 *     Each c0 instance then owns a list of one or more c0_kvmultiset
 *     instances. The head of this list is termed the active KV multiset while
 *     the remainder have been previously frozen and scheduled for ingest into
 *     cN.  The list is maintained in temporal order from newest to oldest. A
 *     c0 instance's KV multiset list is managed in an RCU fashion. Writes are
 *     coordinated through the use of the field c0.c0sk_kvms_mutex. Reads are
 *     coordinated through rcu_read_lock() and rcu_read_unlock().
 *
 *     Each c0_kvmultiset instance contains a fixed vector of c0_kvset
 *     elements that is allocated at the creation of the KV multiset and freed
 *     upon its destruction. Once created, the KV multiset is itself immutable
 *     and contains no synchronization structures.
 *
 *     Each c0_kvset instance contains a Bonsai tree that is write- protected
 *     with the structure field c0s_mutex. A thread performing an insert
 *     operation (i.e., a put or delete) must acquire that mutex. By using a
 *     plurality of c0_kvset instances selected by key hash, the level of
 *     write contention is reduced. Read access to a c0_kvset is coordinated
 *     through rcu_read_lock() and rcu_read_unlock().
 *
 *     Scenario 2:
 *     -----------
 *
 *     Consider the scenario in which multiple threads are using a given c0
 *     instance and it becomes time for c0 to arrange for the current active
 *     KV multiset to be ingested and a new fresh one prepended to the c0
 *     instance's list. Only one thread can arrange for the ingest and
 *     prepend the new KV multiset - no other thread may proceed with an
 *     insert during this window. However, we do not want to block threads
 *     that need to query the KV multiset.
 *
 *     This coordination is performed using the following mechanisms:
 *
 *         (a) Atomic operations on a scalar contained within the c0
 *         (b) A sync pool shared by all threads wishing to access the c0
 *         (c) RCU read lock and unlock
 *
 *     See the function queue_ingest() in c0sk_internal.c for details, but the
 *     following is an overview. Every thread entering queue_ingest() acquires
 *     a mutex from the c0 lock pool based upon its thread ID. It then performs
 *     an atomic increment and fetch of the c0 scalar from (a). If it is the
 *     first thread to do so, the fetch will return the value 1. In this case,
 *     we term the thread "the leader". If the thread is not the first, then
 *     the thread goes to sleep on the condition variable associated with its
 *     lock pool mutex (which in turn drops its mutex).
 *     Upon awakening, these threads simply release their lock pool mutex
 *     and return from queue_ingest() to restart their operation.
 *
 *     If a thread becomes the leader it first locks the per-c0 list mutex.
 *     The leader then proceeds to "freeze" the current active KV multiset,
 *     create a new KV multiset and insert it at the head of the per-c0 list,
 *     and queue the newly frozen item for ingest into cN. Finally, it
 *     proceeds to reset the scalar from (a), awaken all threads that
 *     weren't the leader, and return to look at the head of the KV
 *     multiset list.
 *
 * Mechanism:
 * -----------
 *
 * In order to use RCU semantics, we must enforce the requirement that client
 * application threads register themselves with the c0 subsystem as a whole.
 */

merr_t
c0sk_c0_register(struct c0sk *handle, struct cn *cn, u16 *skidx)
{
    merr_t            err;
    struct c0sk_impl *self;
    int               i;

    if (ev(!handle || !cn || !skidx))
        return merr(EINVAL);

    self = c0sk_h2r(handle);

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        if (self->c0sk_cnv[i] == 0) {
            cn_ref_get(cn);
            self->c0sk_cnv[i] = cn;
            *skidx = i;

            return 0;
        }
    }

    err = merr(ev(ENOSPC));
    hse_elog(HSE_DEBUG "Attempt to register too many c0's with c0sk: @@e", err);

    return err;
}

merr_t
c0sk_c0_deregister(struct c0sk *handle, u16 skidx)
{
    struct c0sk_impl *self;

    if (!handle)
        return merr(ev(EINVAL));

    self = c0sk_h2r(handle);

    assert(skidx < HSE_KVS_COUNT_MAX);
    if (skidx >= HSE_KVS_COUNT_MAX)
        return merr(ev(ERANGE));

    if (self->c0sk_cnv[skidx]) {
        cn_ref_put(self->c0sk_cnv[skidx]);
        self->c0sk_cnv[skidx] = 0;
    }

    return c0sk_sync(handle, HSE_KVDB_SYNC_ASYNC);
}

static struct kmem_cache *c0_cursor_cache;

merr_t
c0sk_init(void)
{
    struct kmem_cache *cache;

    cache = kmem_cache_create(
        "c0_cursor", sizeof(struct c0_cursor), alignof(struct c0_cursor), SLAB_PACKED, NULL);
    if (ev(!cache))
        return merr(ENOMEM);

    c0_cursor_cache = cache;

    return 0;
}

void
c0sk_fini(void)
{
    kmem_cache_destroy(c0_cursor_cache);
    c0_cursor_cache = NULL;
}

merr_t
c0sk_put(
    struct c0sk *            handle,
    u16                      skidx,
    struct kvs_ktuple       *kt,
    const struct kvs_vtuple *vt,
    uintptr_t                seqnoref)
{
    struct c0sk_impl *self = c0sk_h2r(handle);
    u64               start;
    merr_t            err;

    start = perfc_lat_startu(&self->c0sk_pc_op, PERFC_LT_C0SKOP_PUT);

    err = c0sk_putdel(self, skidx, C0SK_OP_PUT, kt, vt, seqnoref);

    if (start > 0) {
        perfc_lat_record(&self->c0sk_pc_op, PERFC_LT_C0SKOP_PUT, start);
        perfc_inc(&self->c0sk_pc_op, PERFC_RA_C0SKOP_PUT);
    }

    return err;
}

merr_t
c0sk_del(struct c0sk *handle, u16 skidx, struct kvs_ktuple *kt, uintptr_t seqnoref)
{
    struct c0sk_impl *self = c0sk_h2r(handle);
    u64               start;
    merr_t            err;

    start = perfc_lat_startu(&self->c0sk_pc_op, PERFC_LT_C0SKOP_DEL);

    err = c0sk_putdel(self, skidx, C0SK_OP_DEL, kt, NULL, seqnoref);

    if (start > 0) {
        perfc_lat_record(&self->c0sk_pc_op, PERFC_LT_C0SKOP_DEL, start);
        perfc_inc(&self->c0sk_pc_op, PERFC_RA_C0SKOP_DEL);
    }

    return err;
}

merr_t
c0sk_prefix_del(struct c0sk *handle, u16 skidx, struct kvs_ktuple *kt, uintptr_t seqnoref)
{
    struct c0sk_impl *self = c0sk_h2r(handle);

    return c0sk_putdel(self, skidx, C0SK_OP_PREFIX_DEL, kt, NULL, seqnoref);
}

/*
 * Tombstone indicated by:
 *     return value == 0 && res == FOUND_TOMB
 */
merr_t
c0sk_get(
    struct c0sk *            handle,
    u16                      skidx,
    u32                      pfx_len,
    const struct kvs_ktuple *kt,
    u64                      view_seq,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf)
{
    struct c0_kvmultiset *c0kvms;
    struct c0sk_impl *    self;
    uintptr_t             key_seqref = 0, ptomb_seqref = 0;
    u64                   start;
    u64                   pfx_seq = 0, val_seq = 0;
    u64                   seq;
    merr_t                err = 0;

    self = c0sk_h2r(handle);
    *res = NOT_FOUND;

    start = perfc_lat_startl(&self->c0sk_pc_op, PERFC_LT_C0SKOP_GET);

    /* Disable ptomb searching if the key has no prefix.
     */
    if (kt->kt_len < pfx_len)
        pfx_len = 0;

    /* Search the list of c0_kvmultisets from newest to oldest...
     */
    rcu_read_lock();
    cds_list_for_each_entry_rcu(c0kvms, &self->c0sk_kvmultisets, c0ms_link)
    {
        struct c0_kvset *c0kvs;

        /* Search for ptomb if key is prefixed.
         * [HSE_REVISIT] Can we skip this search when (pfx_seq > 0) ???
         */
        if (pfx_len > 0) {
            c0kvs = c0kvms_ptomb_c0kvset_get(c0kvms);
            c0kvs_prefix_get_rcu(c0kvs, skidx, kt, view_seq, seqref, pfx_len, &ptomb_seqref);

            seq = HSE_SQNREF_TO_ORDNL(ptomb_seqref);
            if (seq > pfx_seq)
                pfx_seq = seq;
        }

        /* Search for latest value of key w/ seqno <= iseqno. */
        c0kvs = c0kvms_get_hashed_c0kvset(c0kvms, kt->kt_hash);
        err = c0kvs_get_rcu(c0kvs, skidx, kt, view_seq, seqref, res, vbuf, &key_seqref);
        if (ev(err))
            break;

        val_seq = HSE_SQNREF_TO_ORDNL(key_seqref);

        if (*res != NOT_FOUND)
            break;
    }
    rcu_read_unlock();

    if (pfx_seq > val_seq) {
        *res = FOUND_PTMB;
        vbuf->b_len = 0;
    }

    if (start > 0) {
        perfc_lat_record(&self->c0sk_pc_op, PERFC_LT_C0SKOP_GET, start);
        perfc_inc(&self->c0sk_pc_op, PERFC_RA_C0SKOP_GET);
    }

    return err;
}

merr_t
c0sk_pfx_probe(
    struct c0sk *            handle,
    u16                      skidx,
    u32                      pfx_len,
    u32                      sfx_len,
    const struct kvs_ktuple *kt,
    u64                      view_seq,
    uintptr_t                seqref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf)
{
    struct c0_kvmultiset *c0kvms;
    struct c0sk_impl *    self;
    uintptr_t             ptomb_seqref = 0;
    u64                   pfx_seq = 0;
    merr_t                err = 0;

    self = c0sk_h2r(handle);
    *res = NOT_FOUND;

    /* Disable ptomb searching if the key has no prefix.
     */
    if (kt->kt_len < pfx_len)
        pfx_len = 0;

    /* Search the list of c0_kvmultisets from newest to oldest...
     */
    rcu_read_lock();
    cds_list_for_each_entry_rcu(c0kvms, &self->c0sk_kvmultisets, c0ms_link)
    {
        struct c0_kvset *c0kvs;

        /* Search for ptomb if key is prefixed.
         */
        if (pfx_len > 0) {
            c0kvs = c0kvms_ptomb_c0kvset_get(c0kvms);
            c0kvs_prefix_get_rcu(c0kvs, skidx, kt, view_seq, seqref, pfx_len, &ptomb_seqref);

            pfx_seq = HSE_SQNREF_TO_ORDNL(ptomb_seqref);
        }

        err = c0kvms_pfx_probe_rcu(
            c0kvms, skidx, kt, sfx_len, view_seq, seqref, res, qctx, kbuf, vbuf, pfx_seq);
        if (ev(err))
            break;

        if (pfx_seq)
            *res = FOUND_PTMB;

        /* Break if found a ptomb or FOUND_MULTIPLE */
        if (pfx_seq || qctx->seen > 1)
            break;
    }
    rcu_read_unlock();

    return err;
}

merr_t
c0sk_open(
    struct kvdb_rparams *kvdb_rp,
    struct mpool *       mp_dataset,
    const char *         mp_name,
    struct kvdb_health * health,
    struct csched *      csched,
    atomic64_t *         kvdb_seq,
    u64                  gen,
    struct c0sk **       c0skp)
{
    struct c0_kvmultiset *c0kvms;
    struct c0sk_impl *    c0sk;
    merr_t                err;
    uint                  tdmax;
    void                **stashp;

    assert(health);

    c0sk = aligned_alloc(alignof(*c0sk), sizeof(*c0sk));
    if (!c0sk) {
        err = merr(ENOMEM);
        goto errout;
    }

    memset(c0sk, 0, sizeof(*c0sk));

    c0sk->c0sk_kvdb_rp = kvdb_rp;
    c0sk->c0sk_ds = mp_dataset;
    c0sk->c0sk_kvdb_health = health;
    c0sk->c0sk_csched = csched;

    c0sk->c0sk_kvdb_seq = kvdb_seq;

    c0sk->c0sk_kvdbhome = strdup(mp_name);
    if (!c0sk->c0sk_kvdbhome) {
        err = merr(ENOMEM);
        goto errout;
    }

    CDS_INIT_LIST_HEAD(&c0sk->c0sk_kvmultisets);
    INIT_LIST_HEAD(&c0sk->c0sk_sync_waiters);

    INIT_LIST_HEAD(&c0sk->c0sk_rcu_pending);
    c0sk->c0sk_rcu_active = false;

    atomic_set(&c0sk->c0sk_replaying, 0);
    atomic64_set(&c0sk->c0sk_ingest_gen, 0);
    atomic_set(&c0sk->c0sk_ingest_ldrcnt, 0);
    atomic_set(&c0sk->c0sk_ingest_finlat, 30000);
    mutex_init_adaptive(&c0sk->c0sk_kvms_mutex);
    mutex_init(&c0sk->c0sk_sync_mutex);
    cv_init(&c0sk->c0sk_kvms_cv, "c0sk_kvms_cv");

    if (sem_init(&c0sk->c0sk_sync_sema, 0, 1)) {
        err = merr(errno);
        goto errout;
    }

    for (int i = 0; i < NELEM(c0sk->c0sk_ingest_refv); ++i)
        atomic_set(&c0sk->c0sk_ingest_refv[i].refcnt, 0);

    tdmax = clamp_t(uint, kvdb_rp->c0_ingest_threads, 1, HSE_C0_INGEST_THREADS_MAX);

    c0sk->c0sk_wq_ingest = alloc_workqueue("c0sk_ingest", 0, tdmax);
    if (!c0sk->c0sk_wq_ingest) {
        err = merr(ENOMEM);
        goto errout;
    }

    tdmax = clamp_t(uint, kvdb_rp->c0_maint_threads, 1, HSE_C0_MAINT_THREADS_MAX);

    c0sk->c0sk_wq_maint = alloc_workqueue("c0sk_maint", 0, tdmax);
    if (!c0sk->c0sk_wq_maint) {
        err = merr(ENOMEM);
        goto errout;
    }

    c0sk->c0sk_ingest_width_max = kvdb_rp->c0_ingest_width;
    c0sk->c0sk_ingest_width = c0sk->c0sk_ingest_width_max;

    if (gen > 0)
        c0kvms_gen_init(gen);

    stashp = HSE_LIKELY(atomic_read(&c0sk->c0sk_replaying) == 0) ? &c0sk->c0sk_stash : NULL;

    err = c0kvms_create(c0sk->c0sk_ingest_width, c0sk->c0sk_kvdb_seq, stashp, &c0kvms);
    if (err)
        goto errout;

    if (!c0sk_install_c0kvms(c0sk, NULL, c0kvms)) {
        assert(0);
        c0kvms_putref(c0kvms); /* release birth reference */
        err = merr(EINVAL);
        goto errout;
    }

    atomic64_set(&c0sk->c0sk_ingest_order_curr, 0);
    atomic64_set(&c0sk->c0sk_ingest_order_next, 0);

    c0sk_perfc_alloc(c0sk);

    *c0skp = &c0sk->c0sk_handle;

    hse_log(HSE_INFO "c0sk_open(%s) complete", mp_name);

errout:
    if (err) {
        hse_elog(HSE_ERR "c0sk_open(%s) failed: @@e", err, mp_name);

        if (c0sk) {
            destroy_workqueue(c0sk->c0sk_wq_ingest);
            destroy_workqueue(c0sk->c0sk_wq_maint);
            cv_destroy(&c0sk->c0sk_kvms_cv);
            mutex_destroy(&c0sk->c0sk_sync_mutex);
            mutex_destroy(&c0sk->c0sk_kvms_mutex);
            free(c0sk->c0sk_kvdbhome);
            free(c0sk);
        }
    }

    return err;
}

merr_t
c0sk_close(struct c0sk *handle)
{
    struct c0sk_impl *self;

    if (!handle)
        return merr(ev(EINVAL));

    self = c0sk_h2r(handle);
    self->c0sk_closing = true;

    c0sk_sync(handle, HSE_KVDB_SYNC_REFWAIT);

    /* There should be only one (empty) kvms on the list after
     * calling c0sk_sync() and waiting for ingest to complete.
     */
    while (1) {
        struct c0_kvmultiset *first;

        mutex_lock(&self->c0sk_kvms_mutex);
        first = c0sk_get_first_c0kvms(handle);
        if (first) {
            cds_list_del_rcu(&first->c0ms_link);
            --self->c0sk_kvmultisets_cnt;
            perfc_set(
                &self->c0sk_pc_ingest, PERFC_BA_C0SKING_QLEN, (u64)self->c0sk_kvmultisets_cnt);

            assert(c0kvms_get_element_count(first) == 0);
            assert(self->c0sk_kvmultisets_cnt == 0);
        }
        mutex_unlock(&self->c0sk_kvms_mutex);

        if (!first)
            break;

        c0kvms_putref(first);
    }

    destroy_workqueue(self->c0sk_wq_ingest);
    destroy_workqueue(self->c0sk_wq_maint);
    c0kvms_destroy_cache(&self->c0sk_stash);
    cv_destroy(&self->c0sk_kvms_cv);
    mutex_destroy(&self->c0sk_sync_mutex);
    mutex_destroy(&self->c0sk_kvms_mutex);
    c0sk_perfc_free(self);
    free(self->c0sk_kvdbhome);
    free(self);

    return 0;
}

void
c0sk_ctxn_set_set(struct c0sk *handle, struct kvdb_ctxn_set *ctxn_set)
{
    c0sk_h2r(handle)->c0sk_ctxn_set = ctxn_set;
}

void
c0sk_lc_set(struct c0sk *handle, struct lc *lc)
{
    struct c0sk_impl *self;

    if (!handle)
        return;

    self = c0sk_h2r(handle);
    self->c0sk_lc = lc;
}

struct lc *
c0sk_lc_get(struct c0sk *handle)
{
    return handle ? c0sk_h2r(handle)->c0sk_lc : NULL;
}

void
c0sk_min_seqno_set(struct c0sk *handle, u64 seq)
{
    atomic64_set(&c0sk_h2r(handle)->c0sk_ingest_min, seq);
}

u64
c0sk_min_seqno_get(struct c0sk *handle)
{
    assert(handle);
    return atomic64_read(&c0sk_h2r(handle)->c0sk_ingest_min);
}

u64
c0sk_ingest_order_register(struct c0sk *handle)
{
    struct c0sk_impl *self;

    assert(handle);
    self = c0sk_h2r(handle);

    return atomic64_fetch_add(1, &self->c0sk_ingest_order_curr);
}

/* In order to adjust the throttle accurately, c0sk need to measure a few ingests
 * that run concurrently with cn I/O.  So we initialize the throttle at startup
 * to prevent a large backlog of pending c0kvms before we've had enough time
 * to gather sufficient hueristics.
 */
void
c0sk_throttle_sensor(struct c0sk *handle, struct throttle_sensor *sensor)
{
    if (handle) {
        struct c0sk_impl *self = c0sk_h2r(handle);
        uint senval = THROTTLE_SENSOR_SCALE / 2;
        uint finlat = 30000;

        if (self->c0sk_kvdb_rp->throttle_init_policy == THROTTLE_DELAY_START_LIGHT) {
            finlat = 6000;
            senval = 0;
        }

        atomic_set(&self->c0sk_ingest_finlat, finlat);
        throttle_sensor_set(sensor, senval);
        self->c0sk_sensor = sensor;
    }
}

struct kvdb_rparams *
c0sk_rparams(struct c0sk *handle)
{
    struct c0sk_impl *self;

    if (ev(!handle))
        return NULL;

    self = c0sk_h2r(handle);

    return self->c0sk_kvdb_rp;
}

static void
c0sk_sync_debug(struct c0sk_impl *self, u64 waiter_gen)
{
    hse_log(
        HSE_WARNING "%s: %lu %lu %lu %d",
        __func__,
        (ulong)atomic64_read(&self->c0sk_ingest_gen),
        (ulong)waiter_gen,
        (ulong)self->c0sk_release_gen,
        self->c0sk_kvmultisets_cnt);
}

/*
 * Sync only forces all current data to media -- it does not
 * prevent new data from being created while the sync blocks.
 *
 * We register our interest in when this c0kvms has been ingested,
 * and report how many kvmultisets exist once per second until
 * it has been ingested.
 *
 * If we are called as part of close, then there is a higher level
 * mutex which prevents new kvmultisets from being created,
 * and therefore this will block until all data are ingested.
 *
 * cf: c0_kvmultiset_ingest_completion(), release_multiset()
 */
merr_t
c0sk_sync(struct c0sk *handle, const unsigned int flags)
{
    struct c0sk_waiter waiter = {};
    struct c0sk_impl * self;
    merr_t             err;
    int                rc;

    if (ev(!handle))
        return merr(EINVAL);

    self = c0sk_h2r(handle);

    if (self->c0sk_kvdb_rp->read_only)
        return 0;

    /**
     * Don't mark syncing in asynchronous request.
     */
    self->c0sk_syncing = !(flags & HSE_KVDB_SYNC_ASYNC);
    err = c0sk_flush_current_multiset(self, &waiter.c0skw_gen, flags & HSE_KVDB_SYNC_REFWAIT);
    if (ev(err)) {
        self->c0sk_syncing = false;
        return merr_errno(err) == EAGAIN ? 0 : err;
    }

    if (flags & HSE_KVDB_SYNC_ASYNC)
        return err;

    cv_init(&waiter.c0skw_cv, __func__);

    /* Wait here until the current c0kvms is released.  Print
     * the backlog size periodically until we've been signaled.
     */
    mutex_lock(&self->c0sk_sync_mutex);
    list_add_tail(&waiter.c0skw_link, &self->c0sk_sync_waiters);

    while (waiter.c0skw_gen > self->c0sk_release_gen) {
        rc = cv_timedwait(&waiter.c0skw_cv, &self->c0sk_sync_mutex, 1000);

        if (rc && (self->c0sk_kvdb_rp->c0_debug & C0_DEBUG_SYNC)) {
            mutex_unlock(&self->c0sk_sync_mutex);

            c0sk_sync_debug(self, waiter.c0skw_gen);

            mutex_lock(&self->c0sk_sync_mutex);
        }
    }

    self->c0sk_syncing = false;
    list_del(&waiter.c0skw_link);
    mutex_unlock(&self->c0sk_sync_mutex);

    if (self->c0sk_kvdb_rp->c0_debug & C0_DEBUG_SYNC)
        c0sk_sync_debug(self, waiter.c0skw_gen);

    cv_destroy(&waiter.c0skw_cv);

    return 0;
}

/* --------------------------------------------------
 * c0 cursor support
 *
 * Special note on ref-counting transaction kvms: don't.
 * The c0_kvmultiset for a kvdb_ctxn is private to that transaction
 * for the purposes of ref-counting.  In particular, the kvms may
 * exist, but be reset independently of a cursor, which can only
 * happen if the refcnt is 1 (not 2, as would happen here).
 */

static void
c0sk_cursor_debug_val(struct c0_cursor *cur, uintptr_t seqnoref, struct bonsai_kv *bkv);

#define MSCUR_NEXT(_p)         es2mscur(((_p)->c0mc_es.es_next_src))
#define MSCUR_SET_NEXT(_p, _q) ((_p)->c0mc_es.es_next_src = (void *)(_q))

/*
 * These are poorly named to prevent collision with the other
 * poorly named cursor allocator.
 */

static struct c0_kvmultiset_cursor *
c0sk_cursor_get_free(struct c0_cursor *cur)
{
    struct c0_kvmultiset_cursor *p;

    p = cur->c0cur_free;
    if (p) {
        cur->c0cur_free = MSCUR_NEXT(p);
        return p;
    }

    return alloc_aligned(sizeof(*p), SMP_CACHE_BYTES);
}

static void
c0sk_cursor_put_free(struct c0_cursor *cur, struct c0_kvmultiset_cursor *p)
{
    assert(p != cur->c0cur_active);

    /* HSE_REVISIT: keep a count of these to control growth */
    MSCUR_SET_NEXT(p, cur->c0cur_free);
    cur->c0cur_free = p;
}

static void
c0sk_cursor_release(struct c0_cursor *cur)
{
    struct c0_kvmultiset_cursor *this, *next;
    int i;

    this = cur->c0cur_active;
    cur->c0cur_active = NULL;

    /* Destroy KVMS cursors */
    for (i = 0; this; this = next, i++) {
        next = MSCUR_NEXT(this);

        c0kvms_cursor_destroy(this);
        c0sk_cursor_put_free(cur, this);
    }

    /* Drop KVMS references */
    ev(i > cur->c0cur_cnt);
    i = max(cur->c0cur_cnt, i);

    while (i-- > 0) {
        if (cur->c0cur_kvmsv[i]) {
            c0kvms_putref(cur->c0cur_kvmsv[i]);
            cur->c0cur_kvmsv[i] = NULL;
        }
    }

    cur->c0cur_cnt = 0;
}

static void
c0sk_cursor_ptomb_reset(struct c0_cursor *cur)
{
    cur->c0cur_ptomb_key = 0;
    cur->c0cur_ptomb_klen = 0;
    cur->c0cur_ptomb_seq = 0;
    cur->c0cur_ptomb_es = 0;
}

/*
 * look for ingested kvms and release them:
 * instead of crawling the list matching each, find the last
 * and search for this in the cursor list;
 * the ingested kvms are now found in cN
 *
 * It is possible all kvms for this cursor have been ingested;
 * in this case, everything should be released.  However,
 * the c0cursor cannot be destroyed (as in the cache),
 * since this code is also used in the update path.
 */
static void
c0sk_cursor_trim(struct c0_cursor *cur)
{
    struct c0_kvmultiset_cursor *this, *next;
    struct c0_kvmultiset *last;
    struct c0sk_impl *    c0sk;
    u64                   lastgen;
    int                   i, j;
    int                   jmax;

    this = cur->c0cur_active;
    jmax = cur->c0cur_cnt;

    if (ev(!this))
        goto dropall;

    c0sk = c0sk_h2r(cur->c0cur_c0sk);
    lastgen = U64_MAX;
    j = 0;

    rcu_read_lock();
    last = c0sk_get_last_c0kvms(&c0sk->c0sk_handle);
    if (last)
        lastgen = c0kvms_gen_read(last);
    rcu_read_unlock();

    /*
     * Check if everything has been ingested
     */
    if (!cur->c0cur_ctxn && c0kvms_gen_read(this->c0mc_kvms) < lastgen) {
        cur->c0cur_active = NULL;
    } else {
        /* else search the list for the last active kvms */
        for (; this; this = next, ++j) {
            next = MSCUR_NEXT(this);

            if (c0kvms_gen_read(this->c0mc_kvms) <= lastgen) {
                MSCUR_SET_NEXT(this, 0);
                this = next;
                break;
            }
        }
    }

    for (; this; this = next) {
        next = MSCUR_NEXT(this);

        /* reset cached pt if pt was from this kvms */
        if (cur->c0cur_ptomb_es == &this->c0mc_es)
            c0sk_cursor_ptomb_reset(cur);

        bin_heap2_remove_src(cur->c0cur_bh, &this->c0mc_es, false);
        c0kvms_cursor_destroy(this);

        for (i = j; i < jmax; i++) {
            if (cur->c0cur_kvmsv[i] == this->c0mc_kvms) {
                cur->c0cur_kvmsv[i] = NULL;
                j = i + 1;
                break;
            }
        }

        if (ev(i >= jmax, HSE_WARNING))
            assert(i < jmax);

        c0kvms_putref(this->c0mc_kvms);
        c0sk_cursor_put_free(cur, this);
        --cur->c0cur_cnt;

        ++cur->c0cur_summary->n_trim;
        --cur->c0cur_summary->n_kvms;
    }

    if (cur->c0cur_active)
        return;

    /* If the cursor list is empty, drop all kvms references so the
     * cursor init that follows doesn't get additional references (which
     * would cause a leak).
     */
dropall:
    for (i = 0; i < jmax; i++) {
        if (cur->c0cur_kvmsv[i]) {
            c0kvms_putref(cur->c0cur_kvmsv[i]);
            cur->c0cur_kvmsv[i] = NULL;
        }
    }

    cur->c0cur_state = C0CUR_STATE_NEED_ALL;
    cur->c0cur_cnt = 0;
}

static struct c0_kvmultiset_cursor *
c0sk_cursor_new_c0mc(struct c0_cursor *cur, struct c0_kvmultiset *kvms)
{
    struct c0_kvmultiset_cursor *c0mc;

    c0mc = c0sk_cursor_get_free(cur);
    if (!c0mc)
        return 0;

    cur->c0cur_merr = c0kvms_cursor_create(
        kvms,
        c0mc,
        cur->c0cur_skidx,
        cur->c0cur_prefix,
        cur->c0cur_pfx_len,
        cur->c0cur_ct_pfx_len,
        cur->c0cur_reverse);
    if (ev(cur->c0cur_merr)) {
        c0sk_cursor_release(cur);
        return 0;
    }

    return c0mc;
}

static void
c0sk_cursor_record_active_gen(struct c0_cursor *cur, struct c0_kvmultiset **kvmsv, int cnt)
{
    struct c0sk_impl *c0sk = c0sk_h2r(cur->c0cur_c0sk);

    if (cnt) {
        cur->c0cur_act_gen = c0kvms_gen_read(kvmsv[0]);
        if (c0kvms_is_finalized(kvmsv[0]))
            cur->c0cur_act_gen++;
    } else {
        cur->c0cur_act_gen = c0sk->c0sk_release_gen + 1;
    }
}

static merr_t
c0sk_cursor_discover(struct c0_cursor *cur)
{
    struct c0_kvmultiset **kvmsv = cur->c0cur_kvmsv;
    struct c0_kvmultiset * kvms;
    struct c0sk_impl *     c0sk;
    int                    cnt;

    c0sk = c0sk_h2r(cur->c0cur_c0sk);
    kvms = 0;
    cnt = 0;

    /* find the set of kvms we need and gain refs */
    rcu_read_lock();
    cds_list_for_each_entry_rcu(kvms, &c0sk->c0sk_kvmultisets, c0ms_link)
    {
        if (cnt >= HSE_C0_KVSET_CURSOR_MAX)
            break;
        c0kvms_getref(kvms);
        kvmsv[cnt++] = kvms;
    }
    rcu_read_unlock();

    if (cnt >= HSE_C0_KVSET_CURSOR_MAX) {
        hse_log(HSE_ERR "c0sk_cursor_discover: cnt %d - eagain", cnt);
        while (cnt-- > 0)
            c0kvms_putref(kvmsv[cnt]);
        cur->c0cur_merr = ev(merr(EAGAIN));
        return cur->c0cur_merr;
    }

    cur->c0cur_summary->n_kvms = cnt;

    cur->c0cur_cnt = cnt;
    c0sk_cursor_record_active_gen(cur, kvmsv, cnt);

    cur->c0cur_state = C0CUR_STATE_NEED_INIT;
    return 0;
}

static merr_t
c0sk_cursor_activate(struct c0_cursor *cur)
{
    struct c0_kvmultiset_cursor **next, *c0mc;
    int                           i;

    /*
     * kvmsv[] is newest to oldest; the bin_heap source array
     * must also be newest to oldest, so build the linked list
     * in the same order
     */
    next = &cur->c0cur_active;

    for (i = 0; i < cur->c0cur_cnt; ++i) {
        c0mc = c0sk_cursor_new_c0mc(cur, cur->c0cur_kvmsv[i]);
        if (ev(!c0mc)) {
            c0sk_cursor_release(cur);
            return cur->c0cur_merr;
        }

        *next = c0mc;
        MSCUR_SET_NEXT(c0mc, 0);
        next = (void *)&c0mc->c0mc_es.es_next_src;
    }

    return 0;
}

static inline void
c0sk_cursor_prepare(struct c0_cursor *cur)
{
    bin_heap2_prepare_list(cur->c0cur_bh, 0, &cur->c0cur_active->c0mc_es);
    cur->c0cur_state = C0CUR_STATE_READY;
}

static merr_t
c0sk_cursor_init(struct c0_cursor *cur)
{
    if (cur->c0cur_state & C0CUR_STATE_NEED_DISC) {
        cur->c0cur_merr = c0sk_cursor_discover(cur);
        if (ev(cur->c0cur_merr))
            return cur->c0cur_merr;
    }
    cur->c0cur_merr = c0sk_cursor_activate(cur);
    if (ev(cur->c0cur_merr))
        return cur->c0cur_merr;

    c0sk_cursor_prepare(cur);
    return 0;
}

/*
 * A c0sk cursor uses c0cur_kvmsv[] (kvmsv[]) to keep track of all KVMSes, and
 * c0cur_active (list) to track all kvms cursors.
 *
 * kvmsv[] and list throughout the cursor's lifecycle:
 *
 * Create:
 *           - kvmsv[] is populated
 *           - list is NULL
 * Read/Seek:
 *           - list is initialized by traversing kvmsv[]
 * Trim:
 *           - list is trimmed
 *           - corresponding kvmsv[] elements are putref-ed and marked as NULL
 * Update:
 *           - @Trim
 *           - create cursors for new KVMSes and update kvmsv[] with the new
 *             KVMSes. The order of KVMSes in kvmsv[] is always maintained such
 *             that kvmsv[i] is newer than kvmsv[i+1].
 * Save:
 *           - @Trim
 *           - add to cache
 * Destroy:
 *           - Use kvmsv[] to drop references on KVMSes
 *           - Use list to destroy cursors.
 */
merr_t
c0sk_cursor_create(
    struct c0sk *          handle,
    u64                    seqno,
    int                    skidx,
    bool                   reverse,
    u32                    ct_pfx_len,
    const void *           prefix,
    size_t                 pfx_len,
    struct cursor_summary *summary,
    struct c0_cursor **    c0cur)
{
    struct c0_cursor *cur;
    merr_t            err;

    cur = kmem_cache_zalloc(c0_cursor_cache);
    if (ev(!cur))
        return merr(ENOMEM);

    cur->c0cur_summary = summary;
    cur->c0cur_prefix = prefix;
    cur->c0cur_pfx_len = pfx_len;
    cur->c0cur_reverse = reverse;
    cur->c0cur_seqno = seqno;
    cur->c0cur_skidx = skidx;
    cur->c0cur_c0sk = handle;

    cur->c0cur_free = 0;
    cur->c0cur_active = 0;
    cur->c0cur_ct_pfx_len = ct_pfx_len;

    cur->c0cur_summary->skidx = skidx;

    err = bin_heap2_create(
        HSE_C0_KVSET_CURSOR_MAX, reverse ? bn_kv_cmp_rev : bn_kv_cmp, &cur->c0cur_bh);
    if (ev(err)) {
        kmem_cache_free(c0_cursor_cache, cur);
        return err;
    }

    err = c0sk_cursor_discover(cur);
    if (ev(err)) {
        bin_heap2_destroy(cur->c0cur_bh);
        kmem_cache_free(c0_cursor_cache, cur);
        return err;
    }

    *c0cur = cur;
    return cur->c0cur_merr;
}

static struct c0_kvmultiset_cursor *
c0sk_cursor_add_kvms(struct c0_cursor *cur, struct c0_kvmultiset *kvms)
{
    struct c0_kvmultiset_cursor *c0mc;

    c0mc = c0sk_cursor_new_c0mc(cur, kvms);
    if (!c0mc)
        return 0;

    cur->c0cur_merr = bin_heap2_insert_src(cur->c0cur_bh, &c0mc->c0mc_es);
    if (ev(cur->c0cur_merr)) {
        c0kvms_cursor_destroy(c0mc);
        c0sk_cursor_put_free(cur, c0mc);
        return 0;
    }

    MSCUR_SET_NEXT(c0mc, cur->c0cur_active);
    cur->c0cur_active = c0mc;
    ++cur->c0cur_summary->n_kvms;

    return c0mc;
}

struct c0_kvmultiset *
c0sk_get_first_c0kvms(struct c0sk *handle)
{
    struct c0sk_impl *    self = c0sk_h2r(handle);
    struct cds_list_head *head;
    struct c0_kvmultiset *kvms;

    head = &self->c0sk_kvmultisets;
    kvms = cds_list_entry(rcu_dereference(head->next), typeof(*kvms), c0ms_link);

    return (&kvms->c0ms_link == head) ? NULL : kvms;
}

struct c0_kvmultiset *
c0sk_get_last_c0kvms(struct c0sk *handle)
{
    struct c0sk_impl *    self = c0sk_h2r(handle);
    struct c0_kvmultiset *kvms;
    struct cds_list_head *head;

    head = &self->c0sk_kvmultisets;
    kvms = cds_list_entry(rcu_dereference(head->prev), typeof(*kvms), c0ms_link);

    return (&kvms->c0ms_link == head) ? NULL : kvms;
}

void
c0sk_cursor_bind_txn(struct c0_cursor *cur, struct kvdb_ctxn *ctxn)
{
    cur->c0cur_ctxn = ctxn;
}

merr_t
c0sk_cursor_save(struct c0_cursor *cur)
{
    /* discard ingested kvms cursors before caching */
    c0sk_cursor_trim(cur);
    return 0;
}

merr_t
c0sk_cursor_destroy(struct c0_cursor *cur)
{
    struct c0_kvmultiset_cursor *p, *next;

    if (cur->c0cur_bh) {
        c0sk_cursor_release(cur);
        bin_heap2_destroy(cur->c0cur_bh);
    }
    for (p = cur->c0cur_free; p; p = next) {
        next = MSCUR_NEXT(p);
        free_aligned(p);
    }

    kmem_cache_free(c0_cursor_cache, cur);
    return 0;
}

merr_t
c0sk_cursor_seek(struct c0_cursor *cur, const void *seek, size_t seeklen, struct kc_filter *filter)
{
    struct c0_kvmultiset_cursor *this;

    if (ev((cur->c0cur_state & C0CUR_STATE_NEED_INIT) && c0sk_cursor_init(cur)))
        return cur->c0cur_merr;

    cur->c0cur_filter = filter;

    c0sk_cursor_ptomb_reset(cur);
    for (this = cur->c0cur_active; this; this = MSCUR_NEXT(this))
        c0kvms_cursor_seek(this, seek, seeklen, cur->c0cur_ct_pfx_len);

    c0sk_cursor_prepare(cur);
    return 0;
}

/*
 * When a cursor sees a ptomb, it is either from a txn kvms, or a regular kvms.
 * 1. TXN KVMS (seqnoref && seqnoref == val->bv_seqnoref):
 *         A ptomb from this kvms eclipses keys ONLY from the older KVMSes.
 * 2. Regular KVMS (!seqnoref || seqnoref != val->bv_seqnoref):
 *         this KVMS can have a mix of keys - some the ptomb eclipses, some that it doesn't. Since
 *         all values in this kvms have a seqno (either from a committed txn or from a regular
 *         put/del/pdel), save ptomb info and hide appropriate keys from caller.
 *
 * When we get a value to compare against ptomb, once again it's either from:
 * 1. a txn kvms:
 *         Not ptomb affects this. kv pair.
 * 2. a regular kvms:
 *         If ptomb is cached, that means it was from a regular kvms. Output
 *         according to seqnos.
 */
merr_t
c0sk_cursor_read(struct c0_cursor *cur, struct kvs_cursor_element *elem, bool *eof)
{
    struct bonsai_kv *bkv, *dup;
    uintptr_t         seqnoref;

    if (cur->c0cur_state != C0CUR_STATE_READY) {
        if (cur->c0cur_state & C0CUR_STATE_NEED_INIT)
            if (c0sk_cursor_init(cur))
                return ev(cur->c0cur_merr);
    }

    seqnoref = kvdb_ctxn_get_seqnoref(cur->c0cur_ctxn);

    while (bin_heap2_pop(cur->c0cur_bh, (void **)&bkv)) {
        struct key_immediate *imm = &bkv->bkv_key_imm;
        struct bonsai_val *   val;
        u32                   klen = key_imm_klen(imm);
        bool                  is_ptomb = bkv->bkv_flags & BKV_FLAG_PTOMB;
        enum hse_seqno_state  state;
        u64                   seqno = 0;

        if (cur->c0cur_pfx_len) {
            int len = min_t(int, klen, cur->c0cur_pfx_len);
            int rc = memcmp(bkv->bkv_key, cur->c0cur_prefix, len);

            /* Check eof condition */
            if ((cur->c0cur_reverse && rc < 0) || (!cur->c0cur_reverse && rc > 0))
                break;

            /* Skip this key if either,
             *   1. we haven't yet reached pfx, or
             *   2. key is shorter than pfx, but key is NOT A PTOMB.
             */
            if (rc != 0 || (len != cur->c0cur_pfx_len && !is_ptomb))
                continue;
        }

        if (cur->c0cur_filter) {
            const void *maxkey = cur->c0cur_filter->kcf_maxkey;
            size_t      maxlen = cur->c0cur_filter->kcf_maxklen;

            if (keycmp(bkv->bkv_key, klen, maxkey, maxlen) > 0)
                break; /* eof */
        }

        val = c0kvs_findval(bkv, cur->c0cur_seqno, seqnoref);
        if (!val) {
            if (cur->c0cur_debug)
                c0sk_cursor_debug_val(cur, seqnoref, bkv);
            continue;
        }

        assert(!HSE_CORE_IS_PTOMB(val->bv_value) || is_ptomb);
        state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);

        if (cur->c0cur_ptomb_key) {
            int rc = keycmp_prefix(cur->c0cur_ptomb_key, cur->c0cur_ct_pfx_len, bkv->bkv_key, klen);

            if (rc == 0) {
                /* Compare seqnos only if value has an ordinal seqno. */
                if (state == HSE_SQNREF_STATE_DEFINED && seqno < cur->c0cur_ptomb_seq)
                    continue;
            } else {
                c0sk_cursor_ptomb_reset(cur);
            }
        }

        if (is_ptomb) {
            /* Store newest version of a ptomb.
             */
            if (!cur->c0cur_ptomb_key) {
                cur->c0cur_ptomb_key = bkv->bkv_key;
                cur->c0cur_ptomb_klen = klen;
                cur->c0cur_ptomb_es = bkv->bkv_es;
                cur->c0cur_ptomb_seq =
                    state == HSE_SQNREF_STATE_DEFINED ? seqno : cur->c0cur_seqno + 1;
            }
        }

        /*
         * We have a key for c0, but there may be duplicates in other kvmultisets -- this one must
         * hide all the rest.
         */
        while (bin_heap2_peek(cur->c0cur_bh, (void **)&dup)) {
            struct bonsai_val *   dup_val;
            struct key_immediate *dupi = &dup->bkv_key_imm;
            enum hse_seqno_state  dup_state;
            u64                   dup_seqno = 0;

            if (key_imm_klen(imm) != key_imm_klen(dupi) ||
                memcmp(bkv->bkv_key, dup->bkv_key, key_imm_klen(imm)))
                break;

            /* Next key is a dup */
            dup_val = c0kvs_findval(dup, cur->c0cur_seqno, seqnoref);
            if (!dup_val) {
                bin_heap2_pop(cur->c0cur_bh, (void **)&dup); /* No val in cursor's view */
                continue;
            }

            dup_state = seqnoref_to_seqno(dup_val->bv_seqnoref, &dup_seqno);

            if (dup_state == HSE_SQNREF_STATE_UNDEFINED && !HSE_CORE_IS_PTOMB(dup_val->bv_seqnoref))
                break; /* Any non-ptomb from txn must be visible */

            if (!is_ptomb && HSE_CORE_IS_PTOMB(dup_val->bv_seqnoref))
                break;

            if (state == HSE_SQNREF_STATE_DEFINED && dup_state == HSE_SQNREF_STATE_DEFINED &&
                dup_seqno > seqno)
                break;

            bin_heap2_pop(cur->c0cur_bh, (void **)&dup);
        }

        /*
         * NB: this primitive must return tombstones
         * so higher layers can do annihilation
         */

        key2kobj(&elem->kce_kobj, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));

        elem->kce_is_ptomb = false;
        elem->kce_complen = 0;
        elem->kce_seqnoref = val->bv_seqnoref;

        if (HSE_CORE_IS_TOMB(val->bv_value)) {
            kvs_vtuple_init(&elem->kce_vt, val->bv_value, val->bv_xlen);
            if (HSE_CORE_IS_PTOMB(val->bv_value))
                elem->kce_is_ptomb = true;
        } else {
            kvs_vtuple_init(&elem->kce_vt, val->bv_value, bonsai_val_ulen(val));
            elem->kce_complen = bonsai_val_clen(val);
        }

        *eof = false;
        return 0;
    }

    *eof = true;
    return 0;
}

static void
c0sk_cursor_update_active(struct c0_cursor *cur)
{
    struct c0_kvmultiset_cursor *active;

    active = cur->c0cur_active;
    if (!active)
        return;

    /* only need to update bin heap if new underlying sources */
    if (c0kvms_cursor_update(active, cur->c0cur_ct_pfx_len)) {
        /*
         * added a new source to active->c0mc_es
         * which might have the best new value
         * so we must remove this source from *OUR* bh,
         */
        bin_heap2_remove_src(cur->c0cur_bh, &active->c0mc_es, true);
        bin_heap2_insert_src(cur->c0cur_bh, &active->c0mc_es);
    }
}

/*
 * This function updates an existing initialized cursor,
 * either from cache or in use, to trim ingested kvms,
 * and incorporate new kvms since cursor was created.
 *
 * It is not efficient for initial discovery, although it
 * would work correctly for that case, and is coded to
 * address this possibility as an edge case.
 */
merr_t
c0sk_cursor_update(struct c0_cursor *cur, u64 seqno, u32 *flags_out)
{
    struct c0_kvmultiset *new[HSE_C0_KVSET_CURSOR_MAX];
    struct c0_kvmultiset *       kvms = NULL;
    struct c0_kvmultiset_cursor *active, *p;
    struct c0sk_impl *           c0sk;
    int                          retries = 2, cnt, nact;

retry:
    if (flags_out)
        *flags_out = (seqno != cur->c0cur_seqno) ? CURSOR_FLAG_SEQNO_CHANGE : 0;

    cur->c0cur_seqno = seqno;

    c0sk_cursor_ptomb_reset(cur);
    c0sk_cursor_trim(cur);

    /* trimming could possibly have removed all active kvms */
    if (cur->c0cur_state & C0CUR_STATE_NEED_INIT) {
        if (c0sk_cursor_init(cur))
            return ev(cur->c0cur_merr);

        if (!cur->c0cur_ctxn)
            return 0;
    }

    /* HSE_REVISIT: For a bound cursor (!cur->c0cur_ctxn), just add any new kvms from
     * the c0 list where gen(c0kvms) > gen(active).
     */
    active = cur->c0cur_active;
    assert(active->c0mc_kvms == cur->c0cur_kvmsv[0]);

    for (nact = 0, p = active; p; p = MSCUR_NEXT(p))
        ++nact;

    if (ev(nact < 1 || nact < cur->c0cur_cnt, HSE_WARNING)) {
        assert(nact >= cur->c0cur_cnt);
        assert(nact > 0);

        nact = cur->c0cur_cnt;
    }

    c0sk = c0sk_h2r(cur->c0cur_c0sk);
    cnt = 0;

    rcu_read_lock();
    cds_list_for_each_entry_rcu(kvms, &c0sk->c0sk_kvmultisets, c0ms_link)
    {
        if (active && kvms == active->c0mc_kvms)
            break;
        if (cnt + nact >= HSE_C0_KVSET_CURSOR_MAX)
            break;
        c0kvms_getref(kvms);
        new[cnt++] = kvms;
    }
    rcu_read_unlock();

    /* ensure number of cursors created does not overflow arrays */
    if (ev(cnt + nact >= HSE_C0_KVSET_CURSOR_MAX)) {
        while (cnt-- > 0)
            c0kvms_putref(new[cnt]);
        return merr(EAGAIN);
    }

    c0sk_cursor_record_active_gen(cur, new, cnt);

    /* always need to update the cursor that was the current */
    c0sk_cursor_update_active(cur);

    if (cnt > 0) {
        struct c0_kvmultiset **kvmsv = cur->c0cur_kvmsv;

        /* Prepend new[] to kvmsv[].
         */
        memmove(kvmsv + cnt, kvmsv, sizeof(*kvmsv) * cur->c0cur_cnt);

        memcpy(kvmsv, new, sizeof(*kvmsv) * cnt);
        cur->c0cur_cnt += cnt;

        /* Temporal order is critical here:  The newest kvms must have
         * the lowest sort order.  new[] is ordered newest to oldest,
         * and inserting prepends, so traverse new[] backwards
         * such that the newest kvms is prepended last.
         */
        while (cnt-- > 0 && c0sk_cursor_add_kvms(cur, new[cnt]))
            ;

        ev(cnt >= 0, HSE_WARNING);

        /* We should have a new c0cur_active kvms at this point, which means
         * we can now trim the previous c0cur_active if it has been ingested.
         *
         * [HSE_REVISIT] We could eliminate this retry if we could add the
         * new kvms first then prune the ingested ones, feasible???
         */
        if (active && c0kvms_is_ingested(active->c0mc_kvms)) {
            if (retries-- > 0)
                goto retry;

            hse_log(
                HSE_WARNING "%s: cursor %p holding ref on ingested kvms %p",
                __func__,
                cur,
                active->c0mc_kvms);
        }
    }

    return cur->c0cur_merr;
}

/* --------------------------------------------------
 * c0 cursor debugging support
 *
 */

/* GCOV_EXCL_START */

HSE_USED HSE_COLD void
c0sk_cursor_debug_base(struct c0sk *handle, u64 seqno, const void *prefix, int pfx_len, int skidx)
{
    struct cursor_summary summary;
    struct c0_cursor *    cur;

    bool   eof;
    merr_t err;

    err = c0sk_cursor_create(handle, seqno, skidx, 0, 0, prefix, pfx_len, &summary, &cur);
    if (ev(err))
        return;

    printf(
        "created cursor at %p, bh %p, seqno %lu / 0x%lx\n",
        cur,
        cur->c0cur_bh,
        cur->c0cur_seqno,
        cur->c0cur_seqno);
    if (pfx_len) {
        char   disp[128];
        size_t pfx_len = cur->c0cur_pfx_len;

        fmt_pe(disp, sizeof(disp), cur->c0cur_prefix, pfx_len);
        printf("\twith prefix: %zu, %s\n", pfx_len, disp);
    }

    cur->c0cur_debug = 1;
    struct kvs_cursor_element elem;
    while (!c0sk_cursor_read(cur, &elem, &eof) && !eof) {
        struct kvs_vtuple *vt = &elem.kce_vt;
        uint               klen;
        char               kdata[64];
        char               kbuf[64];
        char               vbuf[128];

        key_obj_copy(kdata, sizeof(kdata), &klen, &elem.kce_kobj);
        fmt_hex(kbuf, sizeof(kbuf), kdata, klen);
        fmt_hex(vbuf, sizeof(vbuf), vt->vt_data, kvs_vtuple_vlen(vt));
        printf("%3d, %s = %s, %u\n", klen, kbuf, vbuf, kvs_vtuple_vlen(vt));
    }
    cur->c0cur_debug = 0;

    printf("destroying cursor at %p\n", cur);

    err = c0sk_cursor_destroy(cur);
    if (ev(err))
        return;
}

HSE_USED HSE_COLD void
c0sk_cursor_debug(struct c0_cursor *cur)
{
    c0sk_cursor_debug_base(
        cur->c0cur_c0sk, cur->c0cur_seqno, cur->c0cur_prefix, cur->c0cur_pfx_len, cur->c0cur_skidx);
}

HSE_USED HSE_COLD static void
c0sk_cursor_debug_val(struct c0_cursor *cur, uintptr_t seqnoref, struct bonsai_kv *bkv)
{
    char buf[256];

    fmt_hex(buf, sizeof(buf), bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));
    printf(
        "debug: discard bkv %p view 0x%lx ref 0x%lx rock 0x%lx key %s\n",
        bkv,
        (ulong)cur->c0cur_seqno,
        (ulong)seqnoref,
        (ulong)bkv->bkv_values->bv_seqnoref,
        buf);

    if (cur == (void *)bkv)
        c0sk_cursor_debug(cur);
}

/* GCOV_EXCL_STOP */

struct cn *
c0sk_get_cn(struct c0sk_impl *c0sk, u64 skidx)
{
    return c0sk->c0sk_cnv[skidx];
}

void
c0sk_install_callback(struct c0sk *handle, struct kvdb_callback *cb)
{
    struct c0sk_impl *self = c0sk_h2r(handle);

    self->c0sk_cb = cb;
}

uint64_t
c0sk_gen_current(void)
{
    return c0kvms_gen_current();
}

void
c0sk_gen_set(struct c0sk *handle, uint64_t gen)
{
    struct c0sk_impl *self = c0sk_h2r(handle);
    struct c0_kvmultiset *first;

    mutex_lock(&self->c0sk_kvms_mutex);
    first = c0sk_get_first_c0kvms(handle);
    if (first) {
        c0kvms_gen_init(gen - 1);
        c0kvms_gen_update(first);
    }
    mutex_unlock(&self->c0sk_kvms_mutex);
}

void
c0sk_replaying_enable(struct c0sk *handle)
{
    struct c0sk_impl *self;

    if (!handle)
        return;

    self = c0sk_h2r(handle);
    atomic_set(&self->c0sk_replaying, 1);
}

void
c0sk_replaying_disable(struct c0sk *handle)
{
    struct c0sk_impl *self;

    if (!handle)
        return;

    self = c0sk_h2r(handle);
    atomic_set(&self->c0sk_replaying, 0);
}

uint32_t
c0sk_ingest_width_get(struct c0sk *handle)
{
    struct c0sk_impl *self;

    assert(handle);

    self = c0sk_h2r(handle);

    return self->c0sk_ingest_width;
}

#if HSE_MOCKING
#include "c0sk_ut_impl.i"
#endif /* HSE_MOCKING */
