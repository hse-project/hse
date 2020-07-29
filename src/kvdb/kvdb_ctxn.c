/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/assert.h>
#include <hse_util/alloc.h>
#include <hse_util/atomic.h>
#include <hse_util/barrier.h>
#include <hse_util/slab.h>
#include <hse_util/darray.h>
#include <hse_util/seqno.h>
#include <hse_util/keylock.h>
#include <hse_util/page.h>
#include <hse_util/delay.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0skm.h>
#include <hse_ikvdb/limits.h>

#include "active_ctxn_set.h"
#include "kvdb_ctxn_internal.h"
#include "kvdb_keylock.h"

struct kvdb_ctxn_set {
};

/**
 * struct kvdb_ctxn_set_impl -
 * @ktn_wq:           workqueue struct for queueing transaction worker thread
 * @txn_wkth_delay:        delay in jiffies to use for transaction worker thread
 * @ktn_txn_timeout:      max time to live (in msecs) after which txn is aborted
 * @ktn_tseqno_head:
 * @ktn_tseqno_tail:
 * @ktn_list_mutex:   protects updates to list of allocated transactions
 * @ktn_alloc_list:   RCU list of allocated transactions
 * @ktn_pending:      transactions to be freed when reader thread finishes
 * @ktn_reading:      indicates whether the worker thread is reading the list
 * @ktn_queued:       has the worker thread been queued
 * @ktn_dwork:        delayed work struct
 */
struct kvdb_ctxn_set_impl {
    struct kvdb_ctxn_set     ktn_handle;
    struct workqueue_struct *ktn_wq;
    u64                      txn_wkth_delay;
    u64                      ktn_txn_timeout;

    __aligned(SMP_CACHE_BYTES) atomic64_t ktn_tseqno_head;

    __aligned(SMP_CACHE_BYTES) atomic64_t ktn_tseqno_tail;

    __aligned(SMP_CACHE_BYTES) struct mutex ktn_list_mutex;
    struct cds_list_head ktn_alloc_list;
    struct list_head     ktn_pending;
    atomic_t             ktn_reading;
    bool                 ktn_queued;
    struct delayed_work  ktn_dwork;
};

#define kvdb_ctxn_set_h2r(handle) container_of(handle, struct kvdb_ctxn_set_impl, ktn_handle)

static inline void
kvdb_ctxn_bind_putref(struct kvdb_ctxn_bind *bind)
{
    if (atomic64_dec_and_test(&bind->b_ref)) {
        if (bind->b_ctxn)
            kvdb_ctxn_h2r(bind->b_ctxn)->ctxn_bind = 0;
        free(bind);
    }
}

static inline void
kvdb_ctxn_bind_getref(struct kvdb_ctxn_bind *bind)
{
    atomic64_inc(&bind->b_ref);
}

static inline void
kvdb_ctxn_bind_invalidate(struct kvdb_ctxn_bind *bind)
{
    atomic64_inc(&bind->b_gen);
}

static inline void
kvdb_ctxn_bind_cancel(struct kvdb_ctxn_bind *bind, bool preserve)
{
    bind->b_preserve = preserve;
    bind->b_ctxn = 0;
}

static __always_inline bool
kvdb_ctxn_trylock(struct kvdb_ctxn_impl *ctxn)
{
    return atomic_cmpxchg(&ctxn->ctxn_lock, 0, 1) == 0;
}

static __always_inline void
kvdb_ctxn_unlock(struct kvdb_ctxn_impl *ctxn)
{
    int old __maybe_unused;

    old = atomic_cmpxchg(&ctxn->ctxn_lock, 1, 0);
    assert(old == 1);
}

static void
kvdb_ctxn_set_thread(struct work_struct *work)
{
    enum kvdb_ctxn_state       state;
    struct list_head           freelist, alist;
    struct kvdb_ctxn_impl *    ctxn = 0, *next = 0;
    struct kvdb_ctxn_set_impl *ktn;
    u64                        now;
    u64                        ttl_ns;

    INIT_LIST_HEAD(&alist);

    ktn = container_of(work, struct kvdb_ctxn_set_impl, ktn_dwork.work);

    atomic_set(&ktn->ktn_reading, 1);

    /* Abort all active transactions that have expired. */
    now = get_time_ns();
    ttl_ns = ktn->ktn_txn_timeout * 1000000UL;
    rcu_read_lock();
    cds_list_for_each_entry_rcu(ctxn, &ktn->ktn_alloc_list, ctxn_alloc_link)
    {
        state = seqnoref_to_state(ctxn->ctxn_seqref);
        if (state == KVDB_CTXN_ACTIVE) {
            if (now > (ctxn->ctxn_begin_ts + ttl_ns))
                list_add(&ctxn->ctxn_abort_link, &alist);
        }
    }
    rcu_read_unlock();

    list_for_each_entry (ctxn, &alist, ctxn_abort_link)
        kvdb_ctxn_abort(&ctxn->ctxn_inner_handle);

    atomic_set(&ktn->ktn_reading, 0);

    INIT_LIST_HEAD(&freelist);

    mutex_lock(&ktn->ktn_list_mutex);
    list_splice_tail(&ktn->ktn_pending, &freelist);
    INIT_LIST_HEAD(&ktn->ktn_pending);

    ktn->ktn_queued = !cds_list_empty(&ktn->ktn_alloc_list);
    mutex_unlock(&ktn->ktn_list_mutex);

    if (ktn->ktn_queued)
        queue_delayed_work(ktn->ktn_wq, &ktn->ktn_dwork, ktn->txn_wkth_delay);

    /* Free all transactions that were waiting for the thread
     * to finish reading.
     */
    list_for_each_entry_safe (ctxn, next, &freelist, ctxn_free_link) {
        kvdb_ctxn_cursor_unbind(ctxn->ctxn_bind);
        free_aligned(ctxn);
        ev(1);
    }
}

struct kvdb_ctxn *
kvdb_ctxn_alloc(
    struct kvdb_keylock *   kvdb_keylock,
    atomic64_t *            kvdb_seqno_addr,
    struct kvdb_ctxn_set *  kcs_handle,
    struct active_ctxn_set *active_ctxn_set,
    struct c0sk *           c0sk)
{
    struct kvdb_ctxn_impl *    ctxn;
    struct kvdb_ctxn_set_impl *kvdb_ctxn_set;
    struct kvdb_rparams *      rp;
    bool                       start;

    kvdb_ctxn_set = kvdb_ctxn_set_h2r(kcs_handle);

    ctxn = alloc_aligned(sizeof(*ctxn), __alignof(*ctxn), GFP_KERNEL);
    if (ev(!ctxn))
        return NULL;

    memset(ctxn, 0, sizeof(*ctxn));
    atomic_set(&ctxn->ctxn_lock, 0);
    ctxn->ctxn_seqref = HSE_SQNREF_INVALID;
    ctxn->ctxn_kvdb_keylock = kvdb_keylock;
    ctxn->ctxn_active_set = active_ctxn_set;
    ctxn->ctxn_c0sk = c0sk;
    ctxn->ctxn_kvdb_ctxn_set = kcs_handle;
    ctxn->ctxn_kvdb_seq_addr = kvdb_seqno_addr;
    ctxn->ctxn_tseqno_head = &kvdb_ctxn_set->ktn_tseqno_head;
    ctxn->ctxn_tseqno_tail = &kvdb_ctxn_set->ktn_tseqno_tail;
    ctxn->ctxn_ingest_width = HSE_C0_INGEST_WIDTH_DFLT;
    ctxn->ctxn_ingest_delay = HSE_C0_INGEST_DELAY_DFLT;
    ctxn->ctxn_heap_sz = HSE_C0_CHEAP_SZ_DFLT;

    rp = c0sk_rparams(ctxn->ctxn_c0sk);
    if (rp) {
        ctxn->ctxn_ingest_width = rp->txn_ingest_width;
        ctxn->ctxn_ingest_delay = rp->txn_ingest_delay;
        ctxn->ctxn_heap_sz = rp->txn_heap_sz;
    }

    mutex_lock(&kvdb_ctxn_set->ktn_list_mutex);
    cds_list_add_rcu(&ctxn->ctxn_alloc_link, &kvdb_ctxn_set->ktn_alloc_list);

    start = !kvdb_ctxn_set->ktn_queued;
    if (start)
        kvdb_ctxn_set->ktn_queued = true;
    mutex_unlock(&kvdb_ctxn_set->ktn_list_mutex);

    if (start)
        queue_delayed_work(
            kvdb_ctxn_set->ktn_wq, &kvdb_ctxn_set->ktn_dwork, kvdb_ctxn_set->txn_wkth_delay);

    return &ctxn->ctxn_inner_handle;
}

void
kvdb_ctxn_set_remove(struct kvdb_ctxn_set *handle, struct kvdb_ctxn_impl *ctxn)
{
    struct kvdb_ctxn_set_impl *kvdb_ctxn_set = kvdb_ctxn_set_h2r(handle);
    bool                       delay_free;

    mutex_lock(&kvdb_ctxn_set->ktn_list_mutex);
    cds_list_del_rcu(&ctxn->ctxn_alloc_link);
    delay_free = atomic_read(&kvdb_ctxn_set->ktn_reading);
    if (delay_free)
        list_add_tail(&ctxn->ctxn_free_link, &kvdb_ctxn_set->ktn_pending);
    mutex_unlock(&kvdb_ctxn_set->ktn_list_mutex);

    if (!delay_free) {
        kvdb_ctxn_cursor_unbind(ctxn->ctxn_bind);
        free_aligned(ctxn);
    }
}

void
kvdb_ctxn_free(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn;

    if (ev(!handle))
        return;

    kvdb_ctxn_abort(handle);

    ctxn = kvdb_ctxn_h2r(handle);

    assert(!ctxn->ctxn_bind);
    assert(!ctxn->ctxn_locks_handle);

    if (ctxn->ctxn_kvms)
        c0kvms_putref(ctxn->ctxn_kvms);

    kvdb_ctxn_set_remove(ctxn->ctxn_kvdb_ctxn_set, ctxn);
}

static merr_t
kvdb_ctxn_enable_inserts(struct kvdb_ctxn_impl *ctxn)
{
    struct kvdb_ctxn_locks *locks;
    uintptr_t *             priv;
    merr_t                  err;

    if (!ctxn->ctxn_kvms) {
        err = c0kvms_create(
            ctxn->ctxn_ingest_width,
            ctxn->ctxn_heap_sz,
            ctxn->ctxn_ingest_delay,
            ctxn->ctxn_kvdb_seq_addr,
            !!c0sk_get_mhandle(ctxn->ctxn_c0sk),
            &ctxn->ctxn_kvms);
        if (ev(err))
            return err;
    }

    err = kvdb_ctxn_locks_create(&locks);
    if (ev(err)) {
        c0kvms_putref(ctxn->ctxn_kvms);
        ctxn->ctxn_kvms = NULL;
        return err;
    }

    priv = c0kvms_priv_alloc(ctxn->ctxn_kvms);
    if (ev(!priv)) {
        c0kvms_putref(ctxn->ctxn_kvms);
        kvdb_ctxn_locks_destroy(locks);
        ctxn->ctxn_kvms = NULL;
        return merr(ENOMEM);
    }

    *priv = HSE_SQNREF_UNDEFINED;
    ctxn->ctxn_seqref = HSE_REF_TO_SQNREF(priv);
    ctxn->ctxn_locks_handle = locks;
    ctxn->ctxn_can_insert = 1;

    return 0;
}

merr_t
kvdb_ctxn_begin(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    enum kvdb_ctxn_state   state;
    merr_t                 err;
    u64                    head, tail;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return merr(EPROTO);

    state = seqnoref_to_state(ctxn->ctxn_seqref);

    if (ev(state != KVDB_CTXN_ABORTED && state != KVDB_CTXN_COMMITTED &&
           state != KVDB_CTXN_INVALID)) {
        err = merr(EINVAL);
        goto errout;
    }

    ctxn->ctxn_bind = 0;
    ctxn->ctxn_begin_ts = get_time_ns();

    /* Track the last transaction known to have published its mutations. */
    tail = atomic64_read_acq(ctxn->ctxn_tseqno_tail);

    err = active_ctxn_set_insert(
        ctxn->ctxn_active_set, &ctxn->ctxn_view_seqno, &ctxn->ctxn_active_set_cookie);
    if (ev(err))
        goto errout;

    /* Track the last transaction to have started a commit. */
    head = atomic64_read_acq(ctxn->ctxn_tseqno_head);

    /*
     * Ensure that all commits that began while this transaction's view
     * was established have published their mutations. This transaction must
     * be able to read those mutations to ensure a consistent read snapshot.
     */
    if (tail < head) {
        while (atomic64_read(ctxn->ctxn_tseqno_tail) < head)
            __builtin_ia32_pause();
    }

    ctxn->ctxn_can_insert = 0;
    ctxn->ctxn_seqref = HSE_SQNREF_UNDEFINED;

    /* KVS Cursors need an always-consistent kvms state. */
    if (ctxn->ctxn_kvms)
        c0kvms_reset(ctxn->ctxn_kvms);

errout:
    kvdb_ctxn_unlock(ctxn);

    return err;
}

void
kvdb_ctxn_deactivate(struct kvdb_ctxn_impl *ctxn)
{
    u32   min_changed = 0;
    u64   new_min = U64_MAX;
    void *cookie;

    ctxn->ctxn_can_insert = false;

    cookie = ctxn->ctxn_active_set_cookie;
    ctxn->ctxn_active_set_cookie = NULL;

    active_ctxn_set_remove(ctxn->ctxn_active_set, cookie, &min_changed, &new_min);
    if (min_changed)
        kvdb_keylock_expire(ctxn->ctxn_kvdb_keylock, new_min);
}

static void
kvdb_ctxn_abort_inner(struct kvdb_ctxn_impl *ctxn)
{
    struct kvdb_ctxn_locks *locks;
    struct kvdb_ctxn_bind * bind;
    struct kvdb_keylock *   keylock;

    ctxn->ctxn_seqref = HSE_SQNREF_ABORTED;

    bind = ctxn->ctxn_bind;
    if (bind) {
        bind->b_seq = atomic64_read(ctxn->ctxn_kvdb_seq_addr);
        kvdb_ctxn_bind_cancel(bind, !ctxn->ctxn_can_insert);
        ctxn->ctxn_bind = 0;
    }

    if (!ctxn->ctxn_can_insert) {
        kvdb_ctxn_deactivate(ctxn);
        return;
    }

    keylock = ctxn->ctxn_kvdb_keylock;
    locks = ctxn->ctxn_locks_handle;
    ctxn->ctxn_locks_handle = NULL;

    assert(locks);

    /* Release all the locks that we didn't inherit */
    kvdb_keylock_prune_own_locks(keylock, locks);

    if (kvdb_ctxn_locks_count(locks) > 0) {
        void *cookie = NULL;
        u64   end_seq;

        kvdb_keylock_list_lock(keylock, &cookie);
        end_seq = atomic64_fetch_add(1, ctxn->ctxn_kvdb_seq_addr);
        kvdb_keylock_queue_locks(locks, end_seq, cookie);
        kvdb_keylock_list_unlock(cookie);
    } else {
        kvdb_ctxn_locks_destroy(locks);
    }

    /* At this point the transaction ceases to be considered active */
    kvdb_ctxn_deactivate(ctxn);

    c0kvms_priv_release(ctxn->ctxn_kvms);
}

void
kvdb_ctxn_abort(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    enum kvdb_ctxn_state   state;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return;

    state = seqnoref_to_state(ctxn->ctxn_seqref);

    if (state == KVDB_CTXN_ACTIVE)
        kvdb_ctxn_abort_inner(ctxn);

    kvdb_ctxn_unlock(ctxn);
}

/* Set two ctxn kvms size thresholds T1 and T2 (T1 < T2).
 *
 * if (size < T1):
 *     Retry merge 5 times.
 *     Flush if all merge attempts fail.
 * else if (size < T2):
 *     Try merge once.
 *     Flush after 1 merge failure.
 * else  // size > T2
 *     Always flush src. Do not bother with merge.
 */
merr_t
kvdb_ctxn_merge(
    struct kvdb_ctxn_impl *ctxn,
    int *                  num_retries,
    uintptr_t **           privp,
    struct c0_kvmultiset **dstp)
{
    struct c0_kvmultiset *src = ctxn->ctxn_kvms;

    size_t thresh_lo, thresh_hi;
    size_t src_size;
    merr_t err;

    c0kvms_thresholds_get(src, &thresh_lo, &thresh_hi);
    src_size = c0kvms_used(src);

    if (ev(src_size > thresh_hi || *num_retries == 0))
        return merr(EFBIG); /* Let caller fallback on flush */

    if (ev(src_size > thresh_lo))
        *num_retries = 0;

    while (1) {
        err = c0sk_merge(ctxn->ctxn_c0sk, src, dstp, privp);
        if (!err)
            break;

        if (ev(merr_errno(err) != ENOMEM))
            break;

        if (ev((*num_retries)-- < 1))
            break;

        ev(1);
    }

    return err;
}

/* The flush lock serializes threads performing a flush-commit
 * while ensuring they all make forward progress.  Meanwhile,
 * the flush_busy flag is used to prevent merge-flush threads
 * from getting into the inner commit critical section which
 * could deadlock a flush-commit thread on the keylist lock.
 */
static DEFINE_MUTEX(flush_lock);
static atomic_t flush_busy = ATOMIC_INIT(0);

merr_t
kvdb_ctxn_commit(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl * ctxn = kvdb_ctxn_h2r(handle);
    struct kvdb_ctxn_bind * bind = ctxn->ctxn_bind;
    struct kvdb_ctxn_locks *locks;
    enum kvdb_ctxn_state    state;
    void *                  cookie;
    merr_t                  err;
    struct c0_kvmultiset *  dst;
    struct c0_kvmultiset *  first;
    uintptr_t *             priv;
    uintptr_t               ref;
    u64                     commit_sn;
    u64                     rsvd_sn;
    u64                     head;
    int                     num_retries;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return merr(EPROTO);

    state = seqnoref_to_state(ctxn->ctxn_seqref);
    if (ev(state != KVDB_CTXN_ACTIVE)) {
        kvdb_ctxn_unlock(ctxn);
        return merr(EINVAL);
    }

    /* If this transaction never wrote anything then the commit path is
     * much simpler. We make our "transaction sequence number" be a
     * reference encoded copy of our view sequence number. We also take
     * ourselves out of the set of active transactions, and if that
     * removal may have triggered delayed write-lock releases we take
     * care of that.
     */
    if (!ctxn->ctxn_can_insert) {
        if (bind) {
            bind->b_seq = atomic64_read(ctxn->ctxn_kvdb_seq_addr);
            kvdb_ctxn_bind_cancel(bind, true);
            ctxn->ctxn_bind = 0;
        }

        ctxn->ctxn_seqref = HSE_ORDNL_TO_SQNREF(ctxn->ctxn_view_seqno);
        kvdb_ctxn_deactivate(ctxn);
        kvdb_ctxn_unlock(ctxn);

        return 0;
    }

    /* Acquire a reference on the kvms so that it cannot be freed
     * before we update it via ctxn_seqno (which points into kvms
     * via the kvms priv ptr).
     */
    c0kvms_getref(ctxn->ctxn_kvms);

    num_retries = 5;

retry:
    head = 0;
    priv = NULL;
    dst = NULL;

    err = kvdb_ctxn_merge(ctxn, &num_retries, &priv, &dst);
    if (ev(err)) {
        assert(!dst && !priv);

        /* Serialize all flush operations to ensure we don't
         * deadlock on keylock list lock.
         */
        mutex_lock(&flush_lock);
        atomic_inc(&flush_busy);

        /* To maintain seqno ordering for c1, the following order of
         * operations must be followed:
         *  1. increment head.
         *  2. get seqno.
         *  3. increment tail.
         *  4. Wait for tail to catch up with head.
         *
         * Since a flush needs to reserve a seqno before it returns,
         * increment head before calling flush.
         */
        head = atomic64_inc_acq(ctxn->ctxn_tseqno_head);
        err = c0sk_flush(ctxn->ctxn_c0sk, ctxn->ctxn_kvms);
        if (err) {
            atomic_dec(&flush_busy);
            mutex_unlock(&flush_lock);

            /* Ensure that threads leave in the same order in which they
             * incremented ctxn_tseqno_head.
             */
            while (atomic64_read(ctxn->ctxn_tseqno_tail) + 1 < head)
                __builtin_ia32_pause();
            atomic64_inc(ctxn->ctxn_tseqno_tail);
        }
    }

    /* If there is an error at this point, we can neither publish nor
     * persist any mutations made by this transaction, so we abort it.
     */
    if (ev(err)) {
        kvdb_ctxn_abort_inner(ctxn);
        c0kvms_putref(ctxn->ctxn_kvms);
        kvdb_ctxn_unlock(ctxn);
        return err;
    }

    /* At this point the commit will succeed so we just need to perform
     * each step in the correct order. There are some invariants that we
     * want to maintain and exploit to reduce the overhead associated with
     * handling write locks to ensure snapshot isolation.
     *
     * The overall model used to achieve snapshot isolation is as follows:
     *
     *   - When a transaction A acquires write locks, this collection of
     *     locks must be held past the point that the transaction commits.
     *     The collection of write locks may only be released when every
     *     transaction that began execution prior to the commit of A
     *     completes.
     *
     *   - The active_ctxn_set mechanism is used to efficiently track what
     *     the lowest view sequence number is for any active txn.  If there
     *     are no active txn's, then that number is U64_MAX.
     *
     *   - The write lock collections are held on a list managed by the
     *     kvdb_keylock code. These collections are placed on this list at
     *     commit time. By taking a lock on that list before we determine
     *     the txn's commit sequence number and releasing it after adding
     *     it to the list we ensure that the list is ordered by txn commit
     *     sequence number.
     *
     *   - When any txn becomes inactive by calling kvdb_ctxn_deactivate()
     *     it updates the collection of active txn's. If that update causes
     *     the minimum view sequence number for any active txn to change,
     *     then it will traverse the write lock collection list, removing
     *     any element whose commit sequence number is less than the new
     *     minimum sequence number.
     *
     *   - To account for the case that a given txn A is the only active
     *     txn in the system, we ensure that we put A's write lock
     *     collection on the list before we call kvdb_ctxn_deactivate so
     *     A commit execution will reap its own collection.
     */

    /* The following critical section demarcated by the list lock/unlock
     * calls provide mutual exclusion only for the list referenced by
     * cookie.  The list lock mechanism does, however, limit total
     * concurrency through this section to only a handful of cpus
     * (currently 8 as defined by KVDB_DLOCK_MAX).
     */
    cookie = NULL; /* For error detection by mapi */

    kvdb_keylock_list_lock(ctxn->ctxn_kvdb_keylock, &cookie);

    /* Hold the RCU read lock through the update to *priv to ensure
     * the current active kvms cannot reach the finalized state until
     * after we release the lock.  Note that a ctxn_kvms that has been
     * flushed is not subject to this constraint (it could still be
     * the active kvms, or it could be finalized and awaiting ingest).
     */
    rcu_read_lock();
    if (dst) {
        static atomic_t lock;

        /* merge */
        /*
         * Ensure that threads mint commit sequence numbers in increasing order
         * of ctxn_tseqno_head.
         */
        while (!atomic_cas(&lock, 0, 1))
            __builtin_ia32_pause();
        head = atomic64_inc_acq(ctxn->ctxn_tseqno_head);
        commit_sn = 1 + atomic64_fetch_add_rel(2, ctxn->ctxn_kvdb_seq_addr);
        atomic_cas(&lock, 1, 0);

        rsvd_sn = c0kvms_rsvd_sn_get(dst);

        /* Retry the merge if dst is no longer the active kvms or if
         * commit_sn is lower than the kvms reserved seqno (the latter
         * to ensure rsvd_sn is always the lowest seqno in a kvms).
         */
        first = c0sk_get_first_c0kvms(ctxn->ctxn_c0sk);
        if (ev(first != dst || commit_sn < rsvd_sn || atomic_read(&flush_busy))) {
            rcu_read_unlock();

            kvdb_keylock_list_unlock(cookie);
            c0kvms_priv_release(dst);
            c0kvms_putref(dst);

            /* Ensure that threads leave in the same order in which they
             * incremented ctxn_tseqno_head.
             */
            while (atomic64_read(ctxn->ctxn_tseqno_tail) + 1 < head)
                __builtin_ia32_pause();
            atomic64_inc(ctxn->ctxn_tseqno_tail);

            ev(rsvd_sn == HSE_SQNREF_INVALID);
            ev(commit_sn < rsvd_sn);
            goto retry;
        }

        assert(!c0kvms_is_finalized(dst));
    } else {
        /* flush */

        /* Now that we've acquired our keylock list lock we can
         * allow merge-commit threads into this critsec behind us...
         */
        atomic_dec(&flush_busy);

        rsvd_sn = c0kvms_rsvd_sn_get(ctxn->ctxn_kvms);
        assert(rsvd_sn > 0 && rsvd_sn != HSE_SQNREF_INVALID);
        assert(atomic64_read(ctxn->ctxn_kvdb_seq_addr) >= rsvd_sn);

        commit_sn = rsvd_sn;

        /* For post-mortem analysis...
         */
        first = c0sk_get_first_c0kvms(ctxn->ctxn_c0sk);
        ev(first != ctxn->ctxn_kvms);
        ev(c0kvms_is_finalized(ctxn->ctxn_kvms));
    }

    /* We leverage tseqno head and tail to ensure that we never present
     * a commit_sn to c1 for which there might be a lower commit_sn that
     * has not yet been applied to the kvms (via *priv = ref).  We could
     * accomplish the same thing with a mutex, but this approach greatly
     * improves throughput of the above critical section vs a mutex.
     */
    while (atomic64_read(ctxn->ctxn_tseqno_tail) + 1 < head)
        __builtin_ia32_pause();

    /* This assignment through the pointer gives all the values
     * associated with this transaction an ordinal sequence
     * number. Each of those values has their own pointer to the
     * ordinal value.
     */
    ref = HSE_ORDNL_TO_SQNREF(commit_sn);
    *(uintptr_t *)ctxn->ctxn_seqref = ref;
    if (dst)
        *priv = ref;

    c0skm_set_tseqno(ctxn->ctxn_c0sk, commit_sn);
    atomic64_inc_rel(ctxn->ctxn_tseqno_tail);

    locks = ctxn->ctxn_locks_handle;
    ctxn->ctxn_locks_handle = NULL;

    if (kvdb_ctxn_locks_count(locks) > 0) {
        kvdb_keylock_insert_locks(locks, commit_sn, cookie);
        locks = NULL;
    }

    kvdb_keylock_list_unlock(cookie);

    /* At this point if the merge failed (dst == nil) then the flush
     * succeeded and consumed dst's birth reference.  Otherwise, the
     * merge succeeded and so we must release dst's birth reference.
     */
    if (dst) {
        assert(!c0kvms_is_finalized(dst));

        c0kvms_priv_release(dst);
        c0kvms_putref(dst);
    }
    rcu_read_unlock();

    /* Once the indirect assignment has been performed the
     * transaction itself no longer needs to see the shared value
     * and instead just puts it into its private area. This is
     * preserved until the transaction is re-used and allows us to
     * remember that the state of the transaction is "committed".
     */
    ctxn->ctxn_seqref = ref;

    if (locks)
        kvdb_ctxn_locks_destroy(locks);

    if (bind) {
        bind->b_seq = commit_sn + 1;
        kvdb_ctxn_bind_cancel(bind, true);
        ctxn->ctxn_bind = 0;
    }

    kvdb_ctxn_deactivate(ctxn);

    c0kvms_priv_release(ctxn->ctxn_kvms);
    c0kvms_putref(ctxn->ctxn_kvms);

    if (!dst) {
        mutex_unlock(&flush_lock);
        ctxn->ctxn_kvms = 0;
    }

    kvdb_ctxn_unlock(ctxn);

    return 0;
}

enum kvdb_ctxn_state
kvdb_ctxn_get_state(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    return seqnoref_to_state(ctxn->ctxn_seqref);
}

merr_t
kvdb_ctxn_get_view_seqno(struct kvdb_ctxn *handle, u64 *view_seqno)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE))
        return merr(EPROTO);

    *view_seqno = ctxn->ctxn_view_seqno;

    return 0;
}

struct c0_kvmultiset *
kvdb_ctxn_get_kvms(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    return ctxn ? ctxn->ctxn_kvms : 0;
}

uintptr_t
kvdb_ctxn_get_seqnoref(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    return ctxn ? ctxn->ctxn_seqref : 0;
}

/* This routine determines whether ownership of a write lock can be inherited
 * from one client transaction to another and if so performs the transfer.
 * This can happen if the new transaction started after the commit-time of the
 * previous transaction. If ownership has been inherited, the function
 * returns true.
 *
 * Pre-Conditions at Entry:
 * ------------------------
 *  (1) The keylock table holding the hash is locked by the calling thread.
 *  (2) new_rock is a pointer to the kvdb_ctxn_impl that is attempting
 *      to acquire ownership of the hash.
 *  (3) Ownership of the hash is held by the lock collection pointed to by
 *      the old_rock.
 */
bool
kvdb_ctxn_lock_inherit(
    u64                      start_seq,
    struct keylock_cb_rock * old_rock,
    struct keylock_cb_rock **new_rock)
{
    struct kvdb_ctxn_locks *old_locks = (struct kvdb_ctxn_locks *)old_rock;

    /* The structure pointed to by "old_locks" cannot vanish during this
     * call because of pre-condition (1) above. However, it is entirely
     * possible that old_locks ref goes to 0 at any time and another
     * thread is attempting to unlock the hash at any moment. This is
     * protected against by updating the rock of the entry while we are
     * holding off the other threads so that any "unlock" attempt on the
     * part of the previous owner silently does nothing.
     */

    /* release of lock (1) will handle the write memory barrier needed */

    /* Note that while old_locks holds the key lock its end seqno will
     * be U64_MAX and hence can never be inherited/transferred.
     */
    return (start_seq > kvdb_ctxn_locks_end_seqno(old_locks));
}

merr_t
kvdb_ctxn_put(
    struct kvdb_ctxn *       handle,
    struct c0 *              c0,
    const struct kvs_ktuple *kt,
    const struct kvs_vtuple *vt)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    merr_t                 err = 0;
    struct c0_kvset *      c0kvs;
    u64                    hash;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return merr(EPROTO);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)) {
        err = merr(EPROTO);
        goto errout;
    }

    if (!ctxn->ctxn_can_insert) {
        err = kvdb_ctxn_enable_inserts(ctxn);
        if (ev(err))
            goto errout;
    }

    /* Always use the full key's hash (even when kvs is suffixed) for
     * maximum entropy.  We factor the c0 hash (i.e., the hash of the
     * cn kvs name) into the hash to avoid collisions of identical keys
     * being put into different kvs via independent transactions.
     */
    hash = key_hash64_seed(kt->kt_data, kt->kt_len, c0_hash_get(c0));

    err = kvdb_keylock_lock(
        ctxn->ctxn_kvdb_keylock, ctxn->ctxn_locks_handle, hash, ctxn->ctxn_view_seqno);
    if (err) {
        ev(merr_errno(err) != ECANCELED);
        goto errout;
    }

    if (ctxn->ctxn_bind)
        kvdb_ctxn_bind_invalidate(ctxn->ctxn_bind);

    c0kvs = c0kvms_get_hashed_c0kvset(ctxn->ctxn_kvms, kt->kt_hash);

    err = c0kvs_put(c0kvs, c0_index(c0), kt, vt, ctxn->ctxn_seqref);

errout:
    kvdb_ctxn_unlock(ctxn);

    return err;
}

merr_t
kvdb_ctxn_get(
    struct kvdb_ctxn *       handle,
    struct c0 *              c0,
    struct cn *              cn,
    const struct kvs_ktuple *kt,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    merr_t                 err;
    u64                    view_seqno;
    uintptr_t              seqnoref;
    uintptr_t              rslt_seqnoref;
    struct c0_kvset *      c0kvs;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return merr(EPROTO);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)) {
        err = merr(EPROTO);
        goto errout;
    }

    view_seqno = ctxn->ctxn_view_seqno;
    seqnoref = ctxn->ctxn_seqref;

    if (ctxn->ctxn_can_insert) {
        /* first look in the kvdb_ctxn's private store */
        c0kvs = c0kvms_get_hashed_c0kvset(ctxn->ctxn_kvms, kt->kt_hash);

        err = c0kvs_get(c0kvs, c0_index(c0), kt, view_seqno, seqnoref, res, vbuf, &rslt_seqnoref);

        if (!err && *res == NOT_FOUND) {
            uintptr_t pt_seqref;
            u32       pfx_len = c0_get_pfx_len(c0);

            /* check if there is a ptomb for the key */

            c0kvs = c0kvms_ptomb_c0kvset_get(ctxn->ctxn_kvms);
            if (pfx_len > 0 && kt->kt_len >= pfx_len) {
                /* kvs is prefixed. Check for ptombs.
                 */
                c0kvs_prefix_get(c0kvs, c0_index(c0), kt, view_seqno, pfx_len, &pt_seqref);

                if (pt_seqref != HSE_ORDNL_TO_SQNREF(0)) {
                    vbuf->b_len = 0;
                    *res = FOUND_PTMB;
                }
            }
        }

        /* if we got an error or found it, we're done */
        if (ev(err) || *res != NOT_FOUND)
            goto errout;
    }

    /* look in the c0 container */
    err = c0_get(c0, kt, view_seqno, seqnoref, res, vbuf);

errout:
    kvdb_ctxn_unlock(ctxn);

    return err;
}

merr_t
kvdb_ctxn_del(struct kvdb_ctxn *handle, struct c0 *c0, const struct kvs_ktuple *kt)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    merr_t                 err = 0;
    struct c0_kvset *      c0kvs;
    u64                    hash;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return merr(EPROTO);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)) {
        err = merr(EPROTO);
        goto errout;
    }

    if (!ctxn->ctxn_can_insert) {
        err = kvdb_ctxn_enable_inserts(ctxn);
        if (ev(err))
            goto errout;
    }

    /* Always use the full key's hash (even when kvs is suffixed) for
     * maximum entropy.
     */
    hash = key_hash64_seed(kt->kt_data, kt->kt_len, c0_hash_get(c0));

    err = kvdb_keylock_lock(
        ctxn->ctxn_kvdb_keylock, ctxn->ctxn_locks_handle, hash, ctxn->ctxn_view_seqno);
    if (ev(err))
        goto errout;

    if (ctxn->ctxn_bind)
        kvdb_ctxn_bind_invalidate(ctxn->ctxn_bind);

    c0kvs = c0kvms_get_hashed_c0kvset(ctxn->ctxn_kvms, kt->kt_hash);

    err = c0kvs_del(c0kvs, c0_index(c0), kt, ctxn->ctxn_seqref);

errout:
    kvdb_ctxn_unlock(ctxn);

    return err;
}

merr_t
kvdb_ctxn_pfx_probe(
    struct kvdb_ctxn *       handle,
    struct c0 *              c0,
    struct cn *              cn,
    const struct kvs_ktuple *kt,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    merr_t                 err;
    uintptr_t              pt_seqref;
    struct c0_kvset *      pt_c0kvs;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return merr(EPROTO);

    if (!ctxn->ctxn_can_insert)
        goto skip_txkvms;

    /* Check txn's local mutations */
    err = c0kvms_pfx_probe(
        ctxn->ctxn_kvms,
        c0_index(c0),
        kt,
        ctxn->ctxn_view_seqno,
        ctxn->ctxn_seqref,
        res,
        qctx,
        kbuf,
        vbuf,
        0);
    if (ev(err)) {
        kvdb_ctxn_unlock(ctxn);
        return err;
    }

    if (qctx->seen > 1) {
        kvdb_ctxn_unlock(ctxn);
        return 0;
    }

    if (likely(c0_get_pfx_len(c0) && kt->kt_len >= c0_get_pfx_len(c0))) {
        /* Check if txn contains ptomb for query pfx */
        pt_c0kvs = c0kvms_ptomb_c0kvset_get(ctxn->ctxn_kvms);
        c0kvs_prefix_get(
            pt_c0kvs, c0_index(c0), kt, ctxn->ctxn_view_seqno, c0_get_pfx_len(c0), &pt_seqref);
        if (pt_seqref != HSE_ORDNL_TO_SQNREF(0)) {
            kvdb_ctxn_unlock(ctxn);
            return 0; /* found a ptomb. Do not proceed. */
        }
    }

skip_txkvms:
    /* Look through rest of c0 for pfx */
    c0_pfx_probe(c0, kt, ctxn->ctxn_view_seqno, ctxn->ctxn_seqref, res, qctx, kbuf, vbuf);

    kvdb_ctxn_unlock(ctxn);

    return 0;
}

merr_t
kvdb_ctxn_prefix_del(struct kvdb_ctxn *handle, struct c0 *c0, const struct kvs_ktuple *kt)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    struct c0_kvset *      c0kvs;
    merr_t                 err;

    if (ev(!kvdb_ctxn_trylock(ctxn)))
        return merr(EPROTO);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)) {
        err = merr(EPROTO);
        goto errout;
    }

    if (!ctxn->ctxn_can_insert) {
        err = kvdb_ctxn_enable_inserts(ctxn);
        if (ev(err))
            goto errout;
    }

    if (ctxn->ctxn_bind)
        kvdb_ctxn_bind_invalidate(ctxn->ctxn_bind);

    c0kvs = c0kvms_ptomb_c0kvset_get(ctxn->ctxn_kvms);
    err = c0kvs_prefix_del(c0kvs, c0_index(c0), kt, ctxn->ctxn_seqref);

errout:
    kvdb_ctxn_unlock(ctxn);

    return ev(err);
}

merr_t
kvdb_ctxn_set_create(struct kvdb_ctxn_set **handle_out, u64 txn_timeout_ms, u64 delay_msecs)
{
    struct kvdb_ctxn_set_impl *ktn;

    *handle_out = 0;

    ktn = alloc_aligned(sizeof(*ktn), __alignof(*ktn), GFP_KERNEL);
    if (!ktn)
        return merr(ev(ENOMEM));

    memset(ktn, 0, sizeof(*ktn));

    ktn->ktn_wq = alloc_workqueue("kvdb_ctxn_set", 0, 1);
    if (!ktn->ktn_wq) {
        free_aligned(ktn);
        return merr(ev(ENOMEM));
    }

    atomic64_set(&ktn->ktn_tseqno_head, 0);
    atomic64_set(&ktn->ktn_tseqno_tail, 0);
    atomic_set(&ktn->ktn_reading, 0);
    ktn->ktn_queued = false;
    ktn->ktn_txn_timeout = txn_timeout_ms;
    ktn->txn_wkth_delay = msecs_to_jiffies(delay_msecs);
    INIT_DELAYED_WORK(&ktn->ktn_dwork, kvdb_ctxn_set_thread);

    mutex_init(&ktn->ktn_list_mutex);
    CDS_INIT_LIST_HEAD(&ktn->ktn_alloc_list);
    INIT_LIST_HEAD(&ktn->ktn_pending);

    *handle_out = &ktn->ktn_handle;

    return 0;
}

void
kvdb_ctxn_set_destroy(struct kvdb_ctxn_set *handle)
{
    struct kvdb_ctxn_set_impl *ktn;
    struct kvdb_ctxn_impl *    ctxn = 0, *next;
    bool                       canceled;

    if (ev(!handle))
        return;

    ktn = kvdb_ctxn_set_h2r(handle);

    do {
        mutex_lock(&ktn->ktn_list_mutex);
        canceled = !ktn->ktn_queued || cancel_delayed_work(&ktn->ktn_dwork);
        mutex_unlock(&ktn->ktn_list_mutex);
    } while (!canceled);

    destroy_workqueue(ktn->ktn_wq);

    /* Destroy transactions that haven't been aborted/committed/freed. */
    cds_list_for_each_entry_rcu(ctxn, &ktn->ktn_alloc_list, ctxn_alloc_link)
        list_add_tail(&ctxn->ctxn_free_link, &ktn->ktn_pending);

    list_for_each_entry_safe (ctxn, next, &ktn->ktn_pending, ctxn_free_link)
        kvdb_ctxn_free(&ctxn->ctxn_inner_handle);

    mutex_destroy(&ktn->ktn_list_mutex);

    free_aligned(ktn);
}

struct kvdb_ctxn_bind *
kvdb_ctxn_cursor_bind(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    struct kvdb_ctxn_bind *bind = ctxn->ctxn_bind;

    if (seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)
        return 0;

    if (!bind) {
        struct kvdb_ctxn_bind *old = 0;

        bind = calloc(1, sizeof(*bind));
        if (!bind)
            return 0;
        bind->b_ctxn = handle;

        if (bind != atomic_ptr_cmpxchg((void **)&ctxn->ctxn_bind, old, bind)) {
            free(bind);
            bind = ctxn->ctxn_bind;
        }
    }

    /* HSE_REVISIT: race here if allow multi-threading cursor+txn */

    if (bind) {
        bind->b_update = false;
        bind->b_preserve = false;
        kvdb_ctxn_bind_getref(bind);
    }

    return bind;
}

void
kvdb_ctxn_cursor_unbind(struct kvdb_ctxn_bind *bind)
{
    if (bind)
        kvdb_ctxn_bind_putref(bind);
}
