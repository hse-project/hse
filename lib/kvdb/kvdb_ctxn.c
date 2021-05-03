/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/arch.h>
#include <hse_util/assert.h>
#include <hse_util/alloc.h>
#include <hse_util/atomic.h>
#include <hse_util/barrier.h>
#include <hse_util/slab.h>
#include <hse_util/darray.h>
#include <hse_util/seqno.h>
#include <hse_util/keylock.h>
#include <hse_util/page.h>
#include <hse_util/xrand.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0snr_set.h>
#include <hse_ikvdb/limits.h>

#include "viewset.h"
#include "kvdb_ctxn_internal.h"
#include "kvdb_keylock.h"

#include <semaphore.h>

struct kvdb_ctxn_set {
};

/**
 * struct kvdb_ctxn_set_impl -
 * @ktn_wq:           workqueue struct for queueing transaction worker thread
 * @txn_wkth_delay:   delay in jiffies to use for transaction worker thread
 * @ktn_txn_timeout:  max time to live (in msecs) after which txn is aborted
 * @ktn_dwork:        delayed work struct
 * @ktn_tseqno_head:  used to serialize commits in seqno order
 * @ktn_tseqno_tail:  used to serialize commits in seqno order
 * @ktn_tseqno_sema:  used to limit threads spinning in kvdb_ctxn_set_wait_commits()
 * @ktn_list_mutex:   protects updates to list of allocated transactions
 * @ktn_alloc_list:   RCU list of allocated transactions
 * @ktn_pending:      transactions to be freed when reader thread finishes
 * @ktn_reading:      indicates whether the worker thread is reading the list
 * @ktn_queued:       has the worker thread been queued
 */
struct kvdb_ctxn_set_impl {
    struct kvdb_ctxn_set     ktn_handle;
    struct workqueue_struct *ktn_wq;
    u64                      txn_wkth_delay;
    u64                      ktn_txn_timeout;
    struct delayed_work      ktn_dwork;

    atomic64_t ktn_tseqno_head HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    atomic64_t ktn_tseqno_tail HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    sem_t      ktn_tseqno_sema HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    spinlock_t ktn_tseqno_sync HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    struct mutex         ktn_list_mutex HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct cds_list_head ktn_alloc_list HSE_ALIGNED(SMP_CACHE_BYTES);
    struct list_head     ktn_pending;
    atomic_t             ktn_reading;
    bool                 ktn_queued;
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

static HSE_ALWAYS_INLINE bool
ctxn_trylock(struct kvdb_ctxn_impl *ctxn)
{
    return atomic_cmpxchg(&ctxn->ctxn_lock, 0, 1) == 0;
}

static HSE_ALWAYS_INLINE void
ctxn_unlock(struct kvdb_ctxn_impl *ctxn)
{
    int old HSE_MAYBE_UNUSED;

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
    cds_list_for_each_entry_rcu(ctxn, &ktn->ktn_alloc_list, ctxn_alloc_link) {
        state = seqnoref_to_state(ctxn->ctxn_seqref);
        if (state == KVDB_CTXN_ACTIVE) {
            if (now > (ctxn->ctxn_begin_ts + ttl_ns))
                list_add(&ctxn->ctxn_abort_link, &alist);
        }
    }
    rcu_read_unlock();

    list_for_each_entry(ctxn, &alist, ctxn_abort_link)
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
    list_for_each_entry_safe(ctxn, next, &freelist, ctxn_free_link) {
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
    struct viewset         *viewset,
    struct c0snr_set       *c0snrset,
    struct c0sk            *c0sk)
{
    struct kvdb_ctxn_impl *    ctxn;
    struct kvdb_ctxn_set_impl *kvdb_ctxn_set;
    struct kvdb_rparams *      rp;
    bool                       start;

    kvdb_ctxn_set = kvdb_ctxn_set_h2r(kcs_handle);

    ctxn = alloc_aligned(sizeof(*ctxn), alignof(*ctxn));
    if (ev(!ctxn))
        return NULL;

    memset(ctxn, 0, sizeof(*ctxn));
    atomic_set(&ctxn->ctxn_lock, 0);
    ctxn->ctxn_seqref = HSE_SQNREF_INVALID;
    ctxn->ctxn_kvdb_keylock = kvdb_keylock;
    ctxn->ctxn_viewset = viewset;
    ctxn->ctxn_c0snr_set = c0snrset;
    ctxn->ctxn_c0sk = c0sk;
    ctxn->ctxn_kvdb_ctxn_set = kcs_handle;
    ctxn->ctxn_kvdb_seq_addr = kvdb_seqno_addr;
    ctxn->ctxn_tseqno_head = &kvdb_ctxn_set->ktn_tseqno_head;
    ctxn->ctxn_tseqno_tail = &kvdb_ctxn_set->ktn_tseqno_tail;

    rp = c0sk_rparams(ctxn->ctxn_c0sk);
    if (rp)
        ctxn->ctxn_commit_abort_pct = rp->txn_commit_abort_pct;

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

static void
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
kvdb_ctxn_set_wait_commits(struct kvdb_ctxn_set *handle)
{
    struct kvdb_ctxn_set_impl *kvdb_ctxn_set = kvdb_ctxn_set_h2r(handle);
    u64 head, tail;
    sem_t *sema;
    int spin;

    /*
     * This transaction started its commit only after our view was established.
     * Note that your view must be established prior to calling wait_commits.
     * Every transaction that starts its commit after our view is established
     * will have a commit_seqno strictly greater than our view_seqno.
     */
    head = atomic64_read_acq(&kvdb_ctxn_set->ktn_tseqno_head);

    /*
     * Ensure that all preceding commits have published their mutations.
     * This ensures that we have a consistent read snapshot to work with.
     * We do not expect any new committing transactions' mutations
     * to unexpectedly pop up within our view after this wait is over.
     *
     * Note: At 4-billion commits per second it would take more than 136
     * years for head to wrap.  So we just don't worry about it...
     */
  again:
    spin = 32;

    while (spin > 0) {
        tail = atomic64_read(&kvdb_ctxn_set->ktn_tseqno_tail);
        if (tail >= head)
            return;

        cpu_relax();
        spin--;
    }

    /* At this point the view still isn't stable, but if we busy-wait
     * indefinitely we could bring the system to a crawl.  So we use
     * counting semaphore to limit the number of threads allowed to
     * busy-wait for their view to stabilize.
     */
    sema = &kvdb_ctxn_set->ktn_tseqno_sema;

    if (sem_wait(sema))
        goto again; /* Probably EINTR */

    while (atomic64_read(&kvdb_ctxn_set->ktn_tseqno_tail) < head)
        cpu_relax();

    sem_post(&kvdb_ctxn_set->ktn_tseqno_sema);
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

    kvdb_ctxn_set_remove(ctxn->ctxn_kvdb_ctxn_set, ctxn);
}

static merr_t
kvdb_ctxn_enable_inserts(struct kvdb_ctxn_impl *ctxn)
{
    struct kvdb_ctxn_locks     *locks;
    uintptr_t                  *priv;
    merr_t                      err;

    err = kvdb_ctxn_locks_create(&locks);
    if (ev(err))
        return err;

    priv = c0snr_set_get_c0snr(ctxn->ctxn_c0snr_set, &ctxn->ctxn_inner_handle);
    if (ev(!priv)) {
        kvdb_ctxn_locks_destroy(locks);
        return merr(ECANCELED);
    }

    assert(*priv == HSE_SQNREF_INVALID);
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

    if (ev(!ctxn_trylock(ctxn)))
        return merr(EPROTO);

    state = seqnoref_to_state(ctxn->ctxn_seqref);

    if (ev(state != KVDB_CTXN_ABORTED && state != KVDB_CTXN_COMMITTED &&
           state != KVDB_CTXN_INVALID)) {
        err = merr(EINVAL);
        goto errout;
    }

    ctxn->ctxn_bind = 0;
    ctxn->ctxn_begin_ts = get_time_ns();

    err = viewset_insert(
        ctxn->ctxn_viewset, &ctxn->ctxn_view_seqno, &ctxn->ctxn_viewset_cookie);
    if (ev(err))
        goto errout;

    kvdb_ctxn_set_wait_commits(ctxn->ctxn_kvdb_ctxn_set);

    ctxn->ctxn_can_insert = 0;
    ctxn->ctxn_seqref = HSE_SQNREF_UNDEFINED;

errout:
    ctxn_unlock(ctxn);

    return err;
}

static void
kvdb_ctxn_deactivate(struct kvdb_ctxn_impl *ctxn)
{
    u32   min_changed = 0;
    u64   new_min = U64_MAX;
    void *cookie;

    ctxn->ctxn_can_insert = false;

    cookie = ctxn->ctxn_viewset_cookie;
    ctxn->ctxn_viewset_cookie = NULL;

    viewset_remove(ctxn->ctxn_viewset, cookie, &min_changed, &new_min);
    if (min_changed)
        kvdb_keylock_expire(ctxn->ctxn_kvdb_keylock, new_min);
}

static void
kvdb_ctxn_abort_inner(struct kvdb_ctxn_impl *ctxn)
{
    struct kvdb_ctxn_locks *locks;
    struct kvdb_ctxn_bind * bind;
    struct kvdb_keylock *   keylock;

    if (ctxn->ctxn_can_insert) {
        uintptr_t *priv = (uintptr_t *)ctxn->ctxn_seqref;

        *priv = HSE_SQNREF_ABORTED;

        /* Once the indirect assignment has been performed the
         * transaction itself no longer needs to read the shared value
         * and instead just puts it into its private area. This is
         * preserved until the transaction is reused and allows us to
         * remember that the state of the transaction is "aborted".
         */
        ctxn->ctxn_seqref = HSE_SQNREF_ABORTED;

        c0snr_clear_txn(priv);
    } else {
        ctxn->ctxn_seqref = HSE_SQNREF_ABORTED;
    }

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
}

void
kvdb_ctxn_abort(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    enum kvdb_ctxn_state   state;

    if (ev(!ctxn_trylock(ctxn)))
        return;

    state = seqnoref_to_state(ctxn->ctxn_seqref);

    if (state == KVDB_CTXN_ACTIVE)
        kvdb_ctxn_abort_inner(ctxn);

    ctxn_unlock(ctxn);
}

merr_t
kvdb_ctxn_commit(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl * ctxn = kvdb_ctxn_h2r(handle);
    struct kvdb_ctxn_bind * bind = ctxn->ctxn_bind;
    struct kvdb_ctxn_locks *locks;
    enum kvdb_ctxn_state    state;
    void *                  cookie;
    uintptr_t *             priv;
    uintptr_t               ref;
    u64                     commit_sn;
    u64                     head;

    if (ev(!ctxn_trylock(ctxn)))
        return merr(EPROTO);

    state = seqnoref_to_state(ctxn->ctxn_seqref);
    if (ev(state != KVDB_CTXN_ACTIVE)) {
        ctxn_unlock(ctxn);
        return merr(EINVAL);
    }

    /* Inject a commit fault for testing purposes.  For example, the
     * hse-mongo connector will throw a WriteConflictException (WCE)
     * when kvdb_ctxn_commit() returns an error which should cause
     * mongod to restart the transaction.
     */
    if (ctxn->ctxn_commit_abort_pct) {
        if (ev((xrand64_tls() % 16384) < ctxn->ctxn_commit_abort_pct)) {
            kvdb_ctxn_abort_inner(ctxn);
            ctxn_unlock(ctxn);
            return merr(ECANCELED);
        }
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
        ctxn_unlock(ctxn);

        return 0;
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
     *   - The viewset mechanism is used to efficiently track what
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

    struct kvdb_ctxn_set_impl *kcs = kvdb_ctxn_set_h2r(ctxn->ctxn_kvdb_ctxn_set);
    priv = (uintptr_t *)ctxn->ctxn_seqref;

    /*
     * Ensure that threads mint commit sequence numbers in increasing order
     * of ctxn_tseqno_head.
     */
    spin_lock(&kcs->ktn_tseqno_sync);
    head = atomic64_inc_acq(ctxn->ctxn_tseqno_head);
    commit_sn = 1 + atomic64_fetch_add_rel(2, ctxn->ctxn_kvdb_seq_addr);
    spin_unlock(&kcs->ktn_tseqno_sync);

    /* We leverage tseqno head and tail to ensure that we never present
     * a commit_sn to c1 for which there might be a lower commit_sn that
     * has not yet been applied to the kvms (via *priv = ref).  We could
     * accomplish the same thing with a mutex, but this approach greatly
     * improves throughput of the above critical section vs a mutex.
     */
    while (atomic64_read(ctxn->ctxn_tseqno_tail) + 1 < head)
        cpu_relax();

    /* This assignment through the pointer gives all the values
     * associated with this transaction an ordinal sequence
     * number. Each of those values has their own pointer to the
     * ordinal value.
     */
    ref = HSE_ORDNL_TO_SQNREF(commit_sn);
    *priv = ref;

    atomic64_inc_rel(ctxn->ctxn_tseqno_tail);

    /* Once the indirect assignment has been performed the
     * transaction itself no longer needs to see the shared value
     * and instead just puts it into its private area. This is
     * preserved until the transaction is reused and allows us to
     * remember that the state of the transaction is "committed".
     */
    ctxn->ctxn_seqref = ref;
    c0snr_clear_txn(priv);

    locks = ctxn->ctxn_locks_handle;
    ctxn->ctxn_locks_handle = NULL;

    if (kvdb_ctxn_locks_count(locks) > 0) {
        kvdb_keylock_insert_locks(locks, commit_sn, cookie);
        locks = NULL;
    }

    kvdb_keylock_list_unlock(cookie);

    if (locks)
        kvdb_ctxn_locks_destroy(locks);

    if (bind) {
        bind->b_seq = commit_sn + 1;
        kvdb_ctxn_bind_cancel(bind, true);
        ctxn->ctxn_bind = 0;
    }

    kvdb_ctxn_deactivate(ctxn);

    ctxn_unlock(ctxn);

    return 0;
}

enum kvdb_ctxn_state
kvdb_ctxn_get_state(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    return seqnoref_to_state(ctxn->ctxn_seqref);
}

void
kvdb_ctxn_reset(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    ctxn->ctxn_seqref = HSE_SQNREF_INVALID;
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
kvdb_ctxn_set_create(struct kvdb_ctxn_set **handle_out, u64 txn_timeout_ms, u64 delay_msecs)
{
    struct kvdb_ctxn_set_impl *ktn;
    int limit, rc;

    *handle_out = 0;

    ktn = alloc_aligned(sizeof(*ktn), alignof(*ktn));
    if (ev(!ktn))
        return merr(ENOMEM);

    memset(ktn, 0, sizeof(*ktn));

    /* Limit the number of threads allowed to busy-wait
     * indefinitely in kvdb_ctxn_set_wait_commits().
     */
    limit = clamp_t(int, get_nprocs() / 8, 1, 8);

    rc = sem_init(&ktn->ktn_tseqno_sema, 0, limit);
    if (ev(rc)) {
        int xerrno = errno;

        free_aligned(ktn);
        return merr(xerrno);
    }

    ktn->ktn_wq = alloc_workqueue("kvdb_ctxn_set", 0, 1);
    if (ev(!ktn->ktn_wq)) {
        sem_destroy(&ktn->ktn_tseqno_sema);
        free_aligned(ktn);
        return merr(ENOMEM);
    }

    atomic64_set(&ktn->ktn_tseqno_head, 0);
    atomic64_set(&ktn->ktn_tseqno_tail, 0);
    spin_lock_init(&ktn->ktn_tseqno_sync);
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

    list_for_each_entry_safe(ctxn, next, &ktn->ktn_pending, ctxn_free_link)
        kvdb_ctxn_free(&ctxn->ctxn_inner_handle);

    mutex_destroy(&ktn->ktn_list_mutex);
    sem_destroy(&ktn->ktn_tseqno_sema);

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

merr_t
kvdb_ctxn_trylock_read(
    struct kvdb_ctxn   *handle,
    u64                *view_seqno,
    uintptr_t          *seqref)
{
    merr_t                  err = 0;
    struct kvdb_ctxn_impl  *ctxn;

    assert(handle);

    ctxn = kvdb_ctxn_h2r(handle);

    if (ev(!ctxn_trylock(ctxn)))
        return merr(EPROTO);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)) {
        err = merr(ECANCELED);
        goto errout;
    }

    *view_seqno = ctxn->ctxn_view_seqno;
    *seqref = ctxn->ctxn_seqref;

  errout:
    if (err)
        ctxn_unlock(ctxn);

    return err;
}

merr_t
kvdb_ctxn_trylock_write(
    struct kvdb_ctxn           *handle,
    const struct kvs_ktuple    *kt,
    u64                         keylock_seed,
    uintptr_t                  *seqref)
{
    merr_t                  err = 0;
    struct kvdb_ctxn_impl  *ctxn;
    u64                     hash;

    assert(handle);

    ctxn = kvdb_ctxn_h2r(handle);

    if (ev(!ctxn_trylock(ctxn)))
        return merr(EPROTO);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)) {
        err = merr(ECANCELED);
        goto errout;
    }

    if (!ctxn->ctxn_can_insert) {
        err = kvdb_ctxn_enable_inserts(ctxn);
        if (ev(err))
            goto errout;
    }

    if (keylock_seed) {
        hash = key_hash64_seed(kt->kt_data, kt->kt_len, keylock_seed);
        err = kvdb_keylock_lock(
            ctxn->ctxn_kvdb_keylock, ctxn->ctxn_locks_handle, hash, ctxn->ctxn_view_seqno);

        if (err) {
            ev(merr_errno(err) != ECANCELED);
            goto errout;
        }
    }

    if (ctxn->ctxn_bind)
        kvdb_ctxn_bind_invalidate(ctxn->ctxn_bind);

    *seqref = ctxn->ctxn_seqref;

  errout:
    if (err)
        ctxn_unlock(ctxn);

    return err;
}


void
kvdb_ctxn_unlock(struct kvdb_ctxn *handle)
{
    assert(handle);
    ctxn_unlock(kvdb_ctxn_h2r(handle));
}
