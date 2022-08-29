/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_kvdb_ctxn

#include <stdint.h>

#include <urcu/rculist.h>

#include <hse/util/arch.h>
#include <hse/util/assert.h>
#include <hse/util/alloc.h>
#include <hse/util/atomic.h>
#include <hse/util/slab.h>
#include <hse/util/seqno.h>
#include <hse/util/keylock.h>
#include <hse/util/page.h>
#include <hse/util/xrand.h>
#include <hse/util/event_counter.h>

#include <hse/ikvdb/kvs.h>
#include <hse/ikvdb/kvdb_ctxn.h>
#include <hse/ikvdb/kvdb_rparams.h>
#include <hse/ikvdb/c0_kvmultiset.h>
#include <hse/ikvdb/c0.h>
#include <hse/ikvdb/c0sk.h>
#include <hse/ikvdb/c0snr_set.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/wal.h>

#include "viewset.h"
#include "kvdb_ctxn_internal.h"
#include "kvdb_ctxn_pfxlock.h"
#include "kvdb_keylock.h"

/* clang-format off */

#define kvdb_ctxn_set_h2r(_ktn_handle) \
    container_of(_ktn_handle, struct kvdb_ctxn_set_impl, ktn_handle)

struct kvdb_ctxn_set {
};

/**
 * struct kvdb_ctxn_set_impl -
 * @ktn_wq:           workqueue struct for queueing transaction worker thread
 * @txn_wkth_delay:   delay in jiffies to use for transaction worker thread
 * @ktn_txn_timeout:  max time to live (in msecs) after which txn is aborted
 * @ktn_dwork:        delayed work struct
 * @ktn_tseqno_head:  used to obtain a stable view seqno
 * @ktn_tseqno_tail:  used to obtain a stable view seqno
 * @ktn_list_mutex:   protects updates to list of allocated transactions
 * @ktn_alloc_list:   RCU list of allocated transactions
 * @ktn_pending:      transactions to be freed when reader thread finishes
 * @ktn_reading:      indicates whether the worker thread is reading the list
 * @ktn_queued:       has the worker thread been queued
 */
struct kvdb_ctxn_set_impl {
    struct kvdb_ctxn_set     ktn_handle;
    struct workqueue_struct *ktn_wq;
    uint64_t                 txn_wkth_delay;
    uint64_t                 ktn_txn_timeout;
    struct delayed_work      ktn_dwork;

    atomic_ulong             ktn_tseqno_head HSE_ACP_ALIGNED;
    atomic_ulong             ktn_tseqno_tail HSE_ACP_ALIGNED;

    struct mutex             ktn_list_mutex HSE_ACP_ALIGNED;
    struct list_head         ktn_pending;
    atomic_int               ktn_reading;
    bool                     ktn_queued;

    struct cds_list_head     ktn_alloc_list HSE_ALIGNED(CAA_CACHE_LINE_SIZE);
};

/* clang-format on */

static HSE_ALWAYS_INLINE merr_t
kvdb_ctxn_trylock_impl(struct kvdb_ctxn_impl *ctxn)
{
    mutex_lock(&ctxn->ctxn_lock);

    if (HSE_UNLIKELY(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE)) {
        mutex_unlock(&ctxn->ctxn_lock);
        return merrx(ECANCELED, ctxn->ctxn_expired ? HSE_ERR_CTX_TXN_EXPIRED : 0);
    }

    return 0;
}

static HSE_ALWAYS_INLINE void
kvdb_ctxn_lock_impl(struct kvdb_ctxn_impl *ctxn)
{
    mutex_lock(&ctxn->ctxn_lock);
}

static HSE_ALWAYS_INLINE void
kvdb_ctxn_unlock_impl(struct kvdb_ctxn_impl *ctxn)
{
    mutex_unlock(&ctxn->ctxn_lock);
}

static inline void
kvdb_ctxn_bind_putref(struct kvdb_ctxn_bind *bind)
{
    int refcnt;
    struct kvdb_ctxn *bind_ctxn = bind->b_ctxn;

    if (kvdb_ctxn_trylock_impl(kvdb_ctxn_h2r(bind->b_ctxn)) != 0)
        return;

    refcnt = atomic_dec_return(&bind->b_ref);
    assert(refcnt >= 0);
    if (refcnt == 0)
        bind->b_ctxn = NULL;

    kvdb_ctxn_unlock_impl(kvdb_ctxn_h2r(bind_ctxn));
}

static inline void
kvdb_ctxn_bind_getref(struct kvdb_ctxn_bind *bind)
{
    if (kvdb_ctxn_trylock_impl(kvdb_ctxn_h2r(bind->b_ctxn)) != 0)
        return;

    atomic_inc(&bind->b_ref);
    kvdb_ctxn_unlock_impl(kvdb_ctxn_h2r(bind->b_ctxn));
}

static inline void
kvdb_ctxn_bind_invalidate(struct kvdb_ctxn_bind *bind)
{
    atomic_inc(&bind->b_gen);
}

static inline void
kvdb_ctxn_bind_cancel(struct kvdb_ctxn_bind *bind)
{
    bind->b_ctxn = 0;
}

static void
kvdb_ctxn_reaper(struct work_struct *work)
{
    enum kvdb_ctxn_state       state;
    struct list_head           freelist, alist;
    struct kvdb_ctxn_impl *    ctxn = 0, *next = 0;
    struct kvdb_ctxn_set_impl *ktn;
    uint64_t                   now;
    uint64_t                   ttl_ns;
    unsigned int               abort_cnt = 0;

    INIT_LIST_HEAD(&alist);

    ktn = container_of(work, struct kvdb_ctxn_set_impl, ktn_dwork.work);

    atomic_store(&ktn->ktn_reading, 1);

    /* Abort all active transactions that have expired. */
    now = get_time_ns();
    ttl_ns = ktn->ktn_txn_timeout * 1000000UL;

    rcu_read_lock();
    cds_list_for_each_entry_rcu(ctxn, &ktn->ktn_alloc_list, ctxn_alloc_link) {
        state = seqnoref_to_state(ctxn->ctxn_seqref);
        if (state == KVDB_CTXN_ACTIVE) {
            if (now > (ctxn->ctxn_begin_ts + ttl_ns)) {
                list_add(&ctxn->ctxn_abort_link, &alist);
                ++abort_cnt;
            }
        }
    }
    rcu_read_unlock();

    if (abort_cnt)
        log_info("Aborting %u transactions (expired)", abort_cnt);

    list_for_each_entry(ctxn, &alist, ctxn_abort_link) {
        kvdb_ctxn_abort(&ctxn->ctxn_inner_handle);
        ctxn->ctxn_expired = true;
    }

    atomic_store(&ktn->ktn_reading, 0);

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
        kvdb_ctxn_cursor_unbind(&ctxn->ctxn_bind);
        mutex_destroy(&ctxn->ctxn_lock);
        free(ctxn);
        ev(1);
    }
}

struct kvdb_ctxn *
kvdb_ctxn_alloc(
    struct kvdb_keylock * kvdb_keylock,
    struct kvdb_pfxlock * kvdb_pfxlock,
    atomic_ulong         *kvdb_seqno_addr,
    struct kvdb_ctxn_set *kcs_handle,
    struct viewset *      viewset,
    struct c0snr_set *    c0snrset,
    struct c0sk *         c0sk,
    struct wal *          wal)
{
    struct kvdb_ctxn_impl *    ctxn;
    struct kvdb_ctxn_set_impl *kvdb_ctxn_set;
    bool                       start;

    kvdb_ctxn_set = kvdb_ctxn_set_h2r(kcs_handle);

    ctxn = aligned_alloc(__alignof__(*ctxn), sizeof(*ctxn));
    if (ev(!ctxn))
        return NULL;

    memset(ctxn, 0, sizeof(*ctxn));
    mutex_init(&ctxn->ctxn_lock);
    ctxn->ctxn_seqref = HSE_SQNREF_INVALID;
    ctxn->ctxn_kvdb_pfxlock = kvdb_pfxlock;
    ctxn->ctxn_kvdb_keylock = kvdb_keylock;
    ctxn->ctxn_viewset = viewset;
    ctxn->ctxn_c0snr_set = c0snrset;
    ctxn->ctxn_c0sk = c0sk;
    ctxn->ctxn_wal = wal;
    ctxn->ctxn_kvdb_ctxn_set = kcs_handle;
    ctxn->ctxn_kvdb_seq_addr = kvdb_seqno_addr;

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
        kvdb_ctxn_cursor_unbind(&ctxn->ctxn_bind);
        mutex_destroy(&ctxn->ctxn_lock);
        free(ctxn);
    }
}

/*
 * Ensure that all preceding commits have published their mutations.
 * This ensures that we have a consistent read snapshot to work with.
 * We do not expect any new committing transactions' mutations
 * to unexpectedly pop up within our view after this wait is over.
 *
 * Note that your view must be established prior to calling wait_commits.
 * Every transaction that starts its commit after our view is established
 * will have a commit_seqno strictly greater than our view_seqno.
 *
 * Note: At 4-billion commits per second it would take more than 136
 * years for head to wrap.  So we just don't worry about it...
 */
void
kvdb_ctxn_set_wait_commits(struct kvdb_ctxn_set *handle, uint64_t head)
{
    struct kvdb_ctxn_set_impl *self = kvdb_ctxn_set_h2r(handle);

    if (!head)
        head = atomic_read_acq(&self->ktn_tseqno_head);

    while (atomic_read(&self->ktn_tseqno_tail) < head)
        cpu_relax();
}

void
kvdb_ctxn_free(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn;

    if (ev(!handle))
        return;

    kvdb_ctxn_abort(handle);

    ctxn = kvdb_ctxn_h2r(handle);

    assert(!ctxn->ctxn_locks_handle);
    assert(!ctxn->ctxn_pfxlock_handle);

    kvdb_ctxn_set_remove(ctxn->ctxn_kvdb_ctxn_set, ctxn);
}

static merr_t
kvdb_ctxn_enable_inserts(struct kvdb_ctxn_impl *ctxn)
{
    struct kvdb_ctxn_locks *locks;
    uintptr_t *             priv;
    merr_t                  err;

    kvdb_keylock_expire(ctxn->ctxn_kvdb_keylock, viewset_min_view(ctxn->ctxn_viewset), 1);

    err = kvdb_ctxn_locks_create(&locks);
    if (ev(err))
        return err;

    err = kvdb_ctxn_pfxlock_create(
        ctxn->ctxn_kvdb_pfxlock, ctxn->ctxn_view_seqno, &ctxn->ctxn_pfxlock_handle);
    if (ev(err)) {
        kvdb_ctxn_locks_destroy(locks);
        return err;
    }

    priv = c0snr_set_get_c0snr(ctxn->ctxn_c0snr_set, &ctxn->ctxn_inner_handle);
    if (ev(!priv)) {
        kvdb_ctxn_pfxlock_destroy(ctxn->ctxn_pfxlock_handle);
        ctxn->ctxn_pfxlock_handle = NULL;
        kvdb_ctxn_locks_destroy(locks);
        return merr(ECANCELED);
    }

    assert(*priv == HSE_SQNREF_INVALID);
    *priv = HSE_SQNREF_UNDEFINED;

    ctxn->ctxn_seqref = HSE_REF_TO_SQNREF(priv);
    ctxn->ctxn_locks_handle = locks;
    ctxn->ctxn_can_insert = true;

    return 0;
}

merr_t
kvdb_ctxn_begin(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    enum kvdb_ctxn_state   state;
    uint64_t               tseqno;
    merr_t                 err;

    kvdb_ctxn_lock_impl(ctxn);
    state = seqnoref_to_state(ctxn->ctxn_seqref);

    if (ev(state != KVDB_CTXN_ABORTED && state != KVDB_CTXN_COMMITTED &&
           state != KVDB_CTXN_INVALID)) {
        err = merr(EINVAL);
        goto errout;
    }

    ctxn->ctxn_begin_ts = get_time_ns();
    ctxn->ctxn_can_insert = 0;
    ctxn->ctxn_seqref = HSE_SQNREF_UNDEFINED;
    ctxn->ctxn_bind.b_ctxn = &ctxn->ctxn_inner_handle;
    ctxn->ctxn_expired = false;

    err = viewset_insert(ctxn->ctxn_viewset, &ctxn->ctxn_view_seqno, &tseqno, &ctxn->ctxn_viewset_cookie);
    if (ev(err))
        goto errout;

    kvdb_ctxn_set_wait_commits(ctxn->ctxn_kvdb_ctxn_set, tseqno);

errout:
    kvdb_ctxn_unlock_impl(ctxn);

    return err;
}

static void
kvdb_ctxn_deactivate(struct kvdb_ctxn_impl *ctxn)
{
    uint32_t min_changed = 0;
    uint64_t new_min = UINT64_MAX;
    void *cookie;

    ctxn->ctxn_can_insert = false;

    cookie = ctxn->ctxn_viewset_cookie;
    if (!cookie)
        return;

    if (ctxn->ctxn_pfxlock_handle) {
        kvdb_ctxn_pfxlock_destroy(ctxn->ctxn_pfxlock_handle);
        ctxn->ctxn_pfxlock_handle = NULL;
    }

    ctxn->ctxn_viewset_cookie = NULL;

    viewset_remove(ctxn->ctxn_viewset, cookie, &min_changed, &new_min);

    if (min_changed)
        kvdb_keylock_expire(ctxn->ctxn_kvdb_keylock, new_min, UINT64_MAX);

}

static void
kvdb_ctxn_abort_inner(struct kvdb_ctxn_impl *ctxn)
{
    kvdb_ctxn_bind_cancel(&ctxn->ctxn_bind);

    if (ctxn->ctxn_can_insert) {
        uintptr_t *priv = (uintptr_t *)ctxn->ctxn_seqref;
        struct kvdb_ctxn_locks *locks;
        struct kvdb_keylock *keylock;

        *priv = HSE_SQNREF_ABORTED;

        /* Once the indirect assignment has been performed the
         * transaction itself no longer needs to read the shared value
         * and instead just puts it into its private area. This is
         * preserved until the transaction is reused and allows us to
         * remember that the state of the transaction is "aborted".
         */
        ctxn->ctxn_seqref = HSE_SQNREF_ABORTED;

        c0snr_clear_txn(priv);

        keylock = ctxn->ctxn_kvdb_keylock;
        locks = ctxn->ctxn_locks_handle;
        ctxn->ctxn_locks_handle = NULL;

        assert(locks);

        /* Release all the locks that we didn't inherit */
        kvdb_keylock_prune_own_locks(keylock, locks);

        if (kvdb_ctxn_locks_count(locks) > 0) {
            void *cookie = NULL;
            uint64_t end_seq;

            kvdb_keylock_list_lock(keylock, &cookie);
            end_seq = atomic_fetch_add(ctxn->ctxn_kvdb_seq_addr, 1);
            kvdb_keylock_enqueue_locks(locks, end_seq, cookie);
            kvdb_keylock_list_unlock(cookie);

        } else {
            kvdb_ctxn_locks_destroy(locks);
        }

        wal_txn_abort(ctxn->ctxn_wal, ctxn->ctxn_view_seqno, ctxn->ctxn_wal_cookie);
    } else {
        ctxn->ctxn_seqref = HSE_SQNREF_ABORTED;
    }

    /* At this point the transaction ceases to be considered active */
    kvdb_ctxn_deactivate(ctxn);
}

void
kvdb_ctxn_abort(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    if (kvdb_ctxn_trylock_impl(ctxn) == 0) {
        kvdb_ctxn_abort_inner(ctxn);
        kvdb_ctxn_unlock_impl(ctxn);
    }
}

merr_t
kvdb_ctxn_commit(struct kvdb_ctxn *handle)
{
    merr_t err;
    void *cookie;
    uint64_t head;
    uintptr_t ref;
    uintptr_t *priv;
    uint64_t commit_sn;
    struct kvdb_ctxn_locks *locks;
    struct kvdb_ctxn_set_impl *kcs;
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    struct kvdb_ctxn_bind *bind = &ctxn->ctxn_bind;

    err = kvdb_ctxn_trylock_impl(ctxn);
    if (err)
        return err;

    /* If this transaction never wrote anything then the commit path is
     * much simpler. We make our "transaction sequence number" be a
     * reference encoded copy of our view sequence number. We also take
     * ourselves out of the set of active transactions, and if that
     * removal may have triggered delayed write-lock releases we take
     * care of that.
     */
    if (!ctxn->ctxn_can_insert) {
        kvdb_ctxn_bind_cancel(bind);

        ctxn->ctxn_seqref = HSE_ORDNL_TO_SQNREF(ctxn->ctxn_view_seqno);
        kvdb_ctxn_deactivate(ctxn);
        kvdb_ctxn_unlock_impl(ctxn);

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
     *   - The viewset mechanism is used to efficiently track what the
     *     lowest view sequence number is for any active txn.  If there
     *     are no active txn's, then that number is the current value
     *     of ikdb_seqno.
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
     *     all elements whose commit sequence number is less than the new
     *     minimum sequence number.
     *
     *   - To account for the case that a given txn A is the only active
     *     txn in the system, we ensure that we put A's write lock
     *     collection on the list before we call kvdb_ctxn_deactivate
     *     so that a commit execution will reap its own collection.
     */

    kcs = kvdb_ctxn_set_h2r(ctxn->ctxn_kvdb_ctxn_set);

    /* Prefetch priv to try and avoid a cache miss whithin the critsec.
     */
    priv = (uintptr_t *)ctxn->ctxn_seqref;
    __builtin_prefetch(priv);

    cookie = NULL; /* Set to nil for mapi */

    /* The critical section demarcated by the keylock_list_{lock/unlock}
     * calls provide mutual exclusion only for the list referenced by
     * cookie, and ensures that keylocks are queued to their respective
     * lists in commit sequence number order.  Additionally, the list
     * lock limits concurrency through this section to only a handful
     * of CPUs (currently 4 as defined by KVDB_DLOCK_MAX) which helps
     * to relive contention on the ticket lock.
     */
    kvdb_keylock_list_lock(ctxn->ctxn_kvdb_keylock, &cookie);

    /* The commit ticket lock (tseqno head/tail) ensures that commit sequence
     * numbers are minted and made visible in ticket order.  Acquire semantics
     * on the increment of tseqno head ensure that it is always incremented
     * before commit_sn is computed.  This ticket lock is also used by
     * kvdb_ctxn_set_wait_commit() to ensure visibility of a view seqno
     * obtained asynchronously with respect to this critical section.
     */
    head = atomic_fetch_add(&kcs->ktn_tseqno_head, 1); /* acquire next ticket */

    while (atomic_read(&kcs->ktn_tseqno_tail) < head)
        cpu_relax(); /* wait for our ticket to be served */

    commit_sn = 1 + atomic_fetch_add(ctxn->ctxn_kvdb_seq_addr, 2);

    /* The assignment through *priv gives all the values associated
     * with this transaction an ordinal sequence number. Each of
     * those values has their own pointer to the ordinal value.
     */
    ref = HSE_ORDNL_TO_SQNREF(commit_sn);
    *priv = ref;

    atomic_inc_rel(&kcs->ktn_tseqno_tail); /* release ticket lock */

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
        kvdb_keylock_enqueue_locks(locks, commit_sn, cookie);
        locks = NULL;
    }
    kvdb_keylock_list_unlock(cookie);

    if (locks)
        kvdb_ctxn_locks_destroy(locks);

    kvdb_ctxn_bind_cancel(bind);

    err = wal_txn_commit(ctxn->ctxn_wal, ctxn->ctxn_view_seqno, commit_sn, head,
                         ctxn->ctxn_wal_cookie);

    kvdb_ctxn_pfxlock_seqno_pub(ctxn->ctxn_pfxlock_handle, commit_sn);

    kvdb_ctxn_deactivate(ctxn);
    kvdb_ctxn_unlock_impl(ctxn);

    return err;
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
    ctxn->ctxn_expired = false;
}

merr_t
kvdb_ctxn_get_view_seqno(struct kvdb_ctxn *handle, uint64_t *view_seqno)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    if (ev(seqnoref_to_state(ctxn->ctxn_seqref) != KVDB_CTXN_ACTIVE))
        return merrx(EPROTO, ctxn->ctxn_expired ? HSE_ERR_CTX_TXN_EXPIRED : 0);

    *view_seqno = ctxn->ctxn_view_seqno;

    return 0;
}

uintptr_t
kvdb_ctxn_get_seqnoref(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);

    return ctxn ? ctxn->ctxn_seqref : 0;
}

/* This routine determines whether exclusive ownership of a keylock can be
 * inherited from one client transaction to another.  This can happen if
 * the new transaction starts after the commit or abort of the transaction
 * that currently holds the keylock in an inheritable state.
 *
 * Hence, this function returns true if ownership can be transferred.
 *
 * Pre-Conditions at Entry:
 * ------------------------
 *  (1) The keylock table holding the hash is locked by the calling thread.
 *  (2) Ownership of the hash is held by the lock collection referenced by desc.
 *
 * The lock collection referenced by "desc" cannot vanish during this call
 * because of pre-condition (1) above.  However, it is entirely possible
 * that its ref goes to 0 at any time while another thread is attempting
 * to inherit the lock.  This is protected against by updating the rock
 * of the entry while we are holding off the other threads so that any
 * unlock attempt on the part of the previous owner silently fails.
 *
 * Release of lock (1) will handle the write memory barrier needed.
 *
 * Note that while the lock collection referenced by desc holds the keylock
 * its end seqno will be U64_MAX and hence it can never be transferred.
 */
bool
kvdb_ctxn_lock_inherit(uint32_t desc, uint64_t start_seq)
{
    return (start_seq > kvdb_ctxn_locks_end_seqno(desc));
}

merr_t
kvdb_ctxn_set_create(
    struct kvdb_ctxn_set **handle_out,
    uint64_t txn_timeout_ms,
    uint64_t delay_msecs)
{
    struct kvdb_ctxn_set_impl *ktn;

    *handle_out = 0;

    ktn = aligned_alloc(__alignof__(*ktn), sizeof(*ktn));
    if (ev(!ktn))
        return merr(ENOMEM);

    memset(ktn, 0, sizeof(*ktn));

    ktn->ktn_wq = alloc_workqueue("hse_ctxn_reaper", 0, 1, 1);
    if (ev(!ktn->ktn_wq)) {
        free(ktn);
        return merr(ENOMEM);
    }

    atomic_set(&ktn->ktn_tseqno_head, 0);
    atomic_set(&ktn->ktn_tseqno_tail, 0);
    atomic_set(&ktn->ktn_reading, 0);
    ktn->ktn_queued = false;
    ktn->ktn_txn_timeout = txn_timeout_ms;
    ktn->txn_wkth_delay = msecs_to_jiffies(delay_msecs);
    INIT_DELAYED_WORK(&ktn->ktn_dwork, kvdb_ctxn_reaper);

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

    free(ktn);
}

atomic_ulong *
kvdb_ctxn_set_tseqnop_get(struct kvdb_ctxn_set *handle)
{
    struct kvdb_ctxn_set_impl *kcs = kvdb_ctxn_set_h2r(handle);

    return &kcs->ktn_tseqno_head;
}

void
kvdb_ctxn_set_tseqno_init(struct kvdb_ctxn_set *handle, uint64_t kvdb_seqno)
{
    struct kvdb_ctxn_set_impl *kcs = kvdb_ctxn_set_h2r(handle);

    atomic_set(&kcs->ktn_tseqno_head, kvdb_seqno);
    atomic_set(&kcs->ktn_tseqno_tail, kvdb_seqno);
}

struct kvdb_ctxn_bind *
kvdb_ctxn_cursor_bind(struct kvdb_ctxn *handle)
{
    struct kvdb_ctxn_impl *ctxn = kvdb_ctxn_h2r(handle);
    struct kvdb_ctxn_bind *bind;

    bind = &ctxn->ctxn_bind;
    if (bind->b_ctxn)
        kvdb_ctxn_bind_getref(bind);

    return bind;
}

void
kvdb_ctxn_cursor_unbind(struct kvdb_ctxn_bind *bind)
{
    bool x = !!bind->b_ctxn;

    if (x)
        kvdb_ctxn_bind_putref(bind);
}

merr_t
kvdb_ctxn_trylock_read(struct kvdb_ctxn *handle, uintptr_t *seqref, uint64_t *view_seqno)
{
    struct kvdb_ctxn_impl *ctxn;
    merr_t                 err;

    assert(handle);

    ctxn = kvdb_ctxn_h2r(handle);

    err = kvdb_ctxn_trylock_impl(ctxn);
    if (err)
        return err;

    *view_seqno = ctxn->ctxn_view_seqno;
    *seqref = ctxn->ctxn_seqref;

    return 0;
}

merr_t
kvdb_ctxn_trylock_write(
    struct kvdb_ctxn *handle,
    uintptr_t *       seqref,
    uint64_t *        view_seqno,
    int64_t          *cookie,
    bool              is_ptomb,
    uint64_t          pfxhash,
    uint64_t          hash)
{
    struct kvdb_ctxn_impl *ctxn;
    merr_t                 err;

    assert(handle);

    ctxn = kvdb_ctxn_h2r(handle);

    err = kvdb_ctxn_trylock_impl(ctxn);
    if (err)
        return err;

    if (HSE_UNLIKELY(!ctxn->ctxn_can_insert)) {
        err = wal_txn_begin(ctxn->ctxn_wal, ctxn->ctxn_view_seqno, &ctxn->ctxn_wal_cookie);
        if (err)
            goto errout;

        err = kvdb_ctxn_enable_inserts(ctxn);
        if (err)
            goto errout;
    }

    if (pfxhash) {
        struct kvdb_ctxn_pfxlock *pl = ctxn->ctxn_pfxlock_handle;

        err = is_ptomb ? kvdb_ctxn_pfxlock_excl(pl, pfxhash) :
                         kvdb_ctxn_pfxlock_shared(pl, pfxhash);
        if (err)
            goto errout;
    }

    if (HSE_LIKELY(!is_ptomb)) {
        err = kvdb_keylock_lock(
            ctxn->ctxn_kvdb_keylock, ctxn->ctxn_locks_handle, hash, ctxn->ctxn_view_seqno);

        if (err)
            goto errout;
    }

    if (ctxn->ctxn_bind.b_ctxn)
        kvdb_ctxn_bind_invalidate(&ctxn->ctxn_bind);

    *view_seqno = ctxn->ctxn_view_seqno;
    *seqref = ctxn->ctxn_seqref;
    *cookie = ctxn->ctxn_wal_cookie;

  errout:
    if (err)
        kvdb_ctxn_unlock_impl(ctxn);

    return err;
}

void
kvdb_ctxn_unlock(struct kvdb_ctxn *handle)
{
    assert(handle);
    kvdb_ctxn_unlock_impl(kvdb_ctxn_h2r(handle));
}

#if HSE_MOCKING
#include "kvdb_ctxn_ut_impl.i"
#endif /* HSE_MOCKING */
