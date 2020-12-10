/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/assert.h>
#include <hse_util/alloc.h>
#include <hse_util/atomic.h>
#include <hse_util/spinlock.h>
#include <hse_util/compiler.h>
#include <hse_util/slab.h>
#include <hse_util/keylock.h>
#include <hse_util/platform.h>
#include <hse_util/rcu.h>
#include <hse_util/page.h>
#include <hse_util/cursor_heap.h>

#include <hse/kvdb_perfc.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_ctxn.h>

#include <3rdparty/rbtree.h>

#define MTF_MOCK_IMPL_kvdb_keylock

#include "kvdb_keylock.h"

#define KVDB_DLOCK_MAX 4 /* Must be power-of-2 */
#define KVDB_LOCKS_SZ (16 * 1024 - SMP_CACHE_BYTES)

struct kvdb_keylock {
};

#define kvdb_keylock_h2r(handle) container_of(handle, struct kvdb_keylock_impl, kl_handle)

/**
 * struct kvdb_dlock - per-cpu deferred lock list head
 * @kd_lock:    list lock
 * @kd_list:    list of deferred locks, sorted by minimum view seqno
 * @kd_mvs:     most recently expired minimum view seqno
 */
struct kvdb_dlock {
    struct mutex     kd_lock __aligned(SMP_CACHE_BYTES * 2);
    struct list_head kd_list;
    volatile u64     kd_mvs;
};

/**
 * struct kvdb_keylock_impl - manages key locks across transactions
 * @kl_handle:             handle for klock struct
 * @kl_dlockv:             vector of deferred lock objects
 * @kl_num_tables:         number of keylock tables
 * @kl_num_entries:        max number of entries (across all tables)
 * @kl_entries_per_txn:    number of entries that can be locked by a txn
 * @kl_perfc_set:
 * @kl_keylock:            vector of ptrs to keylock objects
 */
struct kvdb_keylock_impl {
    struct kvdb_keylock kl_handle;
    struct kvdb_dlock   kl_dlockv[KVDB_DLOCK_MAX];

    u64              kl_num_entries;
    u32              kl_entries_per_txn;
    u32              kl_num_tables;
    struct perfc_set kl_perfc_set;
    struct keylock * kl_keylock[];
};

struct kvdb_ctxn_locks {
};

#define kvdb_ctxn_locks_h2r(handle) \
    container_of(handle, struct kvdb_ctxn_locks_impl, ctxn_locks_handle)

/**
 * struct ctxn_locks_tree_entry -
 * @lte_node:
 * @lte_hash:
 * @lte_tindex:     index into kl_keylock[]
 * @lte_inherited:
 * @lte_kfree:      node not from entryv[], must be freed via free
 */
struct ctxn_locks_tree_entry {
    struct rb_node lte_node;
    u64            lte_hash : 48;
    u64            lte_tindex : 10;
    u64            lte_inherited : 1;
    u64            lte_kfree : 1;
};

#define LTE_TINDEX_MAX (1u << 10)

/**
 * struct kvdb_ctxn_locks - container for all the write locks of a transaction.
 * @ctxn_locks_handle:       handle for kvdb_ctxn_locks struct
 * @ctxn_locks_link:         element to link onto the deferred_locks list
 * @ctxn_locks_magic:        used to detect use-after-free
 * @ctxn_locks_end_seqno:    end seqno of the transaction
 * @ctxn_locks_tree:         root of RB tree containing write locks
 * @ctxn_locks_cnt:          number of write locks in this container
 * @ctxn_locks_entryc:       current number of entries from entryv[] in use
 * @ctxn_locks_entrymax:     max number of entries in entryv[]
 * @ctxn_locks_entryv:       small entry cache
 */
struct kvdb_ctxn_locks_impl {
    struct kvdb_ctxn_locks ctxn_locks_handle;
    struct list_head       ctxn_locks_link;
    volatile u64           ctxn_locks_end_seqno;
    uintptr_t              ctxn_locks_magic;

    __aligned(SMP_CACHE_BYTES) struct rb_root ctxn_locks_tree;
    u32 ctxn_locks_cnt;
    u32 ctxn_locks_entryc;
    u32 ctxn_locks_entrymax;

    struct ctxn_locks_tree_entry ctxn_locks_entryv[];
};

_Static_assert(sizeof(struct kvdb_ctxn_locks_impl) < KVDB_LOCKS_SZ, "KVDB_LOCKS_SZ too small");

static struct kmem_cache *kvdb_ctxn_locks_cache;
static struct kmem_cache *kvdb_ctxn_entry_cache;
static atomic_t           kvdb_ctxn_locks_init_ref;

merr_t
kvdb_keylock_create(struct kvdb_keylock **handle_out, u32 num_tables, u64 num_entries)
{
    struct kvdb_keylock_impl *klock;
    merr_t                    err;
    size_t                    sz;
    int                       i;

    *handle_out = NULL;

    num_tables = clamp_t(u32, num_tables, 1, LTE_TINDEX_MAX);

    sz = sizeof(*klock);
    sz += num_tables * sizeof(struct keylock *);
    sz = ALIGN(sz, 1024);

    klock = alloc_aligned(sz, 1024);
    if (ev(!klock))
        return merr(ENOMEM);

    memset(klock, 0, sz);
    num_entries = clamp_t(u64, num_entries, 1, KLE_PLEN_MAX);
    klock->kl_num_entries = num_tables * num_entries;
    klock->kl_entries_per_txn = klock->kl_num_entries / 4;
    klock->kl_num_tables = num_tables;
    memset(&klock->kl_perfc_set, 0, sizeof(klock->kl_perfc_set));

    for (i = 0; i < KVDB_DLOCK_MAX; ++i) {
        mutex_init(&klock->kl_dlockv[i].kd_lock);
        INIT_LIST_HEAD(&klock->kl_dlockv[i].kd_list);
        klock->kl_dlockv[i].kd_mvs = 0;
    }

    for (i = 0; i < num_tables; i++) {
        err = keylock_create(num_entries, kvdb_ctxn_lock_inherit, &klock->kl_keylock[i]);
        if (ev(err)) {
            klock->kl_num_tables = i;
            kvdb_keylock_destroy(&klock->kl_handle);
            return err;
        }
    }

    *handle_out = &klock->kl_handle;

    return 0;
}

void
kvdb_keylock_destroy(struct kvdb_keylock *handle)
{
    struct kvdb_keylock_impl *   klock;
    struct kvdb_ctxn_locks_impl *curr;
    struct kvdb_ctxn_locks_impl *tmp;
    int                          i;

    if (ev(!handle))
        return;

    klock = kvdb_keylock_h2r(handle);

    for (i = 0; i < KVDB_DLOCK_MAX; ++i) {
        struct kvdb_dlock *dlock = klock->kl_dlockv + i;
        struct list_head   expired;

        INIT_LIST_HEAD(&expired);

        mutex_lock(&dlock->kd_lock);
        list_splice(&dlock->kd_list, &expired);
        mutex_unlock(&dlock->kd_lock);

        list_for_each_entry_safe (curr, tmp, &expired, ctxn_locks_link) {
            struct kvdb_ctxn_locks *locks;

            locks = &curr->ctxn_locks_handle;
            kvdb_keylock_release_locks(handle, locks);
            kvdb_ctxn_locks_destroy(locks);
        }

        mutex_destroy(&dlock->kd_lock);
    }

    for (i = 0; i < klock->kl_num_tables; i++)
        keylock_destroy(klock->kl_keylock[i]);

    free_aligned(klock);
}

void
kvdb_keylock_perfc_init(struct kvdb_keylock *handle, struct perfc_set *perfc_set)
{
    struct perfc_set *dst = &kvdb_keylock_h2r(handle)->kl_perfc_set;

    memcpy(dst, perfc_set, sizeof(*dst));
}

void
kvdb_keylock_list_lock(struct kvdb_keylock *handle, void **cookiep)
{
    struct kvdb_keylock_impl *klock = kvdb_keylock_h2r(handle);
    struct kvdb_dlock *       dlock = klock->kl_dlockv;

    dlock += raw_smp_processor_id() % KVDB_DLOCK_MAX;

    mutex_lock(&dlock->kd_lock);
    *cookiep = dlock;
}

void
kvdb_keylock_list_unlock(void *cookie)
{
    struct kvdb_dlock *dlock = cookie;

    assert(dlock);

    mutex_unlock(&dlock->kd_lock);
}

void
kvdb_keylock_queue_locks(struct kvdb_ctxn_locks *handle, u64 end_seqno, void *cookie)
{
    struct kvdb_ctxn_locks_impl *locks = kvdb_ctxn_locks_h2r(handle);
    struct kvdb_dlock *          dlock = cookie;

    assert(dlock);

    assert(kvdb_ctxn_locks_count(handle));

    locks->ctxn_locks_end_seqno = end_seqno;

    list_add_tail(&locks->ctxn_locks_link, &dlock->kd_list);
}

void
kvdb_keylock_insert_locks(struct kvdb_ctxn_locks *handle, u64 end_seqno, void *cookie)
{
    struct kvdb_ctxn_locks_impl *locks = kvdb_ctxn_locks_h2r(handle);
    struct kvdb_dlock *          dlock = cookie;
    struct kvdb_ctxn_locks_impl *elem;

    assert(dlock);

    assert(kvdb_ctxn_locks_count(handle));

    locks->ctxn_locks_end_seqno = end_seqno;

    /* The correct position is more likely toward the end of the list, so
     * traverse in reverse.
     */
    list_for_each_entry_reverse (elem, &dlock->kd_list, ctxn_locks_link) {
        if (end_seqno > elem->ctxn_locks_end_seqno)
            break;
    }

    list_add(&locks->ctxn_locks_link, &elem->ctxn_locks_link);
}

void
kvdb_keylock_prune_own_locks(struct kvdb_keylock *kl_handle, struct kvdb_ctxn_locks *locks_handle)
{
    struct kvdb_keylock_impl *    klock;
    struct kvdb_ctxn_locks_impl * locks;
    struct ctxn_locks_tree_entry *entry;
    struct ctxn_locks_tree_entry *next;
    struct rb_root *              tree;
    void *                        freeme;
    u64                           cnt;

    klock = kvdb_keylock_h2r(kl_handle);
    locks = kvdb_ctxn_locks_h2r(locks_handle);

    tree = &locks->ctxn_locks_tree;
    cnt = locks->ctxn_locks_cnt;
    freeme = NULL;

    rbtree_postorder_for_each_entry_safe(entry, next, tree, lte_node)
    {
        u32 idx = entry->lte_tindex;

        if (entry->lte_inherited)
            continue;

        keylock_unlock(
            klock->kl_keylock[idx], entry->lte_hash, (struct keylock_cb_rock *)locks_handle);

        rb_erase(&entry->lte_node, tree);

        if (entry->lte_kfree) {
            *(void **)entry = freeme;
            freeme = entry;
        }

        assert(cnt > 0);
        cnt--;
    }

    while (freeme) {
        entry = freeme;
        freeme = *(void **)entry;
        kmem_cache_free(kvdb_ctxn_entry_cache, entry);
    }

    locks->ctxn_locks_cnt = cnt;
}

/**
 * kvdb_keylock_expire() - Free all write lock sets whose window has ended
 *
 * @handle:         handle to the KVDB keylock
 * @min_view_sn:    the new minimum view sequence number for any active txn
 */
void
kvdb_keylock_expire(struct kvdb_keylock *handle, u64 min_view_sn)
{
    struct kvdb_ctxn_locks_impl *curr, *tmp;
    struct kvdb_keylock_impl *   klock;
    struct list_head             expired;
    u32                          mask;
    int                          idx;

    klock = kvdb_keylock_h2r(handle);

    /* Start with the dlock onto which we most likely queued
     * a lock set.
     */
    idx = raw_smp_processor_id() % KVDB_DLOCK_MAX;
    mask = (1u << KVDB_DLOCK_MAX) - 1;
    INIT_LIST_HEAD(&expired);

    /* Continously cycle around the wheel of dlocks looking for expired
     * lock sets until we have either visited all the dlocks or find
     * cause to stop looking.
     */
    while (mask) {
        struct kvdb_dlock *dlock = klock->kl_dlockv + idx;

        if (!(mask & (1u << idx)))
            goto next;

        if (dlock->kd_mvs >= min_view_sn)
            return;

        if (!mutex_trylock(&dlock->kd_lock))
            goto next;

        if (min_view_sn > dlock->kd_mvs) {
            dlock->kd_mvs = min_view_sn;

            list_for_each_entry_safe (curr, tmp, &dlock->kd_list, ctxn_locks_link) {

                if (curr->ctxn_locks_end_seqno >= min_view_sn)
                    break;

                /* Allow all locks in this set to be inherited.
                 */
                curr->ctxn_locks_end_seqno = 0;

                list_del(&curr->ctxn_locks_link);
                list_add_tail(&curr->ctxn_locks_link, &expired);
            }
        }
        mutex_unlock(&dlock->kd_lock);

        list_for_each_entry_safe (curr, tmp, &expired, ctxn_locks_link) {
            struct kvdb_ctxn_locks *locks;

            locks = &curr->ctxn_locks_handle;
            kvdb_keylock_release_locks(handle, locks);
            kvdb_ctxn_locks_destroy(locks);
        }

        INIT_LIST_HEAD(&expired);
        mask &= ~(1u << idx);

    next:
        idx = (idx + 1) % KVDB_DLOCK_MAX;
    }
}

/**
 * kvdb_keylock_release_locks() - unlock all the locks acquired by a
 * transaction and destroy the associated tree.
 *
 * This function is called with no locks held, but inside of an RCU
 * read-side critical section.
 *
 * @kl_handle: KVDB keylock handle
 * @locks_handle: transaction locks handle
 */
void
kvdb_keylock_release_locks(struct kvdb_keylock *kl_handle, struct kvdb_ctxn_locks *locks_handle)
{
    struct kvdb_keylock_impl *    klock;
    struct kvdb_ctxn_locks_impl * locks;
    struct ctxn_locks_tree_entry *entry;
    struct ctxn_locks_tree_entry *next;
    struct rb_root *              tree;
    void *                        freeme;

    int cnt __maybe_unused;

    klock = kvdb_keylock_h2r(kl_handle);
    locks = kvdb_ctxn_locks_h2r(locks_handle);

    tree = &locks->ctxn_locks_tree;
    cnt = locks->ctxn_locks_cnt;
    freeme = NULL;

    rbtree_postorder_for_each_entry_safe(entry, next, tree, lte_node)
    {
        u32 idx = entry->lte_tindex;

        assert(cnt-- > 0);

        keylock_unlock(
            klock->kl_keylock[idx], entry->lte_hash, (struct keylock_cb_rock *)locks_handle);

        if (entry->lte_kfree) {
            *(void **)entry = freeme;
            freeme = entry;
        }
    }

    while (freeme) {
        entry = freeme;
        freeme = *(void **)entry;
        kmem_cache_free(kvdb_ctxn_entry_cache, entry);
    }

    assert(cnt == 0);
    locks->ctxn_locks_cnt = 0;
    locks->ctxn_locks_entryc = 0;
    locks->ctxn_locks_tree = RB_ROOT;
}

/**
 * kvdb_keylock_lock() - lock an entry in the KVDB keylock and add it to the
 * transaction's container of acquired write locks.
 *
 * @hklock:         handle to the KVDB keylock
 * @hlocks:         handle to the KVDB ctxn locks
 * @hash:           hash of the key
 * @start_seq:      starting sequence number of the entity requesting the lock
 */
merr_t
kvdb_keylock_lock(
    struct kvdb_keylock *   hklock,
    struct kvdb_ctxn_locks *hlocks,
    u64                     hash,
    u64                     start_seq)
{
    struct kvdb_keylock_impl *    klock;
    struct kvdb_ctxn_locks_impl * ctxn_locks;
    struct rb_node **             link;
    struct rb_node *              parent;
    struct ctxn_locks_tree_entry *entry;
    merr_t                        err;
    u32                           tindex;
    u32                           entryc;
    bool                          inherited;

    assert(hash);

    klock = kvdb_keylock_h2r(hklock);
    ctxn_locks = kvdb_ctxn_locks_h2r(hlocks);

    hash = (hash << 16) >> 16;
    tindex = hash % klock->kl_num_tables;

    link = &ctxn_locks->ctxn_locks_tree.rb_node;
    parent = NULL;
    entry = NULL;

    /* [HSE_REVISIT] The write lock container is currently an RB tree. A
     * hash table might be better.
     */

    /* Traverse the write lock container to check if the lock exists. */
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, struct ctxn_locks_tree_entry, lte_node);

        if (hash < entry->lte_hash)
            link = &(*link)->rb_left;
        else if (hash > entry->lte_hash)
            link = &(*link)->rb_right;
        else
            break;
    }

    /* The lock was previously acquired by this transaction. */
    if (*link) {
        assert(
            keylock_lock(
                klock->kl_keylock[tindex],
                hash,
                start_seq,
                (struct keylock_cb_rock *)hlocks,
                &inherited) == 0);
        assert(entry->lte_hash == hash);
        assert(inherited == false);

        return 0;
    }

    /*
     * [HSE_REVISIT]
     * The transaction has exceeded the limit on the max number of locks
     * it can acquire.
     */
    if (ev(ctxn_locks->ctxn_locks_cnt > klock->kl_entries_per_txn))
        return merr(E2BIG);

    /* Pre-allocate space for the entry since if we inherit ownership we
     * cannot fail.  We first try to allocate from the ctxn_locks entry
     * cache, and fall back on kmalloc if the cache is empty.
     */
    entryc = ctxn_locks->ctxn_locks_entryc;

    if (likely(entryc < ctxn_locks->ctxn_locks_entrymax)) {
        entry = ctxn_locks->ctxn_locks_entryv + entryc;
        ctxn_locks->ctxn_locks_entryc++;
        entry->lte_kfree = false;
    } else {
        entry = kmem_cache_alloc(kvdb_ctxn_entry_cache);
        if (ev(!entry))
            return merr(ENOMEM);

        entry->lte_kfree = true;
    }

    /* Attempt to acquire the lock since it wasn't found in the
     * transaction's container of write locks.
     */
    err = keylock_lock(
        klock->kl_keylock[tindex], hash, start_seq, (struct keylock_cb_rock *)hlocks, &inherited);
    if (!err) {
        perfc_inc(&klock->kl_perfc_set, PERFC_RA_CTXNOP_LOCK_DONE);

        /* The lock was acquired in this attempt. Add it to the
         * container of write locks.
         */
        entry->lte_hash = hash;
        entry->lte_tindex = tindex;
        entry->lte_inherited = inherited;

        rb_link_node(&entry->lte_node, parent, link);
        rb_insert_color(&entry->lte_node, &ctxn_locks->ctxn_locks_tree);

        ctxn_locks->ctxn_locks_cnt++;
    } else {
        perfc_inc(&klock->kl_perfc_set, PERFC_RA_CTXNOP_LOCK_FAILED);

        if (entry->lte_kfree)
            kmem_cache_free(kvdb_ctxn_entry_cache, entry);
        else
            ctxn_locks->ctxn_locks_entryc--;
    }

    return err;
}

static void
kvdb_ctxn_locks_ctor(void *arg)
{
    struct kvdb_ctxn_locks_impl *impl = arg;
    size_t                       implsz;

    implsz = offsetof(struct kvdb_ctxn_locks_impl, ctxn_locks_entryv);
    implsz = ALIGN(implsz, 32);
    assert(sizeof(*impl) >= implsz);

    memset(impl, 0, implsz);
    impl->ctxn_locks_entrymax = KVDB_LOCKS_SZ - implsz;
    impl->ctxn_locks_entrymax /= sizeof(impl->ctxn_locks_entryv[0]);
    impl->ctxn_locks_magic = ~(uintptr_t)impl;
}

merr_t
kvdb_ctxn_locks_create(struct kvdb_ctxn_locks **locksp)
{
    struct kvdb_ctxn_locks_impl *impl;

    impl = kmem_cache_alloc(kvdb_ctxn_locks_cache);
    if (ev(!impl)) {
        *locksp = NULL;
        return merr(ENOMEM);
    }

    assert(impl->ctxn_locks_magic == ~(uintptr_t)impl);

    /* impl is initialized by kvdb_ctxn_locks_ctor().
     */
    impl->ctxn_locks_magic = (uintptr_t)impl;
    impl->ctxn_locks_end_seqno = U64_MAX;
    impl->ctxn_locks_tree = RB_ROOT;
    impl->ctxn_locks_entryc = 0;

    *locksp = &impl->ctxn_locks_handle;
    return 0;
}

void
kvdb_ctxn_locks_destroy(struct kvdb_ctxn_locks *handle)
{
    struct kvdb_ctxn_locks_impl *impl;

    impl = kvdb_ctxn_locks_h2r(handle);

    assert(impl->ctxn_locks_magic == (uintptr_t)impl);
    assert(impl->ctxn_locks_cnt == 0);

    impl->ctxn_locks_magic = ~(uintptr_t)impl;

    kmem_cache_free(kvdb_ctxn_locks_cache, impl);
}

u64
kvdb_ctxn_locks_count(struct kvdb_ctxn_locks *locks_handle)
{
    return kvdb_ctxn_locks_h2r(locks_handle)->ctxn_locks_cnt;
}

u64
kvdb_ctxn_locks_end_seqno(struct kvdb_ctxn_locks *handle)
{
    struct kvdb_ctxn_locks_impl *impl;

    impl = kvdb_ctxn_locks_h2r(handle);

    assert(impl->ctxn_locks_magic == (uintptr_t)impl);

    return impl->ctxn_locks_end_seqno;
}

void
kvdb_ctxn_locks_init(void)
{
    struct ctxn_locks_tree_entry *entry;
    struct kmem_cache *           zone;

    if (atomic_inc_return(&kvdb_ctxn_locks_init_ref) > 1)
        return;

    zone = kmem_cache_create(
        "kvdb_ctxn_locks", KVDB_LOCKS_SZ, 0, SLAB_HWCACHE_ALIGN, kvdb_ctxn_locks_ctor);
    kvdb_ctxn_locks_cache = zone;
    assert(zone); /* [HSE_REVISIT] */

    zone = kmem_cache_create("kvdb_ctxn_entry", sizeof(*entry), 0, 0, NULL);
    kvdb_ctxn_entry_cache = zone;
    assert(zone); /* [HSE_REVISIT] */
}

void
kvdb_ctxn_locks_fini(void)
{
    if (atomic_dec_return(&kvdb_ctxn_locks_init_ref) > 0)
        return;

    kmem_cache_destroy(kvdb_ctxn_locks_cache);
    kvdb_ctxn_locks_cache = NULL;

    kmem_cache_destroy(kvdb_ctxn_entry_cache);
    kvdb_ctxn_entry_cache = NULL;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "kvdb_keylock_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
