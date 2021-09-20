/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/assert.h>
#include <hse_util/alloc.h>
#include <hse_util/atomic.h>
#include <hse_util/spinlock.h>
#include <hse_util/mutex.h>
#include <hse_util/compiler.h>
#include <hse_util/slab.h>
#include <hse_util/keylock.h>
#include <hse_util/rcu.h>
#include <hse_util/page.h>
#include <hse_util/vlb.h>
#include <hse_util/xrand.h>
#include <hse_util/cursor_heap.h>
#include <hse_util/event_counter.h>

#include <hse/kvdb_perfc.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_ctxn.h>

#include <rbtree.h>

#define MTF_MOCK_IMPL_kvdb_keylock

#include "kvdb_keylock.h"

/* clang-format off */

#define KVDB_DLOCK_MAX              (4) /* Must be power-of-2 */
#define CTXN_LOCKS_IMPL_CACHE_SZ    (1024 + SMP_CACHE_BYTES * 2)
#define CTXN_LOCKS_SLAB_CACHE_SZ    (16 * 1024 - SMP_CACHE_BYTES * 2)

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
    struct mutex     kd_lock  HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct list_head kd_list;
    volatile u64     kd_mvs   HSE_ALIGNED(SMP_CACHE_BYTES);
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
 * struct ctxn_locks_entry -
 * @lte_next:       next entry in ctxn_locks_entries list
 * @lte_hash:
 * @lte_tindex:     index into kl_keylock[]
 * @lte_inherited:
 * @lte_node:       rb tree linkage in ctxn_locks_treev[]
 */
struct ctxn_locks_entry {
    void           *lte_next;
    u64             lte_hash;
    u32             lte_tindex;
    bool            lte_inherited;
    struct rb_node  lte_node;
};

/**
 * @cls_entryc:     current number of entries from entryv[] in use
 * @cls_entrymax:   max number of entries in entryv[]
 * @cls_next:       ptr to next slab in list
 * @cls_entryv:     small entry cache
 */
struct ctxn_locks_slab {
    uint                     cls_entryc;
    uint                     cls_entrymax;
    struct ctxn_locks_slab  *cls_next;
    struct ctxn_locks_entry  cls_entryv[];
};

/**
 * struct kvdb_ctxn_locks - container for all the write locks of a transaction.
 * @ctxn_locks_handle:       handle for kvdb_ctxn_locks struct
 * @ctxn_locks_link:         element to link onto the deferred_locks list
 * @ctxn_locks_end_seqno:    end seqno of the transaction
 * @ctxn_locks_magic:        used to detect use-after-free
 * @ctxn_locks_cnt:          number of write locks in this container
 * @ctxn_locks_entries:      linked list of all entries sorted by slab
 * @ctxn_locks_slab:         entry slab from which to alloc new entries
 * @ctxn_locks_treev:        root of RB tree containing write locks
 * @ctxn_locks_slab0:        slab embedded into ctxn_locks allocation
 *
 * All entries in all RB trees are on a singly-linked list (ctxn_locks_entries)
 * sorted by slab such that we can simple walk the list to free all the entries
 * (vs walking each RB tree which would likely thrash the TLB).
 */
struct kvdb_ctxn_locks_impl {
    struct kvdb_ctxn_locks   ctxn_locks_handle;
    struct list_head         ctxn_locks_link;
    volatile u64             ctxn_locks_end_seqno;
    uint32_t                 ctxn_locks_desc;
    uintptr_t                ctxn_locks_magic;

    struct rb_root           ctxn_locks_treev[16];
    u32                      ctxn_locks_cnt;
    struct ctxn_locks_entry *ctxn_locks_entries;
    struct ctxn_locks_slab  *ctxn_locks_slab;
    struct ctxn_locks_slab   ctxn_locks_slab0[];
};

static_assert(sizeof(struct kvdb_ctxn_locks_impl) < CTXN_LOCKS_IMPL_CACHE_SZ / 4,
              "CTXN_LOCKS_IMPL_CACHE_SZ too small");

static_assert(sizeof(struct ctxn_locks_slab) < CTXN_LOCKS_IMPL_CACHE_SZ / 16,
              "CTXN_LOCKS_SLAB_CACHE_SZ too small");

static struct kmem_cache *ctxn_locks_impl_cache  HSE_READ_MOSTLY;
static struct kmem_cache *ctxn_locks_slab_cache  HSE_READ_MOSTLY;

/* clang-format on */

merr_t
kvdb_keylock_create(struct kvdb_keylock **handle_out, u32 num_tables)
{
    struct kvdb_keylock_impl *klock;
    merr_t                    err;
    size_t                    sz;
    uint                      num_entries;
    int                       i;

    *handle_out = NULL;

    num_tables = clamp_t(u32, num_tables, 1, 8192);

    sz = sizeof(*klock);
    sz += num_tables * sizeof(struct keylock *);
    sz = ALIGN(sz, alignof(*klock));

    klock = alloc_aligned(sz, alignof(*klock));
    if (ev(!klock))
        return merr(ENOMEM);

    memset(klock, 0, sz);
    num_entries = KLE_PSL_MAX;
    klock->kl_num_entries = num_tables * num_entries;
    klock->kl_entries_per_txn = klock->kl_num_entries / 4;
    klock->kl_num_tables = num_tables;
    memset(&klock->kl_perfc_set, 0, sizeof(klock->kl_perfc_set));

    for (i = 0; i < KVDB_DLOCK_MAX; ++i) {
        mutex_init(&klock->kl_dlockv[i].kd_lock);
        INIT_LIST_HEAD(&klock->kl_dlockv[i].kd_list);
        klock->kl_dlockv[i].kd_mvs = UINT64_MAX;
    }

    for (i = 0; i < num_tables; i++) {
        err = keylock_create(kvdb_ctxn_lock_inherit, &klock->kl_keylock[i]);
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

        list_for_each_entry_safe(curr, tmp, &expired, ctxn_locks_link) {
            struct kvdb_ctxn_locks *locks;

            locks = &curr->ctxn_locks_handle;
            kvdb_keylock_release_locks(handle, locks);
            kvdb_ctxn_locks_destroy(locks);
            ev(1);
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

    dlock += hse_getcpu(NULL) % KVDB_DLOCK_MAX;

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
kvdb_keylock_enqueue_locks(struct kvdb_ctxn_locks *handle, u64 end_seqno, void *cookie)
{
    struct kvdb_ctxn_locks_impl *locks = kvdb_ctxn_locks_h2r(handle);
    struct kvdb_dlock *          dlock = cookie;
    struct kvdb_ctxn_locks_impl *elem;

    assert(dlock && locks->ctxn_locks_cnt > 0);

    locks->ctxn_locks_end_seqno = end_seqno;

    /* The correct position is more likely toward the end of the list, so
     * traverse in reverse.
     */
    list_for_each_entry_reverse(elem, &dlock->kd_list, ctxn_locks_link) {
        if (end_seqno > elem->ctxn_locks_end_seqno) {
            list_add(&locks->ctxn_locks_link, &elem->ctxn_locks_link);
            return;
        }
    }

    /* Should only be here if the list is empty, it is a grievous error
     * if caller is trying insert a dlock out of view seqno order.
     */
    assert(list_empty(&dlock->kd_list));

    dlock->kd_mvs = end_seqno;
    list_add(&locks->ctxn_locks_link, &dlock->kd_list);
}

void
kvdb_keylock_prune_own_locks(struct kvdb_keylock *kl_handle, struct kvdb_ctxn_locks *locks_handle)
{
    struct kvdb_ctxn_locks_impl *locks = kvdb_ctxn_locks_h2r(locks_handle);
    struct keylock **keylockv = kvdb_keylock_h2r(kl_handle)->kl_keylock;
    struct ctxn_locks_entry *inherited, *entry;
    int64_t cnt;
    uint32_t desc;
    int i;

    desc = locks->ctxn_locks_desc;
    cnt = locks->ctxn_locks_cnt;
    inherited = NULL;

    while (( entry = locks->ctxn_locks_entries )) {
        locks->ctxn_locks_entries = entry->lte_next;

        if (entry->lte_inherited) {
            entry->lte_next = inherited;
            inherited = entry;
            continue;
        }

        keylock_unlock(keylockv[entry->lte_tindex], entry->lte_hash, desc);
        cnt--;
    }

    assert(cnt >= 0);

    if (cnt == 0) {
        struct ctxn_locks_slab *slab;

        while ((slab = locks->ctxn_locks_slab) && slab->cls_next) {
            locks->ctxn_locks_slab = slab->cls_next;
            kmem_cache_free(ctxn_locks_slab_cache, slab);
        }

        assert(slab->cls_entrymax > 0);
        slab->cls_entryc = 0;

        for (i = 0; i < NELEM(locks->ctxn_locks_treev); ++i)
            locks->ctxn_locks_treev[i] = RB_ROOT;
    }

    locks->ctxn_locks_entries = inherited;
    locks->ctxn_locks_cnt = cnt;
}

/**
 * kvdb_keylock_expire() - Free all write lock sets whose window has ended
 *
 * @handle:         handle to the KVDB keylock
 * @min_view_sn:    the new minimum view sequence number for any active txn
 */
void
kvdb_keylock_expire(struct kvdb_keylock *handle, u64 min_view_sn, u64 spin)
{
    struct kvdb_keylock_impl *klock = kvdb_keylock_h2r(handle);
    uint mask, idx;

    /* Start with the dlock onto which we most likely queued a lock set.
     */
    idx = hse_getcpu(NULL) % KVDB_DLOCK_MAX;
    mask = (1u << KVDB_DLOCK_MAX) - 1;

    /* Continuously cycle around the wheel of dlocks looking for expired
     * lock sets until none have an end seqno less than min_view_sn.
     */
    while (mask && spin--) {
        struct kvdb_dlock *dlock = klock->kl_dlockv + idx;
        struct kvdb_ctxn_locks_impl *curr, *tmp;
        struct list_head expired;

        if (!(mask & (1u << idx)) || dlock->kd_mvs >= min_view_sn) {
            mask &= ~(1u << idx);
            idx = (idx + 1) % KVDB_DLOCK_MAX;
            continue;
        }

        if (!mutex_trylock(&dlock->kd_lock)) {
            idx = (idx + 1) % KVDB_DLOCK_MAX;
            continue;
        }

        INIT_LIST_HEAD(&expired);

        if (min_view_sn > dlock->kd_mvs) {
            int batchmax = 16;

            list_for_each_entry_safe(curr, tmp, &dlock->kd_list, ctxn_locks_link) {
                if (curr->ctxn_locks_end_seqno >= min_view_sn) {
                    dlock->kd_mvs = curr->ctxn_locks_end_seqno;
                    break;
                }

                if (--batchmax < 0)
                    break;

                /* Allow all locks in this set to be inherited.
                 */
                curr->ctxn_locks_end_seqno = 0;

                list_del(&curr->ctxn_locks_link);
                list_add_tail(&curr->ctxn_locks_link, &expired);
            }

            if (list_empty(&dlock->kd_list)) {
                dlock->kd_mvs = UINT64_MAX;
                mask &= ~(1u << idx);
            }
        }
        mutex_unlock(&dlock->kd_lock);

        list_for_each_entry_safe(curr, tmp, &expired, ctxn_locks_link) {
            struct kvdb_ctxn_locks *locks;

            locks = &curr->ctxn_locks_handle;
            kvdb_keylock_release_locks(handle, locks);
            kvdb_ctxn_locks_destroy(locks);
        }
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
    struct kvdb_ctxn_locks_impl *locks = kvdb_ctxn_locks_h2r(locks_handle);
    struct ctxn_locks_slab *slab;
    int64_t cnt;
    uint32_t desc;
    int i;

    desc = locks->ctxn_locks_desc;
    cnt = locks->ctxn_locks_cnt;

    if (cnt > 0) {
        struct keylock **keylockv = kvdb_keylock_h2r(kl_handle)->kl_keylock;
        struct ctxn_locks_entry *entry;

        while (( entry = locks->ctxn_locks_entries )) {
            locks->ctxn_locks_entries = entry->lte_next;

            keylock_unlock(keylockv[entry->lte_tindex], entry->lte_hash, desc);
            cnt--;
        }
    }

    assert(cnt == 0);
    locks->ctxn_locks_cnt = 0;

    while ((slab = locks->ctxn_locks_slab) && slab->cls_next) {
        locks->ctxn_locks_slab = slab->cls_next;
        kmem_cache_free(ctxn_locks_slab_cache, slab);
    }

    for (i = 0; i < NELEM(locks->ctxn_locks_treev); ++i)
        locks->ctxn_locks_treev[i] = RB_ROOT;

    assert(slab->cls_entrymax > 0);
    slab->cls_entryc = 0;
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
    struct kvdb_ctxn_locks_impl *locks = kvdb_ctxn_locks_h2r(hlocks);
    struct kvdb_keylock_impl *klock = kvdb_keylock_h2r(hklock);
    struct ctxn_locks_entry *entry;
    struct ctxn_locks_slab *slab;
    struct rb_node **link, *parent;
    struct keylock *keylock;
    struct rb_root *tree;
    bool inherited;
    uint32_t desc;
    u32 tindex;
    merr_t err;

    tindex = hash % klock->kl_num_tables;
    keylock = klock->kl_keylock[tindex];

    desc = locks->ctxn_locks_desc;
    tree = locks->ctxn_locks_treev + (tindex % NELEM(locks->ctxn_locks_treev));
    link = &tree->rb_node;
    parent = NULL;
    entry = NULL;

    /* Traverse the write lock container to check if the lock exists.
     */
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), lte_node);

        if (HSE_UNLIKELY( hash == entry->lte_hash ))
            break;

        link = (hash < entry->lte_hash) ? &parent->rb_left : &parent->rb_right;
    }

    /* The lock was previously acquired by this transaction. */
    if (*link) {
        assert(keylock_lock(keylock, hash, desc, start_seq, &inherited) == 0);
        assert(entry->lte_hash == hash);
        assert(inherited == false);

        return 0;
    }

    /*
     * [HSE_REVISIT]
     * The transaction has exceeded the limit on the max number of locks
     * it can acquire.
     */
    if (ev(locks->ctxn_locks_cnt > klock->kl_entries_per_txn))
        return merr(E2BIG);

    /* Pre-allocate space for the entry since if we inherit ownership we
     * cannot fail.
     */
    slab = locks->ctxn_locks_slab;

    if (HSE_UNLIKELY(slab->cls_entryc >= slab->cls_entrymax)) {
        slab = kmem_cache_alloc(ctxn_locks_slab_cache);
        if (ev(!slab))
            return merr(ENOMEM);

        memset(slab, 0, sizeof(*slab));
        slab->cls_entrymax = CTXN_LOCKS_SLAB_CACHE_SZ - sizeof(*slab);
        slab->cls_entrymax /= sizeof(slab->cls_entryv[0]);
        slab->cls_next = locks->ctxn_locks_slab;
        locks->ctxn_locks_slab = slab;
    }

    entry = slab->cls_entryv + slab->cls_entryc++;

    /* Attempt to acquire the lock since it wasn't found in the
     * transaction's container of write locks.
     */
    err = keylock_lock(keylock, hash, desc, start_seq, &inherited);
    if (!err) {
        locks->ctxn_locks_cnt++;
        entry->lte_next = locks->ctxn_locks_entries;
        locks->ctxn_locks_entries = entry;

        entry->lte_hash = hash;
        entry->lte_tindex = tindex;
        entry->lte_inherited = inherited;

        /* The lock was acquired in this attempt. Add it to the
         * container of write locks.
         */
        rb_link_node(&entry->lte_node, parent, link);
        rb_insert_color(&entry->lte_node, tree);

    } else {
        perfc_inc(&klock->kl_perfc_set, PERFC_RA_CTXNOP_LOCKFAIL);

        slab->cls_entryc--;
    }

    return err;
}

struct kvdb_ctxn_locks *
kvdb_ctxn_locks_desc2locks(uint32_t desc)
{
    return kmem_cache_desc2addr(ctxn_locks_impl_cache, desc);
}

merr_t
kvdb_ctxn_locks_create(struct kvdb_ctxn_locks **locksp)
{
    struct kvdb_ctxn_locks_impl *impl;
    struct ctxn_locks_slab *slab;
    size_t sz;
    int i;

    *locksp = NULL;

    impl = kmem_cache_alloc(ctxn_locks_impl_cache);
    if (ev(!impl))
        return merr(ENOMEM);

    sz = sizeof(*impl) + sizeof(*slab);

    memset(impl, 0, sz);
    impl->ctxn_locks_end_seqno = U64_MAX;
    impl->ctxn_locks_magic = (uintptr_t)impl;

    impl->ctxn_locks_desc = kmem_cache_addr2desc(ctxn_locks_impl_cache, impl);

    if (ev(impl->ctxn_locks_desc == UINT32_MAX)) {
        kmem_cache_free(ctxn_locks_impl_cache, impl);
        return merr(ENOMEM);
    }

    for (i = 0; i < NELEM(impl->ctxn_locks_treev); ++i)
        impl->ctxn_locks_treev[i] = RB_ROOT;

    slab = impl->ctxn_locks_slab0;
    slab->cls_entrymax = CTXN_LOCKS_IMPL_CACHE_SZ - sz;
    slab->cls_entrymax /= sizeof(slab->cls_entryv[0]);
    impl->ctxn_locks_slab = slab;

    *locksp = &impl->ctxn_locks_handle;

    return 0;
}

void
kvdb_ctxn_locks_destroy(struct kvdb_ctxn_locks *handle)
{
    struct kvdb_ctxn_locks_impl *impl = kvdb_ctxn_locks_h2r(handle);

    assert(impl->ctxn_locks_magic == (uintptr_t)impl);
    assert(impl == kmem_cache_desc2addr(ctxn_locks_impl_cache, impl->ctxn_locks_desc));
    assert(impl->ctxn_locks_cnt == 0);
    assert(impl->ctxn_locks_slab->cls_next == NULL);

    impl->ctxn_locks_magic = ~(uintptr_t)impl;

    kmem_cache_free(ctxn_locks_impl_cache, impl);
}

u64
kvdb_ctxn_locks_count(struct kvdb_ctxn_locks *locks_handle)
{
    return kvdb_ctxn_locks_h2r(locks_handle)->ctxn_locks_cnt;
}

u64
kvdb_ctxn_locks_end_seqno(uint32_t desc)
{
    struct kvdb_ctxn_locks *handle = kvdb_ctxn_locks_desc2locks(desc);
    struct kvdb_ctxn_locks_impl *impl = kvdb_ctxn_locks_h2r(handle);

    return impl->ctxn_locks_end_seqno;
}

HSE_COLD merr_t
kvdb_ctxn_locks_init(void)
{
    struct kmem_cache *zone;

    zone = kmem_cache_create("ctxn_locks_impl", CTXN_LOCKS_IMPL_CACHE_SZ, 0, SLAB_DESC, NULL);
    ctxn_locks_impl_cache = zone;

    zone = kmem_cache_create("ctxn_locks_slab", CTXN_LOCKS_SLAB_CACHE_SZ, 0, 0, NULL);
    ctxn_locks_slab_cache = zone;

    if (!ctxn_locks_impl_cache || !ctxn_locks_slab_cache) {
        kvdb_ctxn_locks_fini();
        return merr(ENOMEM);
    }

    return 0;
}

HSE_COLD void
kvdb_ctxn_locks_fini(void)
{
    kmem_cache_destroy(ctxn_locks_impl_cache);
    ctxn_locks_impl_cache = NULL;

    kmem_cache_destroy(ctxn_locks_slab_cache);
    ctxn_locks_slab_cache = NULL;
}

#if HSE_MOCKING
#include "kvdb_keylock_ut_impl.i"
#endif /* HSE_MOCKING */
