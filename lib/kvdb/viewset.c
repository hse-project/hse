/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include "_config.h"

#include <stdalign.h>

#include <hse_util/arch.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>
#include <hse_util/spinlock.h>
#include <hse_util/mutex.h>
#include <hse_util/assert.h>
#include <hse_util/timing.h>
#include <hse_util/log2.h>
#include <hse_util/page.h>
#include <hse_util/barrier.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include "viewset.h"

#include <hse_ikvdb/limits.h>

#include <syscall.h>
#include <semaphore.h>

#define viewlock_t              spinlock_t
#define viewlock_init(_view)    spin_lock_init(&(_view)->vs_lock)
#define viewlock_lock(_view)    spin_lock(&(_view)->vs_lock)
#define viewlock_trylock(_view) spin_trylock(&(_view)->vs_lock)
#define viewlock_unlock(_view)  spin_unlock(&(_view)->vs_lock)

#define treelock_t              struct mutex
#define treelock_init(_tree)    mutex_init_adaptive(&(_tree)->act_lock)
#define treelock_lock(_tree)    mutex_lock(&(_tree)->act_lock)
#define treelock_trylock(_tree) mutex_trylock(&(_tree)->act_lock)
#define treelock_unlock(_tree)  mutex_unlock(&(_tree)->act_lock)

struct viewset {
};

#define VIEWSET_BKT_MAX     (14)

/**
 * struct viewset_bkt -
 * @acb_tree:           ptr to the viewset_tree object
 * @acb_min_view_sns:   minimum view sequence number for the set
 * @acb_active:         count of currently active entries
 */
struct viewset_bkt {
    struct viewset_tree *acb_tree;
    volatile u64         acb_min_view_sns;
    atomic_t             acb_active HSE_ALIGNED(SMP_CACHE_BYTES * 2);
};

/**
 * struct viewset_impl -
 * @vs_handle:         opaque handle for this struct
 * @vs_bkt_end:        ptr to one bucket past the last valid bucket
 * @vs_seqno_addr:
 * @vs_min_view_sn:    set minimum view seqno
 * @vs_min_view_bkt:   bucket which contains current min-view-sn
 * @vs_horizon:
 * @vs_lock:           min_view_sn computation lock
 * @vs_chgaccum:       accumulated changes to apply to vs_changing
 * @vs_changing:       head of a bucket is changing to/from empty
 * @vs_bktv:           active client transaction sets
 */
struct viewset_impl {
    struct viewset      vs_handle;
    atomic64_t         *vs_seqno_addr;
    struct viewset_bkt *vs_bkt_first;
    struct viewset_bkt *vs_bkt_last;

    volatile u64   vs_min_view_sn HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    volatile void *vs_min_view_bkt;
    atomic64_t     vs_horizon;

    struct {
        sem_t  vs_sema  HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    } vs_nodev[2];

    viewlock_t vs_lock      HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    uint       vs_chgaccum  HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic_t   vs_changing  HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    struct viewset_bkt vs_bktv[VIEWSET_BKT_MAX];
};

#define viewset_h2r(handle) container_of(handle, struct viewset_impl, vs_handle)

struct viewset_tree;

struct viewset_entry {
    struct list_head    ace_link;
    struct viewset_bkt *ace_bkt;
    union {
        u64   ace_view_sn;
        void *ace_next;
    };
};

/**
 * struct viewset_tree
 * @act_lock:   lock protecting the list
 * @act_head:   head of list of sorted entries
 * @act_cache:  head of entry cache free list
 * @act_entryv: fixed-size cache of entry objects
 */
struct viewset_tree {
    treelock_t            act_lock  HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct list_head      act_head  HSE_ALIGNED(SMP_CACHE_BYTES);
    struct viewset_entry *act_cache;
    uint                  act_entryc;
    uint                  act_entrymax;
    struct viewset_entry  act_entryv[];
};

static merr_t
viewset_tree_create(u32 max_elts, u32 index, struct viewset_tree **tree)
{
    struct viewset_tree *self;
    size_t sz;

    assert(max_elts > 0);

    sz = sizeof(*self);
    sz += sizeof(self->act_entryv[0]) * max_elts;

    self = alloc_aligned(sz, alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));
    treelock_init(self);
    INIT_LIST_HEAD(&self->act_head);
    self->act_entrymax = max_elts;

    *tree = self;

    return 0;
}

static void
viewset_tree_destroy(struct viewset_tree *self)
{
    free_aligned(self);
}

static struct viewset_entry *
viewset_entry_alloc(struct viewset_tree *tree)
{
    struct viewset_entry *entry;

    entry = tree->act_cache;
    if (entry) {
        tree->act_cache = entry->ace_next;
        return entry;
    }

    if (tree->act_entryc < tree->act_entrymax)
        entry = tree->act_entryv + tree->act_entryc++;

    return entry;
}

static void
viewset_entry_free(struct viewset_tree *tree, struct viewset_entry *entry)
{
    entry->ace_next = tree->act_cache;
    tree->act_cache = entry;
}

merr_t
viewset_create(struct viewset **handle, atomic64_t *kvdb_seqno_addr)
{
    struct viewset_impl *self;
    merr_t err = 0;
    u32 max_elts;
    int i;

    max_elts = HSE_VIEWSET_ELTS_MAX / VIEWSET_BKT_MAX;

    self = alloc_aligned(sizeof(*self), alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));

    for (i = 0; i < VIEWSET_BKT_MAX; ++i) {
        struct viewset_bkt *bkt = self->vs_bktv + i;

        atomic_set(&bkt->acb_active, 0);
        bkt->acb_min_view_sns = U64_MAX;

        err = viewset_tree_create(max_elts, i, &bkt->acb_tree);
        if (ev(err))
            break;
    }

    self->vs_seqno_addr = kvdb_seqno_addr;
    self->vs_min_view_sn = atomic64_read(kvdb_seqno_addr);
    atomic64_set(&self->vs_horizon, self->vs_min_view_sn);
    self->vs_min_view_bkt = NULL;
    for (i = 0; i < NELEM(self->vs_nodev); ++i) {
        sem_init(&self->vs_nodev[i].vs_sema, 0, 3);
    }
    atomic_set(&self->vs_changing, 0);
    viewlock_init(self);
    self->vs_bkt_first = self->vs_bktv + (VIEWSET_BKT_MAX / 2);
    self->vs_bkt_last = self->vs_bkt_first;

    *handle = &self->vs_handle;

    if (err) {
        viewset_destroy(*handle);
        *handle = NULL;
    }

    return err;
}

void
viewset_destroy(struct viewset *handle)
{
    struct viewset_impl *self;
    int i;

    if (ev(!handle))
        return;

    self = viewset_h2r(handle);

    for (i = 0; i < VIEWSET_BKT_MAX; ++i) {
        struct viewset_bkt *bkt = self->vs_bktv + i;

        viewset_tree_destroy(bkt->acb_tree);
    }

    for (i = 0; i < NELEM(self->vs_nodev); ++i)
        sem_destroy(&self->vs_nodev[i].vs_sema);

    free_aligned(self);
}

u64
viewset_horizon(struct viewset *handle)
{
    struct viewset_impl *self = viewset_h2r(handle);

    u64 newh = atomic64_read(self->vs_seqno_addr);
    u64 oldh = atomic64_read(&self->vs_horizon);
    int i;

    /* Read old horizon and KVDB seqno before checking active txn cnt */
    smp_rmb();

    /* Any transaction that began but wasn't reflected in acb_active
     * will have a view seqno that is larger than newh.
     */
    for (i = 0; i < VIEWSET_BKT_MAX; ++i) {
        if (atomic_read(&self->vs_bktv[i].acb_active)) {
            newh = self->vs_min_view_sn;
            break;
        }
    }

    /* self->vs_min_view_sn updates are lazy. self->vs_min_view_sn may be
     * lagging behind a previously returned horizon.
     */
    while (newh > oldh) {
        if (atomic64_cmpxchg(&self->vs_horizon, oldh, newh) == oldh)
            return newh;

        oldh = atomic64_read(&self->vs_horizon);
    }

    assert(oldh >= newh);

    return oldh;
}

/**
 * viewset_update() - update set minimum view seqno
 * @self:       ptr to active_ctxn object
 * @entry_sn:   caller's min view seqno
 *
 * This function must be called with the ace_lock held.
 */
static inline void
viewset_update(struct viewset_impl *self, u64 entry_sn)
{
    struct viewset_bkt *min_bkt, *bkt;
    u64 min_sn;

    min_sn = U64_MAX;
    min_bkt = NULL;

    for (bkt = self->vs_bkt_first; bkt < self->vs_bkt_last; ++bkt) {
        u64 old = bkt->acb_min_view_sns;

        if (old < min_sn) {
            min_sn = old;
            min_bkt = bkt;
        }
    }

    if (atomic_read_acq(&self->vs_changing))
        return;

    /* No active transaction in the system after a remove. */
    if (min_sn == U64_MAX) {
        assert(entry_sn != 0);
        min_sn = entry_sn;
    }

    assert(min_sn >= self->vs_min_view_sn);
    self->vs_min_view_sn = min_sn;
    self->vs_min_view_bkt = min_bkt;
}

merr_t
viewset_insert(struct viewset *handle, u64 *viewp, void **cookiep)
{
    struct viewset_impl *self = viewset_h2r(handle);
    struct viewset_entry *   entry;
    struct viewset_tree *    tree;
    struct viewset_bkt *     bkt;
    bool                     changed;
    uint cpu, core, node;

    hse_getcpu(&cpu, &node, &core);

    /* Choose a bucket to the right of center if the current
     * NUMA node is odd, otherwise to the left of center.
     */
    bkt = self->vs_bktv + (VIEWSET_BKT_MAX / 2);
    if (node % 2)
        bkt += (core / 2) % (VIEWSET_BKT_MAX / 2);
    else
        bkt -= ((core / 2) % (VIEWSET_BKT_MAX / 2)) + 1;

    atomic_inc(&bkt->acb_active);

    tree = bkt->acb_tree;

    treelock_lock(tree);
    entry = viewset_entry_alloc(tree);
    if (ev(!entry)) {
        treelock_unlock(tree);
        atomic_dec(&bkt->acb_active);
        return merr(ENOMEM);
    }

    changed = list_empty(&tree->act_head);
    if (changed)
        atomic_inc_acq(&self->vs_changing);

    entry->ace_view_sn = atomic64_fetch_add(1, self->vs_seqno_addr);
    entry->ace_bkt = bkt;
    list_add_tail(&entry->ace_link, &tree->act_head);

    if (changed) {
        assert(bkt->acb_min_view_sns == U64_MAX);
        bkt->acb_min_view_sns = entry->ace_view_sn;
    }
    treelock_unlock(tree);

    if (changed) {
        bool updated = false;
        sem_t *sema = NULL;

        /* There is just one viewlock, so leverage a counting semaphore
         * to limit the number of threads that can hammer away at it at
         * any given time.
         */
        if (!viewlock_trylock(self)) {
            sema = &self->vs_nodev[node % NELEM(self->vs_nodev)].vs_sema;
            if (sem_wait(sema))
                sema = NULL;
            viewlock_lock(self);
        }

        assert(entry->ace_view_sn >= self->vs_min_view_sn);

        if (bkt < self->vs_bkt_first)
            self->vs_bkt_first = bkt;
        if (bkt >= self->vs_bkt_last)
            self->vs_bkt_last = bkt + 1;

        /* Accumulate changes in vs_chgaccum to reduce the number
         * of atomic operations on vs_changing.
         */
        if (atomic_read(&self->vs_changing) - ++self->vs_chgaccum == 0) {
            atomic_sub_rel(self->vs_chgaccum, &self->vs_changing);
            self->vs_chgaccum = 0;
            viewset_update(self, 0);
            updated = true;
        }
        viewlock_unlock(self);

        if (sema)
            sem_post(sema);

        /* If we skipped the updated because some other thread was
         * making a change then we must ensure we wait until our
         * view has been registered.  Note that I've yet to see
         * this situation occur, but it seems plausible.
         */
        if (!updated) {
            while (ev(self->vs_min_view_sn > entry->ace_view_sn))
                cpu_relax();
        }
    }

    *viewp = entry->ace_view_sn;
    *cookiep = entry;

    return 0;
}

/* GCOV_EXCL_START */
void
viewset_remove(
    struct viewset *handle,
    void *                  cookie,
    u32 *                   min_changed,
    u64 *                   min_view_sn)
{
    struct viewset_impl *self = viewset_h2r(handle);
    struct viewset_entry *   entry, *first;
    struct viewset_tree *    tree;
    struct viewset_bkt *     bkt;
    u64                          entry_sn;
    u64                          min_sn;
    bool                         changed;

    entry = cookie;
    entry_sn = entry->ace_view_sn;
    bkt = entry->ace_bkt;
    tree = bkt->acb_tree;

    treelock_lock(tree);
    changed = list_is_first(&entry->ace_link, &tree->act_head);
    list_del(&entry->ace_link);

    if (changed) {
        first = list_first_entry_or_null(&tree->act_head, typeof(*first), ace_link);
        min_sn = first ? first->ace_view_sn : U64_MAX;

        bkt->acb_min_view_sns = min_sn;
    }

    viewset_entry_free(tree, entry);
    treelock_unlock(tree);

    while (changed) {
        if (atomic_read_acq(&self->vs_changing))
            break;

        if (entry_sn < self->vs_min_view_sn)
            break;

        if (self->vs_min_view_bkt != bkt)
            break;

        if (viewlock_trylock(self)) {
            if (entry_sn >= self->vs_min_view_sn) {
                u64 seq = atomic64_read(self->vs_seqno_addr);
                viewset_update(self, seq);
            }
            viewlock_unlock(self);
            break;
        }

        cpu_relax();
    }

    atomic_dec(&bkt->acb_active);

    *min_view_sn = self->vs_min_view_sn;
    *min_changed = *min_view_sn > entry_sn;
}
/* GCOV_EXCL_STOP */

