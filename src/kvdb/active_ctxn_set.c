/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/arch.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>
#include <hse_util/spinlock.h>
#include <hse_util/assert.h>
#include <hse_util/timing.h>
#include <hse_util/log2.h>
#include <hse_util/page.h>
#include <hse_util/barrier.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include "active_ctxn_set.h"
#include "active_ctxn_set_internal.h"

#include <hse_ikvdb/limits.h>

struct active_ctxn_set {
};

/* The bucket mask is indexed by the number of active transactions
 * to obtain a bitmask used to constrain the number of buckets
 * available to active_ctxn_set_insert().  Keeping the number of
 * buckets reasonably constrained w.r.t the number of active ctxns
 * reduces the overhead required to maintain the horizon.
 */
static const u8 active_ctxn_bkt_maskv[] = {
    3, 3, 3, 3, 7, 7, 7, 7, 7, 7, 7, 15, 15, 15, 15, 15
};

/**
 * struct active_ctxn_bkt -
 * @acb_tree:           ptr to the active_ctxn_tree object
 * @acb_min_view_sns:   minimum view sequence number for the set
 */
struct active_ctxn_bkt {
    struct active_ctxn_tree *acb_tree;
    volatile u64             acb_min_view_sns;
} __aligned(SMP_CACHE_BYTES * 2);

/**
 * struct active_ctxn_set_impl
 * @acs_handle:         opaque handle for this struct
 * @acs_bkt_end:        ptr to one bucket past the last valid bucket
 * @acs_seqno_addr:
 * @acs_min_view_sn:    set minimum view seqno
 * @acs_min_view_bkt:   bucket which contains current min-view-sn
 * @acs_active:         count of active transactions
 * @acs_horizon:
 * @acs_lock:           min_view_sn computation lock
 * @acs_changing:       head of a bucket is changing to/from empty
 * @acs_bktv:           active client transaction sets
 */
struct active_ctxn_set_impl {
    struct active_ctxn_set acs_handle;
    u8                     acs_maskv[NELEM(active_ctxn_bkt_maskv)];
    atomic64_t *           acs_seqno_addr;

    __aligned(SMP_CACHE_BYTES) volatile u64 acs_min_view_sn;
    volatile void *acs_min_view_bkt;

    __aligned(SMP_CACHE_BYTES) atomic_t acs_active;

    __aligned(SMP_CACHE_BYTES) atomic64_t acs_horizon;

    __aligned(SMP_CACHE_BYTES) spinlock_t acs_lock;
    atomic_t                acs_changing;
    struct active_ctxn_bkt *acs_bkt_end;

    struct active_ctxn_bkt acs_bktv[];
};

#define active_ctxn_set_h2r(handle) container_of(handle, struct active_ctxn_set_impl, acs_handle)

struct active_ctxn_entry {
    struct list_head ace_link;
    void *           ace_tree;
    union {
        u64   ace_view_sn;
        void *ace_next;
    };
};

/**
 * struct active_ctxn_tree
 * @act_lock:   lock protecting the list
 * @act_head:   head of list of sorted entries
 * @act_bkt:    ptr to bucket which contains this tree object
 * @act_cache:  head of entry cache free list
 * @act_entryv: fixed-size cache of entry objects
 */
struct active_ctxn_tree {
    spinlock_t                act_lock;
    struct list_head          act_head;
    struct active_ctxn_bkt *  act_bkt;
    struct active_ctxn_entry *act_cache;
    struct active_ctxn_entry  act_entryv[];
};

merr_t
active_ctxn_set_create(struct active_ctxn_set **handle, atomic64_t *kvdb_seqno_addr)
{
    struct active_ctxn_set_impl *self;

    u32    max_elts = HSE_ACTIVE_CTXN_ELTS_MAX;
    u32    max_bkts;
    merr_t err = 0;
    size_t sz;
    int    i;

    max_bkts = NELEM(self->acs_maskv);

    sz = sizeof(*self);
    sz += sizeof(self->acs_bktv[0]) * max_bkts;

    self = alloc_aligned(sz, __alignof(*self), GFP_KERNEL);
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sz);
    memcpy(self->acs_maskv, active_ctxn_bkt_maskv, sizeof(self->acs_maskv));

    for (i = 0; i < max_bkts; ++i) {
        struct active_ctxn_bkt *bkt = self->acs_bktv + i;

        bkt->acb_min_view_sns = U64_MAX;

        err = active_ctxn_tree_create(max_elts, i, &bkt->acb_tree);
        if (ev(err))
            break;

        bkt->acb_tree->act_bkt = bkt;
    }

    self->acs_seqno_addr = kvdb_seqno_addr;
    self->acs_min_view_sn = atomic64_read(kvdb_seqno_addr);
    atomic64_set(&self->acs_horizon, self->acs_min_view_sn);
    self->acs_min_view_bkt = NULL;
    atomic_set(&self->acs_active, 1);
    atomic_set(&self->acs_changing, 0);
    spin_lock_init(&self->acs_lock);
    self->acs_bkt_end = self->acs_bktv;

    *handle = &self->acs_handle;

    if (err) {
        active_ctxn_set_destroy(*handle);
        *handle = NULL;
    }

    return err;
}

void
active_ctxn_set_destroy(struct active_ctxn_set *handle)
{
    struct active_ctxn_set_impl *self;
    int                          i;

    if (ev(!handle))
        return;

    self = active_ctxn_set_h2r(handle);

    for (i = 0; i < NELEM(active_ctxn_bkt_maskv); ++i) {
        struct active_ctxn_bkt *bkt = self->acs_bktv + i;

        active_ctxn_tree_destroy(bkt->acb_tree);
    }

    free_aligned(self);
}

u64
active_ctxn_set_horizon(struct active_ctxn_set *handle)
{
    struct active_ctxn_set_impl *self = active_ctxn_set_h2r(handle);

    u64 newh;
    u64 kvdb_seq = atomic64_read(self->acs_seqno_addr);
    u64 oldh = atomic64_read(&self->acs_horizon);

    /* Read old horizon and KVDB seqno before checking active txn cnt */
    smp_rmb();

    if (atomic_read(&self->acs_active) > 1) {
        newh = self->acs_min_view_sn;
    } else {
        /* Any transaction that began but wasn't reflected in acs_active
         * will have a view seqno that is larger than kvdb_seq.
         */
        newh = kvdb_seq;
    }

    /* self->acs_min_view_sn updates are lazy. self->acs_min_view_sn may be
     * lagging behind a previously returned horizon.
     */
    while (newh > oldh) {
        if (atomic64_cmpxchg(&self->acs_horizon, oldh, newh) == oldh)
            return newh;

        oldh = atomic64_read(&self->acs_horizon);
    }

    assert(oldh >= newh);

    return oldh;
}

/**
 * active_ctxn_set_update() - update set minimum view seqno
 * @self:       ptr to active_ctxn object
 * @entry_sn:   caller's min view seqno
 *
 * This function must be called with the ace_lock held.
 */
static inline void
active_ctxn_set_update(struct active_ctxn_set_impl *self, u64 entry_sn)
{
    struct active_ctxn_bkt *min_bkt, *bkt;
    u64                     min_sn;

    min_sn = U64_MAX;
    min_bkt = NULL;

    for (bkt = self->acs_bktv; bkt < self->acs_bkt_end; ++bkt) {
        u64 old = bkt->acb_min_view_sns;

        if (old < min_sn) {
            min_sn = old;
            min_bkt = bkt;
        }
    }

    if (atomic_read_acq(&self->acs_changing))
        return;

    /* No active transaction in the system after a remove. */
    if (min_sn == U64_MAX) {
        assert(entry_sn != 0);
        min_sn = entry_sn;
    }

    assert(min_sn >= self->acs_min_view_sn);
    self->acs_min_view_sn = min_sn;
    self->acs_min_view_bkt = min_bkt;
}

merr_t
active_ctxn_set_insert(struct active_ctxn_set *handle, u64 *viewp, void **cookiep)
{
    struct active_ctxn_set_impl *self = active_ctxn_set_h2r(handle);
    struct active_ctxn_entry *   entry;
    struct active_ctxn_tree *    tree;
    struct active_ctxn_bkt *     bkt;
    u32                          idx;
    bool                         changed;

    idx = atomic_inc_return(&self->acs_active) / 2;
    if (idx > NELEM(active_ctxn_bkt_maskv) - 1)
        idx = NELEM(active_ctxn_bkt_maskv) - 1;
    idx = raw_smp_processor_id() & self->acs_maskv[idx];

    bkt = self->acs_bktv + idx;
    tree = bkt->acb_tree;

    spin_lock(&tree->act_lock);
    entry = active_ctxn_entry_alloc(&tree->act_cache);
    if (ev(!entry)) {
        spin_unlock(&tree->act_lock);
        atomic_dec(&self->acs_active);
        return merr(ENOMEM);
    }

    changed = list_empty(&tree->act_head);
    if (changed)
        atomic_inc_acq(&self->acs_changing);

    entry->ace_view_sn = atomic64_fetch_add(1, self->acs_seqno_addr);
    entry->ace_tree = tree;
    list_add_tail(&entry->ace_link, &tree->act_head);

    if (changed) {
        assert(bkt->acb_min_view_sns == U64_MAX);
        bkt->acb_min_view_sns = entry->ace_view_sn;
    }
    spin_unlock(&tree->act_lock);

    if (changed) {
        spin_lock(&self->acs_lock);
        assert(entry->ace_view_sn >= self->acs_min_view_sn);

        if (bkt >= self->acs_bkt_end)
            self->acs_bkt_end = bkt + 1;

        if (atomic_dec_rel(&self->acs_changing) == 0)
            active_ctxn_set_update(self, 0);
        spin_unlock(&self->acs_lock);
    }

    *viewp = entry->ace_view_sn;
    *cookiep = entry;

    return 0;
}

BullseyeCoverageSaveOff void
active_ctxn_set_remove(
    struct active_ctxn_set *handle,
    void *                  cookie,
    u32 *                   min_changed,
    u64 *                   min_view_sn)
{
    struct active_ctxn_set_impl *self = active_ctxn_set_h2r(handle);
    struct active_ctxn_entry *   entry, *first;
    struct active_ctxn_tree *    tree;
    struct active_ctxn_bkt *     bkt;
    u64                          entry_sn;
    u64                          min_sn;
    bool                         changed;

    entry = cookie;
    entry_sn = entry->ace_view_sn;
    tree = entry->ace_tree;
    bkt = tree->act_bkt;

    spin_lock(&tree->act_lock);
    changed = list_is_first(&entry->ace_link, &tree->act_head);
    list_del(&entry->ace_link);

    if (changed) {
        first = list_first_entry_or_null(&tree->act_head, typeof(*first), ace_link);
        min_sn = first ? first->ace_view_sn : U64_MAX;

        bkt->acb_min_view_sns = min_sn;
    }

    active_ctxn_entry_free(&tree->act_cache, entry);
    spin_unlock(&tree->act_lock);

    while (changed) {
        if (atomic_read_acq(&self->acs_changing))
            break;

        if (entry_sn < self->acs_min_view_sn)
            break;

        if (self->acs_min_view_bkt != bkt)
            break;

        if (spin_trylock(&self->acs_lock)) {
            if (entry_sn >= self->acs_min_view_sn) {
                u64 seq = atomic64_read(self->acs_seqno_addr);
                active_ctxn_set_update(self, seq);
            }
            spin_unlock(&self->acs_lock);
            break;
        }

        cpu_relax();
    }

    *min_view_sn = self->acs_min_view_sn;
    *min_changed = *min_view_sn > entry_sn;

    atomic_dec(&self->acs_active);
}
BullseyeCoverageRestore

    merr_t
    active_ctxn_tree_create(u32 max_elts, u32 index, struct active_ctxn_tree **tree)
{
    struct active_ctxn_tree *self;
    size_t                   sz;
    int                      i;

    assert(max_elts > 0 && max_elts < 8192);

    sz = sizeof(*self);
    sz += sizeof(self->act_entryv[0]) * max_elts;

    self = alloc_aligned(sz, __alignof(*self), GFP_KERNEL);
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sz);

    for (i = 0; i < max_elts; ++i)
        self->act_entryv[i].ace_next = self->act_entryv + i + 1;

    self->act_entryv[i - 1].ace_next = NULL;
    self->act_cache = self->act_entryv;

    spin_lock_init(&self->act_lock);
    INIT_LIST_HEAD(&self->act_head);

    *tree = self;

    return 0;
}

void
active_ctxn_tree_destroy(struct active_ctxn_tree *self)
{
    free_aligned(self);
}

struct active_ctxn_entry *
active_ctxn_entry_alloc(struct active_ctxn_entry **entry_listp)
{
    struct active_ctxn_entry *entry;

    entry = *entry_listp;
    if (entry) {
        *entry_listp = entry->ace_next;
        entry->ace_view_sn = 0;
    }

    return entry;
}

void
active_ctxn_entry_free(struct active_ctxn_entry **entry_listp, struct active_ctxn_entry *entry)
{
    entry->ace_next = *entry_listp;
    *entry_listp = entry;
}
