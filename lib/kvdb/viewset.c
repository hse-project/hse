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

#include "viewset.h"
#include "viewset_internal.h"

#include <hse_ikvdb/limits.h>

#include <syscall.h>
#include <semaphore.h>

struct viewset {
};

/* The bucket mask is indexed by the number of active transactions
 * to obtain a bitmask used to constrain the number of buckets
 * available to viewset_insert().  Keeping the number of
 * buckets reasonably constrained w.r.t the number of active ctxns
 * reduces the overhead required to maintain the horizon.
 */
static const u8 viewset_bkt_maskv[] = {
    3, 3, 3, 3, 7, 7, 7, 7, 7, 7, 7, 15, 15, 15, 15, 15
};

/**
 * struct viewset_bkt -
 * @acb_tree:           ptr to the viewset_tree object
 * @acb_min_view_sns:   minimum view sequence number for the set
 */
struct viewset_bkt {
    struct viewset_tree *acb_tree;
    volatile u64             acb_min_view_sns;
};

/**
 * struct viewset_impl -
 * @vs_handle:         opaque handle for this struct
 * @vs_bkt_end:        ptr to one bucket past the last valid bucket
 * @vs_seqno_addr:
 * @vs_min_view_sn:    set minimum view seqno
 * @vs_min_view_bkt:   bucket which contains current min-view-sn
 * @vs_horizon:
 * @vs_active:         count of active transactions
 * @vs_lock:           min_view_sn computation lock
 * @vs_chgaccum:       accumulated changes to apply to vs_changing
 * @vs_changing:       head of a bucket is changing to/from empty
 * @vs_bktv:           active client transaction sets
 */
struct viewset_impl {
    struct viewset      vs_handle;
    u8                  vs_maskv[NELEM(viewset_bkt_maskv)];
    atomic64_t         *vs_seqno_addr;
    struct viewset_bkt *vs_bkt_end;

    volatile u64   vs_min_view_sn HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    volatile void *vs_min_view_bkt;
    atomic64_t     vs_horizon;

    struct {
        atomic_t vs_active HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    } vs_nodev[2];

    spinlock_t vs_lock      HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    uint       vs_chgaccum  HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic_t   vs_changing  HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    struct viewset_bkt vs_bktv[] HSE_ALIGNED(SMP_CACHE_BYTES * 2);
};

#define viewset_h2r(handle) container_of(handle, struct viewset_impl, vs_handle)

struct viewset_tree;

struct viewset_entry {
    struct list_head         ace_link;
    struct viewset_tree *ace_tree;
    atomic_t                *ace_active;
    union {
        u64   ace_view_sn;
        void *ace_next;
    };
};

/**
 * struct viewset_tree
 * @act_lock:   lock protecting the list
 * @act_head:   head of list of sorted entries
 * @act_bkt:    ptr to bucket which contains this tree object
 * @act_cache:  head of entry cache free list
 * @act_entryv: fixed-size cache of entry objects
 */
struct viewset_tree {
    spinlock_t                act_lock HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    sem_t                     act_sema;
    struct list_head          act_head HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct viewset_bkt   *act_bkt;
    struct viewset_entry *act_cache;
    struct viewset_entry  act_entryv[];
};

static struct viewset_entry *
viewset_entry_alloc(struct viewset_entry **entry_listp)
{
    struct viewset_entry *entry;

    entry = *entry_listp;
    if (entry)
        *entry_listp = entry->ace_next;

    return entry;
}

static void
viewset_entry_free(struct viewset_entry **entry_listp, struct viewset_entry *entry)
{
    entry->ace_next = *entry_listp;
    *entry_listp = entry;
}

merr_t
viewset_create(struct viewset **handle, atomic64_t *kvdb_seqno_addr)
{
    struct viewset_impl *self;

    u32    max_elts = HSE_VIEWSET_ELTS_MAX;
    u32    max_bkts;
    merr_t err = 0;
    size_t sz;
    int    i;

    max_bkts = NELEM(self->vs_maskv);

    sz = sizeof(*self);
    sz += sizeof(self->vs_bktv[0]) * max_bkts;

    self = alloc_aligned(sz, __alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sz);
    memcpy(self->vs_maskv, viewset_bkt_maskv, sizeof(self->vs_maskv));

    for (i = 0; i < max_bkts; ++i) {
        struct viewset_bkt *bkt = self->vs_bktv + i;

        bkt->acb_min_view_sns = U64_MAX;

        err = viewset_tree_create(max_elts, i, &bkt->acb_tree);
        if (ev(err))
            break;

        bkt->acb_tree->act_bkt = bkt;
    }

    self->vs_seqno_addr = kvdb_seqno_addr;
    self->vs_min_view_sn = atomic64_read(kvdb_seqno_addr);
    atomic64_set(&self->vs_horizon, self->vs_min_view_sn);
    self->vs_min_view_bkt = NULL;
    atomic_set(&self->vs_nodev[0].vs_active, 0);
    atomic_set(&self->vs_nodev[1].vs_active, 0);
    atomic_set(&self->vs_changing, 0);
    spin_lock_init(&self->vs_lock);
    self->vs_bkt_end = self->vs_bktv;

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
    int                          i;

    if (ev(!handle))
        return;

    self = viewset_h2r(handle);

    for (i = 0; i < NELEM(viewset_bkt_maskv); ++i) {
        struct viewset_bkt *bkt = self->vs_bktv + i;

        viewset_tree_destroy(bkt->acb_tree);
    }

    free_aligned(self);
}

u64
viewset_horizon(struct viewset *handle)
{
    struct viewset_impl *self = viewset_h2r(handle);

    u64 newh;
    u64 kvdb_seq = atomic64_read(self->vs_seqno_addr);
    u64 oldh = atomic64_read(&self->vs_horizon);

    /* Read old horizon and KVDB seqno before checking active txn cnt */
    smp_rmb();

    if (atomic_read(&self->vs_nodev[0].vs_active) ||
        atomic_read(&self->vs_nodev[1].vs_active)) {
        newh = self->vs_min_view_sn;
    } else {
        /* Any transaction that began but wasn't reflected in vs_active
         * will have a view seqno that is larger than kvdb_seq.
         */
        newh = kvdb_seq;
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
    u64                     min_sn;

    min_sn = U64_MAX;
    min_bkt = NULL;

    for (bkt = self->vs_bktv; bkt < self->vs_bkt_end; ++bkt) {
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
    atomic_t                    *active;
    sem_t                       *sema;
    uint                         idx;
    bool                         changed;

    static __thread uint cpuid, nodeid, cnt;

    if (cnt++ % 16 == 0) {
        if (HSE_UNLIKELY( syscall(SYS_getcpu, &cpuid, &nodeid, NULL) ))
            cpuid = nodeid = raw_smp_processor_id();
    }

    active = &self->vs_nodev[nodeid & 1].vs_active;

    idx = atomic_inc_return(active) / 2;
    if (idx > NELEM(viewset_bkt_maskv) - 1)
        idx = NELEM(viewset_bkt_maskv) - 1;

    bkt = self->vs_bktv + (cpuid & self->vs_maskv[idx]);
    tree = bkt->acb_tree;
    sema = NULL;

    if (!spin_trylock(&tree->act_lock)) {
        if (idx > 4) {
            sema = &tree->act_sema;
            if (sem_wait(sema))
                sema = NULL; /* Probably EINTR */
        }
        spin_lock(&tree->act_lock);
    }

    entry = viewset_entry_alloc(&tree->act_cache);
    if (ev(!entry)) {
        spin_unlock(&tree->act_lock);
        if (sema)
            sem_post(sema);
        atomic_dec(active);
        return merr(ENOMEM);
    }

    changed = list_empty(&tree->act_head);
    if (changed)
        atomic_inc_acq(&self->vs_changing);

    entry->ace_view_sn = atomic64_fetch_add(1, self->vs_seqno_addr);
    entry->ace_tree = tree;
    entry->ace_active = active;
    list_add_tail(&entry->ace_link, &tree->act_head);

    if (changed) {
        assert(bkt->acb_min_view_sns == U64_MAX);
        bkt->acb_min_view_sns = entry->ace_view_sn;
    }
    spin_unlock(&tree->act_lock);

    if (changed) {
        spin_lock(&self->vs_lock);
        assert(entry->ace_view_sn >= self->vs_min_view_sn);

        if (bkt >= self->vs_bkt_end)
            self->vs_bkt_end = bkt + 1;

        /* Accumulate changes in vs_chgaccum to reduce the number
         * of atomic operations on vs_changing.
         */
        if (atomic_read(&self->vs_changing) - ++self->vs_chgaccum == 0) {
            atomic_sub_rel(self->vs_chgaccum, &self->vs_changing);
            self->vs_chgaccum = 0;
            viewset_update(self, 0);
        }
        spin_unlock(&self->vs_lock);
    }

    if (sema)
        sem_post(sema);

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
    atomic_t                    *active;

    entry = cookie;
    entry_sn = entry->ace_view_sn;
    active = entry->ace_active;
    tree = entry->ace_tree;
    bkt = NULL;

    spin_lock(&tree->act_lock);
    changed = list_is_first(&entry->ace_link, &tree->act_head);
    list_del(&entry->ace_link);

    if (changed) {
        first = list_first_entry_or_null(&tree->act_head, typeof(*first), ace_link);
        min_sn = first ? first->ace_view_sn : U64_MAX;

        bkt = tree->act_bkt;
        bkt->acb_min_view_sns = min_sn;
    }

    viewset_entry_free(&tree->act_cache, entry);
    spin_unlock(&tree->act_lock);

    while (changed) {
        if (atomic_read_acq(&self->vs_changing))
            break;

        if (entry_sn < self->vs_min_view_sn)
            break;

        if (self->vs_min_view_bkt != bkt)
            break;

        if (spin_trylock(&self->vs_lock)) {
            if (entry_sn >= self->vs_min_view_sn) {
                u64 seq = atomic64_read(self->vs_seqno_addr);
                viewset_update(self, seq);
            }
            spin_unlock(&self->vs_lock);
            break;
        }

        cpu_relax();
    }

    atomic_dec(active);

    *min_view_sn = self->vs_min_view_sn;
    *min_changed = *min_view_sn > entry_sn;
}
/* GCOV_EXCL_STOP */

merr_t
viewset_tree_create(u32 max_elts, u32 index, struct viewset_tree **tree)
{
    struct viewset_tree *self;
    size_t                   sz;
    int                      i;

    assert(max_elts > 0 && max_elts < 8192);

    sz = sizeof(*self);
    sz += sizeof(self->act_entryv[0]) * max_elts;

    self = alloc_aligned(sz, __alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sz);

    for (i = 0; i < max_elts; ++i)
        self->act_entryv[i].ace_next = self->act_entryv + i + 1;

    self->act_entryv[i - 1].ace_next = NULL;
    self->act_cache = self->act_entryv;

    spin_lock_init(&self->act_lock);
    INIT_LIST_HEAD(&self->act_head);
    sem_init(&self->act_sema, 0, 4);

    *tree = self;

    return 0;
}

void
viewset_tree_destroy(struct viewset_tree *self)
{
    sem_destroy(&self->act_sema);
    free_aligned(self);
}
