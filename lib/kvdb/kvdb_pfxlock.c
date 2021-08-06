/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 *
 * The pfxlock is a collection of rbtrees that maintain shared and exclusive locks. Each entry
 * contains an end_seqno which is set at the time of commit/abort. An entry can be deleted only
 * when there are no txns in kvdb which have a start seqno larger than the entry's end_seqno.
 * This is handled by the garbage collector thread.
 */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>
#include <hse_util/timer.h>
#include <hse_util/spinlock.h>
#include <hse_util/slab.h>

#include <rbtree/rbtree.h>

#define MTF_MOCK_IMPL_kvdb_pfxlock

#include "kvdb_pfxlock.h"
#include "viewset.h"

struct kvdb_pfxlock_gc {
    struct delayed_work kpl_gc_dwork;
};

struct kvdb_pfxlock_entry {
    u64            kple_hash;
    u64            kple_end_seqno;
    u64            kple_cnt : 63;
    u64            kple_excl : 1;
    struct rb_node kple_node;
};

#define ENTRY_CACHE_CNT_MAX 1000

/* clang-format off */
struct kvdb_pfxlock_tree {
    struct rb_root             kplt_tree HSE_ALIGNED(2 * SMP_CACHE_BYTES);
    spinlock_t                 kplt_spinlock HSE_ALIGNED(SMP_CACHE_BYTES);
    uint                       kplt_entry_cnt;

    /* entry cache */
    uint                       kplt_ecache_cnt;

    struct kvdb_pfxlock_entry  kplt_ecache0[16] HSE_ALIGNED(SMP_CACHE_BYTES);
    struct kvdb_pfxlock_entry *kplt_ecache;
};
/* clang-format on */

struct kvdb_pfxlock {
    struct kvdb_pfxlock_tree        kpl_tree[KVDB_PFXLOCK_NUM_TREES];
    struct workqueue_struct *       kpl_gc_wq;
    struct kvdb_pfxlock_gc          kpl_gc;
    u64                             kpl_gc_delay_ms;
    struct viewset *                kpl_txn_viewset;
};

static void
kpl_gc_worker(struct work_struct *work);

static void
kvdb_pfxlock_entry_free(struct kvdb_pfxlock_tree *tree, struct kvdb_pfxlock_entry *entry)
{
    bool freeme = entry < tree->kplt_ecache0 ||
                  entry >= (tree->kplt_ecache0 + NELEM(tree->kplt_ecache0));

    if (tree->kplt_ecache_cnt < ENTRY_CACHE_CNT_MAX || !freeme) {
        *(void **)entry = tree->kplt_ecache;
        tree->kplt_ecache = entry;
        tree->kplt_ecache_cnt++;
        entry = NULL;
    }

    if (freeme)
        free(entry);
}

static struct kvdb_pfxlock_entry *
kvdb_pfxlock_entry_alloc(struct kvdb_pfxlock_tree *tree)
{
    struct kvdb_pfxlock_entry *e;

    e = tree->kplt_ecache;
    if (e) {
        tree->kplt_ecache = *(void **)e;
        tree->kplt_ecache_cnt--;
    }

    if (!e)
        e = malloc(sizeof(*e));

    return e;
}

merr_t
kvdb_pfxlock_create(struct viewset *txn_viewset, struct kvdb_pfxlock **pfxlock_out)
{
    struct kvdb_pfxlock *     pfxlock;
    struct kvdb_pfxlock_tree *tree;
    int                       i;

    pfxlock = malloc(sizeof(*pfxlock));
    if (ev(!pfxlock))
        return merr(ENOMEM);

    tree = pfxlock->kpl_tree;
    for (i = 0; i < KVDB_PFXLOCK_NUM_TREES; i++) {
        int j;

        tree[i].kplt_tree = RB_ROOT;
        spin_lock_init(&tree[i].kplt_spinlock);
        tree[i].kplt_ecache_cnt = 0;
        tree[i].kplt_ecache = tree[i].kplt_ecache0;

        /* Initialize kplt_ecache with all entries from the embedded cache.
         */
        for (j = 0; j < NELEM(tree[i].kplt_ecache0); j++)
            kvdb_pfxlock_entry_free(&tree[i], &tree[i].kplt_ecache0[j]);
    }

    pfxlock->kpl_txn_viewset = txn_viewset;

    /* Set up GC worker for pfxlock
     */
    pfxlock->kpl_gc_delay_ms = 5000;
    pfxlock->kpl_gc_wq = alloc_workqueue("kpl_gc", 0, 1);
    if (ev(!pfxlock->kpl_gc_wq)) {
        free(pfxlock);
        return merr(ENOMEM);
    }

    INIT_DELAYED_WORK(&pfxlock->kpl_gc.kpl_gc_dwork, kpl_gc_worker);
    queue_delayed_work(
        pfxlock->kpl_gc_wq,
        &pfxlock->kpl_gc.kpl_gc_dwork,
        msecs_to_jiffies(pfxlock->kpl_gc_delay_ms));

    *pfxlock_out = pfxlock;
    return 0;
}

void
kvdb_pfxlock_destroy(struct kvdb_pfxlock *pfxlock)
{
    int i, j;

    if (HSE_UNLIKELY(!pfxlock))
        return;

    while (!cancel_delayed_work(&pfxlock->kpl_gc.kpl_gc_dwork))
        usleep(100);
    destroy_workqueue(pfxlock->kpl_gc_wq);

    for (i = 0; i < KVDB_PFXLOCK_NUM_TREES; i++) {
        struct kvdb_pfxlock_tree  *tree = &pfxlock->kpl_tree[i];
        struct kvdb_pfxlock_entry *entry, *next;
        struct kvdb_pfxlock_entry *last = tree->kplt_ecache0 + NELEM(tree->kplt_ecache0);

        rbtree_postorder_for_each_entry_safe(entry, next, &tree->kplt_tree, kple_node) {
            if (entry < tree->kplt_ecache0 || entry >= last)
                free(entry);
        }

        /* Cleanup cache */
        for (j = 0, entry = tree->kplt_ecache; j < tree->kplt_ecache_cnt; j++) {
            bool freeme;

            entry = tree->kplt_ecache;
            freeme = entry < tree->kplt_ecache0 || entry >= last;

            tree->kplt_ecache = *(void **)entry;
            if (freeme)
                free(entry);
        }
    }

    free(pfxlock);
}

static void
kvdb_pfxlock_entry_add(
    struct rb_node *           parent,
    struct rb_root *           tree,
    struct rb_node **          link,
    struct kvdb_pfxlock_entry *entry)
{
    rb_link_node(&entry->kple_node, parent, link);
    rb_insert_color(&entry->kple_node, tree);
}

merr_t
kvdb_pfxlock_excl(struct kvdb_pfxlock *pfxlock, u64 hash, u64 start_seqno, void **cookie)
{
    struct rb_node **                link, *parent;
    struct kvdb_pfxlock_entry *      entry, *new;
    int                              idx = hash % KVDB_PFXLOCK_NUM_TREES;
    struct rb_root *                 tree = &pfxlock->kpl_tree[idx].kplt_tree;
    spinlock_t *                     spinlock = &pfxlock->kpl_tree[idx].kplt_spinlock;
    bool                             insert = true;

    link = &tree->rb_node;
    parent = NULL;
    entry = NULL;

    spin_lock(spinlock);
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), kple_node);

        if (HSE_UNLIKELY(hash == entry->kple_hash))
            break;

        link = (hash < entry->kple_hash) ? &parent->rb_left : &parent->rb_right;
    }

    if (HSE_UNLIKELY(*link)) {
        entry = rb_entry(*link, typeof(*entry), kple_node);

        if (entry->kple_cnt == 1 && *cookie) {
            /* Caller is the only txn holding this shared lock, fallthrough */
        } else if (start_seqno <= entry->kple_end_seqno) {
            spin_unlock(spinlock);
            return merr(ECANCELED);
        }

        /* This entry can be inherited since it was published before this txn began. Replace.
         */
        insert = false;
        new = entry;
    } else {
        new = kvdb_pfxlock_entry_alloc(&pfxlock->kpl_tree[idx]);
        if (ev(!new)) {
            spin_unlock(spinlock);
            return merr(ENOMEM);
        }
        memset(new, 0, sizeof(*new));
    }

    new->kple_hash = hash;
    new->kple_end_seqno = KVDB_PFXLOCK_ACTIVE;
    new->kple_cnt = 1;
    new->kple_excl = 1;

    if (insert) {
        kvdb_pfxlock_entry_add(parent, tree, link, new);
        pfxlock->kpl_tree[idx].kplt_entry_cnt++;
    }

    spin_unlock(spinlock);
    *cookie = new;
    return 0;
}

merr_t
kvdb_pfxlock_shared(struct kvdb_pfxlock *pfxlock, u64 hash, u64 start_seqno, void **cookie)
{
    uint                             idx = hash % KVDB_PFXLOCK_NUM_TREES;
    struct rb_node **                link, *parent;
    struct rb_root *                 tree = &pfxlock->kpl_tree[idx].kplt_tree;
    spinlock_t *                     spinlock = &pfxlock->kpl_tree[idx].kplt_spinlock;
    struct kvdb_pfxlock_entry *      entry, *new;
    bool                             insert = true;

    link = &tree->rb_node;
    parent = NULL;
    entry = NULL;

    spin_lock(spinlock);
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), kple_node);

        if (hash == entry->kple_hash)
            break;

        link = (hash < entry->kple_hash) ? &parent->rb_left : &parent->rb_right;
    }

    if (*link) {
        if (entry->kple_excl && start_seqno <= entry->kple_end_seqno) {
            spin_unlock(spinlock);
            return merr(ECANCELED);
        }

        /* This entry can be inherited since it was published before this txn began. Replace.
         */
        insert = false;
        new = entry;
    } else {
        new = kvdb_pfxlock_entry_alloc(&pfxlock->kpl_tree[idx]);
        if (ev(!new)) {
            spin_unlock(spinlock);
            return merr(ENOMEM);
        }
        memset(new, 0, sizeof(*new));
    }

    new->kple_hash = hash;
    new->kple_end_seqno = KVDB_PFXLOCK_ACTIVE;
    new->kple_cnt++;
    new->kple_excl = 0;

    if (insert) {
        kvdb_pfxlock_entry_add(parent, tree, link, new);
        pfxlock->kpl_tree[idx].kplt_entry_cnt++;
    }

    spin_unlock(spinlock);

    *cookie = new;
    return 0;
}

void
kvdb_pfxlock_seqno_pub(struct kvdb_pfxlock *pfxlock, u64 end_seqno, void *cookie)
{
    struct kvdb_pfxlock_entry *entry = (struct kvdb_pfxlock_entry *)cookie;
    int                        idx = entry->kple_hash % KVDB_PFXLOCK_NUM_TREES;
    spinlock_t *               spinlock = &pfxlock->kpl_tree[idx].kplt_spinlock;

    spin_lock(spinlock);

    entry->kple_cnt--;
    if (!entry->kple_cnt)
        entry->kple_end_seqno = end_seqno;

    spin_unlock(spinlock);
}

/* Garbage Collection
 */
void
kvdb_pfxlock_prune(struct kvdb_pfxlock *pfxlock)
{
    u64    txn_horizon = viewset_horizon(pfxlock->kpl_txn_viewset);
    int    i;
    char   distbuf[256] HSE_MAYBE_UNUSED;
    size_t off HSE_MAYBE_UNUSED;

    for (i = 0, off = 0; i < KVDB_PFXLOCK_NUM_TREES; i++) {
        struct kvdb_pfxlock_tree  *tree = &pfxlock->kpl_tree[i];
        spinlock_t                *spinlock = &pfxlock->kpl_tree[i].kplt_spinlock;
        struct kvdb_pfxlock_entry *entry, *next;

#ifndef HSE_BUILD_RELEASE
        snprintf_append(distbuf, sizeof(distbuf), &off, "%u ", pfxlock->kpl_tree[i].kplt_entry_cnt);
#endif

        spin_lock(spinlock);
        rbtree_postorder_for_each_entry_safe(entry, next, &tree->kplt_tree, kple_node) {
            if (txn_horizon > entry->kple_end_seqno) {
                pfxlock->kpl_tree[i].kplt_entry_cnt--;
                rb_erase(&entry->kple_node, &tree->kplt_tree);
                kvdb_pfxlock_entry_free(tree, entry);
            }
        }
        spin_unlock(spinlock);
    }

#ifndef HSE_BUILD_RELEASE
    hse_log(HSE_INFO "pfxdist: %s", distbuf);
#endif
}

static void
kpl_gc_worker(struct work_struct *work)
{
    struct kvdb_pfxlock_gc *gc = container_of(work, struct kvdb_pfxlock_gc, kpl_gc_dwork.work);
    struct kvdb_pfxlock *   kpl = container_of(gc, struct kvdb_pfxlock, kpl_gc);

    kvdb_pfxlock_prune(kpl);

    queue_delayed_work(kpl->kpl_gc_wq, &gc->kpl_gc_dwork, msecs_to_jiffies(kpl->kpl_gc_delay_ms));
}

#if HSE_MOCKING
#include "kvdb_pfxlock_ut_impl.i"
#endif /* HSE_MOCKING */
