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

/* clang-format off */

#define KVDB_PFXLOCK_NUM_TREES  (256)
#define KVDB_PFXLOCK_ACTIVE     (UINT64_MAX - 1)
#define KVDB_MCACHE_CNT_MAX     (1024)

struct kvdb_pfxlock_gc {
    struct delayed_work kpl_gc_dwork;
};

struct kvdb_pfxlock_entry {
    struct rb_node kple_node HSE_ALIGNED(SMP_CACHE_BYTES);
    u64            kple_hash;
    u64            kple_end_seqno;
    u64            kple_end_seqno_excl;
    int            kple_refcnt;
    bool           kple_excl;
};

struct kvdb_pfxlock_tree {
    spinlock_t                 kplt_lock HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    struct rb_root             kplt_root HSE_ALIGNED(SMP_CACHE_BYTES);
    struct kvdb_pfxlock_entry *kplt_ecache;
    uint                       kplt_entry_cnt;
    uint                       kplt_mcache_cnt;
    struct kvdb_pfxlock_entry *kplt_mcache;

    struct kvdb_pfxlock_entry  kplt_ecachev[16];
};

struct kvdb_pfxlock {
    struct kvdb_pfxlock_tree        kpl_tree[KVDB_PFXLOCK_NUM_TREES];
    struct workqueue_struct *       kpl_gc_wq;
    struct kvdb_pfxlock_gc          kpl_gc;
    u64                             kpl_gc_delay_ms;
    struct viewset *                kpl_txn_viewset;
};

/* clang-format on */

static void
kpl_gc_worker(struct work_struct *work);

static void
kvdb_pfxlock_entry_free(struct kvdb_pfxlock_tree *tree, struct kvdb_pfxlock_entry *entry)
{
    bool freeme = entry < tree->kplt_ecachev ||
                  entry >= (tree->kplt_ecachev + NELEM(tree->kplt_ecachev));

    if (!freeme) {
        *(void **)entry = tree->kplt_ecache;
        tree->kplt_ecache = entry;
        return;
    }

    if (tree->kplt_mcache_cnt < KVDB_MCACHE_CNT_MAX) {
        *(void **)entry = tree->kplt_mcache;
        tree->kplt_mcache = entry;
        tree->kplt_mcache_cnt++;
        return;
    }

    free(entry);
}

static struct kvdb_pfxlock_entry *
kvdb_pfxlock_entry_alloc(struct kvdb_pfxlock_tree *tree)
{
    struct kvdb_pfxlock_entry *e;

    e = tree->kplt_ecache;
    if (e) {
        tree->kplt_ecache = *(void **)e;
        return e;
    }

    e = tree->kplt_mcache;
    if (e) {
        tree->kplt_mcache = *(void **)e;
        tree->kplt_mcache_cnt--;
        return e;
    }

    return malloc(sizeof(*e));
}

merr_t
kvdb_pfxlock_create(struct viewset *txn_viewset, struct kvdb_pfxlock **pfxlock_out)
{
    struct kvdb_pfxlock *pfxlock;
    int i, j;

    pfxlock = aligned_alloc(alignof(*pfxlock), sizeof(*pfxlock));
    if (ev(!pfxlock))
        return merr(ENOMEM);

    memset(pfxlock, 0, sizeof(*pfxlock));

    for (i = 0; i < KVDB_PFXLOCK_NUM_TREES; i++) {
        struct kvdb_pfxlock_tree *tree = pfxlock->kpl_tree + i;

        spin_lock_init(&tree->kplt_lock);
        tree->kplt_root = RB_ROOT;

        /* Initialize kplt_ecache with all entries from the embedded cache.
         */
        for (j = NELEM(tree->kplt_ecachev) - 1; j >= 0; --j)
            kvdb_pfxlock_entry_free(tree, tree->kplt_ecachev + j);
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
    int i;

    if (HSE_UNLIKELY(!pfxlock))
        return;

    while (!cancel_delayed_work(&pfxlock->kpl_gc.kpl_gc_dwork))
        usleep(100);
    destroy_workqueue(pfxlock->kpl_gc_wq);

    for (i = 0; i < KVDB_PFXLOCK_NUM_TREES; i++) {
        struct kvdb_pfxlock_tree  *tree = &pfxlock->kpl_tree[i];
        struct kvdb_pfxlock_entry *entry, *next;

        rbtree_postorder_for_each_entry_safe(entry, next, &tree->kplt_root, kple_node) {
            kvdb_pfxlock_entry_free(tree, entry);
        }

        /* Cleanup cache */
        while (( entry = tree->kplt_mcache )) {
            tree->kplt_mcache = *(void **)entry;
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
    struct kvdb_pfxlock_entry *      entry;
    struct kvdb_pfxlock_tree        *tree;
    struct rb_root *                 root;
    bool                             insert;

    tree = pfxlock->kpl_tree + (hash % KVDB_PFXLOCK_NUM_TREES);

    root = &tree->kplt_root;
    link = &root->rb_node;
    parent = NULL;
    entry = NULL;

    spin_lock(&tree->kplt_lock);
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), kple_node);

        if (HSE_UNLIKELY(hash == entry->kple_hash))
            break;

        link = (hash < entry->kple_hash) ? &parent->rb_left : &parent->rb_right;
    }

    if (HSE_UNLIKELY(*link)) {
        entry = rb_entry(*link, typeof(*entry), kple_node);

        if (entry->kple_refcnt == 1 && *cookie) {
            /* Caller is the only txn holding this shared lock, fallthrough */
        } else if (entry->kple_refcnt > 1 || start_seqno <= entry->kple_end_seqno ||
            start_seqno <= entry->kple_end_seqno_excl) {

            spin_unlock(&tree->kplt_lock);
            return merr(ECANCELED);
        }

        /* This entry can be inherited since it was published before this txn began. Replace.
         */
        insert = false;
    } else {
        entry = kvdb_pfxlock_entry_alloc(tree);
        if (ev(!entry)) {
            spin_unlock(&tree->kplt_lock);
            return merr(ENOMEM);
        }

        memset(entry, 0, sizeof(*entry));
        insert = true;
    }

    entry->kple_hash = hash;
    entry->kple_end_seqno = KVDB_PFXLOCK_ACTIVE;
    entry->kple_end_seqno_excl = KVDB_PFXLOCK_ACTIVE;
    entry->kple_refcnt = 1;
    entry->kple_excl = true;

    if (insert) {
        kvdb_pfxlock_entry_add(parent, root, link, entry);
        tree->kplt_entry_cnt++;
    }
    spin_unlock(&tree->kplt_lock);

    *cookie = entry;
    return 0;
}

merr_t
kvdb_pfxlock_shared(struct kvdb_pfxlock *pfxlock, u64 hash, u64 start_seqno, void **cookie)
{
    struct rb_node **                link, *parent;
    struct rb_root *                 root;
    struct kvdb_pfxlock_entry *      entry;
    struct kvdb_pfxlock_tree        *tree;
    bool                             insert;

    tree = pfxlock->kpl_tree + (hash % KVDB_PFXLOCK_NUM_TREES);

    root = &tree->kplt_root;
    link = &root->rb_node;
    parent = NULL;
    entry = NULL;

    spin_lock(&tree->kplt_lock);
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), kple_node);

        if (hash == entry->kple_hash)
            break;

        link = (hash < entry->kple_hash) ? &parent->rb_left : &parent->rb_right;
    }

    if (*link) {
        if (entry->kple_excl || start_seqno <= entry->kple_end_seqno_excl) {
            spin_unlock(&tree->kplt_lock);
            return merr(ECANCELED);
        }

        /* This entry can be inherited since it was published before this txn began. Replace.
         */
        insert = false;
    } else {
        entry = kvdb_pfxlock_entry_alloc(tree);
        if (ev(!entry)) {
            spin_unlock(&tree->kplt_lock);
            return merr(ENOMEM);
        }

        memset(entry, 0, sizeof(*entry));
        insert = true;
    }

    entry->kple_hash = hash;
    entry->kple_end_seqno = KVDB_PFXLOCK_ACTIVE;
    entry->kple_refcnt++;

    if (insert) {
        kvdb_pfxlock_entry_add(parent, root, link, entry);
        tree->kplt_entry_cnt++;
    }
    spin_unlock(&tree->kplt_lock);

    *cookie = entry;
    return 0;
}

void
kvdb_pfxlock_seqno_pub(struct kvdb_pfxlock *pfxlock, u64 end_seqno, void *cookie)
{
    struct kvdb_pfxlock_entry *entry = (struct kvdb_pfxlock_entry *)cookie;
    int                        idx = entry->kple_hash % KVDB_PFXLOCK_NUM_TREES;
    spinlock_t *               spinlock = &pfxlock->kpl_tree[idx].kplt_lock;

    spin_lock(spinlock);

    if (--entry->kple_refcnt == 0) {
        entry->kple_end_seqno = end_seqno;

        if (entry->kple_excl) {
            entry->kple_end_seqno_excl = end_seqno;
            entry->kple_excl = false;
        }
    }

    spin_unlock(spinlock);
}

/* Garbage Collection
 */
void
kvdb_pfxlock_prune(struct kvdb_pfxlock *pfxlock)
{
    u64    txn_horizon = viewset_horizon(pfxlock->kpl_txn_viewset);
    int    i;
    char   distbuf[1024] HSE_MAYBE_UNUSED;
    size_t off HSE_MAYBE_UNUSED;

    for (i = 0, off = 0; i < KVDB_PFXLOCK_NUM_TREES; i++) {
        struct kvdb_pfxlock_tree  *tree = &pfxlock->kpl_tree[i];
        struct kvdb_pfxlock_entry *entry, *next;

#ifndef HSE_BUILD_RELEASE
        snprintf_append(distbuf, sizeof(distbuf), &off, " %u", tree->kplt_entry_cnt);
#endif

        spin_lock(&tree->kplt_lock);
        rbtree_postorder_for_each_entry_safe(entry, next, &tree->kplt_root, kple_node) {
            if (txn_horizon > entry->kple_end_seqno) {
                assert(entry->kple_refcnt == 0);
                tree->kplt_entry_cnt--;
                rb_erase(&entry->kple_node, &tree->kplt_root);
                kvdb_pfxlock_entry_free(tree, entry);
            }
        }
        spin_unlock(&tree->kplt_lock);
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
