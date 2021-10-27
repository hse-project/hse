/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 *
 * The pfxlock is a collection of rbtrees that maintain shared and exclusive locks. Each entry
 * contains an end_seqno which is set at the time of commit/abort. An entry can be deleted only
 * when there are no txns in kvdb which have a start seqno larger than the entry's end_seqno.
 * This is handled by the garbage collector thread.
 *
 * Ideally, each prefix hash would be used to select exactly one tree to contain the
 * prefix lock for that hash, and this approach works quite well if the distribution
 * of prefixes is fairly uniform across the array of trees.  However, in order to
 * mitigate lock contention should the distribution cluster around one or two trees,
 * we instead carve up the array of trees into disjoint equal-size ranges such that
 * the prefix hash is used to select the range.  A shared lock attempt may then acquire
 * a prefix lock from any tree within the range, while an exclusive lock attempt must
 * acquire the prefix lock from each and every tree within the range.
 */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>
#include <hse_util/timer.h>
#include <hse_util/mutex.h>
#include <hse_util/slab.h>

#include <rbtree.h>

#define MTF_MOCK_IMPL_kvdb_pfxlock

#include "kvdb_pfxlock.h"
#include "viewset.h"

/* clang-format off */

#define KVDB_PFXLOCK_RANGE_MAX  (6)
#define KVDB_PFXLOCK_TREES_MAX  (KVDB_PFXLOCK_RANGE_MAX * 83)
#define KVDB_PFXLOCK_CACHE_MAX  (1024)

struct kvdb_pfxlock_gc {
    struct delayed_work kpl_gc_dwork;
};

struct kvdb_pfxlock_entry {
    union {
        struct rb_node  kple_node;
        void           *kple_next;
    };
    u64            kple_hash;
    int            kple_refcnt;
    ushort         kple_treeidx;
    bool           kple_excl;
    bool           kple_stale;
    u64            kple_end_seqno;
    u64            kple_end_seqno_excl;
} HSE_ALIGNED(SMP_CACHE_BYTES);

struct kvdb_pfxlock_tree {
    struct mutex               kplt_lock HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    struct rb_root             kplt_root HSE_ALIGNED(SMP_CACHE_BYTES);
    struct kvdb_pfxlock_entry *kplt_ecache;
    volatile uint              kplt_entry_cnt;
    uint                       kplt_mcache_cnt;
    struct kvdb_pfxlock_entry *kplt_mcache;

    struct kvdb_pfxlock_entry  kplt_ecachev[30];
};

struct kvdb_pfxlock {
    struct kvdb_pfxlock_tree   kpl_tree[KVDB_PFXLOCK_TREES_MAX];
    struct workqueue_struct   *kpl_gc_wq;
    struct kvdb_pfxlock_gc     kpl_gc;
    u64                        kpl_gc_delay_ms;
    struct viewset            *kpl_txn_viewset;
};

/* clang-format on */

static void
kpl_gc_worker(struct work_struct *work);

static void
kvdb_pfxlock_entry_free(struct kvdb_pfxlock_tree *tree, struct kvdb_pfxlock_entry *entry)
{
    bool freeme = entry < tree->kplt_ecachev ||
                  entry >= (tree->kplt_ecachev + NELEM(tree->kplt_ecachev));

    entry->kple_hash = -1;

    if (!freeme) {
        entry->kple_next = tree->kplt_ecache;
        tree->kplt_ecache = entry;
        return;
    }

    if (tree->kplt_mcache_cnt < KVDB_PFXLOCK_CACHE_MAX) {
        entry->kple_next = tree->kplt_mcache;
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
        tree->kplt_ecache = e->kple_next;
        return e;
    }

    e = tree->kplt_mcache;
    if (e) {
        tree->kplt_mcache = e->kple_next;
        tree->kplt_mcache_cnt--;
        return e;
    }

    return aligned_alloc(alignof(*e), sizeof(*e));
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

    for (i = 0; i < KVDB_PFXLOCK_TREES_MAX; i++) {
        struct kvdb_pfxlock_tree *tree = pfxlock->kpl_tree + i;

        mutex_init(&tree->kplt_lock);
        tree->kplt_root = RB_ROOT;

        /* Initialize kplt_ecache with all entries from the embedded cache.
         */
        for (j = NELEM(tree->kplt_ecachev) - 1; j >= 0; --j)
            kvdb_pfxlock_entry_free(tree, tree->kplt_ecachev + j);
    }

    pfxlock->kpl_txn_viewset = txn_viewset;

    /* Set up GC worker for pfxlock
     */
    pfxlock->kpl_gc_delay_ms = 1500;
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

    for (i = 0; i < KVDB_PFXLOCK_TREES_MAX; i++) {
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

void *
kvdb_pfxlock_cookie_setexcl(void **cookie)
{
    return (void *)((uintptr_t)cookie | 1lu);
}

void **
kvdb_pfxlock_cookie_isexcl(void *cookie)
{
    bool isexcl = (((uintptr_t)cookie & 7lu) == 1);

    return isexcl ? (void *)((uintptr_t)cookie & ~7lu) : NULL;
}

uint
kvdb_pfxlock_hash2treeidx(uint64_t hash, bool shared)
{
    uint idx;

    idx = hash % (KVDB_PFXLOCK_TREES_MAX / KVDB_PFXLOCK_RANGE_MAX);
    idx *= KVDB_PFXLOCK_RANGE_MAX;

    if (shared) {
        uint cpu, node;

        cpu = hse_getcpu(&node);

        idx += (node % 2) * (KVDB_PFXLOCK_RANGE_MAX / 2);
        idx += cpu % (KVDB_PFXLOCK_RANGE_MAX / 2);
    }

    return idx;
}

merr_t
kvdb_pfxlock_excl(struct kvdb_pfxlock *pfxlock, u64 hash, u64 start_seqno, void **cookie)
{
    struct kvdb_pfxlock_entry *entry;
    struct kvdb_pfxlock_tree *tree;
    uint busyv[KVDB_PFXLOCK_RANGE_MAX];
    uint busyc, nbusy, cookiec;
    void **cookiev;
    uint delay, i;

    if (*cookie) {
        cookiev = kvdb_pfxlock_cookie_isexcl(*cookie);
        if (cookiev) {
            entry = cookiev[0];
            return (entry->kple_hash == hash) ? 0 : merr(EINVAL);
        }

        entry = *cookie;
        if (entry->kple_hash != hash)
            return merr(EINVAL);
    }

    cookiev = calloc(KVDB_PFXLOCK_RANGE_MAX, sizeof(*cookiev));
    if (!cookiev)
        return merr(ENOMEM);

    i = kvdb_pfxlock_hash2treeidx(hash, false); /* get range start index */

    for (nbusy = 0; nbusy < KVDB_PFXLOCK_RANGE_MAX; ++nbusy)
        busyv[nbusy] = nbusy + i;
    busyc = cookiec = 0;
    delay = 1;

    /* One of more shared locks for this prefix hash can appear in any tree
     * within the range given by the tree indices in busyv[].  Therefore,
     * we must acquire an exclusive lock on each tree within the range.
     *
     * Note that it seems extremely unlikely that an app will issue a prefix
     * delete while it has transactions inflight for keys with the prefix it
     * it trying to delete.
     */
    while (delay < USEC_PER_SEC / 10) {
        for (i = 0; i < nbusy; ++i) {
            struct rb_node **link, *parent;
            struct rb_root *root;
            int rc = 0;

            tree = pfxlock->kpl_tree + busyv[i];

            root = &tree->kplt_root;
            link = &root->rb_node;
            parent = NULL;
            entry = NULL;

            mutex_lock(&tree->kplt_lock);
            while (*link) {
                parent = *link;
                entry = rb_entry(parent, typeof(*entry), kple_node);

                if (HSE_UNLIKELY(hash == entry->kple_hash))
                    break;

                link = (hash < entry->kple_hash) ? &parent->rb_left : &parent->rb_right;
            }

            if (*link) {
                entry = rb_entry(*link, typeof(*entry), kple_node);

                if (start_seqno <= entry->kple_end_seqno ||
                    start_seqno <= entry->kple_end_seqno_excl) {
                    rc = ECANCELED;
                } else if (entry->kple_refcnt > 0) {
                    if (entry->kple_refcnt == 1 && *cookie == entry) {
                        /* Caller already holds this shared lock */
                        assert(!entry->kple_excl);
                        entry->kple_excl = true;
                        entry->kple_stale = false;
                    } else {
                        rc = EBUSY;
                    }
                } else {
                    entry->kple_refcnt = 1;
                    entry->kple_excl = true;
                    entry->kple_stale = false;
                }
            } else {
                entry = kvdb_pfxlock_entry_alloc(tree);
                if (entry) {
                    memset(entry, 0, sizeof(*entry));
                    entry->kple_hash = hash;
                    entry->kple_refcnt = 1;
                    entry->kple_treeidx = busyv[i];
                    entry->kple_excl = true;

                    kvdb_pfxlock_entry_add(parent, root, link, entry);
                    tree->kplt_entry_cnt++;
                }
            }
            mutex_unlock(&tree->kplt_lock);

            if (rc || !entry) {
                busyv[busyc++] = busyv[i];

                if (rc == ECANCELED)
                    goto errout;
                continue;
            }

            cookiev[cookiec++] = entry;
        }

        if (busyc == 0) {
            *cookie = kvdb_pfxlock_cookie_setexcl(cookiev);
            return 0;
        }

        nbusy = busyc;
        busyc = 0;

        usleep(delay);
        delay *= 10;
        ev(1);
    }

  errout:
    while (cookiec-- > 0) {
        entry = cookiev[cookiec];
        tree = pfxlock->kpl_tree + entry->kple_treeidx;

        mutex_lock(&tree->kplt_lock);
        entry->kple_refcnt--;
        entry->kple_excl = false;
        mutex_unlock(&tree->kplt_lock);
    }

    free(cookiev);
    ev(1);

    return merr(ECANCELED);
}

merr_t
kvdb_pfxlock_shared(struct kvdb_pfxlock *pfxlock, u64 hash, u64 start_seqno, void **cookie)
{
    struct kvdb_pfxlock_entry *entry;
    struct kvdb_pfxlock_tree *tree;
    struct rb_node **link, *parent;
    struct rb_root *root;
    merr_t err;

    tree = pfxlock->kpl_tree + kvdb_pfxlock_hash2treeidx(hash, true);

    root = &tree->kplt_root;
    link = &root->rb_node;
    parent = NULL;
    entry = NULL;
    err = 0;

    mutex_lock(&tree->kplt_lock);
    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), kple_node);

        if (hash == entry->kple_hash)
            break;

        link = (hash < entry->kple_hash) ? &parent->rb_left : &parent->rb_right;
    }

    if (HSE_LIKELY( *link )) {
        if (entry->kple_excl || start_seqno <= entry->kple_end_seqno_excl) {
            err = merr(ECANCELED);
        } else {
            entry->kple_refcnt++;
            entry->kple_stale = false;
            *cookie = entry;
        }
    } else {
        entry = kvdb_pfxlock_entry_alloc(tree);
        if (entry) {
            memset(entry, 0, sizeof(*entry));
            entry->kple_hash = hash;
            entry->kple_refcnt = 1;
            entry->kple_treeidx = tree - pfxlock->kpl_tree;

            kvdb_pfxlock_entry_add(parent, root, link, entry);
            tree->kplt_entry_cnt++;
            *cookie = entry;
        }

        err = entry ? 0 : merr(ENOMEM);
    }
    mutex_unlock(&tree->kplt_lock);

    return err;
}

void
kvdb_pfxlock_seqno_pub(struct kvdb_pfxlock *pfxlock, u64 end_seqno, void *cookie)
{
    struct kvdb_pfxlock_entry *entry;
    struct kvdb_pfxlock_tree *tree;
    void **cookiev;

    /* If cookie is for an exclusive lock then we must update the end
     * seqnos for each lock in the range.
     */
    cookiev = kvdb_pfxlock_cookie_isexcl(cookie);
    if (cookiev) {
        for (uint i = 0; i < KVDB_PFXLOCK_RANGE_MAX; ++i) {
            entry = cookiev[i];
            tree = pfxlock->kpl_tree + entry->kple_treeidx;

            mutex_lock(&tree->kplt_lock);
            entry->kple_refcnt--;
            entry->kple_excl = false;
            entry->kple_end_seqno = end_seqno;
            entry->kple_end_seqno_excl = end_seqno;
            mutex_unlock(&tree->kplt_lock);
        }

        free(cookiev);
        return;
    }

    /* cookie is for a shared lock...
     */
    entry = cookie;
    tree = pfxlock->kpl_tree + entry->kple_treeidx;

    mutex_lock(&tree->kplt_lock);
    entry->kple_refcnt--;
    if (end_seqno > entry->kple_end_seqno)
        entry->kple_end_seqno = end_seqno;
    mutex_unlock(&tree->kplt_lock);
}

/* Garbage Collection
 */
void
kvdb_pfxlock_prune(struct kvdb_pfxlock *pfxlock)
{
    u64    txn_horizon = viewset_horizon(pfxlock->kpl_txn_viewset);
    uint   skipped HSE_MAYBE_UNUSED = 0;
    uint   scanned HSE_MAYBE_UNUSED = 0;
    uint   pruned HSE_MAYBE_UNUSED = 0;

#ifndef HSE_BUILD_RELEASE
    uint64_t tstart = get_time_ns();
    char     distbuf[4096];
    size_t   off = 0;
#endif

    for (int i = 0; i < KVDB_PFXLOCK_TREES_MAX; i++) {
        struct kvdb_pfxlock_tree  *tree = &pfxlock->kpl_tree[i];
        struct kvdb_pfxlock_entry *entry, *next;

#ifndef HSE_BUILD_RELEASE
        snprintf_append(distbuf, sizeof(distbuf), &off, "%s%x",
                        (i % KVDB_PFXLOCK_RANGE_MAX) ? "" : " ",
                        tree->kplt_entry_cnt);
#endif

        if (tree->kplt_entry_cnt < 2) {
            skipped++;
            continue;
        }

        mutex_lock(&tree->kplt_lock);
        rbtree_postorder_for_each_entry_safe(entry, next, &tree->kplt_root, kple_node) {
            if (txn_horizon > entry->kple_end_seqno) {
                if (entry->kple_refcnt > 0) {
                    entry->kple_stale = false;
                    continue;
                }

                if (!entry->kple_stale) {
                    entry->kple_stale = true;
                    continue;
                }

                rb_erase(&entry->kple_node, &tree->kplt_root);
                kvdb_pfxlock_entry_free(tree, entry);
                tree->kplt_entry_cnt--;

                ++pruned;
            }

            ++scanned;
        }
        mutex_unlock(&tree->kplt_lock);
    }

#ifndef HSE_BUILD_RELEASE
    if (scanned > 0)
        log_info("%4luus %4u/%u %4u %4u  %s",
                 (get_time_ns() - tstart) / 1000,
                 skipped, KVDB_PFXLOCK_TREES_MAX,
                 scanned, pruned, distbuf);
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
