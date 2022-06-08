/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_cn_tree
#define MTF_MOCK_IMPL_cn_tree_compact
#define MTF_MOCK_IMPL_cn_tree_create
#define MTF_MOCK_IMPL_cn_tree_internal
#define MTF_MOCK_IMPL_cn_tree_iter
#define MTF_MOCK_IMPL_ct_view

#include <hse_util/alloc.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_util/mman.h>
#include <hse_util/list.h>
#include <hse_util/mutex.h>
#include <hse_util/logging.h>
#include <hse_util/assert.h>
#include <hse_util/parse_num.h>
#include <hse_util/atomic.h>
#include <hse_util/hlog.h>
#include <hse_util/table.h>
#include <hse_util/keycmp.h>
#include <hse_util/bin_heap.h>
#include <hse_util/log2.h>
#include <hse_util/workqueue.h>
#include <hse_util/compression_lz4.h>

#include <mpool/mpool.h>

#include <hse/limits.h>

#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cn_tree_view.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/kvs_rparams.h>

#include <cn/cn_cursor.h>

#include "cn_tree.h"
#include "cn_tree_compact.h"
#include "cn_tree_create.h"
#include "cn_tree_iter.h"
#include "cn_tree_internal.h"

#include "cn_mblocks.h"
#include "cn_metrics.h"
#include "kvset.h"
#include "cn_perfc.h"
#include "kcompact.h"
#include "blk_list.h"
#include "kv_iterator.h"
#include "wbt_reader.h"
#include "spill.h"
#include "kcompact.h"
#include "kblock_builder.h"
#include "vblock_builder.h"
#include "route.h"
#include "kvset_internal.h"

static struct kmem_cache *cn_node_cache HSE_READ_MOSTLY;

/* A struct kvstarts is-a struct kvset_view.
 */
struct kvstarts {
    struct kvset_view view; /* must be first field! */
    int               start;
};


static void
cn_setname(const char *name)
{
    pthread_setname_np(pthread_self(), name);
}

bool
cn_node_isleaf(const struct cn_tree_node *node);

/*----------------------------------------------------------------
 * SECTION: CN_TREE Traversal Utilities
 */

void
tree_iter_init_node(
    struct cn_tree *     tree,
    struct tree_iter *   iter,
    int                  traverse_order,
    struct cn_tree_node *node)
{
    iter->topdown = (traverse_order == TRAVERSE_TOPDOWN);
    iter->next = node;
    iter->prev = node->tn_parent;
    iter->end = node->tn_parent;
}

void
tree_iter_init(struct cn_tree *tree, struct tree_iter *iter, int traverse_order)
{
    tree_iter_init_node(tree, iter, traverse_order, tree->ct_root);
}

struct cn_tree_node *
tree_iter_next(struct cn_tree *tree, struct tree_iter *iter)
{
    struct cn_tree_node *visit = 0;
    struct cn_tree_node *prev = iter->prev;
    struct cn_tree_node *node = iter->next;
    uint fanout = tree->ct_fanout;
    uint child;

    while (node && node != iter->end && !visit) {
        /*
         * Use current node and previous node to figure out:
         *  - if we should visit node, and
         *  - where we go next.
         *
         * Local var 'child' indicates where to go next.
         */
        if (prev == node->tn_parent) {
            /*
             * Coming down from parent:
             * - start search for next node at child #0, and
             * - visit this node if in topdown mode.
             */
            child = 0;
            if (iter->topdown)
                visit = node;
        } else {
            /*
             * Coming up from child (i.e., prev is a child):
             * - start search for next node at prev's right sibling,
             * - visit this node if in bottomup mode and
             *   prev is the last non-null child, but defer
             *   the decision until we know if prev is last
             *   non-null child.
             */
            for (child = 1; child <= fanout; child++)
                if (prev == node->tn_childv[child - 1])
                    break;
        }

        /* Search for next non-null child. */
        while (child < fanout && !node->tn_childv[child])
            child++;

        /* Now make bottomup visit decision */
        if (!iter->topdown && child == fanout)
            visit = node;

        prev = node;
        node = (child < fanout ? node->tn_childv[child] : node->tn_parent);
    }

    iter->prev = prev;
    iter->next = node;

    return visit;
}

static size_t
cn_node_size(void)
{
    struct cn_tree_node *node HSE_MAYBE_UNUSED;
    size_t                    sz;

    sz = sizeof(*node) + sizeof(*node->tn_childv) * CN_FANOUT_MAX;

    return ALIGN(sz, __alignof__(*node));
}

static struct cn_tree_node *
cn_node_alloc(struct cn_tree *tree, uint level, uint offset)
{
    struct cn_tree_node *tn;

    tn = kmem_cache_zalloc(cn_node_cache);
    if (ev(!tn))
        return NULL;

    if (ev(hlog_create(&tn->tn_hlog, HLOG_PRECISION))) {
        kmem_cache_free(cn_node_cache, tn);
        return NULL;
    }

    INIT_LIST_HEAD(&tn->tn_kvset_list);
    INIT_LIST_HEAD(&tn->tn_rspills);
    mutex_init(&tn->tn_rspills_lock);

    atomic_init(&tn->tn_compacting, 0);
    atomic_init(&tn->tn_busycnt, 0);

    tn->tn_tree = tree;
    tn->tn_loc.node_level = level;
    tn->tn_loc.node_offset = offset;

    tn->tn_size_max = tree->rp->cn_node_size_hi << 20;

    return tn;
}

void
cn_node_free(struct cn_tree_node *tn)
{
    if (tn) {
        hlog_destroy(tn->tn_hlog);
        kmem_cache_free(cn_node_cache, tn);
    }
}

bool
cn_node_isleaf(const struct cn_tree_node *tn)
{
    return tn->tn_parent && tn->tn_childc == 0;
}

bool
cn_node_isroot(const struct cn_tree_node *tn)
{
    return !tn->tn_parent;
}

/**
 * cn_tree_create() - add node to tree during initial tree creation
 *
 * This function is only to be used when building a cn_tree during start up.
 * To add a node during a spill operation, use cn_tree_add_kvset_to_node().
 */
merr_t
cn_tree_create(
    struct cn_tree **   handle,
    const char         *kvsname,
    u32                 cn_cflags,
    struct kvs_cparams *cp,
    struct kvdb_health *health,
    struct kvs_rparams *rp)
{
    struct cn_tree *tree;
    merr_t err;

    *handle = NULL;

    assert(health);

    if (ev(cp->fanout < CN_FANOUT_MIN || cp->fanout > CN_FANOUT_MAX))
        return merr(EINVAL);

    if (ev(cp->pfx_len > HSE_KVS_PFX_LEN_MAX))
        return merr(EINVAL);

    tree = alloc_aligned(sizeof(*tree), __alignof__(*tree));
    if (ev(!tree))
        return merr(ENOMEM);

    memset(tree, 0, sizeof(*tree));
    tree->ct_cp = cp;
    tree->ct_fanout = cp->fanout;
    tree->ct_pfx_len = cp->pfx_len;
    tree->ct_sfx_len = cp->sfx_len;
    tree->ct_kvdb_health = health;
    tree->rp = rp;

    tree->ct_root = cn_node_alloc(tree, 0, 0);
    if (ev(!tree->ct_root)) {
        free_aligned(tree);
        return merr(ENOMEM);
    }

    if (kvsname) {
        tree->ct_route_map = route_map_create(cp, kvsname);
        if (!tree->ct_route_map) {
            cn_tree_destroy(tree);
            return merr(ENOMEM);
        }
    }

    for (uint i = 0; i < cp->fanout; i++) {
        struct cn_tree_node *tn;

        tn = cn_node_alloc(tree, 1, i);
        if (!tn) {
            cn_tree_destroy(tree);
            return merr(ENOMEM);
        }

        tn->tn_parent = tree->ct_root;
        tree->ct_root->tn_childv[i] = tn;
        tree->ct_root->tn_childc += 1;

        if (tree->ct_route_map) {
            /* A cn_tree_node can exist without a corresponding route_node until we have
             * node splits.
             * TODO: add tn->tn_route_node NULL check once we have node splits.
             */
            tn->tn_route_node = route_map_insert(tree->ct_route_map, tn, NULL, 0, i);
        }
    }

    tree->ct_i_nodec = 1;
    tree->ct_l_nodec = cp->fanout;
    tree->ct_lvl_max = 1;

    err = rmlock_init(&tree->ct_lock);
    if (err) {
        cn_tree_destroy(tree);
        return err;
    }

    /* setup cn_tree handle and return */
    *handle = tree;

    return 0;
}

static void
cn_node_destroy_cb(struct cn_work *work)
{
    struct kvset_list_entry *le, *tmp;
    struct cn_tree_node *node;

    node = container_of(work, struct cn_tree_node, tn_destroy_work);

    list_for_each_entry_safe(le, tmp, &node->tn_kvset_list, le_link)
        kvset_put_ref(le->le_kvset);

    cn_node_free(node);
}

void
cn_tree_destroy(struct cn_tree *tree)
{
    struct cn_tree_node *node;
    struct tree_iter iter;

    if (!tree)
        return;

    /*
     * Bottom up traversal is safe in the sense that nodes can be
     * deleted while iterating.
     */
    tree_iter_init(tree, &iter, TRAVERSE_BOTTOMUP);

    while (NULL != (node = tree_iter_next(tree, &iter))) {
        if (node->tn_route_node)
            route_map_delete(tree->ct_route_map, node->tn_route_node);
        cn_work_submit(tree->cn, cn_node_destroy_cb, &node->tn_destroy_work);
    }

    /* Wait for async work to complete...
     */
    cn_ref_wait(tree->cn);

    rmlock_destroy(&tree->ct_lock);
    route_map_destroy(tree->ct_route_map);
    free_aligned(tree);
}

void
cn_tree_setup(
    struct cn_tree *    tree,
    struct mpool *      ds,
    struct cn *         cn,
    struct kvs_rparams *rp,
    struct cndb *       cndb,
    u64                 cnid,
    struct cn_kvdb *    cn_kvdb)
{
    tree->ds = ds;
    tree->cn = cn;
    tree->rp = rp;
    tree->cndb = cndb;
    tree->cnid = cnid;
    tree->cn_kvdb = cn_kvdb;
}

struct cn *
cn_tree_get_cn(const struct cn_tree *tree)
{
    return tree->cn;
}

struct cn_kvdb *
cn_tree_get_cnkvdb(const struct cn_tree *tree)
{
    return tree->cn_kvdb;
}

struct mpool *
cn_tree_get_ds(const struct cn_tree *tree)
{
    return tree->ds;
}

struct kvs_rparams *
cn_tree_get_rp(const struct cn_tree *tree)
{
    return tree->rp;
}

struct cndb *
cn_tree_get_cndb(const struct cn_tree *tree)
{
    return tree->cndb;
}

u64
cn_tree_get_cnid(const struct cn_tree *tree)
{
    return tree->cnid;
}

struct kvs_cparams *
cn_tree_get_cparams(const struct cn_tree *tree)
{
    return tree->ct_cp;
}

bool
cn_tree_is_replay(const struct cn_tree *tree)
{
    return cn_is_replay(tree->cn);
}

/*----------------------------------------------------------------
 * SECTION: CN_TREE Internal Functions to map node locations to node pointers
 */

/* Caller should hold tree read lock if consistent stats are desired */
void
cn_node_stats_get(const struct cn_tree_node *tn, struct cn_node_stats *s_out)
{
    *s_out = tn->tn_ns;
}

/* Helper for cn_tree_samp_* functions.  Do not use directly. */
static void
tn_samp_clear(struct cn_tree_node *tn)
{
    if (!cn_node_isleaf(tn) && tn->tn_hlog) {
        hlog_destroy(tn->tn_hlog);
        tn->tn_hlog = 0;
    } else if (tn->tn_hlog) {
        hlog_reset(tn->tn_hlog);
    }

    memset(&tn->tn_ns, 0, sizeof(tn->tn_ns));
    memset(&tn->tn_samp, 0, sizeof(tn->tn_samp));

    tn->tn_biggest_kvset = 0;
    tn->tn_update_incr_dgen = 0;
}

/* Helper for cn_tree_samp_* functions.  Do not use directly. */
static bool
tn_samp_update_incr(struct cn_tree_node *tn, struct kvset *kvset, bool force)
{
    u64 dgen = kvset_get_dgen(kvset);

    if (!force && dgen <= tn->tn_update_incr_dgen)
        return false;

    if (tn->tn_hlog)
        hlog_union(tn->tn_hlog, kvset_get_hlog(kvset));

    kvset_stats_add(kvset_statsp(kvset), &tn->tn_ns.ns_kst);

    if (tn->tn_update_incr_dgen < dgen)
        tn->tn_update_incr_dgen = dgen;

    if (tn->tn_biggest_kvset < cn_ns_keys(&tn->tn_ns))
        tn->tn_biggest_kvset = cn_ns_keys(&tn->tn_ns);

    return true;
}

/* Helper for cn_tree_samp_* functions.  Do not use directly. */
static void
tn_samp_update_finish(struct cn_tree_node *tn)
{
    struct cn_node_stats *s = &tn->tn_ns;
    const uint            pct_scale = 1024;
    uint                  pct;
    const uint64_t num_keys = cn_ns_keys(s);

    /* Use hlog to estimate number of unique keys, but protect
     * against estimated values outside the valid range.
     * If no hlog, assume all keys are unique.
     */
    if (tn->tn_hlog) {
        s->ns_keys_uniq = hlog_card(tn->tn_hlog);
        if (s->ns_keys_uniq < tn->tn_biggest_kvset)
            s->ns_keys_uniq = tn->tn_biggest_kvset;
        else if (s->ns_keys_uniq > num_keys)
            s->ns_keys_uniq = num_keys;
    } else {
        s->ns_keys_uniq = num_keys;
    }

    /* In the event that a node is composed of only prefix tombstones, it will
     * have 0 keys. Therefore protect against a division-by-zero error.
     */
    if (num_keys > 0) {
        pct = pct_scale * s->ns_keys_uniq / num_keys;
    } else {
        pct = pct_scale;
    }

    {
        u64 cur_alen = s->ns_kst.kst_kalen;
        u64 new_wlen = s->ns_kst.kst_kwlen * pct / pct_scale;
        enum hse_mclass mclass;
        u64 new_clen;

        mclass = cn_tree_node_mclass(tn, HSE_MPOLICY_DTYPE_KEY);
        assert(mclass != HSE_MCLASS_INVALID);
        new_clen = kbb_estimate_alen(tn->tn_tree->cn, new_wlen, mclass);
        s->ns_kclen = min(new_clen, cur_alen);
    }

    {
        u64 cur_alen = s->ns_kst.kst_valen;
        u64 cur_wlen = s->ns_kst.kst_vulen * pct / pct_scale;
        enum hse_mclass mclass;
        u64 new_clen;

        mclass = cn_tree_node_mclass(tn, HSE_MPOLICY_DTYPE_VALUE);
        assert(mclass != HSE_MCLASS_INVALID);
        new_clen = vbb_estimate_alen(tn->tn_tree->cn, cur_wlen, mclass);
        s->ns_vclen = min(new_clen, cur_alen);
    }

    s->ns_pcap = min_t(u64, U16_MAX, 100 * cn_ns_clen(s) / tn->tn_size_max);

    tn->tn_samp.r_alen = 0;
    tn->tn_samp.r_wlen = 0;

    if (cn_node_isleaf(tn)) {
        tn->tn_samp.i_alen = 0;
        tn->tn_samp.l_alen = cn_ns_alen(s);
        tn->tn_samp.l_good = cn_ns_clen(s);
    } else {
        tn->tn_samp.i_alen = cn_ns_alen(s);
        tn->tn_samp.l_alen = 0;
        tn->tn_samp.l_good = 0;

        if (cn_node_isroot(tn)) {
            tn->tn_samp.r_alen = cn_ns_alen(s);
            tn->tn_samp.r_wlen = cn_ns_wlen(s);
        }
    }
}

/* This function must be serialized with other cn_tree_samp_* functions. */
static void
cn_tree_samp_update_compact(struct cn_tree *tree, struct cn_tree_node *tn)
{
    bool                     need_finish = false;
    struct cn_samp_stats     orig = tn->tn_samp;
    struct kvset_list_entry *le;

    tn_samp_clear(tn);

    list_for_each_entry (le, &tn->tn_kvset_list, le_link)
        if (tn_samp_update_incr(tn, le->le_kvset, true))
            need_finish = true;

    if (need_finish)
        tn_samp_update_finish(tn);

    tree->ct_samp.r_alen += tn->tn_samp.r_alen - orig.r_alen;
    tree->ct_samp.r_wlen += tn->tn_samp.r_wlen - orig.r_wlen;
    tree->ct_samp.i_alen += tn->tn_samp.i_alen - orig.i_alen;
    tree->ct_samp.l_alen += tn->tn_samp.l_alen - orig.l_alen;
    tree->ct_samp.l_good += tn->tn_samp.l_good - orig.l_good;
}

/* This function must be serialized with other cn_tree_samp_* functions.
 * It is used for ingest from c0 into root node and for ingesting
 * into children after spill operations.
 */
static void
cn_tree_samp_update_ingest(struct cn_tree *tree, struct cn_tree_node *tn)
{
    struct cn_samp_stats     orig;
    struct kvset_list_entry *le;

    orig = tn->tn_samp;

    le = list_first_entry_or_null(&tn->tn_kvset_list, typeof(*le), le_link);
    if (!le)
        return;

    orig = tn->tn_samp;

    if (tn_samp_update_incr(tn, le->le_kvset, false))
        tn_samp_update_finish(tn);

    tree->ct_samp.r_alen += tn->tn_samp.r_alen - orig.r_alen;
    tree->ct_samp.r_wlen += tn->tn_samp.r_wlen - orig.r_wlen;
    tree->ct_samp.i_alen += tn->tn_samp.i_alen - orig.i_alen;
    tree->ct_samp.l_alen += tn->tn_samp.l_alen - orig.l_alen;
    tree->ct_samp.l_good += tn->tn_samp.l_good - orig.l_good;
}

/* This function must be serialized with other cn_tree_samp_* functions. */
static void
cn_tree_samp_update_spill(struct cn_tree *tree, struct cn_tree_node *tn)
{
    uint fanout = tree->ct_cp->fanout;
    uint i;

    /* A spill is esentially a compaction with an ingest into each child */

    cn_tree_samp_update_compact(tree, tn);

    for (i = 0; i < fanout; i++)
        if (tn->tn_childv[i])
            cn_tree_samp_update_ingest(tree, tn->tn_childv[i]);
}

/* This function must be serialized with other cn_tree_samp_* functions. */
void
cn_tree_samp_init(struct cn_tree *tree)
{
    struct tree_iter     iter;
    struct cn_tree_node *tn;

    /* cn_tree_samp_update_compact() does a full recomputation
     * of samp stats, so use it to initalize tree samp stats.
     */
    memset(&tree->ct_samp, 0, sizeof(tree->ct_samp));

    tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);
    while (NULL != (tn = tree_iter_next(tree, &iter)))
        cn_tree_samp_update_compact(tree, tn);
}

/* This function must be serialized with other cn_tree_samp_* functions
 * if a consistent set of stats is desired.
 */
void
cn_tree_samp(const struct cn_tree *tree, struct cn_samp_stats *s_out)

{
    *s_out = tree->ct_samp;
}

/**
 * cn_tree_insert_kvset - add kvset to tree during initialization
 * @tree:  tree under construction
 * @kvset: new kvset to add to tree
 * @level: node level
 * @offset: node offset
 *
 * This function is used during initialization to insert a kvset at the
 * correct position in node (@level,@offset) of the cn tree.
 *
 * NOTE: It is not intended to be used to update a node after compaction or
 * ingest operations.
 */
merr_t
cn_tree_insert_kvset(struct cn_tree *tree, struct kvset *kvset, uint level, uint offset)
{
    struct kvset_list_entry *entry;
    struct list_head *       head;
    struct cn_tree_node *    node;
    u64                      dgen;

    assert(level <= 1);
    assert(tree->ct_root);
    assert(offset < tree->ct_root->tn_childc);

    node = level == 0 ? tree->ct_root : tree->ct_root->tn_childv[offset];

    dgen = kvset_get_dgen(kvset);

    list_for_each (head, &node->tn_kvset_list) {
        entry = list_entry(head, typeof(*entry), le_link);
        if (dgen > kvset_get_dgen(entry->le_kvset))
            break;
        assert(dgen != kvset_get_dgen(entry->le_kvset));
    }

    kvset_list_add_tail(kvset, head);

    return 0;
}

/**
 * struct vtc_bkt - view table cache bucket
 * @lock:  protects all fields in the bucket
 * @cnt:   number of tables cached in the bucket
 * @max:   max number of tables in the bucket
 * @head:  ptr to singly-linked list of tables
 *
 * The view table cache consists of an array of per-cpu buckets
 * which cache large preallocated tables for use in acquiring
 * references and metadata on all the kvsets in the cn tree.
 * The tables are allocated sufficiently large to avoid table
 * grow operations during tree traversal.
 */
struct vtc_bkt {
    spinlock_t    lock HSE_ACP_ALIGNED;
    uint          cnt;
    uint          max;
    struct table *head;
};

static struct vtc_bkt vtc[16];

static struct table *
vtc_alloc(void)
{
    struct vtc_bkt *bkt;
    struct table *  tab;
    uint            cnt;

    bkt = vtc + (hse_getcpu(NULL) % NELEM(vtc));

    spin_lock(&bkt->lock);
    tab = bkt->head;
    if (tab) {
        bkt->head = tab->priv;
        --bkt->cnt;
    }
    spin_unlock(&bkt->lock);

    if (tab)
        return table_reset(tab);

    /* A 64K table should accomodate a tree with 4096 kvsets
     * before needing to be grown.
     */
    cnt = (64 * 1024) / sizeof(struct kvstarts);

    return table_create(cnt, sizeof(struct kvstarts), false);
}

static void
vtc_free(struct table *tab)
{
    struct vtc_bkt *bkt;

    bkt = vtc + (hse_getcpu(NULL) % NELEM(vtc));

    spin_lock(&bkt->lock);
    if (bkt->cnt < bkt->max) {
        tab->priv = bkt->head;
        bkt->head = tab;
        tab = NULL;
        ++bkt->cnt;
    }
    spin_unlock(&bkt->lock);

    if (ev(tab))
        table_destroy(tab);
}

static void
kvset_view_free(void *arg)
{
    struct kvset_view *v = arg;

    if (v->kvset)
        kvset_put_ref(v->kvset);
}

void
cn_tree_view_destroy(struct table *view)
{
    table_apply(view, kvset_view_free);
    vtc_free(view);
}

merr_t
cn_tree_view_create(struct cn *cn, struct table **view_out)
{
    struct table *           view;
    struct tree_iter         iter;
    struct cn_tree_node *    node;
    void *                   lock;
    struct kvset_list_entry *le;
    struct cn_tree *         tree = cn_get_tree(cn);
    merr_t                   err = 0;
    struct kvset_view *      s;

    view = vtc_alloc();
    if (ev(!view))
        return merr(ENOMEM);

    tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);
    node = tree_iter_next(tree, &iter);

    rmlock_rlock(&tree->ct_lock, &lock);
    while (node) {
        u32 level = node->tn_loc.node_level;

        /* create an entry for the node */
        s = table_append(view);
        if (ev(!s)) {
            err = merr(ENOMEM);
            break;
        }

        s->kvset = 0;
        s->node_loc = node->tn_loc;

        list_for_each_entry (le, &node->tn_kvset_list, le_link) {
            struct kvset *kvset = le->le_kvset;

            s = table_append(view);
            if (ev(!s)) {
                err = merr(ENOMEM);
                break;
            }

            kvset_get_ref(kvset);
            s->kvset = kvset;
            s->node_loc = node->tn_loc;
        }

        if (err)
            break;

        if (level > 0)
            rmlock_yield(&tree->ct_lock, &lock);

        node = tree_iter_next(tree, &iter);
    }
    rmlock_runlock(lock);

    if (err) {
        cn_tree_view_destroy(view);
        view = NULL;
    }

    *view_out = view;

    return err;
}

void
cn_tree_preorder_walk(
    struct cn_tree *          tree,
    enum kvset_order          kvset_order,
    cn_tree_walk_callback_fn *callback,
    void *                    callback_rock)
{
    struct tree_iter         iter;
    struct cn_tree_node *    node;
    struct kvset_list_entry *le;
    void *                   lock;
    bool                     stop = false;

    tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);

    rmlock_rlock(&tree->ct_lock, &lock);
    while (NULL != (node = tree_iter_next(tree, &iter))) {
        bool empty_node = true;

        if (kvset_order == KVSET_ORDER_NEWEST_FIRST) {

            /* newest first ==> head to tail */
            list_for_each_entry (le, &node->tn_kvset_list, le_link) {
                empty_node = false;
                stop = callback(callback_rock, tree, node, &node->tn_loc, le->le_kvset);
                if (stop)
                    goto unlock;
            }
        } else {
            /* oldest first ==> tail to head */
            list_for_each_entry_reverse (le, &node->tn_kvset_list, le_link) {
                empty_node = false;
                stop = callback(callback_rock, tree, node, &node->tn_loc, le->le_kvset);
                if (stop)
                    goto unlock;
            }
        }

        /* end of node */
        if (!empty_node) {
            stop = callback(callback_rock, tree, node, &node->tn_loc, 0);
            if (stop)
                goto unlock;
        }
    }

unlock:
    if (!stop) {
        /* end of tree */
        callback(callback_rock, tree, 0, 0, 0);
    }

    rmlock_runlock(lock);
}

struct cn_tree_node *
cn_tree_node_lookup(struct cn_tree *tree, const void *key, uint keylen)
{
    struct route_node *node;

    assert(tree && key);

    node = route_map_lookup(tree->ct_route_map, key, keylen);
    if (!node)
        return NULL;

    assert(node->rtn_tnode);

    return node->rtn_tnode;
}

struct route_node *
cn_tree_route_get(struct cn_tree *tree, const void *key, uint keylen)
{
    struct route_node *node;
    void *lock;

    assert(tree && key);

    rmlock_rlock(&tree->ct_lock, &lock);
    node = route_map_lookup(tree->ct_route_map, key, keylen);
    rmlock_runlock(lock);

    return node;
}

/**
 * cn_tree_lookup() - search cn tree for a key
 * @tree: cn tree
 * @pc:   perf counters
 * @kt:   key to search for
 * @seq:  view sequence number
 * @res:  (output) result (found value, found tomb, or not found)
 * @kbuf: (output) key if this is a prefix probe
 * @vbuf: (output) value if result @res == %FOUND_VAL or %FOUND_MULTIPLE
 *
 *
 * The following table shows the how the search descends the tree for
 * non-suffixed trees.
 *
 *   is tree     kt->kt_len vs
 *   a prefix    vs
 *   tree?       tree's pfx_len          descend by hash of:
 *   --------    -----------------       -------------------
 *     no        n/a                 ==> full key
 *     yes       kt_len <  pfx_len   ==> full key [1]
 *     yes       kt_len == pfx_len   ==> full key [2]
 *     yes       kt_len >  pfx_len   ==> prefix of key, then full key [3]
 *
 * Notes:
 *  [1]: Keys that are shorter than tree's prefix len are always
 *       stored by hash of full key.
 *
 *  [2]: Keys whose length is equal to the tree's prefix len can use
 *       the prefix hash or the full hash logic.  cn_tree_lookup() uses
 *       the full hash logic to take advantage of the pre-computed hash
 *       in @kt->kt_hash.
 *
 *  [3]: Descend by prefix until a certain depth, then switch to
 *       descend by full key (spill logic, of course, must use same
 *       logic).
 *
 * If the tree is suffixed,
 *
 *  [1]: Keys have to be at least (pfx_len + sfx_len) bytes long.
 *
 *  [2]: A full key hash is replaced with a hash over (keylen - sfx_len) bytes
 *       of the key.
 */
merr_t
cn_tree_lookup(
    struct cn_tree *     tree,
    struct perfc_set *   pc,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct query_ctx *   qctx,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf)
{
    struct cn_tree_node *    node;
    struct key_disc          kdisc;
    void *                   lock;
    merr_t                   err;
    uint                     pc_nkvset;
    uint                     pc_depth;
    enum kvdb_perfc_sidx_cnget pc_cidx;
    u64                      pc_start;
    void *                   wbti;

    __builtin_prefetch(tree);

    *res = NOT_FOUND;
    err = 0;

    pc_cidx = PERFC_LT_CNGET_GET_L5 + 1;
    pc_depth = pc_nkvset = 0;

    pc_start = perfc_lat_startu(pc, PERFC_LT_CNGET_GET);
    if (pc_start > 0) {
        if (perfc_ison(pc, PERFC_LT_CNGET_GET_L0))
            pc_cidx = PERFC_LT_CNGET_GET_L0;
    }

    wbti = NULL;
    if (qctx->qtype == QUERY_PROBE_PFX) {
        err = kvset_wbti_alloc(&wbti);
        if (ev(err))
            return err;
    }

    key_disc_init(kt->kt_data, kt->kt_len, &kdisc);

    rmlock_rlock(&tree->ct_lock, &lock);
    node = tree->ct_root;

    while (node) {
        struct kvset_list_entry *le;

        /* Search kvsets from newest to oldest (head to tail).
         * If an error occurs or a key is found, return immediately.
         */
        list_for_each_entry (le, &node->tn_kvset_list, le_link) {
            struct kvset *kvset;

            kvset = le->le_kvset;
            ++pc_nkvset;

            switch (qctx->qtype) {
                case QUERY_GET:
                    err = kvset_lookup(kvset, kt, &kdisc, seq, res, vbuf);
                    if (err || *res != NOT_FOUND) {
                        rmlock_runlock(lock);

                        if (pc_cidx < PERFC_LT_CNGET_GET_L5 + 1)
                            perfc_lat_record(pc, pc_cidx, pc_start);
                        goto done;
                    }
                    break;

                case QUERY_PROBE_PFX:
                    err = kvset_pfx_lookup(kvset, kt, &kdisc, seq, res, wbti, kbuf, vbuf, qctx);
                    if (err || qctx->seen > 1 || *res == FOUND_PTMB) {
                        rmlock_runlock(lock);

                        ev(err);
                        goto done;
                    }
                    break;
            }
        }

        if (node != tree->ct_root)
            break;

        node = cn_tree_node_lookup(tree, kt->kt_data, kt->kt_len);

        ++pc_depth;
        ++pc_cidx;
    }
    rmlock_runlock(lock);

done:
    if (wbti) {
        perfc_lat_record(pc, PERFC_LT_CNGET_PROBE_PFX, pc_start);
        kvset_wbti_free(wbti);
    } else {
        if (pc_start > 0) {
            uint pc_cidx_lt = (*res == NOT_FOUND) ? PERFC_LT_CNGET_MISS : PERFC_LT_CNGET_GET;

            perfc_lat_record(pc, pc_cidx_lt, pc_start);
            perfc_rec_sample(pc, PERFC_DI_CNGET_DEPTH, pc_depth);
            perfc_rec_sample(pc, PERFC_DI_CNGET_NKVSET, pc_nkvset);
        }
    }

    perfc_inc(pc, *res);

    return err;
}

u64
cn_tree_initial_dgen(const struct cn_tree *tree)
{
    return tree->ct_dgen_init;
}

void
cn_tree_set_initial_dgen(struct cn_tree *tree, u64 dgen)
{
    tree->ct_dgen_init = dgen;
}

bool
cn_tree_is_capped(const struct cn_tree *tree)
{
    return cn_is_capped(tree->cn);
}

/* returns true if token acquired */
bool
cn_node_comp_token_get(struct cn_tree_node *tn)
{
    return atomic_cas(&tn->tn_compacting, 0, 1);
}

void
cn_node_comp_token_put(struct cn_tree_node *tn)
{
    bool b HSE_MAYBE_UNUSED;

    b = atomic_cas(&tn->tn_compacting, 1, 0);
    assert(b);
}

static void
cn_comp_release(struct cn_compaction_work *w)
{
    assert(w->cw_node);

    /* If this work is on the concurrent spill list then it must also
     * be at the head of the list.  If not, it means that the caller
     * applied a spill operation out-of-order such that a reader can
     * now read an old/stale key/value when it should have read a
     * newer one, meaning the kvdb is corrupted.
     */
    if (w->cw_rspill_conc) {
        struct cn_compaction_work *tmp HSE_MAYBE_UNUSED;

        mutex_lock(&w->cw_node->tn_rspills_lock);
        tmp = list_first_entry_or_null(&w->cw_node->tn_rspills, typeof(*tmp), cw_rspill_link);
        assert(tmp == w);
        list_del_init(&w->cw_rspill_link);
        mutex_unlock(&w->cw_node->tn_rspills_lock);
    }

    if (w->cw_err) {
        struct kvset_list_entry *le;
        uint kx;

        /* unmark input kvsets */
        le = w->cw_mark;
        for (kx = 0; kx < w->cw_kvset_cnt; kx++) {
            assert(le);
            assert(kvset_get_workid(le->le_kvset) != 0);
            kvset_set_workid(le->le_kvset, 0);
            le = list_prev_entry(le, le_link);
        }
    }

    if (w->cw_have_token)
        cn_node_comp_token_put(w->cw_node);

    perfc_inc(w->cw_pc, PERFC_BA_CNCOMP_FINISH);

    if (HSE_UNLIKELY(!w->cw_completion)) {
        free(w);
        return;
    }

    /* After this function returns the job will be disassociated
     * from its thread and hence becomes a zombie.  Do not touch
     * *w afterward as it may have already been freed.
     */
    w->cw_completion(w);
}

/**
 * cn_tree_capped_evict() - evict unneeded vblock pages
 * @tree:   cn_tree pointer
 * @first:  ptr to youngest kvset list entry
 * @last:   ptr to oldest kvset list entry
 *
 * This function attempts to identify pages in RAM from vblocks in a
 * capped kvs that are unlikely to be needed and advises the kernel
 * of their suitability for eviction.
 *
 * It scans the list from oldest to youngest kvset looking for kvsets
 * that have expired.  It evicts at most one kvset per scan, and tries
 * to remember where it left off to minimize subsequent scans.
 *
 * Note that this function should only be called within the context
 * of cn_tree_capped_compact() which ensures that the list of kvsets
 * from first to last is not empty and will not be modified.
 */
static void
cn_tree_capped_evict(
    struct cn_tree *         tree,
    struct kvset_list_entry *first,
    struct kvset_list_entry *last)
{
    struct kvset_list_entry *prev;
    struct kvset *           kvset;
    u64                      now;
    u64                      ttl;
    u64                      ctime;

    now = get_time_ns();

    if (tree->ct_capped_ttl > now)
        return;

    if (tree->ct_capped_dgen > kvset_get_dgen(last->le_kvset))
        last = tree->ct_capped_le;

    ttl = tree->rp->capped_evict_ttl * NSEC_PER_SEC;
    kvset = last->le_kvset;

    ctime = kvset_ctime(kvset);
    if (ctime + ttl > now) {
        tree->ct_capped_ttl = ctime + ttl;
        return;
    }

    if (last != first) {
        prev = list_prev_entry(last, le_link);
        tree->ct_capped_dgen = kvset_get_dgen(prev->le_kvset);
        tree->ct_capped_ttl = kvset_ctime(prev->le_kvset) + ttl;
        tree->ct_capped_le = prev;
    }

    kvset_madvise_vmaps(kvset, MADV_DONTNEED);
}

/**
 * cn_tree_capped_compact() - compact a capped tree
 * @tree:   cn_tree pointer
 *
 * This function trims expired kvsets from the tail of the capped kvs.
 */
void
cn_tree_capped_compact(struct cn_tree *tree)
{
    struct kvset_list_entry *le, *next, *mark;
    struct kvset_list_entry *first, *last;
    struct cn_tree_node *    node;
    struct list_head *       head, retired;

    u8     pt_key[sizeof(tree->ct_last_ptomb)];
    void * lock;
    merr_t err;
    u64    txid;
    u64    horizon;
    u64    pt_seq;
    uint   pt_len;
    uint   kvset_cnt;

    node = tree->ct_root;
    head = &node->tn_kvset_list;

    /* While holding the tree read lock we acquire the first and last
     * kvset list entries.  As long as we do not access first->prev
     * nor last->next we can safely iterate between them without
     * holding the tree lock.
     */
    rmlock_rlock(&tree->ct_lock, &lock);
    pt_seq = tree->ct_last_ptseq;
    pt_len = tree->ct_last_ptlen;
    memcpy(pt_key, tree->ct_last_ptomb, pt_len);

    first = list_first_entry(head, typeof(*first), le_link);
    last = list_last_entry(head, typeof(*last), le_link);
    rmlock_runlock(lock);

    if (ev(first == last))
        return;

    horizon = cn_get_seqno_horizon(tree->cn);
    if (horizon > pt_seq)
        horizon = pt_seq;

    kvset_cnt = 0;
    mark = NULL;

    /* Step 1: Identify the kvsets that can be retired.
     */
    for (le = last; le != first; le = list_prev_entry(le, le_link)) {
        const void *max_key = NULL;
        uint  max_klen;

        /* [HSE_REVISIT] mapi breaks initialization of max_key.
         */
        kvset_get_max_key(le->le_kvset, &max_key, &max_klen);

        if (max_key && (!pt_len || kvset_get_seqno_max(le->le_kvset) >= horizon ||
                        keycmp_prefix(pt_key, pt_len, max_key, max_klen) < 0))
            break;

        ++kvset_cnt;
        mark = le;
    }

    perfc_set(cn_pc_capped_get(tree->cn), PERFC_BA_CNCAPPED_PTSEQ, pt_seq);

    if (!mark) {
        cn_tree_capped_evict(tree, first, last);
        return;
    }

    err = cndb_txn_start(tree->cndb, &txid, 0, kvset_cnt, 0,
                         CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON);
    if (ev(err))
        return;

    /* Step 2: Add D-records.
     * Don't need to hold a lock because this is the only thread deleting
     * kvsets from cn and we are sure that there are at least kvset_cnt
     * kvsets in the node.
     */
    for (le = last; true; le = list_prev_entry(le, le_link)) {
        err = kvset_log_d_records(le->le_kvset, false, txid);

        if (ev(err) || le == mark)
            break;
    }

    if (ev(err)) {
        cndb_txn_nak(tree->cndb, txid);
        return;
    }

    /* There must not be any failure conditions after successful ACK_C
     * because the operation has been committed.
     */
    err = cndb_txn_ack_c(tree->cndb, txid);
    if (ev(err))
        return;

    /* Step 3: Remove retired kvsets from node list.
     */
    rmlock_wlock(&tree->ct_lock);
    list_trim(&retired, head, &mark->le_link);
    cn_tree_samp_update_compact(tree, node);
    rmlock_wunlock(&tree->ct_lock);

    /* Step 4: Delete retired kvsets outside the tree write lock.
     */
    list_for_each_entry_safe (le, next, &retired, le_link) {
        kvset_mark_mblocks_for_delete(le->le_kvset, false, txid);
        kvset_put_ref(le->le_kvset);
    }
}

merr_t
cn_tree_prepare_compaction(struct cn_compaction_work *w)
{
    merr_t                   err = 0;
    struct cn_tree_node *    node = w->cw_node;
    struct kvset_list_entry *le;
    u32                      i;
    struct kv_iterator **    ins = 0;
    u32                      n_outs;
    u32                      fanout;
    struct kvset_mblocks *   outs = 0;
    struct kvset_vblk_map    vbm = {};
    struct workqueue_struct *vra_wq;

    fanout = w->cw_tree->ct_fanout;
    n_outs = fanout;

    /* if we are compacting, we only have a single output */
    if (w->cw_action == CN_ACTION_COMPACT_K || w->cw_action == CN_ACTION_COMPACT_KV)
        n_outs = 1;

    ins = calloc(w->cw_kvset_cnt, sizeof(*ins));
    outs = calloc(n_outs, sizeof(*outs));

    if (ev(!ins || !outs)) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    w->cw_output_nodev = calloc(n_outs, sizeof(w->cw_output_nodev[0]));
    if (!w->cw_output_nodev) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    vra_wq = cn_get_maint_wq(node->tn_tree->cn);

    /*
     * Create one iterator for each input kvset.  The list 'ins' must be
     * ordered such that 'ins[i]' is newer then 'ins[i+1]'.  We walk the
     * list from old to new, so the 'ins' list is populated from
     * 'ins[n-1]' to 'ins[0]'.
     *
     * The kvset list lock is not required because the kvsets we are
     * looking at are adacent in the list and are marked (with a workid).
     * Just be careful not to try to iterate outside the range of marked
     * kvsets.
     */
    for (i = 0, le = w->cw_mark; i < w->cw_kvset_cnt; i++, le = list_prev_entry(le, le_link)) {

        struct kv_iterator **iter = &ins[w->cw_kvset_cnt - 1 - i];

        if (i == 0)
            assert(kvset_get_dgen(le->le_kvset) == w->cw_dgen_lo);
        if (i == w->cw_kvset_cnt - 1)
            assert(kvset_get_dgen(le->le_kvset) == w->cw_dgen_hi);

        err = kvset_iter_create(
            le->le_kvset, w->cw_io_workq, vra_wq, w->cw_pc, w->cw_iter_flags, iter);
        if (ev(err))
            goto err_exit;

        kvset_iter_set_stats(*iter, &w->cw_stats);
    }

    /* k-compaction keeps all the vblocks from the source kvsets
     * vbm_blkv[0] is the id of the first vblock of the newest kvset
     * vbm_blkv[n] is the id of the last vblock of the oldest kvset
     */
    if (w->cw_action == CN_ACTION_COMPACT_K) {
        err = kvset_keep_vblocks(&vbm, ins, w->cw_kvset_cnt);
        if (ev(err))
            goto err_exit;
    }

    w->cw_inputv = ins;
    w->cw_outc = n_outs;
    w->cw_outv = outs;
    w->cw_vbmap = vbm;
    w->cw_level = w->cw_node->tn_loc.node_level;

    /* Enable dropping of tombstones in merge logic if 'mark' is
     * the oldest kvset in the node and we're not spilling.
     */
    w->cw_drop_tombs = (w->cw_action != CN_ACTION_SPILL) &&
        (w->cw_mark == list_last_entry(&node->tn_kvset_list, struct kvset_list_entry, le_link));

    return 0;

err_exit:
    if (ins) {
        for (i = 0; i < w->cw_kvset_cnt; i++)
            if (ins[i])
                ins[i]->kvi_ops->kvi_release(ins[i]);
        free(ins);
        free(vbm.vbm_blkv);
    }
    free(outs);
    free(w->cw_output_nodev);

    return err;
}

/*----------------------------------------------------------------
 *
 * SECTION: Cn Tree Compaction (k-compaction, kv-compaction, spill)
 *
 * The following annotated call graph of functions in this section provides an
 * overview of the code structure.  The compaction scheduler (csched) submits
 * jobs to the short term scheduler (STS).  Callbacks from STS land in
 * cn_comp(), which is the top of the call graph shown here.  Underscores are
 * used to preserve whitespace.
 *
 *    cn_comp()
 *    ___ cn_comp_compact()   // merge kvsets into kvsets
 *    _______ cn_spill()      //   for spill and kv-compact
 *    _______ cn_kcompact()   //   for k-compact
 *    ___ cn_comp_finish()    // commit, update and cleaup
 *    _______ cn_comp_commit()
 *    ___________ cn_comp_commit_spill()           // commit to cndb
 *    _______________ cn_comp_update_spill()       //   update cn tree
 *    ___________ cn_comp_commit_kvcompact()       // commit to cndb
 *    _______________ cn_comp_update_kvcompact()   //   update cn tree
 *    _______ cn_comp_cleanup()
 *    _______ cn_comp_release()
 *    ___________ w->cw_completion()               // completion callback
 *
 */

/**
 * cn_comp_update_kvcompact() - Update tree after k-compact and kv-compact
 * See section comment for more info.
 */
static void
cn_comp_update_kvcompact(struct cn_compaction_work *work, struct kvset *new_kvset)
{
    struct cn_tree *         tree = work->cw_tree;
    u64                      txid = work->cw_work_txid;
    struct kvset_list_entry *le, *tmp;
    struct list_head         retired_kvsets;
    uint                     i;

    if (ev(work->cw_err))
        return;

    INIT_LIST_HEAD(&retired_kvsets);
    assert(work->cw_dgen_lo == kvset_get_workid(work->cw_mark->le_kvset));

    rmlock_wlock(&tree->ct_lock);
    {
        assert(!list_empty(&work->cw_node->tn_kvset_list));
        le = work->cw_mark;
        for (i = 0; i < work->cw_kvset_cnt; i++) {
            tmp = list_prev_entry(le, le_link);
            list_del(&le->le_link);
            list_add(&le->le_link, &retired_kvsets);
            le = tmp;
        }

        if (new_kvset) {
            kvset_list_add(new_kvset, &le->le_link);
            work->cw_node->tn_cgen++;
        }
    }

    cn_tree_samp(tree, &work->cw_samp_pre);

    cn_tree_samp_update_compact(tree, work->cw_node);

    cn_tree_samp(tree, &work->cw_samp_post);

    atomic_sub_rel(&work->cw_node->tn_busycnt, (1u << 16) + work->cw_kvset_cnt);
    rmlock_wunlock(&tree->ct_lock);

    /* Delete retired kvsets. */
    list_for_each_entry_safe (le, tmp, &retired_kvsets, le_link) {

        assert(kvset_get_dgen(le->le_kvset) >= work->cw_dgen_lo);
        assert(kvset_get_dgen(le->le_kvset) <= work->cw_dgen_hi);

        kvset_mark_mblocks_for_delete(le->le_kvset, work->cw_keep_vblks, txid);
        kvset_put_ref(le->le_kvset);
    }
}

/**
 * cn_comp_commit_kvcompact() - commit k- and kv-compact operation to cndb log
 * See section comment for more info.
 */
static merr_t
cn_comp_commit_kvcompact(struct cn_compaction_work *work, struct kvset *kvset)
{
    struct kvset_list_entry *le;
    u32                      i;
    merr_t                   err;

    assert(work->cw_dgen_lo == kvset_get_workid(work->cw_mark->le_kvset));

    /* Update CNDB with "D" records.  No need to lock kvset as long as
     * we only access the marked kvsets.
     */
    le = work->cw_mark;
    for (i = 0; i < work->cw_kvset_cnt; i++) {
        err = kvset_log_d_records(le->le_kvset, work->cw_keep_vblks, work->cw_work_txid);
        if (ev(err))
            return err;

        le = list_prev_entry(le, le_link);
    }

    /* There must not be any failure conditions after successful ACK_C
     * because the operation has been committed.
     */
    err = cndb_txn_ack_c(work->cw_tree->cndb, work->cw_work_txid);
    if (ev(err))
        return err;

    /* Update tree and stats.  No failure paths allowed after ACK_C. */
    cn_comp_update_kvcompact(work, kvset);

    return 0;
}

/**
 * cn_comp_update_spill() - update tree after spill operation
 * See section comment for more info.
 */
static void
cn_comp_update_spill(struct cn_compaction_work *work, struct kvset **kvsets)
{
    struct cn_tree *         tree = work->cw_tree;
    u64                      txid = work->cw_work_txid;
    struct cn_tree_node *    pnode = work->cw_node;
    struct kvset_list_entry *le, *tmp;
    struct list_head         retired_kvsets;
    struct cn_tree_node *    node;

    if (ev(work->cw_err))
        return;

    INIT_LIST_HEAD(&retired_kvsets);

    rmlock_wlock(&tree->ct_lock);
    {
        for (uint i = 0; i < work->cw_outc; i++) {
            if (kvsets[i]) {
                node = work->cw_output_nodev[i];
                assert(node);
                kvset_list_add(kvsets[i], &node->tn_kvset_list);
                node->tn_cgen++;
            }
        }

        /* Move old kvsets from parent node to retired list.
         * Asserts:
         * - Each input kvset just spilled must still be on pnode's kvset list.
         * - The dgen of the oldest input kvset must match work struct dgen_lo
         *   (i.e., concurrent spills from a node must be committed in order).
         */
        for (uint i = 0; i < work->cw_kvset_cnt; i++) {
            assert(!list_empty(&pnode->tn_kvset_list));
            le = list_last_entry(&pnode->tn_kvset_list, struct kvset_list_entry, le_link);
            assert(i > 0 || work->cw_dgen_lo == kvset_get_dgen(le->le_kvset));
            list_del(&le->le_link);
            list_add(&le->le_link, &retired_kvsets);
        }

        cn_tree_samp(tree, &work->cw_samp_pre);

        cn_tree_samp_update_spill(tree, pnode);

        cn_tree_samp(tree, &work->cw_samp_post);

        atomic_sub_rel(&pnode->tn_busycnt, (1u << 16) + work->cw_kvset_cnt);
    }
    rmlock_wunlock(&tree->ct_lock);

    /* Delete old kvsets. */
    list_for_each_entry_safe (le, tmp, &retired_kvsets, le_link) {
        kvset_mark_mblocks_for_delete(le->le_kvset, false, txid);
        kvset_put_ref(le->le_kvset);
    }
}

/**
 * cn_comp_commit_spill() - commit spill operation to cndb log
 * See section comment for more info.
 */
static merr_t
cn_comp_commit_spill(struct cn_compaction_work *work, struct kvset **kvsets)
{
    struct cn_tree *         tree = work->cw_tree;
    merr_t                   err;
    struct kvset_list_entry *le;

    /* Precondition: n_outputs == tree fanout */
    assert(work->cw_outc == tree->ct_fanout);
    if (ev(work->cw_outc != tree->ct_fanout))
        return merr(EBUG);

    /* Update CNDB with "D" records.  No need to lock kvset as long as
     * we only access the marked kvsets.
     */
    le = work->cw_mark;
    for (uint i = 0; i < work->cw_kvset_cnt; i++) {
        assert(le);

        err = kvset_log_d_records(le->le_kvset, work->cw_keep_vblks, work->cw_work_txid);
        if (ev(err))
            goto done;
        le = list_prev_entry(le, le_link);
    }

    /* There must not be any failure conditions after successful ACK_C
     * because the operation has been committed.
     */
    err = cndb_txn_ack_c(tree->cndb, work->cw_work_txid);
    if (ev(err))
        goto done;

    /* Update tree and stats.  No failure paths allowed after ACK_C. */
    cn_comp_update_spill(work, kvsets);

done:
    return err;
}

/**
 * cn_comp_commit() - commit compaction operation to cndb log
 * See section comment for more info.
 */
static void
cn_comp_commit(struct cn_compaction_work *w)
{
    struct kvset ** kvsets = 0;
    struct mbset ***vecs = 0;
    uint *          cnts = 0;
    uint            i, alloc_len;
    bool            spill, use_mbsets;
    uint            scatter;

    if (ev(w->cw_err))
        goto done;

    assert(w->cw_outc);

    spill = w->cw_outc > 1;

    use_mbsets = w->cw_action == CN_ACTION_COMPACT_K;

    alloc_len = sizeof(*kvsets) * w->cw_outc;
    if (use_mbsets) {
        /* For k-compaction, create new kvset with references to
         * mbsets from input kvsets instead of creating new mbsets.
         * We need extra allocations for this.
         */
        alloc_len += sizeof(*vecs) * w->cw_kvset_cnt;
        alloc_len += sizeof(*cnts) * w->cw_kvset_cnt;
    }

    kvsets = calloc(1, alloc_len);
    if (ev(!kvsets)) {
        w->cw_err = merr(ENOMEM);
        goto done;
    }

    scatter = 0;
    if (use_mbsets) {
        struct kvset_list_entry *le;

        vecs = (void *)(kvsets + w->cw_outc);
        cnts = (void *)(vecs + w->cw_kvset_cnt);

        /* The kvset represented by vecs[i] must be newer than
         * the kvset represented by vecs[i+1] (that is, in same order
         * as the vector of iterators used in the compaction/merge
         * loops).
         */
        le = w->cw_mark;
        i = w->cw_kvset_cnt;
        while (i--) {
            vecs[i] = kvset_get_vbsetv(le->le_kvset, &cnts[i]);
            scatter += (kvset_get_scatter_score(le->le_kvset));
            le = list_prev_entry(le, le_link);
        }
    }

    for (i = 0; i < w->cw_outc; i++) {
        struct kvset_meta km = {};

        /* [HSE_REVISIT] there may be vblks to delete!!! */
        if (!w->cw_outv[i].hblk.bk_blkid)
            continue;

        km.km_dgen = w->cw_dgen_hi;
        km.km_vused = w->cw_outv[i].bl_vused;

        /* Lend hblk, kblk, and vblk lists to kvset_create().
         * Yes, the struct copy is a bit gross, but it works and
         * avoids unnecessary allocations of temporary lists.
         */
        km.km_hblk = w->cw_outv[i].hblk;
        km.km_kblk_list = w->cw_outv[i].kblks;
        km.km_vblk_list = w->cw_outv[i].vblks;
        km.km_capped = cn_is_capped(w->cw_tree->cn);
        km.km_restored = false;
        km.km_scatter = use_mbsets ? scatter : (km.km_vused ? 1 : 0);

        if (spill) {
            struct cn_tree_node *node = w->cw_output_nodev[i];

            assert(node);
            km.km_compc = 0;
            km.km_node_level = node->tn_loc.node_level;
            km.km_node_offset = node->tn_loc.node_offset;

        } else {
            struct kvset_list_entry *le = w->cw_mark;

            km.km_compc = w->cw_compc;

            /* If we're in the middle of a run then do not increment compc
             * if it would become greater than the next older kvset.
             */
            le = list_next_entry_or_null(le, le_link, &w->cw_node->tn_kvset_list);
            if (!le || w->cw_compc < kvset_get_compc(le->le_kvset))
                km.km_compc++;

            km.km_node_level = w->cw_node->tn_loc.node_level;
            km.km_node_offset = w->cw_node->tn_loc.node_offset;
        }
        w->cw_err =
            cndb_txn_meta(w->cw_tree->cndb, w->cw_work_txid, w->cw_tree->cnid, w->cw_tagv[i], &km);
        if (ev(w->cw_err))
            goto done;

        if (use_mbsets) {
            w->cw_err = kvset_create2(
                w->cw_tree, w->cw_tagv[i], &km, w->cw_kvset_cnt, cnts, vecs, &kvsets[i]);
        } else {
            w->cw_err = kvset_create(w->cw_tree, w->cw_tagv[i], &km, &kvsets[i]);
        }
        if (ev(w->cw_err))
            goto done;
    }

    if (spill)
        w->cw_err = cn_comp_commit_spill(w, kvsets);
    else
        w->cw_err = cn_comp_commit_kvcompact(w, kvsets[0]);
done:
    if (w->cw_err && kvsets) {
        for (i = 0; i < w->cw_outc; i++) {
            if (kvsets[i])
                kvset_put_ref(kvsets[i]);
        }
    }

    /* always free kvset ptrs */
    free(kvsets);
}

/**
 * cn_comp_cleanup() - cleanup after compaction operation
 * See section comment for more info.
 */
static void
cn_comp_cleanup(struct cn_compaction_work *w)
{
    bool kcompact = w->cw_action == CN_ACTION_COMPACT_K;
    uint i;


    if (HSE_UNLIKELY(w->cw_err)) {

        /* Failed spills cause node to become "wedged"  */
        if (ev(w->cw_rspill_conc && !w->cw_node->tn_rspills_wedged))
            w->cw_node->tn_rspills_wedged = 1;

        /* Log errors if debugging or if job was not canceled.
         * Canceled jobs are expected, so there's no need to log them
         * unless debugging.
         */
        if (w->cw_debug || !w->cw_canceled)
            log_errx("compaction error @@e: sts/job %u comp %s rule %s"
                     " cnid %lu lvl %u off %u dgenlo %lu dgenhi %lu wedge %d",
                     w->cw_err,
                     sts_job_id_get(&w->cw_job),
                     cn_action2str(w->cw_action),
                     cn_comp_rule2str(w->cw_comp_rule),
                     cn_tree_get_cnid(w->cw_tree),
                     w->cw_node->tn_loc.node_level,
                     w->cw_node->tn_loc.node_offset,
                     w->cw_dgen_lo,
                     w->cw_dgen_hi,
                     w->cw_node->tn_rspills_wedged);

        if (merr_errno(w->cw_err) == ENOSPC)
            w->cw_tree->ct_nospace = true;

        if (w->cw_outv)
            cn_mblocks_destroy(w->cw_ds, w->cw_outc, w->cw_outv, kcompact, w->cw_commitc);
    }

    free(w->cw_vbmap.vbm_blkv);
    free(w->cw_tagv);
    free(w->cw_output_nodev);
    if (w->cw_outv) {
        for (i = 0; i < w->cw_outc; i++) {
            blk_list_free(&w->cw_outv[i].kblks);
            blk_list_free(&w->cw_outv[i].vblks);
        }
        free(w->cw_outv);
    }
}

/**
 * get_completed_spill() - reorder ingests into root node
 * See section comment for more info.
 */
static struct cn_compaction_work *
get_completed_spill(struct cn_tree_node *node)
{
    struct cn_compaction_work *w = 0;

    mutex_lock(&node->tn_rspills_lock);

    w = list_first_entry_or_null(&node->tn_rspills, typeof(*w), cw_rspill_link);
    if (!w)
        goto done;

    /* Punt if job on head of list is not done or another thread is already committing it. */
    if (!atomic_read(&w->cw_rspill_done) || atomic_read(&w->cw_rspill_commit_in_progress)) {
        w = 0;
        goto done;
    }

    /* Job on head of spill completion list is ready to be processed.
     * - Set "commit_in_progress" status, but leave on list until commit is done.
     * - If the node is wedged, it means an earlier job has failed, in
     *   which case we force failure on this job to prevent out of
     *   order completion.
     * - If the node is not wedged, and this job has failed then it
     *   will cause the node to be wedged, but this will be handled
     *   later to catch downstream errors.
     */

    atomic_set(&w->cw_rspill_commit_in_progress, 1);

    if (ev(node->tn_rspills_wedged && !w->cw_err)) {
        w->cw_err = merr(ESHUTDOWN);
        w->cw_canceled = true;
    }

done:
    mutex_unlock(&node->tn_rspills_lock);

    return w;
}

/**
 * cn_comp_compact() - perform the actual compaction operation
 * See section comment for more info.
*/
static void
cn_comp_compact(struct cn_compaction_work *w)
{
    struct kvdb_health *hp;

    bool   kcompact = (w->cw_action == CN_ACTION_COMPACT_K);
    bool   skip_commit = false;
    merr_t err;
    u32    i;

    if (ev(w->cw_err))
        return;

    w->cw_horizon = cn_get_seqno_horizon(w->cw_tree->cn);
    w->cw_cancel_request = cn_get_cancel(w->cw_tree->cn);

    perfc_inc(w->cw_pc, PERFC_BA_CNCOMP_START);

    cn_setname(w->cw_threadname);

    w->cw_t1_qtime = get_time_ns();

    hp = w->cw_tree->ct_kvdb_health;
    assert(hp);

    err = kvdb_health_check(hp, KVDB_HEALTH_FLAG_ALL);
    if (ev(err))
        goto err_exit;

    /* cn_tree_prepare_compaction() will initiate I/O
     * if ASYNCIO is enabled.
     */
    err = cn_tree_prepare_compaction(w);
    if (ev(err)) {
        kvdb_health_error(hp, err);
        goto err_exit;
    }

    w->cw_t2_prep = get_time_ns();

    /* cn_kcompact handles k-compaction, cn_spill handles spills
     * and kv-compaction. */
    w->cw_keep_vblks = kcompact;

    if (kcompact)
        err = cn_kcompact(w);
    else
        err = cn_spill(w);

    if (merr_errno(err) == ESHUTDOWN && atomic_read(w->cw_cancel_request))
        w->cw_canceled = true;

    /* defer status check until *after* cleanup */
    for (i = 0; i < w->cw_kvset_cnt; i++)
        if (w->cw_inputv[i])
            w->cw_inputv[i]->kvi_ops->kvi_release(w->cw_inputv[i]);
    free(w->cw_inputv);
    if (ev(err)) {
        if (!w->cw_canceled)
            kvdb_health_error(hp, err);
        goto err_exit;
    }

    w->cw_t3_build = get_time_ns();

    /* if k-compaction and no kblocks, then force keepv to false. */
    if (kcompact && w->cw_outv[0].kblks.n_blks == 0) {
        skip_commit = true;
        w->cw_keep_vblks = false;
    }

    if (!skip_commit) {
        w->cw_tagv = calloc(w->cw_outc, sizeof(*w->cw_tagv));
        if (!w->cw_tagv) {
            err = merr(ev(ENOMEM));
            kvdb_health_event(hp, KVDB_HEALTH_FLAG_NOMEM, err);
            goto err_exit;
        }
    }

    {
        int nc = (skip_commit) ? 0 : w->cw_outc;
        int nd = w->cw_kvset_cnt;

        err = cndb_txn_start(w->cw_tree->cndb, &w->cw_work_txid, nc, nd, 0, CNDB_INVAL_INGESTID,
                             CNDB_INVAL_HORIZON);
        if (ev(err)) {
            kvdb_health_error(hp, err);
            goto err_exit;
        }
    }

    if (!skip_commit) {
        u64 context = 0; /* must initially be zero */

        /* Note: cn_mblocks_commit() creates "C" records in CNDB */
        err = cn_mblocks_commit(
            w->cw_ds,
            w->cw_tree->cndb,
            w->cw_tree->cnid,
            w->cw_work_txid,
            w->cw_outc,
            w->cw_outv,
            kcompact ? CN_MUT_KCOMPACT : CN_MUT_OTHER,
            &w->cw_commitc,
            &context,
            w->cw_tagv);

        if (ev(err)) {
            kvdb_health_error(hp, err);
            goto err_exit;
        }
    }

    w->cw_t4_commit = get_time_ns();

err_exit:
    w->cw_err = err;
    if (w->cw_canceled && !w->cw_err)
        w->cw_err = merr(ESHUTDOWN);
}

/**
 * cn_comp_finish() - finish a committed compaction operation
 * See section comment for more info.
 */
static void
cn_comp_finish(struct cn_compaction_work *w)
{
    cn_comp_commit(w);
    cn_comp_cleanup(w);
    cn_comp_release(w);
}

/**
 * cn_comp() - perform a cn tree compaction operation
 *
 * This function is invoked by short tern schedeler by way of callbacks
 * cn_comp_cancel_cb() and cn_comp_slice_cb().  See section comment for more
 * info.
 */
static void
cn_comp(struct cn_compaction_work *w)
{
    u64               tstart;
    struct cn        *cn = w->cw_tree->cn;
    struct perfc_set *pc = w->cw_pc;

    tstart = perfc_lat_start(pc);

    cn_comp_compact(w);

    /* Detach this job from the callback thread as we're about
     * to either hand it off to the monitor thread or leave it
     * on the rspill list for some other thread to finish.
     */
    sts_job_detach(&w->cw_job);

    /* Acquire a cn reference here to prevent cn from closing
     * before we finish updating the latency perf counter.
     * Do not touch *w after calling cn_comp_finish()
     * as it may have already been freed.
     */
    cn_ref_get(cn);
    if (w->cw_rspill_conc) {
        struct cn_tree_node *node;

        /* Mark this root spill as done.  Then process tn_rspill_list
         * to ensure concurrent root spills are completed in the
         * correct order.
         */
        atomic_set(&w->cw_rspill_done, 1);
        node = w->cw_node;
        while (NULL != (w = get_completed_spill(node)))
            cn_comp_finish(w);
    } else {
        /* Non-root spill (only one at a time per node). */
        cn_comp_finish(w);
        w = NULL;
    }

    perfc_lat_record(pc, PERFC_LT_CNCOMP_TOTAL, tstart);
    cn_ref_put(cn);
}

/**
 * cn_comp_slice_cb() - sts callback to run an sts job slice
 */
void
cn_comp_slice_cb(struct sts_job *job)
{
    struct cn_compaction_work *w = container_of(job, typeof(*w), cw_job);

    cn_comp(w);
}

/**
 * cn_tree_ingest_update() - Update the cn tree with the new kvset
 * @tree:  pointer to struct cn_tree.
 * @le:    kvset's link on the kvset list.
 * @ptomb: max ptomb seen in this ingest. Valid only if cn is of type 'capped'.
 *         Ignored otherwise.
 * @ptlen: length of @ptomb.
 * @ptseq: seqno of @ptomb.
 */
void
cn_tree_ingest_update(struct cn_tree *tree, struct kvset *kvset, void *ptomb, uint ptlen, u64 ptseq)
{
    struct cn_samp_stats pre, post;

    /* cn trees always have root nodes */
    assert(tree->ct_root);

    rmlock_wlock(&tree->ct_lock);
    kvset_list_add(kvset, &tree->ct_root->tn_kvset_list);
    tree->ct_root->tn_cgen++;

    cn_inc_ingest_dgen(tree->cn);

    /* Record ptomb as the max ptomb seen by this cn */
    if (cn_get_flags(tree->cn) & CN_CFLAG_CAPPED) {
        memcpy(tree->ct_last_ptomb, ptomb, ptlen);
        tree->ct_last_ptlen = ptlen;
        tree->ct_last_ptseq = ptseq;
    }

    /* update tree samp stats, get diff, and notify csched */
    cn_tree_samp(tree, &pre);
    cn_tree_samp_update_ingest(tree, tree->ct_root);
    cn_tree_samp(tree, &post);

    assert(post.i_alen >= pre.i_alen);
    assert(post.r_wlen >= pre.r_wlen);
    assert(post.l_alen == pre.l_alen);
    assert(post.l_good == pre.l_good);

    rmlock_wunlock(&tree->ct_lock);

    csched_notify_ingest(
        cn_get_sched(tree->cn), tree, post.r_alen - pre.r_alen, post.r_wlen - pre.r_wlen);
}

void
cn_tree_perfc_shape_report(
    struct cn_tree *  tree,
    struct perfc_set *rnode,
    struct perfc_set *inode,
    struct perfc_set *lnode)
{
    struct cn_tree_node *tn;
    struct tree_iter     iter;
    struct perfc_set *   pcv[3];
    uint                 i, n;
    void *               lock;

    struct {
        u64 nodec;
        u64 avglen;
        u64 maxlen;
        u64 avgsize;
        u64 maxsize;
    } ssv[3];

    memset(ssv, 0, sizeof(ssv));

    rmlock_rlock(&tree->ct_lock, &lock);
    n = 0;

    tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);

    while (NULL != (tn = tree_iter_next(tree, &iter))) {
        u64 len, size;

        if (!tn->tn_parent)
            i = 0;
        else if (!cn_node_isleaf(tn))
            i = 1;
        else
            i = 2;

        len = cn_ns_kvsets(&tn->tn_ns);
        size = cn_ns_alen(&tn->tn_ns);

        ssv[i].nodec++;
        ssv[i].avglen += len;
        ssv[i].avgsize += size;
        ssv[i].maxlen = max(ssv[i].maxlen, len);
        ssv[i].maxsize = max(ssv[i].maxsize, size);

        if ((++n % 128) == 0)
            rmlock_yield(&tree->ct_lock, &lock);
    }
    rmlock_runlock(lock);

    pcv[0] = rnode;
    pcv[1] = inode;
    pcv[2] = lnode;

    for (i = 0; i < 3; i++) {

        if (ssv[i].nodec) {
            ssv[i].avglen /= ssv[i].nodec;
            ssv[i].avgsize /= ssv[i].nodec;

            /* Report sizes in MiB */
            ssv[i].avgsize /= 1024 * 1024;
            ssv[i].maxsize /= 1024 * 1024;
        }

        perfc_set(pcv[i], PERFC_BA_CNSHAPE_NODES, ssv[i].nodec);
        perfc_set(pcv[i], PERFC_BA_CNSHAPE_AVGLEN, ssv[i].avglen);
        perfc_set(pcv[i], PERFC_BA_CNSHAPE_AVGSIZE, ssv[i].avgsize);
        perfc_set(pcv[i], PERFC_BA_CNSHAPE_MAXLEN, ssv[i].maxlen);
        perfc_set(pcv[i], PERFC_BA_CNSHAPE_MAXSIZE, ssv[i].maxsize);
    }
}

HSE_WEAK enum hse_mclass
cn_tree_node_mclass(struct cn_tree_node *tn, enum hse_mclass_policy_dtype dtype)
{
    struct mclass_policy *policy;
    enum hse_mclass_policy_age age;

    INVARIANT(tn);

    policy = cn_get_mclass_policy(tn->tn_tree->cn);
    age = cn_node_isleaf(tn) ? HSE_MPOLICY_AGE_LEAF :
        (cn_node_isroot(tn) ? HSE_MPOLICY_AGE_ROOT : HSE_MPOLICY_AGE_INTERNAL);

    return mclass_policy_get_type(policy, age, dtype);
}

void
cn_tree_node_get_min_key(struct cn_tree_node *tn, void *kbuf, size_t kbuf_sz, uint *min_klen)
{
    struct kvset_list_entry *le;
    const void *min_key = NULL;
    void *lock;

    INVARIANT(kbuf && kbuf_sz > 0 && min_klen);

    *min_klen = 0;

    rmlock_rlock(&tn->tn_tree->ct_lock, &lock);
    list_for_each_entry (le, &tn->tn_kvset_list, le_link) {
        struct kvset *kvset = le->le_kvset;
        const void *key;
        uint klen;

        kvset_get_min_key(kvset, &key, &klen);

        if (!min_key || keycmp(key, klen, min_key, *min_klen) < 0) {
            min_key = key;
            *min_klen = klen;
        }
    }
    assert(min_key && *min_klen > 0);

    memcpy(kbuf, min_key, min_t(size_t, kbuf_sz, *min_klen));
    rmlock_runlock(lock);
}

void
cn_tree_node_get_max_key(struct cn_tree_node *tn, void *kbuf, size_t kbuf_sz, uint *max_klen)
{
    struct kvset_list_entry *le;
    const void *max_key = NULL;
    void *lock;

    INVARIANT(kbuf && kbuf_sz > 0 && max_klen);

    *max_klen = 0;

    rmlock_rlock(&tn->tn_tree->ct_lock, &lock);
    list_for_each_entry (le, &tn->tn_kvset_list, le_link) {
        struct kvset *kvset = le->le_kvset;
        const void *key;
        uint klen;

        kvset_get_max_key(kvset, &key, &klen);

        if (!max_key || keycmp(key, klen, max_key, *max_klen) > 0) {
            max_key = key;
            *max_klen = klen;
        }
    }
    assert(max_key && *max_klen > 0);

    memcpy(kbuf, max_key, min_t(size_t, kbuf_sz, *max_klen));
    rmlock_runlock(lock);
}

merr_t
cn_tree_init(void)
{
    struct kmem_cache *cache;
    int                i;

    /* Initialize the view table cache.
     */
    for (i = 0; i < NELEM(vtc); ++i) {
        struct vtc_bkt *bkt = vtc + i;

        spin_lock_init(&bkt->lock);
        bkt->max = 8;
    }

    assert(HSE_ACP_LINESIZE >= alignof(struct cn_tree_node));

    cache = kmem_cache_create("cntreenode", cn_node_size(), HSE_ACP_LINESIZE, SLAB_PACKED, NULL);
    if (ev(!cache)) {
        return merr(ENOMEM);
    }

    cn_node_cache = cache;

    return 0;
}

void
cn_tree_fini(void)
{
    int i;

    kmem_cache_destroy(cn_node_cache);
    cn_node_cache = NULL;

    for (i = 0; i < NELEM(vtc); ++i) {
        struct vtc_bkt *bkt = vtc + i;
        struct table *  tab;

        while ((tab = bkt->head)) {
            bkt->head = tab->priv;
            table_destroy(tab);
        }
    }
}

#if HSE_MOCKING
struct cn_tree_node *
cn_tree_find_node(struct cn_tree *tree, const struct cn_node_loc *loc)
{
    struct cn_tree_node *tn;
    struct tree_iter iter;

    tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);

    while (NULL != (tn = tree_iter_next(tree, &iter))) {
        if (tn->tn_loc.node_offset == loc->node_offset &&
            tn->tn_loc.node_level == loc->node_level) {
            break;
        }
    }

    return tn;
}

#include "cn_tree_ut_impl.i"
#include "cn_tree_compact_ut_impl.i"
#include "cn_tree_create_ut_impl.i"
#include "cn_tree_internal_ut_impl.i"
#include "cn_tree_iter_ut_impl.i"
#include "cn_tree_view_ut_impl.i"
#endif /* HSE_MOCKING */
