/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_cn_tree
#define MTF_MOCK_IMPL_cn_tree_compact
#define MTF_MOCK_IMPL_cn_tree_create
#define MTF_MOCK_IMPL_cn_tree_cursor
#define MTF_MOCK_IMPL_cn_tree_internal
#define MTF_MOCK_IMPL_cn_tree_iter
#define MTF_MOCK_IMPL_ct_view

#define _GNU_SOURCE /* for pthread_setname_np() */

#include <hse_util/alloc.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_util/mman.h>
#include <hse_util/list.h>
#include <hse_util/mutex.h>
#include <hse_util/logging.h>
#include <hse_util/assert.h>
#include <hse_util/rwsem.h>
#include <hse_util/parse_num.h>
#include <hse_util/atomic.h>
#include <hse_util/hlog.h>
#include <hse_util/darray.h>
#include <hse_util/table.h>
#include <hse_util/keycmp.h>
#include <hse_util/bin_heap.h>
#include <hse_util/log2.h>
#include <hse_util/workqueue.h>
#include <hse_util/compression_lz4.h>

#include <mpool/mpool.h>

#include <hse/hse_limits.h>

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

#include "cn_tree.h"
#include "cn_tree_compact.h"
#include "cn_tree_create.h"
#include "cn_tree_cursor.h"
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
#include "pscan.h"
#include "spill.h"
#include "kcompact.h"
#include "kblock_builder.h"
#include "vblock_builder.h"

static struct kmem_cache *cn_node_cache;
static atomic_t           cn_tree_init_ref;

/* A struct kvstarts is-a struct kvset_view.
 */
struct kvstarts {
    struct kvset_view view; /* must be first field! */
    int               start;
    int               pt_start;
};

/**
 * kvset_iter_release_work -
 */
struct kir_work {
    struct work_struct  kir_work;
    uint                kir_iterc;
    struct kv_iterator *kir_iterv[];
};

static void
kvset_iterv_release_cb(struct work_struct *work)
{
    struct kir_work *w;
    uint             i;

    w = container_of(work, struct kir_work, kir_work);

    for (i = 0; i < w->kir_iterc; ++i)
        kvset_iter_release(w->kir_iterv[i]);

    free(work);
}

static void
kvset_iterv_release(uint iterc, struct kv_iterator **iterv, struct workqueue_struct *wq)
{
    struct kir_work *w;

    size_t sz, itervsz;
    uint   i;

    if (!iterc)
        return;

    if (wq) {
        itervsz = sizeof(w->kir_iterv[0]) * iterc;
        sz = sizeof(*w) + itervsz;

        w = malloc(sz);
        if (w) {
            INIT_WORK(&w->kir_work, kvset_iterv_release_cb);
            w->kir_iterc = iterc;
            memcpy(w->kir_iterv, iterv, itervsz);

            queue_work(wq, &w->kir_work);
            return;
        }
    }

    for (i = 0; i < iterc; ++i)
        kvset_iter_release(iterv[i]);
    ev(1);
}

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
    struct kvs_cparams * cp = tree->ct_cp;
    u32                  child;

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
            for (child = 1; child <= cp->cp_fanout; child++)
                if (prev == node->tn_childv[child - 1])
                    break;
        }

        /* Search for next non-null child. */
        while (child < cp->cp_fanout && !node->tn_childv[child])
            child++;

        /* Now make bottomup visit decision */
        if (!iter->topdown && child == cp->cp_fanout)
            visit = node;

        prev = node;
        node = (child < cp->cp_fanout ? node->tn_childv[child] : node->tn_parent);
    }

    iter->prev = prev;
    iter->next = node;

    return visit;
}

static inline u32
path_step_to_target(struct cn_tree *tree, struct cn_node_loc *tgt, u32 curr_level)
{
    u32 shift = 0, child_branch;
    u32 fanout_bits = ilog2(tree->ct_cp->cp_fanout);

    if (tgt->node_level > curr_level)
        shift = fanout_bits * (tgt->node_level - 1 - curr_level);

    child_branch = (tgt->node_offset >> shift) & tree->ct_fanout_mask;

    return child_branch;
}

static size_t
cn_node_size(void)
{
    struct cn_tree_node *node __maybe_unused;
    size_t                    sz;

    sz = sizeof(*node) + sizeof(*node->tn_childv) * CN_FANOUT_MAX;

    return ALIGN(sz, __alignof(*node));
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

    tn->tn_tree = tree;
    tn->tn_loc.node_level = level;
    tn->tn_loc.node_offset = offset;

    {
        /* Compute max node size */
        u64 scale;
        u64 hi = tree->rp->cn_node_size_hi << 20;
        u64 lo = tree->rp->cn_node_size_lo << 20;
        u64 nodes = nodes_in_level(ilog2(tree->ct_cp->cp_fanout), level);

        /* Scale by large value (1<<20) to get adequate resolution. */
        assert(nodes);
        scale = (tn->tn_loc.node_offset << 20) / nodes;
        tn->tn_size_max = lo + ((scale * (hi - lo)) >> 20);
    }

    tn->tn_pfx_spill = tree->ct_pfx_len > 0 && level < tree->ct_cp->cp_pfx_pivot;

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

struct cn_node_destroy_work {
    struct work_struct   dw_work;
    struct cn_tree_node *dw_node;
    atomic_t *           dw_inflight;
};

static void
cn_node_destroy_cb(struct work_struct *work)
{
    struct cn_node_destroy_work *w;
    struct kvset_list_entry *    le, *tmp;
    struct cn_tree_node *        node;

    w = container_of(work, struct cn_node_destroy_work, dw_work);
    node = w->dw_node;

    list_for_each_entry_safe (le, tmp, &node->tn_kvset_list, le_link)
        kvset_put_ref(le->le_kvset);

    cn_node_free(node);

    if (w->dw_inflight) {
        atomic_dec(w->dw_inflight);
        free(work);
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

uint
cn_node_level(const struct cn_tree_node *node)
{
    return node->tn_loc.node_level;
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
    struct cn_tstate *  tstate,
    u32                 cn_cflags,
    struct kvs_cparams *cp,
    struct kvdb_health *health,
    struct kvs_rparams *rp)
{
    struct cn_tree *tree;
    merr_t err;

    *handle = NULL;

    assert(health);

    if (ev(cp->cp_fanout < 1 << CN_FANOUT_BITS_MIN || cp->cp_fanout > 1 << CN_FANOUT_BITS_MAX))
        return merr(EINVAL);

    if (ev(cp->cp_pfx_len > HSE_KVS_MAX_PFXLEN))
        return merr(EINVAL);

    tree = alloc_aligned(sizeof(*tree), __alignof(*tree));
    if (ev(!tree))
        return merr(ENOMEM);

    memset(tree, 0, sizeof(*tree));
    tree->ct_cp = cp;
    tree->ct_fanout_bits = ilog2(cp->cp_fanout);
    tree->ct_fanout_mask = tree->ct_cp->cp_fanout - 1;
    tree->ct_pfx_len = cp->cp_pfx_len;
    tree->ct_sfx_len = cp->cp_sfx_len;

    if (tstate) {
        struct cn_khashmap *khm = &tree->ct_khmbuf;

        spin_lock_init(&khm->khm_lock);

        tstate->ts_get(tstate, &khm->khm_gen, khm->khm_mapv);
        khm->khm_gen_committed = khm->khm_gen;

        tree->ct_khashmap = khm;
        tree->ct_tstate = tstate;
    }

    tree->ct_depth_max = cn_tree_max_depth(tree->ct_fanout_bits);

    tree->ct_kvdb_health = health;
    tree->rp = rp;

    tree->ct_root = cn_node_alloc(tree, 0, 0);
    if (ev(!tree->ct_root)) {
        free_aligned(tree);
        return merr(ENOMEM);
    }

    /* no internal nodes, one leaf node (root) */
    tree->ct_i_nodec = 0;
    tree->ct_l_nodec = 1;
    tree->ct_lvl_max = 0; /* root at level 0 */

    err = rmlock_init(&tree->ct_lock);
    if (err) {
        cn_tree_destroy(tree);
        return err;
    }

    /* setup cn_tree handle and return */
    *handle = tree;

    return 0;
}

void
cn_tree_destroy(struct cn_tree *tree)
{
    struct workqueue_struct *wq;
    struct cn_tree_node *    node;
    struct tree_iter         iter;
    atomic_t                 inflight;
    ulong                    nodecnt;
    ulong                    tstart;

    if (!tree)
        return;

    atomic_set(&inflight, 0);
    tstart = get_time_ns();
    nodecnt = 0;
    wq = NULL;

    /* Create a workqueue so that we can destroy the tree nodes
     * concurrently, as doing so yields a 4x reduction in teardown
     * time (vs destroying them one-by-one).
     */
    if (tree->ct_l_nodec > 1) {
        int nthreads = min_t(int, tree->ct_l_nodec, 16);

        wq = alloc_workqueue("cn_tree_destroy", 0, nthreads);
    }

    /*
     * Bottom up traversal is safe in the sense that nodes can be
     * deleted while iterating.
     */
    tree_iter_init(tree, &iter, TRAVERSE_BOTTOMUP);

    while (NULL != (node = tree_iter_next(tree, &iter))) {
        struct cn_node_destroy_work *w, dw;

        w = malloc(sizeof(*w));
        if (w) {
            atomic_inc(&inflight);
            w->dw_inflight = &inflight;
        } else {
            w = &dw;
            w->dw_inflight = NULL;
        }

        INIT_WORK(&w->dw_work, cn_node_destroy_cb);
        w->dw_node = node;

        if (wq)
            queue_work(wq, &w->dw_work);
        else
            cn_node_destroy_cb(&w->dw_work);

        ++nodecnt;
    }

    /* Wait here for all inflight work to complete...
     */
    destroy_workqueue(wq);

    hse_log(
        HSE_DEBUG "%s: destroyed %lu nodes on wq %p in %lu ms "
                  "(inflight %d, nodec %u)",
        __func__,
        nodecnt,
        wq,
        (ulong)(get_time_ns() - tstart) / 1000000,
        atomic_read(&inflight),
        tree->ct_l_nodec);

    assert(atomic_dec_return(&inflight) == -1);

    rmlock_destroy(&tree->ct_lock);
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

struct cn_khashmap *
cn_tree_get_khashmap(const struct cn_tree *tree)
{
    return tree->ct_khashmap;
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

/**
 * cn_tree_find_parent_child_link() - Find the parent->child link for a
 *                                    child at given target location.
 * @tree: tree to search
 * @tgt: (input) location of child node
 * @parent: (output) ptr to child's parent
 * @link: (output) ptr to parent's child ptr (eg, &parent->child[2])
 *
 * Notes:
 *  - The target node need not exist.  Use cn_tree_find_node()
 *    if you need to map a node location to an existing node.
 *  - On return, if @parent == NULL, then the target node is
 *    the root of the tree.
 */
/* [HSE_REVISIT] This is old code and is currently only used in unit tests
 * to see if a node is in a tree.  Remove it from here and implement
 * find_node() in the unit test itself.
 */
static merr_t
cn_tree_find_parent_child_link(
    struct cn_tree *       tree,
    struct cn_node_loc *   tgt,
    struct cn_tree_node ** parent_out,
    struct cn_tree_node ***link_out)
{
    struct cn_tree_node * parent;
    struct cn_tree_node **link;
    u32                   level;

    if (tgt->node_level > tree->ct_depth_max)
        return merr(ev(EINVAL));

    if (tgt->node_offset >= nodes_in_level(tree->ct_fanout_bits, tgt->node_level))
        return merr(ev(EINVAL));

    parent = NULL;
    link = &tree->ct_root;

    for (level = 0; level < tgt->node_level; level++) {
        u32 branch;

        if (!*link)
            return merr(ev(EINVAL));
        branch = path_step_to_target(tree, tgt, level);
        parent = *link;
        link = &parent->tn_childv[branch];
    }

    *parent_out = parent;
    *link_out = link;
    return 0;
}

/**
 * cn_tree_find_node() - Map a node location to a node pointer.
 *
 * @tree: tree to search
 * @loc: (input) node location
 *
 * Returns NULL if tree @tree has no node at location @loc.
 */
/* [HSE_REVISIT] This is old code and is currently only used in unit tests
 * to see if a node is in a tree.  Remove it from here and implement
 * find_node() in the unit test itself.
 */
struct cn_tree_node *
cn_tree_find_node(struct cn_tree *tree, struct cn_node_loc *loc)
{
    struct cn_tree_node * parent;
    struct cn_tree_node **link = 0; /* for gcc4.4 */

    if (cn_tree_find_parent_child_link(tree, loc, &parent, &link))
        return NULL;

    return *link;
}

/**
 * cn_tree_create_node - add kvset to tree during initialization
 * @tree:  tree under construction
 *
 * This function is used during initialization to add a node to the cn tree.
 * It will create nodes along the path from root to the new node.
 *
 * NOTE: It is not intended to be used to update a node after compaction or
 * ingest operations.
 */
merr_t
cn_tree_create_node(
    struct cn_tree *      tree,
    uint                  node_level,
    uint                  node_offset,
    struct cn_tree_node **node_out)
{
    struct cn_tree_node **link, *parent;
    struct cn_node_loc    loc;
    uint                  level, offset;

    if (node_level > tree->ct_depth_max ||
        node_offset >= nodes_in_level(tree->ct_fanout_bits, node_level))
        return merr(ev(EINVAL));

    loc.node_level = node_level;
    loc.node_offset = node_offset;

    offset = 0;
    parent = 0;
    link = &tree->ct_root;

    for (level = 0; level <= node_level; level++) {

        uint cx; /* child index */

        if (!*link) {
            *link = cn_node_alloc(tree, level, offset);
            if (!*link)
                return merr(ev(ENOMEM));
            (*link)->tn_parent = parent;

            parent->tn_childc++;
            if (parent->tn_childc == 1)
                tree->ct_i_nodec++;
            else
                tree->ct_l_nodec++;
            tree->ct_lvl_max = max(tree->ct_lvl_max, level);
        }

        cx = path_step_to_target(tree, &loc, level);
        offset = node_nth_child_offset(tree->ct_fanout_bits, &(*link)->tn_loc, cx);
        parent = *link;
        link = &(*link)->tn_childv[cx];
    }

    if (node_out)
        *node_out = parent;
    return 0;
}

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

    /* Use hlog to estimate number of unique keys, but protect
     * against estimated values outside the valid range.
     * If no hlog, assume all keys are unique.
     */
    if (tn->tn_hlog) {
        s->ns_keys_uniq = hlog_card(tn->tn_hlog);
        if (s->ns_keys_uniq < tn->tn_biggest_kvset)
            s->ns_keys_uniq = tn->tn_biggest_kvset;
        else if (s->ns_keys_uniq > cn_ns_keys(s))
            s->ns_keys_uniq = cn_ns_keys(s);
    } else {
        s->ns_keys_uniq = cn_ns_keys(s);
    }

    pct = pct_scale * s->ns_keys_uniq / cn_ns_keys(s);

    {
        u64 cur_alen = s->ns_kst.kst_kalen;
        u64 new_wlen = s->ns_kst.kst_kwlen * pct / pct_scale;
        u64 new_clen = kbb_estimate_alen(tn->tn_tree->cn, new_wlen, MP_MED_CAPACITY);

        s->ns_kclen = min(new_clen, cur_alen);
    }

    {
        u64 cur_alen = s->ns_kst.kst_valen;
        u64 cur_wlen = s->ns_kst.kst_vulen * pct / pct_scale;
        u64 new_clen = vbb_estimate_alen(tn->tn_tree->cn, cur_wlen, MP_MED_CAPACITY);

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
 * It is used for ingest into root node (c0/c1 to cN) and for ingesting
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
    uint fanout = tree->ct_cp->cp_fanout;
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
 * correct position in node (@level,@offset) of the cn tree.  It will create
 * the node if necessary.
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
    merr_t                   err;

    dgen = kvset_get_dgen(kvset);

    err = cn_tree_create_node(tree, level, offset, &node);
    if (ev(err))
        return err;

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
    __aligned(SMP_CACHE_BYTES) spinlock_t lock;
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

    bkt = vtc + (raw_smp_processor_id() % NELEM(vtc));

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

    bkt = vtc + (raw_smp_processor_id() % NELEM(vtc));

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
    u64                      tdgenv[32];
    struct table *           view;
    struct tree_iter         iter;
    struct cn_tree_node *    node;
    void *                   lock;
    struct kvset_list_entry *le;
    struct cn_tree *         tree = cn_get_tree(cn);
    merr_t                   err = 0;
    struct kvset_view *      s;

    if (ev(tree->ct_depth_max > NELEM(tdgenv) - 1)) {
        assert(tree->ct_depth_max < NELEM(tdgenv));
        return merr(EINVAL);
    }

    view = vtc_alloc();
    if (ev(!view))
        return merr(ENOMEM);

    tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);
    node = tree_iter_next(tree, &iter);
    tdgenv[0] = -1;

#define dgen_at(_idx) (tdgenv[1 + _idx])

    rmlock_rlock(&tree->ct_lock, &lock);
    while (node) {
        /* recover least dgen of parent when entering a node */
        u32 level = node->tn_loc.node_level;
        u64 dgen = dgen_at(level - 1);

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
            u64           x;

            x = kvset_get_dgen(kvset);
            if (ev(x > dgen)) {
                /* order was perturbed; probably a spill */
                err = merr(EAGAIN);
                break;
            }

            s = table_append(view);
            if (ev(!s)) {
                err = merr(ENOMEM);
                break;
            }

            kvset_get_ref(kvset);
            s->kvset = kvset;
            s->node_loc = node->tn_loc;

            dgen = x;
        }

        if (err)
            break;

        if (level > 0)
            rmlock_yield(&tree->ct_lock, &lock);

        /* Remember the smallest dgen in this node. */
        dgen_at(level) = dgen;

        node = tree_iter_next(tree, &iter);
    }
    rmlock_runlock(lock);

#undef dgen_at

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

static __always_inline uint
khashmap2child(struct cn_khashmap *khashmap, u64 hash, uint shift, uint level)
{
    uint child = hash >> (shift * level);

    if (khashmap) {
        child %= CN_TSTATE_KHM_SZ;
        child = khashmap->khm_mapv[child];
    }

    return child;
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
    struct cn_khashmap *     khashmap;
    struct kvset_list_entry *le;
    struct key_disc          kdisc;
    void *                   lock;
    merr_t                   err;
    u32                      child;
    u32                      shift;
    uint                     pc_nkvset;
    u64                      pc_start;
    u64                      spill_hash = 0;
    u16                      pc_lvl, pc_lvl_start, pc_depth;
    bool                     pfx_hashing, first;
    void *                   wbti;

    __builtin_prefetch(tree);

    err = 0;
    *res = NOT_FOUND;

    pc_depth = pc_nkvset = 0;
    pc_lvl = CNGET_LMAX;
    pc_lvl_start = 0;

    pc_start = perfc_lat_start(pc);
    if (pc_start > 0) {
        if (perfc_ison(pc, PERFC_LT_CNGET_GET_L0)) {
            pc_lvl = PERFC_LT_CNGET_GET_L0;
            pc_lvl_start = pc_start;
        }
    } else {
        pc = NULL;
    }

    wbti = NULL;
    if (qctx->qtype == QUERY_PROBE_PFX) {
        err = kvset_wbti_alloc(&wbti);
        if (ev(err))
            return err;
    }

    key_disc_init(kt->kt_data, kt->kt_len, &kdisc);

    node = tree->ct_root;
    shift = tree->ct_fanout_bits;
    khashmap = tree->ct_khashmap;
    if (khashmap) {
        shift = CN_KHASHMAP_SHIFT;
        __builtin_prefetch(khashmap);
    }

    pfx_hashing = kt->kt_len > tree->ct_pfx_len && node->tn_pfx_spill;
    first = true;

    rmlock_rlock(&tree->ct_lock, &lock);
    while (node) {
        bool yield = false;

        /* Search kvsets from newest to oldest (head to tail).
         * If an error occurs or a key is found, return immediately.
         */
        list_for_each_entry (le, &node->tn_kvset_list, le_link) {
            struct kvset *kvset;

            kvset = le->le_kvset;
            yield = true;
            ++pc_nkvset;

            switch (qctx->qtype) {
                case QUERY_GET:
                    err = kvset_lookup(kvset, kt, &kdisc, seq, res, vbuf);
                    if (err || *res != NOT_FOUND) {
                        rmlock_runlock(lock);
                        if (pc_lvl < CNGET_LMAX)
                            perfc_lat_record(pc, pc_lvl, pc_lvl_start);
                        goto done;
                    }
                    break;

                case QUERY_PROBE_PFX:
                    err = kvset_pfx_lookup(kvset, kt, &kdisc, seq, res, wbti, kbuf, vbuf, qctx);
                    if (ev(err) || qctx->seen > 1 || *res == FOUND_PTMB) {
                        rmlock_runlock(lock);
                        goto done;
                    }
                    break;
            }
        }

        if (pc_depth > 0 && yield)
            rmlock_yield(&tree->ct_lock, &lock);

        if (first && pfx_hashing) {
            /* Descend by prefix key */
            spill_hash = key_hash64(kt->kt_data, tree->ct_pfx_len);
            first = false;
        } else if (first || (pfx_hashing && !node->tn_pfx_spill)) {
            if (pfx_hashing && !node->tn_pfx_spill)
                pfx_hashing = false;
            first = false;

            /* Descend by full key because: 1) tree is not a
             * prefix tree, or 2) kt_len <= pfx_len, 3) or
             * switching from prefix to full key descent.
             */
            if (!tree->ct_sfx_len || wbti) {
                if (!kt->kt_hash)
                    kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);

                spill_hash = kt->kt_hash;
            } else {
                size_t hashlen;

                assert(qctx->qtype == QUERY_GET);
                hashlen = kt->kt_len - tree->ct_sfx_len;
                spill_hash = key_hash64(kt->kt_data, hashlen);
            }
        }

        child = khashmap2child(khashmap, spill_hash, shift, pc_depth);
        child &= tree->ct_fanout_mask;
        node = node->tn_childv[child];

        __builtin_prefetch(node);

        if (pc_lvl < CNGET_LMAX) {
            perfc_lat_record(pc, pc_lvl++, pc_lvl_start);
            pc_lvl_start = perfc_lat_start(pc);
        }

        ++pc_depth;
    }
    rmlock_runlock(lock);

done:
    if (pc && !wbti) {
        /* latencies first - close in time */
        perfc_lat_record(pc, PERFC_LT_CNGET_GET, pc_start);

        switch (*res) {
            case NOT_FOUND:
                perfc_lat_record(pc, PERFC_LT_CNGET_MISS, pc_start);
                perfc_inc(pc, PERFC_RA_CNGET_MISS);
                break;
            case FOUND_TMB:
                perfc_inc(pc, PERFC_RA_CNGET_TOMB);
                break;
            default:
                break;
        }

        perfc_inc(pc, PERFC_RA_CNGET_GET);
        perfc_rec_sample(pc, PERFC_DI_CNGET_DEPTH, pc_depth);
        perfc_rec_sample(pc, PERFC_DI_CNGET_NKVSET, pc_nkvset);
    }

    if (wbti) {
        kvset_wbti_free(wbti);
        if (pc)
            perfc_lat_record(pc, PERFC_LT_CNGET_PROBEPFX, pc_start);
    }

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

u32
cn_tree_fanout_bits(const struct cn_tree *tree)
{
    return tree->ct_fanout_bits;
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
    return atomic_cmpxchg(&tn->tn_compacting, 0, 1) == 0;
}

void
cn_node_comp_token_put(struct cn_tree_node *tn)
{
    __maybe_unused int oldval;

    oldval = atomic_cmpxchg(&tn->tn_compacting, 1, 0);
    assert(oldval == 1);
}

static void
cn_comp_release(struct cn_compaction_work *w)
{
    struct kvset_list_entry *le;
    uint                     kx;

    assert(w->cw_node);

    if (w->cw_rspill_conc) {
        /* This work is on the concurrent spill list.  It should not be
         * released unless it is at head of list.  Verify it is at
         * head and remove it.
         */
        struct cn_compaction_work *tmp __maybe_unused;

        mutex_lock(&w->cw_node->tn_rspills_lock);
        tmp = list_first_entry_or_null(&w->cw_node->tn_rspills, typeof(*tmp), cw_rspill_link);
        assert(tmp == w);
        list_del_init(&w->cw_rspill_link);
        mutex_unlock(&w->cw_node->tn_rspills_lock);
    }

    if (w->cw_err) {
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

    if (ev(w->cw_bonus))
        atomic_dec(w->cw_bonus);
    w->cw_bonus = NULL;

    if (w->cw_completion)
        w->cw_completion(w);
    else
        free(w);
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
        void *max_key;
        uint  max_klen;

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

    err = cndb_txn_start(tree->cndb, &txid, CNDB_INVAL_INGESTID, 0, kvset_cnt, 0);
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
    bool *                   drop_tombs = 0;
    struct kvset_mblocks *   outs = 0;
    struct kvset_vblk_map    vbm = {};
    bool                     oldest;
    struct workqueue_struct *vra_wq;

    fanout = 1 << w->cw_tree->ct_fanout_bits;
    n_outs = fanout;

    /* if we are compacting, we only have a single output */
    if (w->cw_action < CN_ACTION_SPILL)
        n_outs = 1;

    ins = calloc(w->cw_kvset_cnt, sizeof(*ins));
    outs = calloc(n_outs, sizeof(*outs));
    drop_tombs = calloc(n_outs, sizeof(*drop_tombs));

    if (ev(!ins || !drop_tombs || !outs)) {
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

        /* If successful, kvset_iter_create() adopts this reference.
         */
        kvset_get_ref(le->le_kvset);

        err = kvset_iter_create(
            le->le_kvset, w->cw_io_workq, vra_wq, w->cw_pc, w->cw_iter_flags, iter);
        if (ev(err)) {
            kvset_put_ref(le->le_kvset);
            goto err_exit;
        }
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

    /* Enable dropping of tombstones in merge logic if 'mark' is
     * the oldest kvset in the node, and the node has no children.
     */
    oldest =
        (w->cw_mark == list_last_entry(&node->tn_kvset_list, struct kvset_list_entry, le_link));

    if (n_outs == 1) {
        /* compacting: if ANY children, do not drop tombs */
        drop_tombs[0] = oldest;
        for (i = 0; i < fanout; ++i) {
            if (node->tn_childv[i]) {
                drop_tombs[0] = false;
                break;
            }
        }
    } else if (oldest) {
        for (i = 0; i < n_outs; i++)
            drop_tombs[i] = node->tn_childv[i] == NULL;
    }

    /*
     * set work struct outputs
     */
    w->cw_inputv = ins;
    w->cw_outc = n_outs;
    w->cw_outv = outs;
    w->cw_vbmap = vbm;
    w->cw_drop_tombv = drop_tombs;
    w->cw_hash_shift = 0;

    if (n_outs > 1) {
        uint bits = w->cw_tree->ct_fanout_bits;

        if (cn_tree_get_khashmap(w->cw_tree))
            bits = CN_KHASHMAP_SHIFT;

        w->cw_hash_shift = bits * node->tn_loc.node_level;
    }

    return 0;

err_exit:
    if (ins) {
        for (i = 0; i < w->cw_kvset_cnt; i++)
            if (ins[i])
                ins[i]->kvi_ops->kvi_release(ins[i]);
        free(ins);
        free(vbm.vbm_blkv);
    }
    free(drop_tombs);
    free(outs);

    return err;
}

/*----------------------------------------------------------------
 * SECTION: Prefix Scans
 *
 * Ideally, this code would live in pscan.c, but the create function
 * deeply understands the cn_tree traversal and locking models.
 */

#define hash_bits(C, L) (((C)->pfxhash >> ((C)->shift * (L))) & (C)->mask)

/*
 * Min heap comparator.
 *
 * Returns:
 *   < 0 : a_blob < b_blob
 *   > 0 : a_blob > b_blob
 *  == 0 : a_blob == b_blob
 */
static int
cn_kv_cmp(const void *a_blob, const void *b_blob)
{
    const struct cn_kv_item *a = a_blob;
    const struct cn_kv_item *b = b_blob;

    return key_obj_cmp(&a->kobj, &b->kobj);
}

/*
 * Max heap comparator with a caveat: A ptomb sorts before all keys w/ matching
 * prefix.
 *
 * Returns:
 *   < 0 : a_blob > b_blob
 *   > 0 : a_blob < b_blob
 *  == 0 : a_blob == b_blob
 */
static int
cn_kv_cmp_rev(const void *a_blob, const void *b_blob)
{
    const struct cn_kv_item *a = a_blob;
    const struct cn_kv_item *b = b_blob;
    size_t                   a_klen = a->kobj.ko_pfx_len + a->kobj.ko_sfx_len;
    size_t                   b_klen = b->kobj.ko_pfx_len + b->kobj.ko_sfx_len;

    int rc;

    if (!(a->vctx.is_ptomb ^ b->vctx.is_ptomb))
        return key_obj_cmp(&b->kobj, &a->kobj);

    /* Exactly one of a and b is a ptomb. */
    if (a->vctx.is_ptomb && a_klen <= b_klen) {
        rc = key_obj_ncmp(&b->kobj, &a->kobj, a_klen);
        if (rc == 0)
            return -1; /* a wins */
    } else if (b->vctx.is_ptomb && b_klen <= a_klen) {
        rc = key_obj_ncmp(&b->kobj, &a->kobj, b_klen);
        if (rc == 0)
            return 1; /* b wins */
    }

    /* Non-ptomb key is shorter than ptomb. Full key compare. */
    return key_obj_cmp(&b->kobj, &a->kobj);
}

static void
kvstart_put_ref(void *arg)
{
    struct kvstarts *s = arg;

    assert(s->view.kvset);

    kvset_put_ref(s->view.kvset);
}

merr_t
cn_tree_cursor_active_kvsets(struct pscan *cur, u32 *active, u32 *total)
{
    *active = bin_heap2_width(cur->bh);
    *total = cur->iterc;
    return 0;
}

merr_t
cn_tree_cursor_create(struct pscan *cur, struct cn_tree *tree)
{
    u64                      tdgenv[32];
    struct workqueue_struct *vra_wq;
    struct cn_tree_node *    node;
    struct cn_khashmap *     khashmap;
    struct kvset_list_entry *le;
    void *                   lock;
    struct table *           view;
    struct tree_iter         iter, *iterp;
    struct kv_iterator **    kv_iter;
    struct element_source ** esrc;
    uint                     iterc;
    uint                     shift;
    enum kvset_iter_flags    flags;

    merr_t err = 0;
    int    i;

    assert(cur->iterc == 0);
    iterp = NULL;
    iterc = 0;

    /* [HSE_REVISIT] Replace the following code to create table view with
     * cn_tree_view_create().
     */

    /*
     * Dgen must follow a strict ordering:
     * 1. within node, strictly decrease L->R.
     * 2. Within tree, strictly decrease top->bottom.
     * 3. Children must be less than least kvset in parent.
     * 4. Siblings may be relatively unordered, but must
     *    obey the tree rules.
     *
     * If a violation is found, assume a spill finished during
     * this create.  If so, the next attempt should succeed.
     */
    if (ev(tree->ct_depth_max > NELEM(tdgenv) - 1)) {
        assert(tree->ct_depth_max < NELEM(tdgenv));
        return merr(EINVAL);
    }

    view = vtc_alloc();
    if (ev(!view))
        return merr(ENOMEM);

    /*
     * find all the kvsets, and collect in a table:
     * the root node in particular may have hundreds of kvsets
     * but no child node should be much larger than 8 kvsets
     * and the depth is typically 3 for a large (>32g key) database.
     *
     * We must collect these pointers first, since we
     * need to police the set prior to creating iterators
     * and bin_heap_create requires a vector + len.
     *
     * The logic for descending the tree is similar to the logic
     * cn_tree_lookup().
     */

    node = tree->ct_root;
    khashmap = cn_tree_get_khashmap(tree);
    shift = khashmap ? CN_KHASHMAP_SHIFT : cur->shift;

#define dgen_at(_idx) (tdgenv[1 + _idx])

    rmlock_rlock(&tree->ct_lock, &lock);
    cur->dgen = tdgenv[0] = cn_get_ingest_dgen(cur->cn);
    while (node) {

        /* recover least dgen of parent when entering a node */
        u32 level = node->tn_loc.node_level;
        u64 dgen = dgen_at(level - 1);

        list_for_each_entry (le, &node->tn_kvset_list, le_link) {
            struct kvset *   kvset = le->le_kvset;
            struct kvstarts *s;
            u64              x;
            int              start;
            int              pt_start;

            x = kvset_get_dgen(kvset);
            if (ev(x > dgen)) {
                /* order was perturbed; probably a spill */
                err = merr(EAGAIN);
                break;
            }

            assert(x <= cur->dgen);

            /* determine if this kvset participates.
             * If prefixed tree, check if kvset has ptombs.
             */
            pt_start = kvset_pt_start(kvset);

            /* check if key lies within this kvset's range */
            start = kvset_kblk_start(kvset, cur->pfx, -cur->pfx_len, cur->reverse);
            if (start < 0 && pt_start < 0)
                continue;

            s = table_append(view);
            if (ev(!s)) {
                err = merr(ENOMEM);
                break;
            }

            kvset_get_ref(kvset);
            s->view.kvset = kvset;
            s->view.node_loc = node->tn_loc;
            s->start = start;
            s->pt_start = pt_start;

            dgen = x;

            ++iterc;
        }

        if (unlikely(err)) {
            rmlock_runlock(lock);

            hse_elog(
                HSE_NOTICE "%s: cnid %lx pfx_len %d dgen %lu loc %u,%u: @@e",
                err,
                __func__,
                (ulong)tree->cnid,
                cur->pfx_len,
                (ulong)dgen,
                level,
                node->tn_loc.node_offset);
            goto errout;
        }

        if (level > 0)
            rmlock_yield(&tree->ct_lock, &lock);

        /* Remember the smallest dgen in this node. */
        dgen_at(level) = dgen;

        if (iterp) {
            /* in region of tree that spills on hash of full key */
            node = tree_iter_next(tree, iterp);
        } else if (node->tn_pfx_spill && cur->pfx_len >= cur->ct_pfx_len) {
            uint child;

            /* descend by prefix hash */
            child = khashmap2child(khashmap, cur->pfxhash, shift, level);
            child &= cur->mask;
            node = node->tn_childv[child];
        } else {
            /* switch from prefix key hash to full key hash */
            iterp = &iter;
            tree_iter_init_node(tree, iterp, TRAVERSE_TOPDOWN, node);
            /* iter->next is inited to the node we just processed.
             * Call next twice to avoid processing this node again.
             */
            node = tree_iter_next(tree, iterp);
            node = tree_iter_next(tree, iterp);
        }
    }
    rmlock_runlock(lock);

#undef dgen_at

    /* if nothing found, no further work needed; set eof and return */
    if (iterc == 0) {
        vtc_free(view);
        cur->eof = 1;
        return 0;
    }

    if (iterc > cur->itermax) {
        uint itermax = ALIGN(iterc, 256);

        free(cur->iterv);
        free(cur->esrcv);

        cur->iterv = malloc(itermax * sizeof(*cur->iterv));
        cur->esrcv = malloc(itermax * sizeof(*cur->esrcv));

        if (ev(!cur->iterv || !cur->esrcv)) {
            err = merr(ENOMEM);
            goto errout;
        }

        cur->itermax = itermax;
    }

    flags = kvset_iter_flag_mcache;
    if (cur->reverse)
        flags |= kvset_iter_flag_reverse;
    vra_wq = cn_get_maint_wq(cur->cn);

    kv_iter = cur->iterv;
    esrc = cur->esrcv;

    assert(cur->iterc == 0);

    for (i = 0; i < iterc; ++i) {
        struct kvstarts *   s = table_at(view, i);
        struct kv_iterator *p;
        struct kvset *      ks = s->view.kvset;

        err = kvset_iter_create(ks, NULL, vra_wq, NULL, flags, &p);
        if (ev(err))
            goto errout;

        /* kvset_iter_create() adopted our kvset reference.
         */
        s->view.kvset = NULL;

        if (cur->pfx_len) {
            bool eof;

            err = kvset_iter_seek(p, cur->pfx, -cur->pfx_len, &eof);
        } else {
            err = kvset_iter_set_start(p, s->start, s->pt_start);
        }

        if (ev(err)) {
            kvset_iter_release(p);
            goto errout;
        }

        *kv_iter++ = p;
        *esrc++ = &p->kvi_es;

        ++cur->iterc;
    }

    for (i = 0; i < cur->iterc; ++i) {
        assert(cur->iterv[i]);
    }

    err = bin_heap2_create(cur->iterc, cur->reverse ? cn_kv_cmp_rev : cn_kv_cmp, &cur->bh);
    if (ev(err))
        goto errout;

    err = bin_heap2_prepare(cur->bh, cur->iterc, cur->esrcv);
    if (ev(err))
        goto errout;

    cursor_summary_add_dgen(cur->summary, cur->dgen);
    cur->summary->n_kvset = cur->iterc;

errout:
    if (err) {
        cn_tree_cursor_destroy(cur);
        table_apply(view, kvstart_put_ref);
    }

    vtc_free(view);

    return err;
}

static merr_t
cn_tree_capped_cursor_update(struct pscan *cur, struct cn_tree *tree)
{
    struct workqueue_struct *vra_wq;
    struct cn_tree_node *    node;
    struct kvset_list_entry *le;
    enum kvset_iter_flags    flags;
    int                      iterc, new_cnt, old_cnt;
    merr_t                   err = 0;
    struct table *           view;
    struct kv_iterator **    p;
    struct element_source ** q;
    void *                   lock;
    bool                     allocated;
    int                      i;
    u64                      dgen = 0;
    u64                      node_oldest_dgen;
    struct perfc_set *       pc = cn_pc_capped_get(tree->cn);

    node = tree->ct_root;
    if (!node) {
        cur->eof = 1;
        return 0;
    }

    bin_heap2_destroy(cur->bh);
    cur->bh = NULL;
    cur->eof = 0;

    view = vtc_alloc();
    if (ev(!view))
        return merr(ENOMEM);

    /* Identify new kvsets and the old ones that are still valid.
     */
    rmlock_rlock(&tree->ct_lock, &lock);

    old_cnt = new_cnt = 0;

    list_for_each_entry (le, &node->tn_kvset_list, le_link) {
        struct kvset *   ks = le->le_kvset;
        struct kvstarts *s;
        u64              ks_dgen = kvset_get_dgen(le->le_kvset);

        if (ks_dgen <= cur->dgen)
            break;

        s = table_append(view);
        if (ev(!s)) {
            rmlock_runlock(lock);
            err = merr(ENOMEM);
            goto errout;
        }

        s->view.kvset = ks;
        s->view.node_loc = node->tn_loc;
        s->start = 0;
        s->pt_start = kvset_pt_start(ks);

        kvset_get_ref(ks);
        dgen = dgen ?: ks_dgen;
        new_cnt++;
    }

    le = list_last_entry(&node->tn_kvset_list, struct kvset_list_entry, le_link);
    node_oldest_dgen = kvset_get_dgen(le->le_kvset);
    rmlock_runlock(lock);

    /* Find the oldest kvset in cur->iterv[] that's still alive in the node.
     */
    for (i = cur->iterc - 1; i >= 0; i--) {
        struct kv_iterator *it = cur->iterv[i];
        u64 ks_dgen = kvset_get_dgen(kvset_from_iter(it));

        if (ks_dgen >= node_oldest_dgen)
            break;
    }

    old_cnt = i + 1;

    perfc_add(pc, PERFC_BA_CNCAPPED_NEW, new_cnt);
    perfc_add(pc, PERFC_BA_CNCAPPED_OLD, old_cnt);

    iterc = old_cnt + new_cnt;

    /* The cursor's kvset list contains kvsets that are either
     *   1. no longer part of the cn tree (compacted away), or
     *   2. still part of the tree and are hence still valid.
     *
     * First 'old_cnt' kvsets are still valid. Retire the rest.
     */
    if (old_cnt < cur->iterc) {
        kvset_iterv_release(cur->iterc - old_cnt, &cur->iterv[old_cnt], cn_get_maint_wq(cur->cn));

        memset(cur->iterv + old_cnt, 0, (cur->iterc - old_cnt) * sizeof(cur->iterv[0]));
    }

    if (!iterc) {
        cur->iterc = iterc;
        vtc_free(view);
        cur->eof = 1;
        return 0; /* no kvsets in cn */
    }

    if (!new_cnt)
        goto done;

    cur->dgen = dgen;

    allocated = false;
    p = cur->iterv;
    q = cur->esrcv;

    /* Grow iterator vectors if necessary.
     */
    if (iterc > cur->itermax) {
        uint itermax = ALIGN(iterc, 256);

        p = malloc(itermax * sizeof(*cur->iterv));
        q = malloc(itermax * sizeof(*cur->esrcv));

        if (ev(!p || !q)) {
            free(p);
            free(q);
            err = merr(ENOMEM);
            goto errout;
        }

        cur->itermax = itermax;
        allocated = true;
    }

    /* Move the old iterators to make room for the new kvsets' iterators.
     */
    memmove(p + new_cnt, cur->iterv, old_cnt * sizeof(*p));
    memmove(q + new_cnt, cur->esrcv, old_cnt * sizeof(*q));

    if (allocated) {
        free(cur->iterv);
        free(cur->esrcv);
        cur->iterv = p;
        cur->esrcv = q;
    }

    flags = kvset_iter_flag_mcache;
    if (cur->reverse)
        flags |= kvset_iter_flag_reverse;
    vra_wq = cn_get_maint_wq(cur->cn);

    /* Create iterators for the new kvsets.
     */
    for (i = 0; i < new_cnt; i++) {
        struct kvstarts *   s = table_at(view, i);
        struct kv_iterator *iter;
        struct kvset *      ks = s->view.kvset;

        err = kvset_iter_create(ks, NULL, vra_wq, NULL, flags, &iter);
        if (ev(err))
            break;

        /* kvset_iter_create() adopted our kvset reference.
         */
        s->view.kvset = NULL;

        /* The kvs layer always seeks the cursor after an update. So
         * position at the beginning of the kvset.
         */
        err = kvset_iter_set_start(iter, s->start, s->pt_start);
        if (ev(err)) {
            kvset_iter_release(iter);
            break;
        }

        cur->iterv[i] = iter;
        cur->esrcv[i] = &iter->kvi_es;
    }

    if (err) {
        /* Not all iterators in cur->iterv[] have been setup. So cleanup
         * only the onses that are valid.
         */

        while (i--)
            kvset_iter_release(cur->iterv[i]); /* new iters */

        for (i = new_cnt; i < iterc; i++)
            kvset_iter_release(cur->iterv[i]); /* old iters */

        cur->iterc = 0; /* mark all kvset iterators as destroyed */
        goto errout;
    }

done:
    for (i = 0; i < iterc; ++i) {
        assert(cur->iterv[i]);
    }

    cur->iterc = iterc;
    err = bin_heap2_create(cur->iterc, cn_kv_cmp, &cur->bh);
    if (ev(err))
        goto errout;

    err = bin_heap2_prepare(cur->bh, cur->iterc, cur->esrcv);
    if (ev(err))
        goto errout;

    vtc_free(view);

    return 0;

errout:

    cn_tree_cursor_destroy(cur);
    table_apply(view, kvstart_put_ref);
    vtc_free(view);

    cur->merr = err;
    return err;
}

merr_t
cn_tree_cursor_update(struct pscan *cur, struct cn_tree *tree)
{
    if (cur->pt_set) {
        uint len;

        /* Cached ptomb should survive even if the underlying kvset
         * resources are released (deferred deletes).
         */
        key_obj_copy(cur->pt_buf, sizeof(cur->pt_buf), &len, &cur->pt_kobj);
        assert(len == cur->ct_pfx_len);
        key2kobj(&cur->pt_kobj, cur->pt_buf, cur->ct_pfx_len);
    }

    if (ev(cn_is_capped(cur->cn) && !cur->reverse))
        return cn_tree_capped_cursor_update(cur, tree);

    kvset_iterv_release(cur->iterc, cur->iterv, cn_get_maint_wq(cur->cn));
    bin_heap2_destroy(cur->bh);

    /* Note that we intentionally preserve the iterv and esrcv
     * buffers for reuse by cn_tree_cursor_create().
     */
    cur->iterc = 0;
    cur->bh = NULL;
    cur->eof = 0;

    return cn_tree_cursor_create(cur, tree);
}

/* cn_tree_cursor_destroy() doesn't really destroy the cursor object,
 * rather it just releases most of the resources associated with it.
 */
void
cn_tree_cursor_destroy(struct pscan *cur)
{
    kvset_iterv_release(cur->iterc, cur->iterv, cn_get_maint_wq(cur->cn));
    bin_heap2_destroy(cur->bh);
    cur->bh = 0;

    free(cur->iterv);
    free(cur->esrcv);
    cur->itermax = 0;
    cur->iterc = 0;
    cur->iterv = 0;
    cur->esrcv = 0;

    /* [HSE_REVISIT] emit statistics */
}

/* Call drop_dups() only if item is regular tomb, and not a ptomb. */
static void
drop_dups(struct pscan *cur, struct cn_kv_item *item)
{
    struct cn_kv_item *dup;

    while (bin_heap2_peek(cur->bh, (void **)&dup)) {

        if (key_obj_cmp(&dup->kobj, &item->kobj))
            return;

        /* If dup is ptomb and item isn't, leave dup be so it can hide
         * the appropriate keys.
         */
        if (dup->vctx.is_ptomb)
            return;

        bin_heap2_pop(cur->bh, (void **)&dup);
    }
}

/*
 * compare item's prefix to cursor's prefix.
 *
 * rc <  0 : itempfx < cursor's pfx
 * rc >  0 : itempfx > cursor's pfx
 * rc == 0 : itempfx == cursor's pfx
 */
static int
cur_item_cmp(struct pscan *cur, struct cn_kv_item *item)
{
    int            rc;
    struct key_obj ko_pfx;

    key2kobj(&ko_pfx, cur->pfx, cur->pfx_len);

    /* When cursor's pfx_len is larger than tree's pfx_len, allow ptombs to
     * pass through. To correctly compare ptomb w/ cursor's pfx in this
     * case, invert the order of args to keycmp_prefix() and then invert
     * signedness of rc.
     */
    if (item->vctx.is_ptomb && cur->pfx_len > cur->ct_pfx_len) {
        rc = key_obj_cmp_prefix(&item->kobj, &ko_pfx);
        rc = -rc;
    } else {
        rc = key_obj_cmp_prefix(&ko_pfx, &item->kobj);
    }

    if (cur->reverse)
        rc = -rc;

    return rc;
}

/*
 * cn_tree_cursor_read - returns the next value in the cursor
 * @cur: the cursor returned from cn_cursor_create
 * @kvt: result struct: key and values kept here
 * @eof: ptr to value set to true if eof or non-restartable error
 *
 * Returns 0 on success.  Errors may be retried unless @*eof is true.
 */
merr_t
cn_tree_cursor_read(struct pscan *cur, struct kvs_kvtuple *kvt, bool *eof)
{
    struct cn_kv_item   item, *popme;
    u64                 seq;
    bool                end;
    bool                is_tomb;
    const void *        vdata;
    uint                vlen;
    uint                complen;
    uint                klen;
    int                 rc;
    struct kv_iterator *kv_iter = 0;
    struct key_obj      filter_ko = { 0 };

    if (ev(cur->merr))
        return cur->merr;

    if (cur->eof) {
        *eof = cur->eof;
        return 0;
    }

    if (unlikely(cur->filter))
        key2kobj(&filter_ko, cur->filter->kcf_maxkey, cur->filter->kcf_maxklen);

    do {

        if (!bin_heap2_peek(cur->bh, (void **)&popme)) {
            *eof = (cur->eof = 1);
            return 0;
        }

        /* copy out bh item before bin_heap2_pop() overwrites its
         * element (*popme).
         */
        item = *popme;
        is_tomb = item.vctx.is_ptomb;

        bin_heap2_pop(cur->bh, (void **)&popme);

        rc = cur_item_cmp(cur, &item);
        if (rc > 0) {
            end = true;
            continue;
        } else if (rc < 0) {
            *eof = (cur->eof = 1);
            return 0;
        }

        if (unlikely(cur->filter)) {
            if (key_obj_cmp(&item.kobj, &filter_ko) > 0) {
                *eof = (cur->eof = 1);
                return 0;
            }
        }

        kv_iter = kvset_cursor_es_h2r(item.src);
        end = false;

        do {
            enum kmd_vtype vtype;
            u32            vbidx;
            u32            vboff;

            if (!kvset_iter_next_vref(
                    kv_iter, &item.vctx, &seq, &vtype, &vbidx,
                    &vboff, &vdata, &vlen, &complen)) {
                end = true;
                break;
            }

            cur->merr =
                kvset_iter_next_val(kv_iter, &item.vctx, vtype, vbidx,
                    vboff, &vdata, &vlen, &complen);
            if (ev(cur->merr))
                return cur->merr;

        } while (seq > cur->seqno);
        if (end)
            continue;

        if (HSE_CORE_IS_PTOMB(vdata) &&
            (!cur->pt_set || key_obj_cmp(&cur->pt_kobj, &item.kobj) != 0)) {
            /* only store ptomb w/ highest seqno (less than cur's
             * seqno)
             * i.e. first occurrence of this ptomb
             */
            assert(cur->ct_pfx_len > 0);
            cur->pt_set = 1;
            cur->pt_kobj = item.kobj;
            cur->pt_seq = seq;

            /* [HSE_REVISIT]
             * if ptomb, move all srcs > item->src past pfx only if
             * ptomb was NOT from the spread region.
             */
        }

        /* A kvset can have a matching key and ptomb such that the key
         * is newer than ptomb. So drop dups only if regular tomb.
         */
        is_tomb = HSE_CORE_IS_TOMB(vdata) && !HSE_CORE_IS_PTOMB(vdata);
        if (is_tomb)
            drop_dups(cur, &item);

        if (cur->pt_set) {
            if (key_obj_cmp_prefix(&cur->pt_kobj, &item.kobj) == 0) {
                if (HSE_CORE_IS_PTOMB(vdata) || seq < cur->pt_seq)
                    end = true;
            } else {
                cur->pt_set = 0;
                cur->pt_seq = 0;
            }
        }

    } while (end || is_tomb);

    assert(!HSE_CORE_IS_TOMB(vdata));

    /* copyout before drop dups! */
    kvt->kvt_key.kt_data = key_obj_copy(cur->buf, cur->bufsz, &klen, &item.kobj);
    kvt->kvt_key.kt_len = klen;
    // what about kt_hash ??? */

    kvs_vtuple_init(&kvt->kvt_value, cur->buf + kvt->kvt_key.kt_len, vlen);

    if (complen) {
        extern struct compress_ops compress_lz4_ops;
        uint len_check;

        cur->merr = compress_lz4_ops.cop_decompress(vdata, complen,
            kvt->kvt_value.vt_data, vlen, &len_check);
        if (ev(cur->merr))
            return cur->merr;
        if (ev(len_check != vlen)) {
            assert(0);
            cur->merr = merr(EBUG);
            return cur->merr;
        }

    } else {
        memcpy(kvt->kvt_value.vt_data, vdata, vlen);
    }

    cur->stats.ms_keys_out++;
    cur->stats.ms_key_bytes_out += kvt->kvt_key.kt_len;
    cur->stats.ms_val_bytes_out += vlen;

    drop_dups(cur, &item);

    *eof = 0;
    return 0;
}

#define handle_to_kvset_iter(_handle) container_of(_handle, struct kvset_iterator, handle)

/*
 * Move the cursor to key.
 */
merr_t
cn_tree_cursor_seek(
    struct pscan *     cur,
    const void *       key,
    u32                len,
    struct kc_filter * filter,
    struct kvs_ktuple *kt)
{
    int               i;
    int               first;
    struct perfc_set *pc = cn_pc_capped_get(cur->cn);

    /* A cursor in error cannot be used. */
    if (ev(cur->merr))
        return cur->merr;

    cur->filter = filter;

    /* No place to seek to on an empty list */
    if (cur->iterc == 0) {
        cur->eof = 1;
        if (kt)
            kt->kt_len = 0;
        return 0;
    }

    /* Allow seek after reading to eof - to reread data */
    if (cur->eof)
        cur->eof = 0;

    /* [HSE_REVISIT]: this is parallelizable */
    first = -1; /* first kvset that is not at EOF */
    for (i = cur->iterc - 1; i >= 0; --i) {
        bool eof = false;

        if (cur->filter) {
            struct kvset *ks = kvset_from_iter(cur->iterv[i]);
            const void *  minkey, *smaxkey;
            u16           minklen, smaxklen;

            kvset_minkey(ks, &minkey, &minklen);
            smaxkey = cur->filter->kcf_maxkey;
            smaxklen = cur->filter->kcf_maxklen;

            /* If there's no overlap between the seek range and the
             * kvset's range, skip it.
             */
            if (!cur->reverse && keycmp(smaxkey, smaxklen, minkey, minklen) < 0) {
                kvset_iter_mark_eof(cur->iterv[i]);
                continue;
            }
        }

        assert(cur->iterv[i]);

        cur->merr = kvset_iter_seek(cur->iterv[i], key, len, &eof);
        if (ev(cur->merr))
            return cur->merr;

        if (!eof)
            first = first < 0 ? i : first;
    }

    if (first >= 0) {
        u32 depth = cur->iterc - first;

        perfc_set(pc, PERFC_BA_CNCAPPED_DEPTH, (depth * 10000) / cur->iterc);
    }

    /*
     * If we have a problem here, the cursor becomes invalid,
     * and cannot be reused.  Only recovery is to destroy it.
     */
    cur->merr = bin_heap2_prepare(cur->bh, cur->iterc, cur->esrcv);
    perfc_set(pc, PERFC_BA_CNCAPPED_ACTIVE, (10000 * bin_heap2_width(cur->bh)) / cur->iterc);

    /*
     * If asked for what we found, return the key here.
     * NOTE: is not necessarily the next key to be returned
     * via cursor read because this code does not filter
     * tombstones, but cursor read does.
     */
    if (kt) {
        struct cn_kv_item  item = {};
        struct cn_kv_item *i = &item;

        kt->kt_len = 0;
        if (bin_heap2_peek(cur->bh, (void **)&i)) {
            uint len;

            kt->kt_data = key_obj_copy(cur->buf, cur->bufsz, &len, &i->kobj);
            kt->kt_len = len;
        }
    }

    return cur->merr;
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

        if (new_kvset)
            kvset_list_add(new_kvset, &le->le_link);
    }

    cn_tree_samp(tree, &work->cw_samp_pre);

    cn_tree_samp_update_compact(tree, work->cw_node);

    cn_tree_samp(tree, &work->cw_samp_post);

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

struct spill_child {
    struct cn_tree_node *node;
    struct kvset *       kvset;
};

/**
 * cn_comp_update_spill() - update tree after spill operation
 * See section comment for more info.
 */
static void
cn_comp_update_spill(struct cn_compaction_work *work, struct spill_child *childv)
{
    struct cn_tree *         tree = work->cw_tree;
    u64                      txid = work->cw_work_txid;
    struct cn_tree_node *    pnode = work->cw_node;
    struct kvset_list_entry *le, *tmp;
    u32                      cx, kx;
    struct list_head         retired_kvsets;

    if (ev(work->cw_err))
        return;

    INIT_LIST_HEAD(&retired_kvsets);

    rmlock_wlock(&tree->ct_lock);
    {

        for (cx = 0; cx < work->cw_outc; cx++) {
            struct cn_tree_node *cnode;
            struct kvset *       kvset;

            kvset = childv[cx].kvset;
            if (!kvset)
                continue;

            cnode = childv[cx].node;
            if (cnode) {
                /* Add new kvsets to new children. */
                assert(!pnode->tn_childv[cx]);

                kvset_list_add(kvset, &cnode->tn_kvset_list);
                cnode->tn_parent = pnode;
                pnode->tn_childv[cx] = cnode;
                pnode->tn_childc++;
                if (pnode->tn_childc == 1)
                    tree->ct_i_nodec++;
                else
                    tree->ct_l_nodec++;

                tree->ct_lvl_max = max(tree->ct_lvl_max, cnode->tn_loc.node_level);

            } else {
                /* Add new kvset to existing child */
                cnode = pnode->tn_childv[cx];
                assert(cnode);

                kvset_list_add(kvset, &cnode->tn_kvset_list);
            }
        }

        /* Move old kvsets from parent node to retired list.
         * Asserts:
         * - Each input kvset just spilled must still be on pnode's kvset list.
         * - The dgen of the oldest input kvset must match work struct dgen_lo
         *   (i.e., concurrent spills from a node must be committed in order).
         */
        for (kx = 0; kx < work->cw_kvset_cnt; kx++) {
            assert(!list_empty(&pnode->tn_kvset_list));
            le = list_last_entry(&pnode->tn_kvset_list, struct kvset_list_entry, le_link);
            assert(kx > 0 || work->cw_dgen_lo == kvset_get_dgen(le->le_kvset));
            list_del(&le->le_link);
            list_add(&le->le_link, &retired_kvsets);
        }

        cn_tree_samp(tree, &work->cw_samp_pre);

        cn_tree_samp_update_spill(tree, pnode);

        cn_tree_samp(tree, &work->cw_samp_post);
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
    struct cn_tree_node *    node = work->cw_node;
    merr_t                   err = 0;
    struct kvset_list_entry *le;
    u32                      cx, kx;
    struct spill_child *     childv;

    /* Precondition: n_outputs == tree fanout */
    assert(work->cw_outc == tree->ct_cp->cp_fanout);
    if (ev(work->cw_outc != tree->ct_cp->cp_fanout))
        return merr(EBUG);

    childv = calloc(tree->ct_cp->cp_fanout, sizeof(*childv));
    if (!childv)
        return merr(EBUG);

    for (cx = 0; cx < work->cw_outc; cx++) {
        childv[cx].kvset = kvsets[cx];
        childv[cx].node = NULL;

        if (!kvsets[cx])
            continue;

        if (!node->tn_childv[cx]) {

            childv[cx].node = cn_node_alloc(
                tree,
                node->tn_loc.node_level + 1,
                node_nth_child_offset(tree->ct_fanout_bits, &node->tn_loc, cx));
            if (ev(!childv[cx].node)) {
                err = merr(ENOMEM);
                goto done;
            }
        }
    }

    /* Update CNDB with "D" records.  No need to lock kvset as long as
     * we only access the marked kvsets.
     */
    le = work->cw_mark;
    for (kx = 0; kx < work->cw_kvset_cnt; kx++) {
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
    cn_comp_update_spill(work, childv);

done:
    if (err) {
        while (cx-- > 0)
            cn_node_free(childv[cx].node);
    }
    free(childv);

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
        if (w->cw_outv[i].kblks.n_blks == 0)
            continue;

        km.km_dgen = w->cw_dgen_hi;
        km.km_vused = w->cw_outv[i].bl_vused;

        /* Lend kblk and vblk lists to kvset_create().
         * Yes, the struct copy is a bit gross, but it works and
         * avoids unnecessary allocations of temporary lists.
         */
        km.km_kblk_list = w->cw_outv[i].kblks;
        km.km_vblk_list = w->cw_outv[i].vblks;
        km.km_capped = cn_is_capped(w->cw_tree->cn);
        km.km_restored = false;
        km.km_scatter = use_mbsets ? scatter : (km.km_vused ? 1 : 0);

        if (spill) {
            km.km_compc = 0;
            km.km_node_level = w->cw_node->tn_loc.node_level + 1;
            km.km_node_offset =
                node_nth_child_offset(w->cw_tree->ct_fanout_bits, &w->cw_node->tn_loc, i);
        } else {
            km.km_compc = w->cw_compc + 1;
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


    if (unlikely(w->cw_err)) {

        /* Failed spills cause node to become "wedged"  */
        if (ev(w->cw_rspill_conc && !w->cw_node->tn_rspills_wedged))
            w->cw_node->tn_rspills_wedged = 1;

        /* Log errors if debugging or if job was not canceled.
         * Canceled jobs are expected, so there's no need to log them
         * unless debugging.
         */
        if (w->cw_debug || !w->cw_canceled)
            hse_elog(HSE_ERR "compaction error @@e: sts/job %u comp %s rule %s"
                " cnid %lu lvl %u off %u dgenlo %lu dgenhi %lu wedge %d",
                w->cw_err,
                w->cw_job.sj_id,
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

    bool   kcompact = w->cw_action == CN_ACTION_COMPACT_K;
    bool   skip_commit = false;
    merr_t err;
    u32    i;
    u64    ns;
    u64    ingestsz;

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

    ns = get_time_ns();
    if (kcompact)
        err = cn_kcompact(w);
    else
        err = cn_spill(w);

    /* [HSE_REVISIT] The combination of key_bytes_out and val_bytes_out
     * seems more than what is written to the media for kcompaction.
     * Discarding the kcompation for bandwidth calculation for now.
     */
    if (kcompact) {
        ns = 0;
        ingestsz = 0;
    } else {
        ns = get_time_ns() - ns;
        ingestsz = w->cw_stats.ms_key_bytes_out;
        ingestsz += w->cw_stats.ms_val_bytes_out;
    }

    if (merr_errno(err) == ESHUTDOWN && atomic_read(w->cw_cancel_request))
        w->cw_canceled = true;

    /* defer status check until *after* cleanup */
    for (i = 0; i < w->cw_kvset_cnt; i++)
        if (w->cw_inputv[i])
            w->cw_inputv[i]->kvi_ops->kvi_release(w->cw_inputv[i]);
    free(w->cw_inputv);
    free(w->cw_drop_tombv);
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

        err = cndb_txn_start(w->cw_tree->cndb, &w->cw_work_txid, CNDB_INVAL_INGESTID, nc, nd, 0);
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
            NULL,
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
void
cn_comp(struct cn_compaction_work *w)
{
    u64               tstart;
    struct perfc_set *pc = w->cw_pc;

    tstart = perfc_lat_start(pc);
    cn_comp_compact(w);

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
    }
    perfc_lat_record(pc, PERFC_LT_CNCOMP_TOTAL, tstart);
}

/**
 * cn_comp_cancel_cb() - sts callback when a job is canceled
 */
void
cn_comp_cancel_cb(struct sts_job *job)
{
    struct cn_compaction_work *w;

    w = container_of(job, struct cn_compaction_work, cw_job);

    if (w->cw_debug)
        hse_log(HSE_NOTICE "sts/job %u cancel callback", w->cw_job.sj_id);

    w->cw_canceled = true;
    w->cw_err = merr(ESHUTDOWN);

    cn_comp(w);
}

/**
 * cn_comp_slice_cb() - sts callback to run an sts job slice
 */
void
cn_comp_slice_cb(struct sts_job *job)
{
    struct cn_compaction_work *w;

    w = container_of(job, struct cn_compaction_work, cw_job);

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

    assert(post.i_alen > pre.i_alen);
    assert(post.r_wlen > pre.r_wlen);
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

merr_t
cn_tree_init(void)
{
    struct kmem_cache *cache;
    int                i;

    if (atomic_inc_return(&cn_tree_init_ref) > 1)
        return 0;

    /* Initialize the view table cache.
     */
    for (i = 0; i < NELEM(vtc); ++i) {
        struct vtc_bkt *bkt = vtc + i;

        spin_lock_init(&bkt->lock);
        bkt->max = 8;
    }

    cache = kmem_cache_create("cntreenode", cn_node_size(), SMP_CACHE_BYTES, 0, NULL);
    if (ev(!cache)) {
        atomic_dec(&cn_tree_init_ref);
        return merr(ENOMEM);
    }

    cn_node_cache = cache;

    return 0;
}

void
cn_tree_fini(void)
{
    int i;

    if (atomic_dec_return(&cn_tree_init_ref) > 0)
        return;

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

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_tree_ut_impl.i"
#include "cn_tree_compact_ut_impl.i"
#include "cn_tree_create_ut_impl.i"
#include "cn_tree_cursor_ut_impl.i"
#include "cn_tree_internal_ut_impl.i"
#include "cn_tree_iter_ut_impl.i"
#include "cn_tree_view_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
