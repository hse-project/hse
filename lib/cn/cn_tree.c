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

#include <sys/mman.h>

#include <hse_util/alloc.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_util/list.h>
#include <hse_util/mutex.h>
#include <hse/logging/logging.h>
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
#include "kvcompact.h"
#include "kblock_builder.h"
#include "vblock_builder.h"
#include "route.h"
#include "kvset_internal.h"
#include "node_split.h"

static struct kmem_cache *cn_node_cache HSE_READ_MOSTLY;

static void
cn_setname(const char *name)
{
    pthread_setname_np(pthread_self(), name);
}

static size_t
cn_node_size(void)
{
    return ALIGN(sizeof(struct cn_tree_node), __alignof__(struct cn_tree_node));
}

struct cn_tree_node *
cn_node_alloc(struct cn_tree *tree, uint64_t nodeid)
{
    struct cn_tree_node *tn;

    tn = kmem_cache_zalloc(cn_node_cache);
    if (ev(!tn))
        return NULL;

    if (ev(hlog_create(&tn->tn_hlog, HLOG_PRECISION))) {
        kmem_cache_free(cn_node_cache, tn);
        return NULL;
    }

    INIT_LIST_HEAD(&tn->tn_link);
    INIT_LIST_HEAD(&tn->tn_kvset_list);

    atomic_init(&tn->tn_compacting, 0);
    atomic_init(&tn->tn_busycnt, 0);

    tn->tn_tree = tree;
    tn->tn_isroot = (nodeid == 0);
    tn->tn_nodeid = nodeid;

    tn->tn_split_size = (size_t)tree->rp->cn_split_size << 30;

    mutex_init(&tn->tn_spill_mtx);
    cv_init(&tn->tn_spill_cv);

    mutex_init(&tn->tn_ss_lock);
    INIT_LIST_HEAD(&tn->tn_ss_list);
    tn->tn_ss_spilling = 0;
    tn->tn_ss_splitting = false;
    cv_init(&tn->tn_ss_cv);

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

static void
cn_subspill_enqueue(struct subspill *ss, struct cn_tree_node *tn)
{
    struct subspill *entry;

    mutex_lock(&tn->tn_ss_lock);

    /* Add ss at the right position in the node's mutation list. The list is sorted by
     * sgen - smallest to largest.
     */
    list_for_each_entry(entry, &tn->tn_ss_list, ss_link) {
        if (ss->ss_sgen < entry->ss_sgen)
            break;
    }

    list_add_tail(&ss->ss_link, entry ? &entry->ss_link : &tn->tn_ss_list);
    mutex_unlock(&tn->tn_ss_lock);
}

static struct subspill *
cn_subspill_pop(struct cn_tree_node *tn)
{
    struct subspill *entry;
    bool found = false;

    mutex_lock(&tn->tn_ss_lock);

    entry = list_first_entry_or_null(&tn->tn_ss_list, typeof(*entry), ss_link);
    if (entry && entry->ss_sgen == atomic_read(&tn->tn_sgen) + 1) {
        list_del(&entry->ss_link);
        entry->ss_applied = true;
        found = true;
    }

    mutex_unlock(&tn->tn_ss_lock);

    return found ? entry : NULL;
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

    if (ev(cp->pfx_len > HSE_KVS_PFX_LEN_MAX))
        return merr(EINVAL);

    tree = aligned_alloc(__alignof__(*tree), sizeof(*tree));
    if (ev(!tree))
        return merr(ENOMEM);

    memset(tree, 0, sizeof(*tree));
    INIT_LIST_HEAD(&tree->ct_nodes);
    tree->ct_pfx_len = cp->pfx_len;
    tree->ct_sfx_len = cp->sfx_len;
    tree->rp = rp;
    tree->ct_cp = cp;
    tree->ct_rspill_dt = 1;
    tree->ct_kvdb_health = health;

    tree->ct_root = cn_node_alloc(tree, 0);
    if (ev(!tree->ct_root)) {
        free(tree);
        return merr(ENOMEM);
    }

    list_add(&tree->ct_root->tn_link, &tree->ct_nodes);

    if (kvsname) {
        tree->ct_route_map = route_map_create(CN_FANOUT_MAX);
        if (!tree->ct_route_map) {
            cn_tree_destroy(tree);
            return merr(ENOMEM);
        }
    }

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
    struct cn_tree_node *node, *next;

    if (!tree)
        return;

    /* Verify root node is at head of the list.
     */
    assert(tree->ct_root == list_first_entry(&tree->ct_nodes, typeof(*node), tn_link));

    /* Destroy root node last via safe reverse iteration of ct_nodes.
     */
    list_for_each_entry_reverse_safe(node, next, &tree->ct_nodes, tn_link) {
        if (node->tn_route_node)
            route_map_delete(tree->ct_route_map, node->tn_route_node);
        cn_work_submit(tree->cn, cn_node_destroy_cb, &node->tn_destroy_work);
    }

    /* Wait for async work to complete...
     */
    cn_ref_wait(tree->cn);

    rmlock_destroy(&tree->ct_lock);
    route_map_destroy(tree->ct_route_map);
    free(tree);
}

void
cn_tree_setup(
    struct cn_tree *    tree,
    struct mpool *      mp,
    struct cn *         cn,
    struct kvs_rparams *rp,
    struct cndb *       cndb,
    u64                 cnid,
    struct cn_kvdb *    cn_kvdb)
{
    tree->mp = mp;
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
cn_tree_get_mp(const struct cn_tree *tree)
{
    return tree->mp;
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
        if (s->ns_keys_uniq > num_keys)
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

    s->ns_hclen = s->ns_kst.kst_halen;
    s->ns_pcap = min_t(uint16_t, UINT16_MAX, 100 * cn_ns_clen(s) / tn->tn_split_size);

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
void
cn_tree_samp_init(struct cn_tree *tree)
{
    struct cn_tree_node *tn;

    /* cn_tree_samp_update_compact() does a full recomputation
     * of samp stats, so use it to initalize tree samp stats.
     */
    memset(&tree->ct_samp, 0, sizeof(tree->ct_samp));

    cn_tree_foreach_node(tn, tree) {
        cn_tree_samp_update_compact(tree, tn);
    }
}

/* This function must be serialized with other cn_tree_samp_* functions
 * if a consistent set of stats is desired.
 */
void
cn_tree_samp(const struct cn_tree *tree, struct cn_samp_stats *s_out)

{
    *s_out = tree->ct_samp;
}

struct cn_tree_node *
cn_tree_find_node(struct cn_tree *tree, uint64_t nodeid)
{
    struct cn_tree_node *node;

    cn_tree_foreach_node(node, tree) {
        if (node->tn_nodeid == nodeid)
            break;
    }

    return node;
}

/**
 * cn_tree_insert_kvset - add kvset to tree during initialization
 * @tree:  tree under construction
 * @kvset: new kvset to add to tree
 * @nodeid: node ID
 *
 * This function is used during initialization to insert a kvset
 * into the correct node of the cn tree.
 *
 * NOTE: It is not intended to be used to update a node after compaction or
 * ingest operations.
 */
merr_t
cn_tree_insert_kvset(struct cn_tree *tree, struct kvset *kvset, uint64_t nodeid)
{
    struct cn_tree_node *node;

    assert(tree->ct_root == list_first_entry(&tree->ct_nodes, typeof(*node), tn_link));

    node = cn_tree_find_node(tree, nodeid);
    if (!node) {
        assert(0);
        return merr(EBUG);
    }

    return cn_node_insert_kvset(node, kvset);
}

merr_t
cn_node_insert_kvset(struct cn_tree_node *node, struct kvset *kvset)
{
    struct list_head *head;
    u64 dgen = kvset_get_dgen(kvset);

    list_for_each(head, &node->tn_kvset_list) {
        struct kvset_list_entry *entry;

        entry = list_entry(head, typeof(*entry), le_link);
        if (dgen > kvset_get_dgen(entry->le_kvset))
            break;
    }

    kvset_list_add_tail(kvset, head);

    return 0;
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
    table_destroy(view);
}

merr_t
cn_tree_view_create(struct cn *cn, struct table **view_out)
{
    struct table *           view;
    struct cn_tree_node *    node;
    void *                   lock;
    struct cn_tree *         tree = cn_get_tree(cn);
    merr_t                   err = 0;
    uint nodecnt;

    nodecnt = (128 * 1024) / sizeof(struct kvset_view);

    view = table_create(nodecnt, sizeof(struct kvset_view), false);
    if (ev(!view))
        return merr(ENOMEM);

    rmlock_rlock(&tree->ct_lock, &lock);
    nodecnt = 0;

    cn_tree_foreach_node(node, tree) {
        struct kvset_list_entry *le;
        struct kvset_view *s;

        /* create an entry for the node */
        s = table_append(view);
        if (ev(!s)) {
            err = merr(ENOMEM);
            break;
        }

        s->kvset = NULL;
        s->nodeid = node->tn_nodeid;
        s->eklen = 0;

        if (node->tn_route_node)
            route_node_keycpy(node->tn_route_node, s->ekbuf, sizeof(s->ekbuf), &s->eklen);

        list_for_each_entry(le, &node->tn_kvset_list, le_link) {
            struct kvset *kvset = le->le_kvset;

            s = table_append(view);
            if (ev(!s)) {
                err = merr(ENOMEM);
                break;
            }

            kvset_get_ref(kvset);
            s->kvset = kvset;
            s->nodeid = kvset_get_nodeid(kvset);
            s->eklen = 0;

            assert(s->nodeid == node->tn_nodeid);
        }

        if (err)
            break;

        if ((nodecnt++ % 16) == 0)
            rmlock_yield(&tree->ct_lock, &lock);
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
    struct cn_tree_node *    node;
    struct kvset_list_entry *le;
    void *                   lock;
    bool                     stop;

    rmlock_rlock(&tree->ct_lock, &lock);
    stop = false;

    cn_tree_foreach_node(node, tree) {
        bool empty_node = true;

        if (kvset_order == KVSET_ORDER_NEWEST_FIRST) {

            /* newest first ==> head to tail */
            list_for_each_entry (le, &node->tn_kvset_list, le_link) {
                empty_node = false;
                stop = callback(callback_rock, tree, node, le->le_kvset);
                if (stop)
                    goto unlock;
            }
        } else {
            /* oldest first ==> tail to head */
            list_for_each_entry_reverse (le, &node->tn_kvset_list, le_link) {
                empty_node = false;
                stop = callback(callback_rock, tree, node, le->le_kvset);
                if (stop)
                    goto unlock;
            }
        }

        /* end of node */
        if (!empty_node) {
            stop = callback(callback_rock, tree, node, NULL);
            if (stop)
                goto unlock;
        }
    }

unlock:
    if (!stop) {
        /* end of tree */
        callback(callback_rock, tree, NULL, NULL);
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
 * @qctx: query context (if this is a prefix probe)
 * @kbuf: (output) key if this is a prefix probe
 * @vbuf: (output) value if result @res == %FOUND_VAL or %FOUND_MULTIPLE
 */
merr_t
cn_tree_lookup(
    struct cn_tree *     tree,
    struct perfc_set *   pc,
    struct kvs_ktuple *  kt,
    uint64_t             seq,
    enum key_lookup_res *res,
    struct query_ctx *   qctx,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf)
{
    enum kvdb_perfc_sidx_cnget pc_cidx;
    struct cn_tree_node *node;
    struct key_disc kdisc;
    uint64_t pc_start;
    void *lock, *wbti;
    merr_t err;

    *res = NOT_FOUND;

    pc_start = perfc_lat_startu(pc, PERFC_LT_CNGET_GET);
    pc_cidx = PERFC_LT_CNGET_GET_LEAF + 1;

    if (qctx) {
        err = kvset_wbti_alloc(&wbti);
        if (ev(err))
            return err;
    } else {
        if (pc_start > 0) {
            if (perfc_ison(pc, PERFC_LT_CNGET_GET_ROOT))
                pc_cidx = PERFC_LT_CNGET_GET_ROOT;
        }
        wbti = NULL;
    }

    key_disc_init(kt->kt_data, kt->kt_len, &kdisc);

    rmlock_rlock(&tree->ct_lock, &lock);
    node = tree->ct_root;
    err = 0;

    while (node) {
        struct kvset_list_entry *le;

        /* Search kvsets from newest to oldest (head to tail).
         * If an error occurs or a key is found, return immediately.
         */
        list_for_each_entry(le, &node->tn_kvset_list, le_link) {
            struct kvset *kvset = le->le_kvset;

            if (qctx) {
                err = kvset_pfx_lookup(kvset, kt, &kdisc, seq, res, wbti, kbuf, vbuf, qctx);
                if (err || qctx->seen > 1 || *res == FOUND_PTMB)
                    goto done;
            } else {
                err = kvset_lookup(kvset, kt, &kdisc, seq, res, vbuf);
                if (err || *res != NOT_FOUND)
                    goto done;

                pc_cidx++;
            }
        }

        if (cn_node_isleaf(node))
            break;

        node = cn_tree_node_lookup(tree, kt->kt_data, kt->kt_len);
    }

  done:
    rmlock_runlock(lock);

    if (qctx) {
        perfc_lat_record(pc, PERFC_LT_CNGET_PROBE_PFX, pc_start);
        kvset_wbti_free(wbti);
    } else {
        if (pc_start > 0) {
            uint pc_cidx_lt = (*res == NOT_FOUND) ? PERFC_LT_CNGET_MISS : PERFC_LT_CNGET_GET;

            perfc_lat_record(pc, pc_cidx_lt, pc_start);

            if (pc_cidx < PERFC_LT_CNGET_GET_LEAF + 1)
                perfc_lat_record(pc, pc_cidx, pc_start);
        }
    }

    perfc_inc(pc, *res);

    return err;
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

    perfc_inc(w->cw_pc, PERFC_BA_CNCOMP_FINISH);
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
    struct cndb_txn         *cndb_txn;

    u8     pt_key[sizeof(tree->ct_last_ptomb)];
    void * lock;
    merr_t err;
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

    if (!mark)
        goto err_out;

    err = cndb_record_txstart(tree->cndb, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON, 0,
                              kvset_cnt, &cndb_txn);
    if (ev(err))
        goto err_out;

    /* Step 2: Log kvset delete records.
     * Don't need to hold a lock because this is the only thread deleting
     * kvsets from cn and we are sure that there are at least kvset_cnt
     * kvsets in the node.
     */
    le = mark;
    while (1) {
        err = kvset_delete_log_record(le->le_kvset, cndb_txn);
        if (ev(err) || le == last)
            break;

        le = list_next_entry(le, le_link);
    }

    if (ev(err)) {
        cndb_record_nak(tree->cndb, cndb_txn);
        goto err_out;
    }

    /* Step 3: Remove retired kvsets from node list.
     */
    rmlock_wlock(&tree->ct_lock);
    list_trim(&retired, head, &mark->le_link);
    cn_tree_samp_update_compact(tree, node);
    rmlock_wunlock(&tree->ct_lock);

    /* Step 4: Delete retired kvsets outside the tree write lock.
     */
    list_for_each_entry_safe(le, next, &retired, le_link) {
        kvset_mark_mblocks_for_delete(le->le_kvset, false);
        kvset_put_ref(le->le_kvset);
    }

    return;

err_out:
    cn_tree_capped_evict(tree, first, last);
    return;
}

merr_t
cn_tree_prepare_compaction(struct cn_compaction_work *w)
{
    struct kvset_mblocks    *outs = 0;
    struct kvset_vblk_map    vbm = {};
    struct workqueue_struct *vra_wq;
    struct cn_tree_node     *node = w->cw_node;
    struct kvset_list_entry *le;
    struct kv_iterator     **ins = NULL;
    merr_t err = 0;
    size_t outsz = 0;
    u32 n_outs;
    uint i;
    const bool kcompact = (w->cw_action == CN_ACTION_COMPACT_K);
    const bool split = (w->cw_action == CN_ACTION_SPLIT);

    n_outs = 1;

    w->cw_horizon = cn_get_seqno_horizon(w->cw_tree->cn);
    w->cw_cancel_request = cn_get_cancel(w->cw_tree->cn);

    perfc_inc(w->cw_pc, PERFC_BA_CNCOMP_START);

    cn_setname(w->cw_threadname);

    /* If we are k/kv-compacting, we only have a single output.
     *
     * Node split creates at most twice the number of kvsets as the source node (n_outs)
     * The two output nodes for split are stored in cw_split.nodev[]
     */
    if (split) {
        if (cn_ns_kvsets(&w->cw_node->tn_ns) != w->cw_kvset_cnt)
            return merr(EBUG);

        n_outs = 2 * w->cw_kvset_cnt;
    } else {
        if (kcompact || w->cw_action == CN_ACTION_COMPACT_KV)
            n_outs = 1;

        ins = calloc(w->cw_kvset_cnt, sizeof(*ins));
        if (!ins)
            return merr(ENOMEM);

        outsz = sizeof(w->cw_output_nodev[0]);
    }

    outsz += (sizeof(*outs) + sizeof(*w->cw_kvsetidv));
    outs = calloc(n_outs, outsz);
    if (!outs) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    w->cw_kvsetidv = (void *)(outs + n_outs);
    if (!split)
        w->cw_output_nodev = (void *)(w->cw_kvsetidv + n_outs);

    w->cw_vgmap = NULL;
    if (kcompact || split) {
        w->cw_vgmap = calloc(n_outs, sizeof(*w->cw_vgmap));
        if (!w->cw_vgmap) {
            err = merr(ENOMEM);
            goto err_exit;
        }

        if (split) {
            size_t sz = HSE_KVS_KEY_LEN_MAX +
                n_outs * (sizeof(*(w->cw_split.commit)) + sizeof(*(w->cw_split.dgen)) +
                          sizeof(*(w->cw_split.compc))) +
                w->cw_kvset_cnt * sizeof(*(w->cw_split.purge));

            w->cw_split.key = calloc(1, sz);
            if (!w->cw_split.key) {
                err = merr(ENOMEM);
                goto err_exit;
            }

            w->cw_split.commit = w->cw_split.key + HSE_KVS_KEY_LEN_MAX;
            w->cw_split.dgen = (void *)(w->cw_split.commit + n_outs);
            w->cw_split.compc = (void *)(w->cw_split.dgen + n_outs);
            w->cw_split.purge = (void *)(w->cw_split.compc + n_outs);
        }
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
     *
     * Node splits do not need input iterators because there's no merge loop.
     */
    for (i = 0, le = w->cw_mark; !split && i < w->cw_kvset_cnt;
         i++, le = list_prev_entry(le, le_link)) {

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
    if (kcompact) {
        err = kvset_keep_vblocks(&vbm, w->cw_vgmap, ins, w->cw_kvset_cnt);
        if (ev(err))
            goto err_exit;
    }

    w->cw_inputv = ins;
    w->cw_outc = n_outs;
    w->cw_outv = outs;
    w->cw_vbmap = vbm;

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
        if (w->cw_vgmap) {
            if (kcompact)
                vgmap_free(w->cw_vgmap[0]); /* one output kvset for k-compact */
            else if (split)
                free(w->cw_split.key);
            free(w->cw_vgmap);
        }
    }
    free(outs);

    return err;
}

/*----------------------------------------------------------------
 *
 * SECTION: Cn Tree Compaction (k-compaction, kv-compaction, spill)
 */

/**
 * cn_comp_update_kvcompact() - Update tree after k-compact and kv-compact
 * See section comment for more info.
 */
static void
cn_comp_update_kvcompact(struct cn_compaction_work *work, struct kvset *new_kvset)
{
    struct cn_tree *         tree = work->cw_tree;
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
    rmlock_wunlock(&tree->ct_lock);

    /* Delete retired kvsets. */
    list_for_each_entry_safe(le, tmp, &retired_kvsets, le_link) {

        assert(kvset_get_dgen(le->le_kvset) >= work->cw_dgen_lo);
        assert(kvset_get_dgen(le->le_kvset) <= work->cw_dgen_hi);

        kvset_mark_mblocks_for_delete(le->le_kvset, work->cw_keep_vblks);
        kvset_put_ref(le->le_kvset);
    }
}

static bool
cn_node_spill_wait(struct cn_compaction_work *w, struct cn_tree_node *tn)
{
    atomic_long *node_sgen = &w->cw_node->tn_sgen;
    struct kvdb_health *hp = w->cw_tree->ct_kvdb_health;

    mutex_lock(&tn->tn_spill_mtx);

    while (w->cw_sgen != atomic_read(node_sgen) + 1 &&
           !atomic_read(w->cw_cancel_request) &&
           !kvdb_health_check(hp, KVDB_HEALTH_FLAG_ALL)) {

        long timeout_ms = 100;

        /* TODO: We could be waiting here for ten minutes or more when
         * using slow media, so better to use cv_wait() and fix the
         * shutdown path to wake up waiters.
         */
        cv_timedwait(&tn->tn_spill_cv, &tn->tn_spill_mtx, timeout_ms, "spilwait");
    }

    mutex_unlock(&tn->tn_spill_mtx);

    return !atomic_read(w->cw_cancel_request) && !kvdb_health_check(hp, KVDB_HEALTH_FLAG_ALL);
}

static void
cn_node_spill_broadcast(struct cn_tree_node *tn)
{
    mutex_lock(&tn->tn_spill_mtx);
    atomic_inc(&tn->tn_sgen);
    cv_broadcast(&tn->tn_spill_cv);
    mutex_unlock(&tn->tn_spill_mtx);
}

static void
cn_spill_delete_kvsets(struct cn_compaction_work *work)
{
    struct list_head         retired_kvsets;
    struct cn_tree          *tree = work->cw_tree;
    struct cn_tree_node     *pnode = work->cw_node;
    struct kvset_list_entry *le, *tmp;
    struct cndb_txn         *tx;

    assert(!work->cw_err);

    INIT_LIST_HEAD(&retired_kvsets);

    work->cw_err = cndb_record_txstart(work->cw_tree->cndb, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON,
                                       0, work->cw_kvset_cnt, &tx);
    if (work->cw_err)
        goto done;

    le = work->cw_mark;
    assert(le == list_last_entry(&pnode->tn_kvset_list, struct kvset_list_entry, le_link));

    for (uint i = 0; i < work->cw_kvset_cnt; i++) {
        INVARIANT(le);

        work->cw_err = kvset_delete_log_record(le->le_kvset, tx);
        if (work->cw_err)
            goto done;

        le = list_prev_entry(le, le_link);
    }

    rmlock_wlock(&tree->ct_lock);

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

    /* Advance the change generation on the spill source node
     * to ensure it is reevaluated by csched/sp3_dirty_node().
     */
    pnode->tn_cgen++;

    cn_tree_samp_update_compact(tree, pnode);
    rmlock_wunlock(&tree->ct_lock);

done:
    /* Delete old kvsets. */
    list_for_each_entry_safe(le, tmp, &retired_kvsets, le_link) {
        kvset_mark_mblocks_for_delete(le->le_kvset, false);
        kvset_put_ref(le->le_kvset);
    }

    /* Signal all the waiting spills.
     */
    cn_node_spill_broadcast(pnode);
}

/**
 * cn_comp_update_split() - update tree after a node split operation
 */
static void
cn_comp_update_split(
    struct cn_compaction_work *w,
    struct kvset *const       *kvsets,
    struct cn_tree_node       *nodev[static 2])
{
    struct cn_tree *tree = w->cw_tree;
    struct kvset_list_entry *le, *tmp;
    struct list_head retired_kvsets;
    struct cn_tree_node *src = w->cw_node;
    struct cn_tree_node *left = nodev[LEFT], *right = nodev[RIGHT];
    uint k = 0;

    if (w->cw_err)
        return;

    assert(left || right);

    INIT_LIST_HEAD(&retired_kvsets);

    /* Add the left half of the split kvsets to the 'left' node.
     * This need not be done under the tree lock as the new left node is not published yet.
     */
    if (left) {
        assert(list_empty(&left->tn_kvset_list));
        for (k = 0; k < w->cw_kvset_cnt; k++) {
            if (kvsets[k])
                kvset_list_add_tail(kvsets[k], &left->tn_kvset_list);
        }

        w->cw_split.nodev[LEFT] = left;
    }

    if (w->cw_debug & CW_DEBUG_SPLIT)
        cn_split_node_stats_dump(w, src, "source");

    rmlock_wlock(&tree->ct_lock);
    {
        /* Move all the source kvsets from the source node to the retired list.
         */
        list_splice(&src->tn_kvset_list, &retired_kvsets);
        INIT_LIST_HEAD(&src->tn_kvset_list);

        /* Add the right half of the split kvsets to the 'right' node.
         */
        if (right) {
            assert(list_empty(&right->tn_kvset_list));

            for (k = w->cw_kvset_cnt; k < w->cw_outc; k++) {
                if (kvsets[k])
                    kvset_list_add_tail(kvsets[k], &right->tn_kvset_list);
            }

            assert(route_node_keycmp(right->tn_route_node, w->cw_split.key, w->cw_split.klen) > 0);

            w->cw_split.nodev[RIGHT] = right;
            right->tn_cgen++;
        }

        /* Update route map with the left edge and add the new left node to the cN tree list.
         * The 'right' node is already part of the cn tree list.
         */
        if (left) {
            if (route_map_insert_by_node(tree->ct_route_map, left->tn_route_node))
                abort();

            assert(route_node_keycmp(left->tn_route_node, w->cw_split.key, w->cw_split.klen) == 0);

            list_add_tail(&left->tn_link, &tree->ct_nodes);
            left->tn_cgen++;
        }

        /* Update samp stats
         */
        for (int i = 0; i < 2 && w->cw_split.nodev[i]; i++) {
            cn_tree_samp(tree, &w->cw_samp_pre);
            cn_tree_samp_update_compact(tree, w->cw_split.nodev[i]);
            cn_tree_samp(tree, &w->cw_samp_post);
        }

        if (w->cw_debug & CW_DEBUG_SPLIT) {
            cn_split_node_stats_dump(w, left, "left");
            cn_split_node_stats_dump(w, right, "right");
        }
    }
    rmlock_wunlock(&tree->ct_lock);

    /* Delete retired kvsets
     */
    k = 0;
    list_for_each_entry_safe(le, tmp, &retired_kvsets, le_link) {
        struct kvset *ks = le->le_kvset;

        kvset_purge_blklist_add(ks, &w->cw_split.purge[k]);
        blk_list_free(&w->cw_split.purge[k]);

        kvset_mark_mbset_for_delete(ks, false);
        kvset_put_ref(ks);
        k++;
    }
}

static void
cn_comp_update_subspill(
    struct cn_compaction_work *work,
    struct cn_tree_node       *node,
    struct kvset              *kvset)
{
    struct cn_tree *tree = work->cw_tree;

    if (work->cw_err)
        return;

    INVARIANT(node);
    INVARIANT(kvset);

    rmlock_wlock(&tree->ct_lock);

    assert(node);
    kvset_list_add(kvset, &node->tn_kvset_list);
    node->tn_cgen++;

    cn_tree_samp(tree, &work->cw_samp_pre);
    cn_tree_samp_update_ingest(tree, node);
    cn_tree_samp(tree, &work->cw_samp_post);

    rmlock_wunlock(&tree->ct_lock);
}

/**
 * cn_comp_commit() - commit compaction operation to cndb log
 * See section comment for more info.
 */
static void
cn_comp_commit(struct cn_compaction_work *w)
{
    struct kvset  **kvsets = 0;
    struct mbset ***vecs = 0;
    uint           *cnts = 0;
    void          **cookiev = 0;
    uint            alloc_len;
    const bool      is_kcompact = (w->cw_action == CN_ACTION_COMPACT_K);
    const bool      is_split = (w->cw_action == CN_ACTION_SPLIT);
    bool            use_mbsets = is_kcompact;
    bool            txn_nak = false;
    merr_t          err = 0;
    uint            i;

    struct cn_tree_node *split_nodev[2] = { 0 };
    uint64_t             split_nodeidv[2];
    struct cndb_txn     *tx;

    struct kvdb_health *hp = w->cw_tree->ct_kvdb_health;

    assert(w->cw_action != CN_ACTION_SPILL);

    if (w->cw_err)
        goto done;

    assert(w->cw_outc);

    /* if k-compaction and no kblocks, then force keepv to false. */
    if (is_kcompact && w->cw_outv[0].kblks.n_blks == 0)
        w->cw_keep_vblks = false;

    alloc_len = sizeof(*kvsets) * w->cw_outc;
    if (use_mbsets && w->cw_keep_vblks) {
        /* For k-compaction, create new kvset with references to
         * mbsets from input kvsets instead of creating new mbsets.
         * We need extra allocations for this.
         */
        alloc_len += sizeof(*vecs) * w->cw_kvset_cnt;
        alloc_len += sizeof(*cnts) * w->cw_kvset_cnt;
    }

    kvsets = calloc(1, alloc_len + (w->cw_outc * sizeof(*cookiev)));
    if (!kvsets) {
        err = merr(ENOMEM);
        goto done;
    }

    cookiev = (void *)kvsets + alloc_len;

    if (use_mbsets && w->cw_keep_vblks) {
        struct kvset_list_entry *le;
        uint i;

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
            le = list_prev_entry(le, le_link);
        }
    }

    err = cndb_record_txstart(w->cw_tree->cndb, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON,
                                    w->cw_outc, w->cw_kvset_cnt, &tx);
    if (err) {
        kvdb_health_error(hp, err);
        goto done;
    }

    txn_nak = true;

    if (is_split) {
        err = cn_split_nodes_alloc(w, split_nodeidv, split_nodev);
        if (err)
            goto done;
    }

    for (i = 0; i < w->cw_outc; i++) {

        struct kvset_meta km = {};

        /* A k-compact with sufficient tombs could annihilate all keys,
         * in which case it will have no h or k blocks, but it may have
         * vblocks that need to be deleted.
         *
         * [HSE_REVISIT] Are there any other corner cases?
         */
        if (!w->cw_outv[i].hblk.bk_blkid) {
            assert(w->cw_outv[i].kblks.n_blks == 0);
            continue;
        }

        km.km_dgen = w->cw_dgen_hi;
        km.km_vused = w->cw_outv[i].bl_vused;

        /* Lend hblk, kblk, and vblk lists to kvset_open().
         * Yes, the struct copy is a bit gross, but it works and
         * avoids unnecessary allocations of temporary lists.
         */
        km.km_hblk = w->cw_outv[i].hblk;
        km.km_kblk_list = w->cw_outv[i].kblks;
        km.km_vblk_list = w->cw_outv[i].vblks;

        km.km_rule = w->cw_rule;
        km.km_capped = cn_is_capped(w->cw_tree->cn);
        km.km_restored = false;

        if (is_split) {
            km.km_compc = w->cw_split.compc[i];
            km.km_nodeid = split_nodeidv[i / w->cw_kvset_cnt];
            km.km_dgen = w->cw_split.dgen[i];
        } else {
            km.km_compc = w->cw_compc;
            km.km_nodeid = w->cw_node->tn_nodeid;
        }

        /* CNDB: Log kvset add records.
         */
        err = cndb_record_kvset_add(
                        w->cw_tree->cndb, tx, w->cw_tree->cnid,
                        km.km_nodeid, &km, w->cw_kvsetidv[i], km.km_hblk.bk_blkid,
                        w->cw_outv[i].kblks.n_blks, (uint64_t *)w->cw_outv[i].kblks.blks,
                        w->cw_outv[i].vblks.n_blks, (uint64_t *)w->cw_outv[i].vblks.blks,
                        &cookiev[i]);

        if (err) {
            kvdb_health_error(hp, err);
            goto done;
        }


        if (is_split) {
            err = commit_mblocks(w->cw_mp, &w->cw_split.commit[i]);
            if (!err)
                blk_list_free(&w->cw_split.commit[i]);
        } else {
            err = cn_mblocks_commit(w->cw_mp, 1, &w->cw_outv[i],
                                          is_kcompact ? CN_MUT_KCOMPACT : CN_MUT_OTHER);
        }

        if (err) {
            kvdb_health_error(hp, err);
            goto done;
        }

        if (use_mbsets) {
            err = kvset_open2(w->cw_tree, w->cw_kvsetidv[i], &km,
                              w->cw_keep_vblks ? w->cw_kvset_cnt : 0, cnts, vecs, &kvsets[i]);
        } else {
            err = kvset_open(w->cw_tree, w->cw_kvsetidv[i], &km, &kvsets[i]);
        }

        if (err)
            goto done;
    }

    /* CNDB: Log kvset delete records.
     */
    {
        struct kvset_list_entry *le = w->cw_mark;

        for (uint i = 0; i < w->cw_kvset_cnt; i++) {
            assert(le);

            err = kvset_delete_log_record(le->le_kvset, tx);
            if (err)
                goto done;

            le = list_prev_entry(le, le_link);
        }
    }

    /* CNDB: Ack all the kvset add records.
     */
    for (i = 0; i < w->cw_outc; i++) {
        if (!w->cw_outv[i].hblk.bk_blkid)
            continue;

        err = cndb_record_kvset_add_ack(w->cw_tree->cndb, tx, cookiev[i]);
        if (err)
            goto done;
    }

    switch (w->cw_action) {
    case CN_ACTION_NONE:
        break;

    case CN_ACTION_COMPACT_K:
    case CN_ACTION_COMPACT_KV:
        cn_comp_update_kvcompact(w, kvsets[0]);
        break;

    case CN_ACTION_SPILL:
        assert(0);
        break;

    case CN_ACTION_SPLIT:
        cn_comp_update_split(w, kvsets, split_nodev);
        break;
    }

done:
    w->cw_t4_commit = get_time_ns();

    w->cw_err = w->cw_err ?: err;

    if (w->cw_err) {
        if (txn_nak)
            cndb_record_nak(w->cw_tree->cndb, tx);

        for (i = 0; i < w->cw_outc && kvsets; i++) {
            if (kvsets[i])
                kvset_put_ref(kvsets[i]);
        }

        if (is_split)
            cn_split_nodes_free(w, split_nodev);
    }

    /* always free these ptrs */
    free(kvsets);
}

/**
 * cn_comp_cleanup() - cleanup after compaction operation
 * See section comment for more info.
 */
static void
cn_comp_cleanup(struct cn_compaction_work *w)
{
    const bool kcompact = (w->cw_action == CN_ACTION_COMPACT_K);
    const bool spill = (w->cw_action == CN_ACTION_SPILL);
    const bool split = (w->cw_action == CN_ACTION_SPLIT);

    if (split) {
        struct cn_tree_node *tn = w->cw_node;

        mutex_lock(&tn->tn_ss_lock);
        tn->tn_ss_splitting = false;
        tn->tn_tree->ct_split_cnt--;
        cv_broadcast(&tn->tn_ss_cv);
        mutex_unlock(&tn->tn_ss_lock);
    }

    atomic_sub_rel(&w->cw_node->tn_busycnt, (1u << 16) + w->cw_kvset_cnt);

    if (w->cw_have_token)
        cn_node_comp_token_put(w->cw_node);

    if (w->cw_err) {

        /* Failed spills cause node to become "wedged"  */
        if (spill && !w->cw_tree->ct_rspills_wedged) {
            log_info("root node wedged, spills disabled");
            w->cw_tree->ct_rspills_wedged = true;
        }

        /* Log errors if debugging or if job was not canceled.
         * Canceled jobs are expected, so there's no need to log them
         * unless debugging.
         */
        if (!w->cw_canceled)
            log_errx("compaction error sts/job %u action %s rule %s"
                     " cnid %lu nodeid %lu dgenlo %lu dgenhi %lu wedge %d"
                     " build_ms %lu",
                     w->cw_err,
                     sts_job_id_get(&w->cw_job),
                     cn_action2str(w->cw_action),
                     cn_rule2str(w->cw_rule),
                     cn_tree_get_cnid(w->cw_tree),
                     w->cw_node->tn_nodeid,
                     w->cw_dgen_lo,
                     w->cw_dgen_hi,
                     w->cw_tree->ct_rspills_wedged,
                     (w->cw_t3_build - w->cw_t2_prep) / 1000000);

        if (merr_errno(w->cw_err) == ENOSPC)
            w->cw_tree->ct_nospace = true;

        if (split) {
            for (uint i = 0; i < w->cw_outc && w->cw_split.commit; i++) {
                delete_mblocks(w->cw_mp, &w->cw_split.commit[i]);
                blk_list_free(&w->cw_split.commit[i]);
                if (i < w->cw_kvset_cnt) {
                    assert(w->cw_split.purge);
                    blk_list_free(&w->cw_split.purge[i]);
                }
            }
        } else if (!spill) {
            cn_mblocks_destroy(w->cw_mp, w->cw_outc, w->cw_outv, kcompact);
        }
    }

    free(w->cw_vbmap.vbm_blkv);

    if (w->cw_vgmap) {
        if (kcompact) {
            vgmap_free(w->cw_vgmap[0]); /* One output kvset for k-compact */
        } else if (split) {
            for (uint i = 0; i < w->cw_outc; i++)
                vgmap_free(w->cw_vgmap[i]);

            free(w->cw_split.key);
        }

        free(w->cw_vgmap);
    }

    if (w->cw_outv) {
        for (uint i = 0; i < w->cw_outc; i++) {
            blk_list_free(&w->cw_outv[i].kblks);
            blk_list_free(&w->cw_outv[i].vblks);
        }
        free(w->cw_outv);
    }
}

merr_t
cn_subspill_commit(struct subspill *ss)
{
    struct kvset *kvset = 0;
    void *cookie = 0;
    merr_t err;
    struct cndb_txn *tx;
    struct kvset_meta km;
    struct kvset_mblocks *mblks = &ss->ss_mblks;
    struct cn_compaction_work *w = ss->ss_work;
    struct cndb *cndb = w->cw_tree->cndb;

    if (!ss->ss_added)
        return 0;

    if (!mblks->hblk.bk_blkid) {
        assert(mblks->kblks.n_blks == 0);
        return 0;
    }

    err = cndb_record_txstart(cndb, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON, 1, 0, &tx);
    if (err)
        return err;

    cn_subspill_get_kvset_meta(ss, &km);

    /* CNDB: Log kvset add records.
     */
    err = cndb_record_kvset_add(cndb, tx, w->cw_tree->cnid, km.km_nodeid,
                                &km, ss->ss_kvsetid, km.km_hblk.bk_blkid,
                                mblks->kblks.n_blks, (uint64_t *)mblks->kblks.blks,
                                mblks->vblks.n_blks, (uint64_t *)mblks->vblks.blks, &cookie);
    if (err)
        goto done;

    err = cn_mblocks_commit(w->cw_mp, 1, mblks, CN_MUT_OTHER);
    if (err)
        goto done;

    err = kvset_open(w->cw_tree, ss->ss_kvsetid, &km, &kvset);
    if (err)
        goto done;

    /* CNDB: Ack kvset add record.
     */
    err = cndb_record_kvset_add_ack(cndb, tx, cookie);
    if (err)
        goto done;

    cn_comp_update_subspill(w, ss->ss_node, kvset);

    blk_list_free(&ss->ss_mblks.kblks);
    blk_list_free(&ss->ss_mblks.vblks);

done:
    w->cw_t4_commit = get_time_ns();

    if (err) {
        cndb_record_nak(cndb, tx);
        kvset_put_ref(kvset);
    }

    return err;
}

static merr_t
cn_subspill_apply(struct subspill *ss)
{
    struct cn_compaction_work *w = ss->ss_work;
    merr_t err;

    err = cn_subspill_commit(ss);
    if (err)
        return err;

    if (ss->ss_added) {
        w->cw_output_nodev[0] = ss->ss_node;
        w->cw_checkpoint(w);
    }

    return 0;
}

static merr_t
cn_comp_spill(struct cn_compaction_work *w)
{
    struct subspill *ss;
    struct spillctx *sctx;
    struct cn_tree *tree = w->cw_tree;
    struct route_node *rtn = 0;
    atomic_uint *spillingp = NULL;
    uint cnum = 0;
    merr_t err;

    err = cn_spill_create(w, &sctx);
    if (err)
        return err;

    while (1) {
        struct cn_tree_node *node;
        struct route_node *rtnext;
        void *lock;
        struct kvset_list_entry *le;
        uint64_t node_dgen;
        unsigned char ekey[HSE_KVS_KEY_LEN_MAX];
        uint eklen;

        rmlock_rlock(&tree->ct_lock, &lock);
        rtnext = rtn ? route_node_next(rtn) : route_map_first_node(tree->ct_route_map);
        if (!rtnext) {
            rmlock_runlock(lock);
            break;
        }

        node = route_node_tnode(rtnext);

        mutex_lock(&node->tn_ss_lock);
        if (node->tn_ss_splitting) {
            rmlock_runlock(lock);

            tree->ct_rspill_slp++;
            cv_wait(&node->tn_ss_cv, &node->tn_ss_lock, "spltwait");
            tree->ct_rspill_slp--;
            mutex_unlock(&node->tn_ss_lock);
            continue;
        }

        spillingp = &node->tn_ss_spilling;
        node->tn_ss_spilling++;
        mutex_unlock(&node->tn_ss_lock);

        rtn = rtnext;

        le = list_first_entry_or_null(&node->tn_kvset_list, typeof(*le), le_link);
        node_dgen = le ? kvset_get_dgen(le->le_kvset) : 0;

        route_node_keycpy(rtn, ekey, sizeof(ekey), &eklen);
        rmlock_runlock(lock);

        ss = cn_spill_get_nth_subspill(sctx, cnum);
        INVARIANT(ss);

        ++cnum;

        err = cn_subspill(ss, sctx, node, node_dgen, ekey, eklen);
        if (err)
            break;

        /* Enqueue subspill only if there are older spills that need to update this node
         * before us.
         */
        if (ss->ss_sgen == atomic_read(&node->tn_sgen) + 1) {
            err = cn_subspill_apply(ss);
            if (err)
                break;

            atomic_inc(&node->tn_sgen);
            node->tn_ss_spilling--;
        } else {
            cn_subspill_enqueue(ss, node);
        }

        /* Apply subspills that are ready. */
        while ((ss = cn_subspill_pop(node))) {
            err = cn_subspill_apply(ss);
            if (err)
                goto errout;

            atomic_inc(&node->tn_sgen);
            node->tn_ss_spilling--;
        }

        spillingp = NULL;
    }

    w->cw_t3_build = get_time_ns();

  errout:
    if (err) {
        if (merr_errno(err) != ESHUTDOWN)
            kvdb_health_error(tree->ct_kvdb_health, err);

        if (spillingp)
            (*spillingp) -= 1;
    } else {

        /* Serialize the deletion of input kvsets.
         */
        if (cn_node_spill_wait(w, w->cw_tree->ct_root))
            cn_spill_delete_kvsets(w);
    }

    /* On error, remove any enqueued subspills */
    if (kvdb_health_check(tree->ct_kvdb_health, KVDB_HEALTH_FLAG_ALL)) {
        int i;

        for (i = 0; i < cnum; i++) {
            struct cn_tree_node *tn;

            ss = cn_spill_get_nth_subspill(sctx, i);
            tn = ss->ss_node;

            mutex_lock(&tn->tn_ss_lock);
            if (!ss->ss_added || ss->ss_applied) {
                mutex_unlock(&tn->tn_ss_lock);
                continue;
            }

            list_del(&ss->ss_link);
            tn->tn_ss_spilling--;

            blk_list_free(&ss->ss_mblks.kblks);
            blk_list_free(&ss->ss_mblks.vblks);

            mutex_unlock(&tn->tn_ss_lock);
        }
    }

    cn_spill_destroy(sctx);

    return err;
}

/**
 * cn_comp_compact() - perform the actual compaction operation
 * See section comment for more info.
*/
static void
cn_comp_compact(struct cn_compaction_work *w)
{
    bool kcompact = (w->cw_action == CN_ACTION_COMPACT_K);
    struct kvdb_health *hp = w->cw_tree->ct_kvdb_health;

    merr_t err = 0;

    if (w->cw_err)
        return;

    assert(hp);

    w->cw_err = kvdb_health_check(hp, KVDB_HEALTH_FLAG_ALL);
    if (w->cw_err)
        return;

    w->cw_keep_vblks = kcompact;
    hp = w->cw_tree->ct_kvdb_health;
    assert(hp);

    w->cw_err = cn_tree_prepare_compaction(w);
    if (w->cw_err) {
        if (merr_errno(w->cw_err) != ESHUTDOWN)
            kvdb_health_error(hp, w->cw_err);
        return;
    }

    w->cw_t2_prep = get_time_ns();

    /* cn_kcompact handles k-compaction, cn_spill handles spills
     * and kv-compaction.
     */
    w->cw_keep_vblks = (w->cw_action == CN_ACTION_COMPACT_K);

    switch (w->cw_action) {
    case CN_ACTION_NONE:
        err = merr(EINVAL);
        break;

    case CN_ACTION_COMPACT_K:
        err = cn_kcompact(w);
        break;

    case CN_ACTION_COMPACT_KV:
        err = cn_kvcompact(w);
        break;

    case CN_ACTION_SPILL:
        err = cn_comp_spill(w);
        break;

    case CN_ACTION_SPLIT:
        err = cn_split(w);
        break;
    }

    w->cw_t3_build = get_time_ns();

    if (merr_errno(err) == ESHUTDOWN && atomic_read(w->cw_cancel_request))
        w->cw_canceled = true;

    /* defer status check until *after* cleanup */
    for (uint i = 0; i < w->cw_kvset_cnt && w->cw_inputv; i++) {
        if (w->cw_inputv[i])
            w->cw_inputv[i]->kvi_ops->kvi_release(w->cw_inputv[i]);
    }

    free(w->cw_inputv);

    if (ev(err)) {
        if (!w->cw_canceled)
            kvdb_health_error(hp, err);
        goto err_exit;
    }

err_exit:
    w->cw_err = err;
    if (w->cw_canceled && !w->cw_err)
        w->cw_err = merr(ESHUTDOWN);
}

/**
 * cn_compact() - perform a cn tree compaction operation
 */
void
cn_compact(struct cn_compaction_work *w)
{
    u64               tstart;
    struct perfc_set *pc = w->cw_pc;

    tstart = perfc_lat_start(pc);
    w->cw_t1_qtime = tstart;

    cn_comp_compact(w);

    /* Detach this job from the callback thread as we're about
     * to either hand it off to the monitor thread or leave it
     * on the rspill list for some other thread to finish.
     */
    sts_job_detach(&w->cw_job);

    /* Commit the compaction if this isn't a spill. For a spill operation, each subspill to a child
     * was committed as the spill progressed.
     */
    if (w->cw_action != CN_ACTION_SPILL)
        cn_comp_commit(w);

    cn_comp_cleanup(w);
    cn_comp_release(w);

    w->cw_t5_finish = get_time_ns();
    perfc_lat_record(pc, PERFC_LT_CNCOMP_TOTAL, tstart);
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
    struct perfc_set *lnode)
{
    struct cn_tree_node *tn;
    struct perfc_set *   pcv[2];
    void *               lock;

    struct {
        u64 nodec;
        u64 avglen;
        u64 maxlen;
        u64 avgsize;
        u64 maxsize;
    } ssv[2];

    memset(ssv, 0, sizeof(ssv));

    rmlock_rlock(&tree->ct_lock, &lock);
    cn_tree_foreach_node(tn, tree) {
        uint64_t len, size, i;

        i = cn_node_isroot(tn) ? 0 : 1;
        len = cn_ns_kvsets(&tn->tn_ns);
        size = cn_ns_alen(&tn->tn_ns);

        ssv[i].nodec++;
        ssv[i].avglen += len;
        ssv[i].avgsize += size;
        ssv[i].maxlen = max(ssv[i].maxlen, len);
        ssv[i].maxsize = max(ssv[i].maxsize, size);
    }
    rmlock_runlock(lock);

    pcv[0] = rnode;
    pcv[1] = lnode;

    for (size_t i = 0; i < 2; i++) {

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
    age = cn_node_isroot(tn) ? HSE_MPOLICY_AGE_ROOT : HSE_MPOLICY_AGE_LEAF;

    return mclass_policy_get_type(policy, age, dtype);
}

uint
cn_tree_node_scatter(const struct cn_tree_node *tn)
{
    struct kvset_list_entry *le;
    uint scatter = 0;

    list_for_each_entry_reverse(le, &tn->tn_kvset_list, le_link) {
        const uint vgroups = kvset_get_vgroups(le->le_kvset);

        /* Exclude oldest kvsets with no scatter.
         */
        if (scatter + vgroups > 1)
            scatter += vgroups;
    }
    return scatter;
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
        uint klen = 0;

        kvset_get_max_key(kvset, &key, &klen);

        if (klen > 0 && (!max_key || keycmp(key, klen, max_key, *max_klen) > 0)) {
            max_key = key;
            *max_klen = klen;
        }
    }

    if (max_key)
        memcpy(kbuf, max_key, min_t(size_t, kbuf_sz, *max_klen));
    rmlock_runlock(lock);
}

merr_t
cn_tree_init(void)
{
    struct kmem_cache *cache;

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
    kmem_cache_destroy(cn_node_cache);
    cn_node_cache = NULL;
}

#if HSE_MOCKING
#include "cn_tree_ut_impl.i"
#include "cn_tree_compact_ut_impl.i"
#include "cn_tree_create_ut_impl.i"
#include "cn_tree_internal_ut_impl.i"
#include "cn_tree_iter_ut_impl.i"
#include "cn_tree_view_ut_impl.i"
#endif /* HSE_MOCKING */
