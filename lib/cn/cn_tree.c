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
#include <bsd/string.h>

#include <bsd/stdlib.h>
#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>

#include <hse/util/alloc.h>
#include <hse/util/event_counter.h>
#include <hse/util/page.h>
#include <hse/util/slab.h>
#include <hse/util/list.h>
#include <hse/util/mutex.h>
#include <hse/logging/logging.h>
#include <hse/util/assert.h>
#include <hse/util/parse_num.h>
#include <hse/util/atomic.h>
#include <hse/util/hlog.h>
#include <hse/util/table.h>
#include <hse/util/keycmp.h>
#include <hse/util/bin_heap.h>
#include <hse/util/log2.h>
#include <hse/util/fmt.h>
#include <hse/util/printbuf.h>
#include <hse/util/workqueue.h>
#include <hse/util/compression_lz4.h>
#include <hse/experimental.h>

#include <hse/mpool/mpool.h>

#include <hse/limits.h>

#include <hse/ikvdb/key_hash.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/cndb.h>
#include <hse/ikvdb/kvdb_health.h>
#include <hse/ikvdb/cn_tree_view.h>
#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/cn_kvdb.h>
#include <hse/ikvdb/cursor.h>
#include <hse/ikvdb/sched_sts.h>
#include <hse/ikvdb/csched.h>
#include <hse/ikvdb/kvs_rparams.h>

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
#include "move.h"

static struct kmem_cache *cn_node_cache HSE_READ_MOSTLY;

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

    tn->tn_nodeid = nodeid;
    tn->tn_tree = tree;
    INIT_LIST_HEAD(&tn->tn_link);
    tn->tn_split_size = (size_t)tree->rp->cn_split_size << 30;

    INIT_LIST_HEAD(&tn->tn_kvset_list);

    atomic_set(&tn->tn_compacting, 0);
    atomic_set(&tn->tn_busycnt, 0);

    for (uint i = 0; i < NELEM(tn->tn_dnode_linkv); ++i)
        INIT_LIST_HEAD(&tn->tn_dnode_linkv[i]);

    sp3_node_init(&tn->tn_sp3n);

    INIT_LIST_HEAD(&tn->tn_ss_list);
    atomic_set(&tn->tn_ss_spilling, 0);

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
    struct cn_tree *tree = tn->tn_tree;
    struct subspill *entry;

    /* Add ss at the right position in the node's mutation list. The list is sorted by
     * sgen - smallest to largest.
     */
    mutex_lock(&tree->ct_ss_lock);
    list_for_each_entry(entry, &tn->tn_ss_list, ss_link) {
        if (ss->ss_sgen < entry->ss_sgen)
            break;
    }

    list_add_tail(&ss->ss_link, entry ? &entry->ss_link : &tn->tn_ss_list);
    mutex_unlock(&tree->ct_ss_lock);
}

static struct subspill *
cn_subspill_pop(struct cn_tree_node *tn)
{
    struct cn_tree *tree = tn->tn_tree;
    struct subspill *entry;
    bool found = false;

    mutex_lock(&tree->ct_ss_lock);

    entry = list_first_entry_or_null(&tn->tn_ss_list, typeof(*entry), ss_link);
    if (entry && entry->ss_sgen == atomic_read(&tn->tn_sgen) + 1) {
        list_del(&entry->ss_link);
        found = true;
    }

    mutex_unlock(&tree->ct_ss_lock);

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
    tree->rp = rp;
    tree->ct_cp = cp;
    mutex_init(&tree->ct_ss_lock);
    cv_init(&tree->ct_ss_cv);
    tree->ct_rspill_dt = 1;
    atomic_set(&tree->ct_split_cnt, 0);
    tree->ct_kvdb_health = health;

    tree->ct_root = cn_node_alloc(tree, 0);
    if (ev(!tree->ct_root)) {
        free(tree);
        return merr(ENOMEM);
    }

    list_add(&tree->ct_root->tn_link, &tree->ct_nodes);

    tree->ct_route_map = route_map_create(CN_FANOUT_MAX);
    if (!tree->ct_route_map) {
        cn_tree_destroy(tree);
        return merr(ENOMEM);
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

    if (cn_node_isleaf(tn)) {
        tn->tn_samp.r_alen = 0;
        tn->tn_samp.l_alen = cn_ns_alen(s);
        tn->tn_samp.l_good = cn_ns_clen(s);
        tn->tn_samp.l_vgarb = cn_ns_vgarb(s);
    } else {
        tn->tn_samp.r_alen = cn_ns_alen(s);
        tn->tn_samp.l_alen = 0;
        tn->tn_samp.l_good = 0;
        tn->tn_samp.l_vgarb = 0;
    }
}

/* This function must be serialized with other cn_tree_samp_* functions. */
static void
cn_tree_samp_update_compact(struct cn_tree *tree, struct cn_tree_node *tn)
{
    struct kvset_list_entry *le;
    bool need_finish = false;

    cn_samp_sub(&tree->ct_samp, &tn->tn_samp);
    tn_samp_clear(tn);

    list_for_each_entry(le, &tn->tn_kvset_list, le_link)
        if (tn_samp_update_incr(tn, le->le_kvset, true))
            need_finish = true;

    if (need_finish)
        tn_samp_update_finish(tn);

    cn_samp_add(&tree->ct_samp, &tn->tn_samp);
}

/* This function must be serialized with other cn_tree_samp_* functions.
 * It is used for ingest from c0 into root node and for ingesting
 * into children after spill operations.
 */
static void
cn_tree_samp_update_ingest(struct cn_tree *tree, struct cn_tree_node *tn)
{
    struct kvset_list_entry *le;

    le = list_first_entry_or_null(&tn->tn_kvset_list, typeof(*le), le_link);
    if (!le)
        return;

    cn_samp_sub(&tree->ct_samp, &tn->tn_samp);

    if (tn_samp_update_incr(tn, le->le_kvset, false))
        tn_samp_update_finish(tn);

    cn_samp_add(&tree->ct_samp, &tn->tn_samp);
}

void
cn_tree_samp_update_move(struct cn_compaction_work *w, struct cn_tree_node *tn)
{
    struct cn_tree *tree = w->cw_tree;

    cn_tree_samp_update_compact(tree, tn);
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

    list_for_each(head, &node->tn_kvset_list) {
        const struct kvset_list_entry *entry = list_entry(head, typeof(*entry), le_link);

        if (kvset_younger(kvset, entry->le_kvset))
            break;
    }

    kvset_list_add_tail(kvset, head);

    return 0;
}

static void
u64_to_human(char *buf, size_t bufsz, uint64_t val, uint64_t thresh)
{
    if (val >= thresh) {
        const char *sep = "\0kmgtpezy";

        val *= 10;
        while (val >= thresh) {
            val /= 1000;
            ++sep;
        }
        snprintf(buf, bufsz, "%5.1lf%c", val / 10.0, *sep);
    } else {
        u64_to_string(buf, bufsz, val);
    }
}

static bool HSE_NONNULL(1, 2)
cn_tree_common_to_json(
    cJSON *const object,
    const struct kvset_stats *stats,
    const uint64_t dgen,
    const uint32_t compc,
    const uint32_t vgroups,
    const bool human)
{
    bool bad;

    INVARIANT(object);
    INVARIANT(stats);

    bad = !cJSON_AddNumberToObject(object, "dgen", dgen);
    bad |= !cJSON_AddNumberToObject(object, "compc", compc);

    if (human) {
        char kbuf[64], tbuf[64], pbuf[64];

        u64_to_human(kbuf, sizeof(kbuf), stats->kst_keys, 10000);
        u64_to_human(tbuf, sizeof(tbuf), stats->kst_tombs, 10000);
        u64_to_human(pbuf, sizeof(pbuf), stats->kst_ptombs, 10000);

        bad |= !cJSON_AddStringToObject(object, "keys", kbuf);
        bad |= !cJSON_AddStringToObject(object, "tombs", tbuf);
        bad |= !cJSON_AddStringToObject(object, "ptombs", pbuf);
    } else {
        bad |= !cJSON_AddNumberToObject(object, "keys", stats->kst_keys);
        bad |= !cJSON_AddNumberToObject(object, "tombs", stats->kst_tombs);
        bad |= !cJSON_AddNumberToObject(object, "ptombs", stats->kst_ptombs);
    }

    if (human) {
        char hbuf[64], kbuf[64], vbuf[64], gbuf[64];

        u64_to_human(hbuf, sizeof(hbuf), stats->kst_hwlen, 10000);
        u64_to_human(kbuf, sizeof(kbuf), stats->kst_kwlen, 10000);
        u64_to_human(vbuf, sizeof(vbuf), stats->kst_vwlen, 10000);
        u64_to_human(gbuf, sizeof(gbuf), stats->kst_vgarb, 10000);

        bad |= !cJSON_AddStringToObject(object, "hlen", hbuf);
        bad |= !cJSON_AddStringToObject(object, "klen", kbuf);
        bad |= !cJSON_AddStringToObject(object, "vlen", vbuf);
        bad |= !cJSON_AddStringToObject(object, "vgarb", gbuf);
    } else {
        bad |= !cJSON_AddNumberToObject(object, "hlen", stats->kst_hwlen);
        bad |= !cJSON_AddNumberToObject(object, "klen", stats->kst_kwlen);
        bad |= !cJSON_AddNumberToObject(object, "vlen", stats->kst_vwlen);
        bad |= !cJSON_AddNumberToObject(object, "vgarb", stats->kst_vgarb);
    }

    bad |= !cJSON_AddNumberToObject(object, "hblocks", stats->kst_hblks);
    bad |= !cJSON_AddNumberToObject(object, "kblocks", stats->kst_kblks);
    bad |= !cJSON_AddNumberToObject(object, "vblocks", stats->kst_vblks);
    bad |= !cJSON_AddNumberToObject(object, "vgroups", vgroups);

    return bad;
}

merr_t
cn_tree_to_json(
    struct cn_tree *tree,
    const bool human,
    const bool kvsets,
    cJSON **const root_out)
{
    void *lock;
    cJSON *root;
    cJSON *nodes;
    merr_t err = 0;
    bool bad = false;
    uint64_t tree_dgen = 0;
    uint32_t tree_compc = 0;
    struct cn_tree_node *tn;
    uint32_t tree_kvsets = 0;
    uint32_t tree_vgroups = 0;
    struct kvset_stats tree_stats = { 0 };
    struct hse_kvdb_compact_status status;

    INVARIANT(tree && root_out);

    *root_out = NULL;

    root = cJSON_CreateObject();
    if (ev(!root))
        return merr(ENOMEM);

    nodes = cJSON_AddArrayToObject(root, "nodes");
    if (!nodes) {
        err = merr(ENOMEM);
        goto out;
    }

    rmlock_rlock(&tree->ct_lock, &lock);
    cn_tree_foreach_node(tn, tree) {
        ulong now;
        char ekbuf[24];
        uint eklen = 0;
        uint64_t node_dgen = 0;
        uint32_t node_compc = 0;
        uint32_t node_kvsets = 0;
        uint32_t node_vgroups = 0;
        struct kvset_list_entry *le;
        cJSON *node, *kvsetv = NULL;

        node = cJSON_CreateObject();
        if (!node || !cJSON_AddItemToArray(nodes, node)) {
            err = merr(ENOMEM);
            break;
        }

        bad |= !cJSON_AddNumberToObject(node, "id", tn->tn_nodeid);

        if (kvsets) {
            kvsetv = cJSON_AddArrayToObject(node, "kvsets");
            if (ev(!kvsetv)) {
                err = merr(ENOMEM);
                break;
            }
        }

        if (tn->tn_route_node)
            route_node_keycpy(tn->tn_route_node, ekbuf, sizeof(ekbuf), &eklen);

        if (eklen > 0) {
            char kbuf[sizeof(ekbuf) * 3 + 1];

            fmt_hexp(kbuf, sizeof(kbuf), ekbuf,
                     min_t(size_t, eklen, sizeof(ekbuf)), "", 2, ".", "");
            bad |= !cJSON_AddStringToObject(node, "edge_key", kbuf);
        } else {
            bad |= !cJSON_AddNullToObject(node, "edge_key");
        }

        now = jclock_ns;

        list_for_each_entry(le, &tn->tn_kvset_list, le_link) {
            cJSON *kvset;
            uint64_t dgen;
            uint32_t vgroups, compc;
            const struct cn_compaction_work *w;

            dgen = kvset_get_dgen(le->le_kvset);
            if (node_dgen < dgen)
                node_dgen = dgen;

            compc = kvset_get_compc(le->le_kvset);
            if (node_compc < compc)
                node_compc = compc;

            vgroups = kvset_get_vgroups(le->le_kvset);
            node_vgroups += vgroups;

            node_kvsets++;

            if (!kvsetv)
                continue;

            kvset = cJSON_CreateObject();
            if (!kvset || !cJSON_AddItemToArray(kvsetv, kvset)) {
                err = merr(ENOMEM);
                break;
            }

            bad |= cn_tree_common_to_json(kvset, kvset_statsp(le->le_kvset), dgen, compc,
                vgroups, human);
            bad |= !cJSON_AddStringToObject(kvset, "rule", cn_rule2str(le->le_kvset->ks_rule));

            w = kvset_get_work(le->le_kvset);
            if (w) {
                cJSON *job;
                const char *wmesg = sts_job_wmesg_get(&w->cw_job);
                const uint64_t tm = (now - w->cw_t0_enqueue) / NSEC_PER_SEC;

                job = cJSON_AddObjectToObject(kvset, "job");
                if (!job) {
                    err = merr(ENOMEM);
                    break;
                }

                bad |= !cJSON_AddNumberToObject(job, "id", sts_job_id_get(&w->cw_job));
                bad |= !cJSON_AddStringToObject(job, "action", cn_action2str(w->cw_action));
                bad |= !cJSON_AddStringToObject(job, "rule", cn_rule2str(w->cw_rule));
                bad |= !cJSON_AddStringToObject(job, "wmesg", wmesg);
                bad |= !cJSON_AddNumberToObject(job, "progress", sts_job_progress_get(&w->cw_job));
                bad |= !cJSON_AddNumberToObject(job, "time", tm);
            } else {
                bad |= !cJSON_AddNullToObject(kvset, "job");
            }
        }

        if (err)
            break;

        if (!kvsets)
            bad |= !cJSON_AddNumberToObject(node, "kvsets", node_kvsets);

        bad |= cn_tree_common_to_json(node, &tn->tn_ns.ns_kst, node_dgen, node_compc,
            node_vgroups, human);

        kvset_stats_add(&tn->tn_ns.ns_kst, &tree_stats);

        if (tree_dgen < node_dgen)
            tree_dgen = node_dgen;
        if (tree_compc < node_compc)
            tree_compc = node_compc;
        tree_vgroups += node_vgroups;

        tree_kvsets += node_kvsets;
    }
    rmlock_runlock(lock);

out:
    if (err) {
        cJSON_Delete(root);
        return err;
    }

    bad |= !cJSON_AddNumberToObject(root, "cnid", tree->cnid);
    bad |= !cJSON_AddNumberToObject(root, "fanout", tree->ct_fanout);
    bad |= !cJSON_AddNumberToObject(root, "kvsets", tree_kvsets);

    csched_compact_status_get(cn_get_sched(tree->cn), &status);
    bad |= !cJSON_AddNumberToObject(root, "samp_curr", status.kvcs_samp_curr);
    bad |= cn_tree_common_to_json(root, &tree_stats, tree_dgen, tree_compc, tree_vgroups, human);

    if (ev(bad)) {
        cJSON_Delete(root);
        return merr(ENOMEM);
    }

    *root_out = root;

    return 0;
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

merr_t
cn_tree_prefix_probe(
    struct cn_tree *     tree,
    struct perfc_set *   pc,
    struct kvs_ktuple *  kt,
    uint64_t             seq,
    enum key_lookup_res *res,
    struct query_ctx *   qctx,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf)
{
    struct cn_tree_node *node;
    struct key_disc kdisc;
    uint64_t pc_start;
    void *lock, *wbti;
    merr_t err;

    *res = NOT_FOUND;

    pc_start = perfc_lat_startu(pc, PERFC_LT_CNGET_GET);

    err = kvset_wbti_alloc(&wbti);
    if (ev(err))
        return err;

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

            err = kvset_pfx_lookup(kvset, kt, &kdisc, seq, res, wbti, kbuf, vbuf, qctx);
            if (err || qctx->seen > 1 || *res == FOUND_PTMB)
                goto done;

        }

        if (cn_node_isleaf(node)) {
            int rc;
            struct route_node *rn = node->tn_route_node;

            rc = route_node_keycmp_prefix(kt->kt_data, kt->kt_len, rn);
            if (rc < 0)
                break;

            assert(rc == 0);

            rn = route_node_next(rn);
            if (!rn)
                break;

            node = route_node_tnode(rn);

        } else {

            node = cn_tree_node_lookup(tree, kt->kt_data, kt->kt_len);
        }
    }

  done:
    rmlock_runlock(lock);

    perfc_lat_record(pc, PERFC_LT_CNGET_PROBE_PFX, pc_start);
    kvset_wbti_free(wbti);

    perfc_inc(pc, *res);

    return err;
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
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf)
{
    enum kvdb_perfc_sidx_cnget pc_cidx;
    struct cn_tree_node *node;
    struct key_disc kdisc;
    uint64_t pc_start;
    void *lock;
    merr_t err;

    *res = NOT_FOUND;

    pc_start = perfc_lat_startu(pc, PERFC_LT_CNGET_GET);
    pc_cidx = PERFC_LT_CNGET_GET_LEAF + 1;

    if (pc_start > 0) {
        if (perfc_ison(pc, PERFC_LT_CNGET_GET_ROOT))
            pc_cidx = PERFC_LT_CNGET_GET_ROOT;
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

            err = kvset_lookup(kvset, kt, &kdisc, seq, res, vbuf);
            if (err || *res != NOT_FOUND)
                goto done;

            pc_cidx++;
        }

        if (cn_node_isleaf(node))
            break;

        node = cn_tree_node_lookup(tree, kt->kt_data, kt->kt_len);
    }

  done:
    rmlock_runlock(lock);

    if (pc_start > 0) {
        uint pc_cidx_lt = (*res == NOT_FOUND) ? PERFC_LT_CNGET_MISS : PERFC_LT_CNGET_GET;

        perfc_lat_record(pc, pc_cidx_lt, pc_start);

        if (pc_cidx < PERFC_LT_CNGET_GET_LEAF + 1)
            perfc_lat_record(pc, pc_cidx, pc_start);
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
        kvset_get_max_nonpt_key(le->le_kvset, &max_key, &max_klen);

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

static merr_t
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
    uint32_t n_outs = 1;
    uint i;
    const bool kcompact = (w->cw_action == CN_ACTION_COMPACT_K);
    const bool split = (w->cw_action == CN_ACTION_SPLIT);

    if (w->cw_action == CN_ACTION_ZSPILL || w->cw_action == CN_ACTION_JOIN)
        return 0; /* no resources needed for zspill/join */

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
            const size_t sz = HSE_KVS_KEY_LEN_MAX +
                n_outs * (sizeof(*(w->cw_split.commit)) + sizeof(*(w->cw_split.dgen_hi)) +
                          sizeof(*(w->cw_split.dgen_lo)) +
                          sizeof(*(w->cw_split.compc))) +
                w->cw_kvset_cnt * sizeof(*(w->cw_split.purge));

            w->cw_split.key = calloc(1, sz);
            if (!w->cw_split.key) {
                err = merr(ENOMEM);
                goto err_exit;
            }

            w->cw_split.commit = w->cw_split.key + HSE_KVS_KEY_LEN_MAX;
            w->cw_split.dgen_hi = (void *)(w->cw_split.commit + n_outs);
            w->cw_split.dgen_lo = (void *)(w->cw_split.dgen_hi + n_outs);
            w->cw_split.compc = (void *)(w->cw_split.dgen_lo + n_outs);
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

        assert(i > 0 || kvset_get_dgen(le->le_kvset) == w->cw_dgen_hi_min);
        assert(i < w->cw_kvset_cnt - 1 || kvset_get_dgen(le->le_kvset) == w->cw_dgen_hi);

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
    w->cw_drop_tombs = (w->cw_action != CN_ACTION_SPILL) && (w->cw_action != CN_ACTION_ZSPILL) &&
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

    rmlock_wlock(&tree->ct_lock);
    {
        le = work->cw_mark;
        for (i = 0; i < work->cw_kvset_cnt; i++) {
            assert(&le->le_link != &work->cw_node->tn_kvset_list);
            assert(kvset_get_work(le->le_kvset) == work);

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
    list_for_each_entry_safe(le, tmp, &retired_kvsets, le_link) {

        assert(kvset_get_dgen(le->le_kvset) >= work->cw_dgen_hi_min);
        assert(kvset_get_dgen(le->le_kvset) <= work->cw_dgen_hi);

        kvset_mark_mblocks_for_delete(le->le_kvset, work->cw_keep_vblks);
        kvset_put_ref(le->le_kvset);
    }
}

static merr_t
cn_node_spill_wait(struct cn_compaction_work *w)
{
    struct cn_tree *tree = w->cw_tree;
    merr_t err = 0;

    mutex_lock(&tree->ct_ss_lock);
    while (1) {
        err = kvdb_health_check(tree->ct_kvdb_health, KVDB_HEALTH_FLAG_ALL);
        if (err)
            break;

        if (atomic_read(w->cw_cancel_request)) {
            err = merr(ESHUTDOWN);
            break;
        }

        if (w->cw_sgen == atomic_read(&w->cw_node->tn_sgen) + 1)
            break;

        atomic_inc(&tree->ct_rspill_slp);
        cv_wait(&tree->ct_ss_cv, &tree->ct_ss_lock, "spilwait");
        atomic_dec(&tree->ct_rspill_slp);
    }
    mutex_unlock(&tree->ct_ss_lock);

    return err;
}

static void
cn_spill_delete_kvsets(struct cn_compaction_work *work)
{
    struct list_head         retired_kvsets;
    struct cn_tree          *tree = work->cw_tree;
    struct cn_tree_node     *pnode = work->cw_node;
    struct kvset_list_entry *le, *tmp;
    struct cn_samp_stats     pre, post;
    struct cndb_txn         *tx;

    assert(!work->cw_err);

    INIT_LIST_HEAD(&retired_kvsets);

    work->cw_err = cndb_record_txstart(work->cw_tree->cndb, 0,
                                       CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON,
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

    /* Move old kvsets from parent node to retired list.
     * Asserts:
     * - Each input kvset just spilled must still be on pnode's kvset list.
     * - The dgen of the oldest input kvset must match work struct dgen_lo
     *   (i.e., concurrent spills from a node must be committed in order).
     */
    rmlock_wlock(&tree->ct_lock);

    for (uint i = 0; i < work->cw_kvset_cnt; i++) {
        le = list_last_entry(&pnode->tn_kvset_list, struct kvset_list_entry, le_link);
        assert(&le->le_link != &pnode->tn_kvset_list);
        assert(kvset_get_work(le->le_kvset) == work);

        assert(i > 0 || work->cw_dgen_hi_min == kvset_get_dgen(le->le_kvset));
        list_del(&le->le_link);
        list_add(&le->le_link, &retired_kvsets);
    }

    cn_tree_samp(tree, &pre);
    cn_tree_samp_update_compact(tree, pnode);
    cn_tree_samp(tree, &post);
    rmlock_wunlock(&tree->ct_lock);

    cn_samp_sub(&post, &pre);
    cn_samp_add(&work->cw_samp_post, &post);

done:
    /* Advance the spill gen and signal all the waiting spill threads.
     */
    mutex_lock(&tree->ct_ss_lock);
    if (work->cw_err)
        kvdb_health_error(tree->ct_kvdb_health, work->cw_err);
    else
        atomic_inc(&pnode->tn_sgen);
    cv_broadcast(&tree->ct_ss_cv);
    mutex_unlock(&tree->ct_ss_lock);

    /* Delete old kvsets (retired_kvsets will be empty on error).
     */
    list_for_each_entry_safe(le, tmp, &retired_kvsets, le_link) {
        kvset_mark_mblocks_for_delete(le->le_kvset, false);
        kvset_put_ref(le->le_kvset);
    }
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

        left->tn_split_ns = get_time_ns() + 60 * NSEC_PER_SEC;
        left->tn_split_ns += (left->tn_split_ns % 1048576) * 32;
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

            assert(route_node_keycmp(w->cw_split.key, w->cw_split.klen, right->tn_route_node) < 0);

            right->tn_split_ns = get_time_ns() + 60 * NSEC_PER_SEC;
            right->tn_split_ns += (right->tn_split_ns % 1048576) * 32;
            w->cw_split.nodev[RIGHT] = right;
        }

        /* Update route map with the left edge and add the new left node to the cN tree list.
         * The 'right' node is already part of the cn tree list.
         */
        if (left) {
            if (route_map_insert_by_node(tree->ct_route_map, left->tn_route_node))
                abort();

            assert(route_node_keycmp(w->cw_split.key, w->cw_split.klen, left->tn_route_node) == 0);

            /* Insert the "left" node to the left of the node in the tree
             * nodes list from which it was split.
             */
            list_add_tail(&left->tn_link, &src->tn_link);
            tree->ct_fanout++;
        }

        /* Update samp stats
         */
        cn_tree_samp(tree, &w->cw_samp_pre);
        for (int i = 0; i < 2 && w->cw_split.nodev[i]; i++)
            cn_tree_samp_update_compact(tree, w->cw_split.nodev[i]);
        cn_tree_samp(tree, &w->cw_samp_post);

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

        assert(kvset_get_work(le->le_kvset) == w);

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
    struct cn_samp_stats pre, post;

    if (work->cw_err)
        return;

    INVARIANT(node);
    INVARIANT(kvset);

    rmlock_wlock(&tree->ct_lock);
    kvset_list_add(kvset, &node->tn_kvset_list);

    cn_tree_samp(tree, &pre);
    cn_tree_samp_update_ingest(tree, node);
    cn_tree_samp(tree, &post);
    rmlock_wunlock(&tree->ct_lock);

    /* Accumulate each subspill delta so that csched can apply
     * them to sp->samp in sp3_process_workitem() after the spill
     * job finishes (regardless of error).
     */
    cn_samp_sub(&post, &pre);
    cn_samp_add(&work->cw_samp_post, &post);
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

    assert(w->cw_action != CN_ACTION_SPILL && w->cw_action != CN_ACTION_ZSPILL);

    if (w->cw_err)
        goto done;

    assert(w->cw_outc);

    /* if k-compaction and no kblocks, then force keepv to false. */
    if (is_kcompact && w->cw_outv[0].kblks.idc == 0)
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
        if (!w->cw_outv[i].hblk_id) {
            assert(w->cw_outv[i].kblks.idc == 0);
            continue;
        }

        km.km_vused = w->cw_outv[i].bl_vused;
        km.km_vgarb = w->cw_outv[i].bl_vtotal - km.km_vused;

        /* Lend hblk, kblk, and vblk lists to kvset_open().
         * Yes, the struct copy is a bit gross, but it works and
         * avoids unnecessary allocations of temporary lists.
         */
        km.km_hblk_id = w->cw_outv[i].hblk_id;
        km.km_kblk_list = w->cw_outv[i].kblks;
        km.km_vblk_list = w->cw_outv[i].vblks;

        km.km_capped = cn_is_capped(w->cw_tree->cn);
        km.km_restored = false;

        if (is_split) {
            km.km_compc = w->cw_split.compc[i];
            km.km_nodeid = split_nodeidv[i / w->cw_kvset_cnt];
            km.km_dgen_hi = w->cw_split.dgen_hi[i];
            km.km_dgen_lo = w->cw_split.dgen_lo[i];
            km.km_rule = (i / w->cw_kvset_cnt) ? CN_RULE_RSPLIT : CN_RULE_LSPLIT;
        } else {
            km.km_compc = w->cw_compc;
            km.km_nodeid = w->cw_node->tn_nodeid;
            km.km_dgen_hi = w->cw_dgen_hi;
            km.km_dgen_lo = w->cw_dgen_lo;
            km.km_rule = w->cw_rule;
        }

        /* CNDB: Log kvset add records.
         */
        err = cndb_record_kvset_add(
                        w->cw_tree->cndb, tx, w->cw_tree->cnid,
                        km.km_nodeid, &km, w->cw_kvsetidv[i], km.km_hblk_id,
                        w->cw_outv[i].kblks.idc, w->cw_outv[i].kblks.idv,
                        w->cw_outv[i].vblks.idc, w->cw_outv[i].vblks.idv,
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
        if (!w->cw_outv[i].hblk_id)
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

    case CN_ACTION_ZSPILL:
    case CN_ACTION_SPILL:
        assert(0);
        break;

    case CN_ACTION_SPLIT:
        cn_comp_update_split(w, kvsets, split_nodev);
        break;

    case CN_ACTION_JOIN:
        assert(0);
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
    const bool spill = (w->cw_action == CN_ACTION_SPILL || w->cw_action == CN_ACTION_ZSPILL);
    const bool split = (w->cw_action == CN_ACTION_SPLIT);
    const bool join = (w->cw_action == CN_ACTION_JOIN);

    if (split || join) {
        struct cn_tree *tree = w->cw_tree;

        mutex_lock(&tree->ct_ss_lock);
        if (join) {
            w->cw_join->tn_ss_joining = 0;
            w->cw_node->tn_ss_joining = 0;
        } else {
            w->cw_node->tn_ss_splitting = false;
        }

        atomic_dec(&tree->ct_split_cnt);
        cv_broadcast(&tree->ct_ss_cv);
        mutex_unlock(&tree->ct_ss_lock);
    }

    if (w->cw_err) {
        if (!join) {
            struct cn_tree *tree = w->cw_tree;

            /* unmark input kvsets */

            rmlock_wlock(&tree->ct_lock);
            if (w->cw_action == CN_ACTION_ZSPILL) {
                struct kvset_list_entry *le;

                /* A zspill may have been interrupted after moving kvsets to its znode,
                 * in which case cn_move() has already reset the workid in the kvsets.
                 */
                list_for_each_entry_reverse(le, &w->cw_node->tn_kvset_list, le_link) {
                    if (kvset_get_work(le->le_kvset) == w)
                        kvset_set_work(le->le_kvset, NULL);
                }
            } else {
                struct kvset_list_entry *le = w->cw_mark;

                for (uint kx = 0; kx < w->cw_kvset_cnt; kx++) {
                    assert(&le->le_link != &w->cw_node->tn_kvset_list);
                    assert(kvset_get_work(le->le_kvset) == w);

                    kvset_set_work(le->le_kvset, NULL);
                    le = list_prev_entry(le, le_link);
                }
            }

            /* Failed spills cause node to become "wedged"  */
            if (spill && !tree->ct_rspills_wedged) {
                if (merr_errno(w->cw_err) != ESHUTDOWN)
                    log_errx("root node wedged, spills disabled (cnid %lu)",
                             w->cw_err, tree->cnid);
                tree->ct_rspills_wedged = true;
            }
            rmlock_wunlock(&tree->ct_lock);
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
                     w->cw_dgen_hi_min,
                     w->cw_dgen_hi,
                     w->cw_tree->ct_rspills_wedged,
                     (w->cw_t3_build - w->cw_t2_prep) / 1000000);

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

        if (w->cw_join)
            cn_node_comp_token_put(w->cw_join);
    }

    atomic_sub_rel(&w->cw_node->tn_busycnt, (1u << 16) + w->cw_kvset_cnt);

    if (w->cw_have_token)
        cn_node_comp_token_put(w->cw_node);

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

    perfc_inc(w->cw_pc, PERFC_BA_CNCOMP_FINISH);
}

static merr_t
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

    if (!mblks->hblk_id) {
        assert(mblks->kblks.idc == 0);
        return 0;
    }

    err = cndb_record_txstart(cndb, 0, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON, 1, 0, &tx);
    if (err)
        return err;

    cn_subspill_get_kvset_meta(ss, &km);

    /* CNDB: Log kvset add records.
     */
    err = cndb_record_kvset_add(cndb, tx, w->cw_tree->cnid, km.km_nodeid,
                                &km, ss->ss_kvsetid, km.km_hblk_id,
                                mblks->kblks.idc, mblks->kblks.idv,
                                mblks->vblks.idc, mblks->vblks.idv, &cookie);
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
    merr_t err = 0;
    bool delete_node = false;
    struct cn_tree_node *outnode;

    if (!ss->ss_added)
        return 0;

    if (ss->ss_is_zspill) {
        err = cn_move(w, w->cw_node, ss->ss_zspill.zsp_src_list,
                      w->cw_kvset_cnt, delete_node, ss->ss_node);

        w->cw_output_nodev = &outnode;

    } else {
        err = cn_subspill_commit(ss);
    }

    if (!err) {
        w->cw_output_nodev[0] = ss->ss_node;
        w->cw_checkpoint(w);
    }

    return err;
}

/*
 * Determine if a kvset in the root node can be "zspilled" to a leaf node.
 *
 * A zspill is allowed if the following conditions are met:
 *  1. The min and max keys of the kvset should map to the same leaf node.
 *  2. There should be no ptomb that would span multiple nodes and hence need to be propagated.
 *
 * Returns the target leaf node if zspill is possible, NULL if not.
 *
 * Notes:
 * - Tree must be locked when this function is called, so the route map
 *   doesn't mutate.
 */
struct cn_tree_node *
cn_kvset_can_zspill(struct kvset *ks, struct route_map *map)
{
    unsigned char maxkbuf[HSE_KVS_KEY_LEN_MAX];
    const void *maxkey, *maxptkey, *minkey;
    uint16_t maxklen, maxptklen, minklen;
    struct route_node *rn;

    maxptkey = 0;
    maxklen = minklen = maxptklen = 0;

    kvset_minkey(ks, &minkey, &minklen);
    kvset_maxkey(ks, &maxkey, &maxklen);
    kvset_max_ptkey(ks, &maxptkey, &maxptklen);

    /* There are 3 possiblities regarding the max ptkey of the kvset.
     *  1. maxptkey == maxkey
     *  2. maxptkey <  maxkey && maxptkey == pfx(maxkey)
     *  3. maxptkey <  maxkey && maxptkey <  pfx(maxkey)
     *
     * In cases 1 and 2, in addition to checking that the min and max key both map to the same
     * child node, we should also ensure that the ptomb will not need to be propagated to any other
     * children.
     *
     * This is done by padding the maxptkey with 0xff and using that as the max key of the kvset.
     */
    if (maxptkey && keycmp_prefix(maxptkey, maxptklen, maxkey, maxklen) == 0) {
        maxklen = maxptklen;

        memcpy(maxkbuf, maxptkey, maxptklen);
        memset(maxkbuf + maxptklen, 0xff, sizeof(maxkbuf) - maxptklen);
        maxkey = maxkbuf;
    }

    rn = route_map_lookup(map, minkey, minklen);
    assert(rn);

    if (route_node_keycmp(maxkey, maxklen, rn) > 0)
        return NULL;

    return route_node_tnode(rn);
}

static bool
cn_node_can_zspill(
    struct cn_compaction_work *w,
    struct kvset_list_entry  **kvset_list,
    struct cn_tree_node      **znode_out)
{
    struct cn_tree_node *znode = NULL;
    struct kvset_list_entry *first, *le;

    first = le = w->cw_mark;

    /* Confirm that the operation can still be a zspill.
     */
    for (uint32_t i = 0; i < w->cw_kvset_cnt; ++i) {
        struct cn_tree_node *tn;

        assert(&le->le_link != &w->cw_node->tn_kvset_list);
        assert(kvset_get_work(le->le_kvset) == w);

        first = le;

        tn = cn_kvset_can_zspill(le->le_kvset, w->cw_tree->ct_route_map);
        if (!tn)
            return false;

        if (!znode)
            znode = tn;
        else if (tn->tn_nodeid != znode->tn_nodeid)
            return false;

        le = list_prev_entry(le, le_link);
    }

    *znode_out = znode;
    *kvset_list = first;

    return true;
}

static bool
cn_comp_zspill(struct cn_compaction_work *w)
{
    struct cn_tree *tree = w->cw_tree;
    struct cn_tree_node *znode;
    void *lock;

    rmlock_rlock(&tree->ct_lock, &lock);

    /* Confirm that the input kvsets still map to the same child node.
     */
    if (!cn_node_can_zspill(w, &w->cw_zspill.kvset_list, &znode)) {
        rmlock_runlock(lock);
        return false;
    }

    /* Confirm that znode is not undergoing a split or a join.
     */
    mutex_lock(&tree->ct_ss_lock);
    if (znode->tn_ss_splitting || znode->tn_ss_joining) {
        mutex_unlock(&tree->ct_ss_lock);
        rmlock_runlock(lock);
        return false;
    }

    /* Since znode is neither splitting nor joining, the operation can continue as a zspill.
     * Increment znode's spill ref to prevent split/join until after the zspill has completed.
     */
    atomic_inc_acq(&znode->tn_ss_spilling);
    mutex_unlock(&tree->ct_ss_lock);
    rmlock_runlock(lock);

    w->cw_zspill.znode = znode;

    return true;
}

static merr_t
cn_comp_spill(struct cn_compaction_work *w)
{
    struct subspill *ss_saved = NULL, *ss = NULL;
    struct cn_tree *tree = w->cw_tree;
    struct route_node *rtn = NULL;
    atomic_uint *spillingp = NULL;
    struct spillctx *sctx = NULL;
    merr_t err = 0;
    bool is_zspill = w->cw_action == CN_ACTION_ZSPILL;
    struct cn_tree_node *znode = NULL;

    if (is_zspill) {
        znode = w->cw_zspill.znode;
    } else {
        err = cn_spill_create(w, &sctx);
        if (err)
            return err;
    }

    while (1) {
        uint8_t ekey[HSE_KVS_KEY_LEN_MAX];
        struct kvset_list_entry *le;
        struct cn_tree_node *tn;
        struct route_node *rtnext;
        uint64_t node_dgen;
        void *lock;
        uint eklen;

        rmlock_rlock(&tree->ct_lock, &lock);
        rtnext = rtn ? route_node_next(rtn) : route_map_first_node(tree->ct_route_map);
        if (!rtnext) {
            rmlock_runlock(lock);
            break;
        }

        tn = route_node_tnode(rtnext);
        if (!tn->tn_route_node)
            abort();

        /* If there is a pending split or this is the left node of a pending
         * join (joining < 0), then we must wait here for the split/join to
         * complete before starting the next subspill.  That said, if there
         * are pending subspills, we must not wait if our sgen would cause
         * those subspills to be applied (because they all hold a spill ref,
         * and waiting here in that case would cause a deadlock).
         *
         * Similarly, if this is the right node of a pending join (joining > 0),
         * then we must complete the subspill into this node before the join
         * may proceed.  Note that we keep the route and tree node from the
         * previous spill pinned throughout the sleep.
         */
        mutex_lock(&tree->ct_ss_lock);
        if (tn->tn_ss_splitting || tn->tn_ss_joining < 0) {
            const bool should_wait = !is_zspill || (tn->tn_nodeid != znode->tn_nodeid);

            ss = list_last_entry_or_null(&tn->tn_ss_list, typeof(*ss), ss_link);

            if (should_wait && (!ss || w->cw_sgen > ss->ss_sgen)) {
                const char *wmesg;

                rmlock_runlock(lock);

                wmesg = tn->tn_ss_splitting ? "spltwait" : "joinwait";

                atomic_inc(&tree->ct_rspill_slp);
                cv_wait(&tree->ct_ss_cv, &tree->ct_ss_lock, wmesg);
                atomic_dec(&tree->ct_rspill_slp);

                mutex_unlock(&tree->ct_ss_lock);
                continue;
            }

            ss = NULL;
        }

        /* Drop ref from previous subspill.
         */
        if (spillingp)
            atomic_dec_rel(spillingp);

        /* Incrementing tn_ss_spilling while holding the tree lock is sufficient
         * to keep both the route and tree node pinned across the subspill.  This
         * works because csched will never schedule a job that changes routes for
         * for nodes undergoing a spill.
         */
        spillingp = &tn->tn_ss_spilling;
        atomic_inc_acq(spillingp);
        mutex_unlock(&tree->ct_ss_lock);

        rtn = rtnext;
        route_node_keycpy(rtn, ekey, sizeof(ekey), &eklen);

        le = list_first_entry_or_null(&tn->tn_kvset_list, typeof(*le), le_link);
        node_dgen = le ? kvset_get_dgen(le->le_kvset) : 0;
        rmlock_runlock(lock);

        /* Most spills will allocate just one subspill object and reuse it
         * for the duration of the spill.  Cleanup due to errors in the
         * middle of a spill is not trivial.
         */
        if (!ss_saved) {
            ss_saved = malloc(sizeof(*ss_saved));
            if (!ss_saved) {
                err = merr(ENOMEM);
                break;
            }
        }

        memset(ss_saved, 0, sizeof(*ss_saved));
        ss = ss_saved; /* do not clear ss_saved! */

        if (is_zspill) {
            ss->ss_work = w;
            ss->ss_sgen = w->cw_sgen;
            ss->ss_node = tn;
            ss->ss_is_zspill = true;

            if (tn->tn_nodeid == znode->tn_nodeid) {
                ss->ss_added = true;
                ss->ss_zspill.zsp_src_list = w->cw_zspill.kvset_list;
            }

        } else {
            err = cn_subspill(ss, sctx, tn, node_dgen, ekey, eklen);
            if (err) {
                ss = NULL; /* will be freed via ss_saved */
                break;
            }
        }

        /* Enqueue the subspill only if there are older spills that need to update
         * this node ahead of us, in which case we must acquire an additional spill
         * ref (which is safe outside the tree lock because we already hold a ref).
         *
         * If cn_subspill_apply() fails, then the subspill object "ss" is transferred
         * to "ss_saved" and eventually cleaned up at the end of this function.
         */
        if (ss->ss_sgen == atomic_read(&tn->tn_sgen) + 1) {
            err = cn_subspill_apply(ss);
            if (err)
                break;

            atomic_inc_rel(&tn->tn_sgen);
        } else {
            atomic_inc(spillingp);
            cn_subspill_enqueue(ss, tn);
            ss_saved = NULL;
        }

        /* Apply subspills that are ready. */
        while ((ss = cn_subspill_pop(tn))) {
            err = cn_subspill_apply(ss);
            if (err) {
                atomic_dec_rel(spillingp);
                goto errout;
            }

            atomic_inc_rel(&tn->tn_sgen);
            atomic_dec_rel(spillingp);

            if (!ss_saved)
                ss_saved = ss;
            else
                free(ss);
        }

        assert(atomic_read(spillingp) > 0);
    }

    w->cw_t3_build = get_time_ns();

  errout:
    if (ss_saved != ss)
        free(ss_saved);
    ss_saved = ss;

    if (spillingp)
        atomic_dec_rel(spillingp);

    if (err) {
        if (merr_errno(err) != ESHUTDOWN)
            kvdb_health_error(tree->ct_kvdb_health, err);
    } else {
        if (ss_saved)
            abort();

        /* Serialize the deletion of input kvsets.
         */
        err = cn_node_spill_wait(w);
        if (!err) {
            if (is_zspill) {
                mutex_lock(&tree->ct_ss_lock);
                atomic_inc(&w->cw_node->tn_sgen);
                cv_broadcast(&tree->ct_ss_cv);
                mutex_unlock(&tree->ct_ss_lock);

                atomic_dec_rel(&znode->tn_ss_spilling);
            } else {
                cn_spill_delete_kvsets(w);
            }
        }
    }

    /* On error, remove all enqueued subspills.
     */
    if (err) {
        struct cn_tree_node *tn;
        void *lock;

        rmlock_rlock(&tree->ct_lock, &lock);

        /* Wake up all rspill threads awaiting serialization.
         */
        mutex_lock(&tree->ct_ss_lock);
        if (ss_saved && ss_saved->ss_node) {
            list_add_tail(&ss_saved->ss_link, &ss_saved->ss_node->tn_ss_list);
        }
        cv_broadcast(&tree->ct_ss_cv);
        mutex_unlock(&tree->ct_ss_lock);

        cn_tree_foreach_leaf(tn, tree) {
            struct list_head head;
            struct subspill *next;

            INIT_LIST_HEAD(&head);

            mutex_lock(&tree->ct_ss_lock);
            list_splice(&tn->tn_ss_list, &head);
            INIT_LIST_HEAD(&tn->tn_ss_list);
            mutex_unlock(&tree->ct_ss_lock);

            list_for_each_entry_safe(ss, next, &head, ss_link) {
                if (!is_zspill) {
                    blk_list_free(&ss->ss_mblks.kblks);
                    blk_list_free(&ss->ss_mblks.vblks);
                }

                atomic_dec_rel(&tn->tn_ss_spilling);
                free(ss);
            }
        }
        rmlock_runlock(lock);
    }

    cn_spill_destroy(sctx);

    return err;
}

/**
 * cn_comp_compact() - perform the actual compaction operation
 * See section comment for more info.
 *
 * [HSE_REVISIT] If a spill/zspill action leaves this function too early
 * it will prevent proper advance of the spill gen and potentially leave
 * ongoing and/or future spill threads stuck in cn_node_spill_wait().
 */
static void
cn_comp_compact(struct cn_compaction_work *w)
{
    struct kvdb_health *hp = w->cw_tree->ct_kvdb_health;
    merr_t err = 0;

    assert(hp);
    assert(!w->cw_err);

    w->cw_keep_vblks = (w->cw_action == CN_ACTION_COMPACT_K);

    w->cw_horizon = cn_get_seqno_horizon(w->cw_tree->cn);
    w->cw_cancel_request = cn_get_cancel(w->cw_tree->cn);

    perfc_inc(w->cw_pc, PERFC_BA_CNCOMP_START);

    if (w->cw_action == CN_ACTION_ZSPILL) {
        bool can_zspill;

        /* If the conditions for zspill are no longer true then we must
         * downgrade the operation to an rspill in order to properly
         * advance the spill gen.
         */
        can_zspill = cn_comp_zspill(w);
        if (!can_zspill) {
            w->cw_action = CN_ACTION_SPILL;
            w->cw_rule = CN_RULE_RSPILL;
        }
    }

    w->cw_err = cn_tree_prepare_compaction(w);
    if (w->cw_err) {
        if (merr_errno(w->cw_err) != ESHUTDOWN)
            kvdb_health_error(hp, w->cw_err);
        return;
    }

    w->cw_t2_prep = get_time_ns();

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

    case CN_ACTION_ZSPILL:
    case CN_ACTION_SPILL:
        err = cn_comp_spill(w);
        break;

    case CN_ACTION_SPLIT:
        err = cn_split(w);
        break;

    case CN_ACTION_JOIN:
        err = cn_join(w);
        break;
    }

    w->cw_t3_build = get_time_ns();

    if (merr_errno(err) == ESHUTDOWN && atomic_read(w->cw_cancel_request))
        w->cw_canceled = true;

    /* defer status check until *after* cleanup */
    if (w->cw_inputv) {
        for (uint i = 0; i < w->cw_kvset_cnt; i++) {
            if (w->cw_inputv[i])
                w->cw_inputv[i]->kvi_ops->kvi_release(w->cw_inputv[i]);
        }

        free(w->cw_inputv);
    }

    if (w->cw_canceled) {
        w->cw_err = err ? err : merr(ESHUTDOWN);
    } else {
        if (err)
            kvdb_health_error(hp, err);
        w->cw_err = err;
    }
}

/**
 * cn_compact() - perform a cn tree compaction operation
 */
void
cn_compact(struct cn_compaction_work *w)
{
    struct perfc_set *pc = w->cw_pc;

    w->cw_t1_qtime = perfc_lat_start(pc);

    cn_comp_compact(w);

    /* Commit the compaction if this isn't a spill or join.
     * For a spill operation, each subspill to a child was committed as the spill progressed.
     * For a join operation, cn_move() commits the operation.
     */
    if (w->cw_action != CN_ACTION_SPILL &&
        w->cw_action != CN_ACTION_ZSPILL &&
        w->cw_action != CN_ACTION_JOIN) {

        cn_comp_commit(w);
    }

    cn_comp_cleanup(w);

    w->cw_t5_finish = get_time_ns();
    perfc_lat_record(pc, PERFC_LT_CNCOMP_TOTAL, w->cw_t1_qtime);
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
    size_t kwlen, vwlen;

    /* cn trees always have root nodes */
    assert(tree->ct_root);

    rmlock_wlock(&tree->ct_lock);
    kvset_list_add(kvset, &tree->ct_root->tn_kvset_list);
    kwlen = kvset_get_kwlen(kvset);
    vwlen = kvset_get_vwlen(kvset);

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

    assert(post.r_alen >= pre.r_alen);
    assert(post.l_alen == pre.l_alen);
    assert(post.l_good == pre.l_good);

    rmlock_wunlock(&tree->ct_lock);

    csched_notify_ingest(cn_get_sched(tree->cn), tree,
                         post.r_alen - pre.r_alen, kwlen, vwlen);
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

        kvset_get_max_nonpt_key(kvset, &key, &klen);

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
#endif /* HSE_MOCKING */
