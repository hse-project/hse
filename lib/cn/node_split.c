/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <hse_util/element_source.h>
#include <hse_util/event_counter.h>
#include <hse/error/merr.h>
#include <hse_util/assert.h>
#include <hse_util/keycmp.h>
#include <hse/logging/logging.h>
#include <hse_util/list.h>

#include <hse_ikvdb/kvset_view.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/cn.h>

#include "cn_tree.h"
#include "cn_metrics.h"
#include "cn_tree_internal.h"
#include "cn_tree_compact.h"
#include "kvset.h"
#include "node_split.h"
#include "kvset_internal.h"
#include "wbt_internal.h"
#include "route.h"

struct reverse_kblk_iterator {
    struct kvset *ks;
    struct element_source es;
    uint32_t offset;
};

struct forward_wbt_leaf_iterator {
    struct kvset *ks;
    struct element_source es;
    struct {
        uint32_t kblk_idx;
        uint32_t leaf_idx;
    } offset;
};

static bool
reverse_kblk_iterator_next(struct element_source *source, void **data)
{
    struct reverse_kblk_iterator *iter;

    INVARIANT(source);
    INVARIANT(data);

    iter = container_of(source, struct reverse_kblk_iterator, es);

    /* If the offset is 0, that means we have already seen it, continuing past
     * this point would index the array with an underflowed offset.
     */
    if (iter->offset == 0)
        return false;

    assert(iter->offset <= iter->ks->ks_st.kst_kblks);

    *data = &iter->ks->ks_kblks[--iter->offset];

    return true;
}

static void
reverse_kblk_iterator_init(
    struct reverse_kblk_iterator *const iter,
    struct kvset *const ks)
{
    INVARIANT(iter);
    INVARIANT(ks);

    iter->ks = ks;
    iter->offset = ks->ks_st.kst_kblks;
    iter->es = es_make(reverse_kblk_iterator_next, NULL, NULL);
}

/* Kblock comparison function
 *
 * Used with the binheap to iterate over kblocks reverse sorted by each kblock's
 * min key.  The kblock with the largest min key comes out of the binheap
 * first, the kblock with the smallest min key comes out last.
 *
 * Given two kblocks A and B, the return value is:
 *  -  0            : first key in A = first key in B
 *  -  negative int : first key in A > first key in B
 *  -  positive int : first key in A < first key in B
 */
static int
kblk_compare(const void *const a, const void *const b)
{
    const struct kvset_kblk *kblk_a = a, *kblk_b = b;

    INVARIANT(a);
    INVARIANT(b);

    return -1 * keycmp(kblk_a->kb_koff_min, kblk_a->kb_klen_min, kblk_b->kb_koff_min,
        kblk_b->kb_klen_min);
}

static merr_t
find_inflection_points(
    const struct cn_tree_node *const tn,
    uint64_t *const seen_kvlen,
    uint32_t *const offsets)
{
    merr_t err;
    struct bin_heap *bh;
    struct kvset_list_entry *le;
    struct kvset_kblk *inflection_kblk = NULL;
    struct reverse_kblk_iterator *iters;
    struct element_source **srcs;
    void *buf = NULL;
    uint64_t limit;
    uint64_t num_kvsets;
    uint64_t total_kvlen = 0;
    uint64_t kvset_idx = 0;
    uint64_t kvlen = 0;

    INVARIANT(tn);
    INVARIANT(seen_kvlen);
    INVARIANT(offsets);

    num_kvsets = cn_ns_kvsets(&tn->tn_ns);

    err = bin_heap_create(num_kvsets, kblk_compare, &bh);
    if (ev(err))
        return err;

    buf = malloc(num_kvsets * (sizeof(*iters) + sizeof(void *)));
    if (ev(!buf)) {
        err = merr(ENOMEM);
        goto out;
    }

    iters = buf;
    srcs = buf + num_kvsets * sizeof(*iters);

    list_for_each_entry(le, &tn->tn_kvset_list, le_link) {
        struct kvset_metrics metrics;
        struct reverse_kblk_iterator *iter = &iters[kvset_idx];

        kvset_get_metrics(le->le_kvset, &metrics);

        total_kvlen += metrics.tot_kvlen;

        reverse_kblk_iterator_init(iter, le->le_kvset);

        srcs[kvset_idx] = &(iter)->es;

        kvset_idx++;
    }

    assert(kvset_idx == num_kvsets);

    /* Stop when we have reached at least 50% of the node's key/value data.
     */
    limit = total_kvlen / 2;

    log_debug("node %lu inflection limit: %lu/%lu (%lf%%)",
        tn->tn_nodeid, limit, total_kvlen, (double)limit * 100 / total_kvlen);

    err = bin_heap_prepare(bh, num_kvsets, srcs);
    if (ev(err))
        goto out;

    while (kvlen <= limit && bin_heap_pop(bh, (void **)&inflection_kblk))
        kvlen += inflection_kblk->kb_metrics.tot_kvlen;
    assert(inflection_kblk);

    log_debug("node %lu inflection key kvlen: %lu/%lu (%lf%%)",
        tn->tn_nodeid, kvlen, total_kvlen, (double)kvlen * 100 / total_kvlen);

    /* Gather the offsets we ended at for each kvset. These will seed the
     * starting positions of the element sources in the next bin heap.
     */
    for (uint64_t i = 0; i < num_kvsets; i++) {
        int res;
        struct kvset_kblk *curr;
        struct reverse_kblk_iterator *iter = iters + i;
        struct kvset *ks = iter->ks;

        offsets[i] = iter->offset;

        if (ks->ks_st.kst_kblks == 0)
            continue;

        curr = ks->ks_kblks + iter->offset;
        if (curr == inflection_kblk) {
            log_debug("node %lu iterator %lu inflection point (kvset, kblock): (%lu, %u)",
                tn->tn_nodeid, i, i, iter->offset);
            continue;
        }

        res = keycmp(curr->kb_koff_min, curr->kb_klen_min, inflection_kblk->kb_koff_min,
            inflection_kblk->kb_klen_min);
        if (res >= 0) {
            log_debug("node %lu iterator %lu inflection point (kvset, kblock): (%lu, %u)",
                tn->tn_nodeid, i, i, iter->offset);
            continue;
        }

        /* If the current kblock lies entirely to the left of the inflection
         * key, go to the next kblock since the split key must be greater than
         * or equal to the inflection key.
         */
        if (iter->offset < ks->ks_st.kst_kblks - 1 &&
                keycmp(curr->kb_koff_max, curr->kb_klen_max, inflection_kblk->kb_koff_min,
                    inflection_kblk->kb_klen_min) <= 0) {
            iter->offset++;
            curr++;
        }

        log_debug("node %lu iterator %lu inflection point (kvset, kblock): (%lu, %u)",
            tn->tn_nodeid, i, i, iter->offset);
        offsets[i] = iter->offset;
    }

    /* Using the iterator offsets, we can exactly calculate how much key/value
     * data exists to the left of every iterator's kblock. This kvlen will be
     * used as the starting point for the forward WBT leaf node iteration.
     */
    kvlen = 0;
    for (uint64_t i = 0; i < num_kvsets; i++) {
        struct reverse_kblk_iterator *iter = iters + i;

        if (iter->ks->ks_st.kst_kblks == 0)
            continue;

        for (uint32_t j = 0; j < iter->offset; j++) {
            const struct kvset_kblk *kblk = &iter->ks->ks_kblks[j];

            kvlen += kblk->kb_metrics.tot_kvlen;
        }
    }
    assert(kvlen <= total_kvlen / 2);

    log_debug("node %lu seen kvlen: %lu/%lu (%lf%%)",
        tn->tn_nodeid, kvlen, total_kvlen, (double)kvlen * 100 / total_kvlen);

    *seen_kvlen = kvlen;

out:
    free(buf);
    bin_heap_destroy(bh);

    return err;
}

static bool
forward_wbt_leaf_iterator_next(struct element_source *source, void **data)
{
    struct kvset_kblk *kblk;
    struct wbt_desc *desc;
    struct forward_wbt_leaf_iterator *iter = container_of(source, struct forward_wbt_leaf_iterator, es);

    INVARIANT(source);
    INVARIANT(data);

    if (iter->offset.kblk_idx >= iter->ks->ks_st.kst_kblks)
        return false;

    kblk = &iter->ks->ks_kblks[iter->offset.kblk_idx];
    desc = &kblk->kb_wbt_desc;

    assert(iter->offset.leaf_idx < desc->wbd_leaf_cnt);

    /* Preload the cache inorder to increase performance. In testing, finding
     * the split key became ~98.6% faster.
     */
    if (iter->offset.leaf_idx == 0)
        kbr_madvise_wbt_leaf_nodes(&kblk->kb_kblk_desc, desc, MADV_WILLNEED);

    *data = kblk->kb_kblk_desc.map_base + desc->wbd_first_page * PAGE_SIZE +
        iter->offset.leaf_idx * WBT_NODE_SIZE;

    assert(((struct wbt_node_hdr_omf *)(*data))->wbn_magic == WBT_LFE_NODE_MAGIC);

    /* Move to next kblock if we have exhausted all the WBT leaf nodes in the
     * current kblock.
     */
    if (iter->offset.leaf_idx == desc->wbd_leaf_cnt - 1) {
        iter->offset.kblk_idx++;
        iter->offset.leaf_idx = 0;
    } else {
        iter->offset.leaf_idx++;
    }

    return true;
}

static void
forward_wbt_leaf_iterator_init(
    struct forward_wbt_leaf_iterator *const iter,
    struct kvset *const ks,
    const uint32_t kblk_idx)
{
    INVARIANT(ks);
    INVARIANT(iter);

    iter->ks = ks;
    iter->offset.kblk_idx = kblk_idx;
    iter->offset.leaf_idx = 0;
    iter->es = es_make(forward_wbt_leaf_iterator_next, NULL, NULL);
}

/* WBT leaf node comparison function, used by binheap
 *
 * Given two nodes A and B, the return value is:
 *  -  0            : first key in A = first key in B
 *  -  negative int : first key in A < first key in B
 *  -  positive int : first key in A > first key in B
 */
static int
wbt_leaf_compare(const void *const a, const void *const b)
{
    const struct wbt_node_hdr_omf *wbt_node_a = a, *wbt_node_b = b;
    const struct wbt_lfe_omf *lfe_a, *lfe_b;
    struct key_obj key_a, key_b;

    INVARIANT(a);
    INVARIANT(b);

    lfe_a = wbt_lfe(wbt_node_a, 0);
    wbt_node_pfx(wbt_node_a, &key_a.ko_pfx, &key_a.ko_pfx_len);
    wbt_lfe_key(wbt_node_a, lfe_a, &key_a.ko_sfx, &key_a.ko_sfx_len);

    lfe_b = wbt_lfe(wbt_node_b, 0);
    wbt_node_pfx(wbt_node_b, &key_b.ko_pfx, &key_b.ko_pfx_len);
    wbt_lfe_key(wbt_node_b, lfe_b, &key_b.ko_sfx, &key_b.ko_sfx_len);

    /* Return the WBT leaf node with the smallest key. */
    return key_obj_cmp(&key_a, &key_b);
}

static merr_t
find_split_key(
    const struct cn_tree_node *const tn,
    uint64_t seen_kvlen,
    const uint32_t *const offsets,
    void *const key_buf,
    const size_t key_buf_sz,
    unsigned int *const key_len)
{
    merr_t err;
    struct bin_heap *bh;
    struct kvset_list_entry *le;
    uint64_t num_kvsets;
    struct forward_wbt_leaf_iterator *iters;
    struct element_source **srcs;
    const struct wbt_lfe_omf *lfe;
    struct key_obj key;
    uint64_t limit;
    struct wbt_node_hdr_omf *wnode = NULL;
    void *buf = NULL;
    uint64_t total_kvlen = 0;
    uint64_t kvset_idx = 0;

    INVARIANT(tn);
    INVARIANT(offsets);
    INVARIANT(key_buf);
    INVARIANT(key_buf_sz > 0);
    INVARIANT(key_len);

    num_kvsets = cn_ns_kvsets(&tn->tn_ns);

    err = bin_heap_create(num_kvsets, wbt_leaf_compare, &bh);
    if (ev(err))
        return err;

    /* Forgive me for I have sinned; allocate all necessary memory for managing
     * iterators and element sources in one go.
     */
    buf = malloc(num_kvsets * (sizeof(*iters) + sizeof(void *)));
    if (ev(!buf)) {
        err = merr(ENOMEM);
        goto out;
    }

    iters = buf;
    srcs = buf + num_kvsets * sizeof(*iters);

    list_for_each_entry(le, &tn->tn_kvset_list, le_link) {
        struct kvset_metrics metrics;
        struct forward_wbt_leaf_iterator *iter = &iters[kvset_idx];

        kvset_get_metrics(le->le_kvset, &metrics);

        total_kvlen += metrics.tot_kvlen;

        forward_wbt_leaf_iterator_init(iter, le->le_kvset, offsets[kvset_idx]);

        srcs[kvset_idx] = &(iter)->es;

        kvset_idx++;
    }

    /* Stop when we have reached at least 50% of the node's key/value data.
     */
    limit = total_kvlen / 2;

    log_debug("node %lu split limit: %lu/%lu (%lf%%)",
        tn->tn_nodeid, limit, total_kvlen, (double)limit * 100 / total_kvlen);

    assert(seen_kvlen <= total_kvlen / 2);
    assert(kvset_idx == num_kvsets);

    err = bin_heap_prepare(bh, num_kvsets, srcs);
    if (ev(err))
        goto out;

    while (seen_kvlen <= limit && bin_heap_pop(bh, (void **)&wnode))
        seen_kvlen += omf_wbn_kvlen(wnode);
    assert(wnode);

    log_debug("node %lu split key kvlen: %lu/%lu (%lf%%)",
        tn->tn_nodeid, seen_kvlen, total_kvlen, (double)seen_kvlen * 100 / total_kvlen);

    assert(omf_wbn_num_keys(wnode) > 0);

    /* Get first leaf node entry */
    lfe = wbt_lfe(wnode, 0);
    wbt_node_pfx(wnode, &key.ko_pfx, &key.ko_pfx_len);
    wbt_lfe_key(wnode, lfe, &key.ko_sfx, &key.ko_sfx_len);

    key_obj_copy(key_buf, key_buf_sz, key_len, &key);
    assert(*key_len <= HSE_KVS_KEY_LEN_MAX);

out:
    free(buf);
    bin_heap_destroy(bh);

    return err;
}

merr_t
cn_tree_node_get_split_key(
    const struct cn_tree_node *const node,
    void *const key_buf,
    const size_t key_buf_sz,
    unsigned int *const key_len)
{
    merr_t err;
    uint64_t kvlen = 0;
    uint32_t *offsets = NULL;

    offsets = malloc(cn_ns_kvsets(&node->tn_ns) * sizeof(*offsets));
    if (ev(!offsets))
        return merr(ENOMEM);

    err = find_inflection_points(node, &kvlen, offsets);
    if (ev(err))
        goto out;

    err = find_split_key(node, kvlen, offsets, key_buf, key_buf_sz, key_len);
    if (ev(err))
        goto out;

out:
    free(offsets);

    return err;
}

static void
kvset_split_res_init(struct cn_compaction_work *w, struct kvset_split_res *result, uint ks_idx)
{
    memset(result, 0, sizeof(*result));

    for (int i = LEFT; i <= RIGHT; i++) {
        uint idx = (i == LEFT ? ks_idx : ks_idx + w->cw_kvset_cnt);

        result->ks[i].blks = &w->cw_outv[idx];
        blk_list_init(&result->ks[i].blks->kblks);
        blk_list_init(&result->ks[i].blks->vblks);
        result->ks[i].blks->bl_vused = 0;

        result->ks[i].blks_commit = &w->cw_split.commit[idx];
        blk_list_init(result->ks[i].blks_commit);

        result->ks[i].vgmap = &w->cw_vgmap[idx];
    }

    result->blks_purge = &w->cw_split.purge[ks_idx];
    blk_list_init(result->blks_purge);
}

static void
kvset_split_res_free(struct kvset *ks, struct kvset_split_res *result)
{
    if (!ks)
        return;

    for (int i = LEFT; i <= RIGHT; i++) {
        blk_list_free(&result->ks[i].blks->kblks);
        blk_list_free(&result->ks[i].blks->vblks);

        delete_mblocks(ks->ks_mp, result->ks[i].blks_commit);
        blk_list_free(result->ks[i].blks_commit);
    }

    blk_list_free(result->blks_purge);
}

merr_t
cn_split(struct cn_compaction_work *w)
{
    struct kvset_split_wargs *wargs;
    struct workqueue_struct *wq;
    struct kvset_list_entry *le;
    struct key_obj split_kobj;
    atomic_uint inflight;
    struct cndb *cndb;
    merr_t err = 0;
    bool drop_ptomb_ks[2] = { true, true };
    uint i;

    INVARIANT(w);

    cndb = cn_tree_get_cndb(w->cw_tree);

    err = cn_tree_node_get_split_key(w->cw_node, w->cw_split.key, HSE_KVS_KEY_LEN_MAX,
                                     &w->cw_split.klen);
    if (err)
        return err;

    key2kobj(&split_kobj, w->cw_split.key, w->cw_split.klen);

    if (atomic_read(w->cw_cancel_request))
        return merr(ESHUTDOWN);

    assert(!list_empty(&w->cw_node->tn_kvset_list));

    wargs = calloc(w->cw_kvset_cnt, sizeof(*wargs));
    if (!wargs)
        return merr(ENOMEM);

    wq = cn_get_io_wq(w->cw_tree->cn);
    atomic_set(&inflight, w->cw_kvset_cnt);

    for (i = 0, le = list_first_entry(&w->cw_node->tn_kvset_list, typeof(*le), le_link);
         i < w->cw_kvset_cnt;
         i++, le = list_next_entry(le, le_link)) {

        INIT_WORK(&wargs[i].work, kvset_split_worker);
        wargs[i].ks = le->le_kvset;
        wargs[i].split_kobj = &split_kobj;
        wargs[i].pc = w->cw_pc;
        wargs[i].inflightp = &inflight;
        kvset_split_res_init(w, &wargs[i].result, i);

        if (!queue_work(wq, &wargs[i].work)) {
            atomic_dec(&inflight);
            err = merr(EBUG);
            break;
        }
    }

    /* Poll for all our kvset-split work to complete.  Ideally, we'd call
     * flush_workqueue() here, but that can severely stall new requests.
     */
    while (atomic_read(&inflight) > 0) {
        const struct timespec req = {
            .tv_nsec = 100 * 1000
        };

        hse_nanosleep(&req, NULL, "nodesplt");
    }

    for (i = w->cw_kvset_cnt; !err && i-- > 0;) {
        if (wargs[i].err) {
            err = wargs[i].err;
            break;
        }

        for (int k = LEFT; k <= RIGHT; k++) {
            struct kvset_split_res *result = &wargs[i].result;
            struct kvset_mblocks *blks = result->ks[k].blks;
            uint idx = (k == LEFT ? i : i + w->cw_kvset_cnt);

            if (blks->hblk_id != 0) {
                if (drop_ptomb_ks[k] && blks->kblks.n_blks > 0)
                    drop_ptomb_ks[k] = false;

                assert(blks->kblks.n_blks > 0 || blks->vblks.n_blks == 0);

                if (HSE_UNLIKELY(drop_ptomb_ks[k])) {
                    assert(result->ks[k].blks_commit->n_blks == 1);

                    /* Drop contiguous kvsets containing only ptombs, starting from the oldest.
                     */
                    delete_mblock(w->cw_mp, blks->hblk_id);
                    blk_list_free(result->ks[k].blks_commit);
                } else {
                    w->cw_kvsetidv[idx] = cndb_kvsetid_mint(cndb);
                    w->cw_split.dgen_hi[idx] = wargs[i].ks->ks_dgen_hi;
                    w->cw_split.dgen_lo[idx] = wargs[i].ks->ks_dgen_lo;
                    w->cw_split.compc[idx] = wargs[i].ks->ks_compc;
                }
            }
        }
    }

    ev_info(drop_ptomb_ks[0] || drop_ptomb_ks[1]);

    for (i = 0; err && i < w->cw_kvset_cnt; i++)
        kvset_split_res_free(wargs[i].ks, &wargs[i].result);

    free(wargs);

    return err;
}

static bool
check_valid_kvsets(const struct cn_compaction_work *w, enum split_side side)
{
    uint start, end;

    if (side == LEFT) {
        start = 0;
        end = w->cw_kvset_cnt;
    } else {
        start = w->cw_kvset_cnt;
        end = w->cw_outc;
    }

    for (uint i = start; i < end; i++) {
        if (w->cw_kvsetidv[i] != CNDB_INVAL_KVSETID)
            return true;
    }

    return false;
}

merr_t
cn_split_nodes_alloc(
    const struct cn_compaction_work *w,
    uint64_t                         nodeidv[static 2],
    struct cn_tree_node             *nodev[static 2])
{
    nodev[LEFT] = nodev[RIGHT] = NULL;

    if (check_valid_kvsets(w, LEFT)) {
        struct cn_tree *tree = w->cw_tree;
        struct cn_tree_node *node;
        uint64_t nodeid = cndb_nodeid_mint(cn_tree_get_cndb(w->cw_tree));

        node = cn_node_alloc(tree, nodeid);
        if (!node)
            return merr(ENOMEM);

        /* Allocate a route node using the split key as its edge key.
         */
        node->tn_route_node =
            route_node_alloc(tree->ct_route_map, node, w->cw_split.key, w->cw_split.klen);
        if (!node->tn_route_node) {
            cn_node_free(node);
            return merr(ENOMEM);
        }

        nodeidv[LEFT] = nodeid;
        nodev[LEFT] = node;

        atomic_set(&node->tn_sgen, w->cw_node->tn_sgen);
    }

    if (check_valid_kvsets(w, RIGHT)) {
        /* Use the source node as the right node */
        nodeidv[RIGHT] = w->cw_node->tn_nodeid;
        nodev[RIGHT] = w->cw_node;
    }

    return 0;
}

void
cn_split_nodes_free(const struct cn_compaction_work *w, struct cn_tree_node *nodev[static 2])
{
    if (nodev[LEFT]) {
        route_node_free(w->cw_tree->ct_route_map, nodev[LEFT]->tn_route_node);
        cn_node_free(nodev[LEFT]);
    }

    nodev[LEFT] = nodev[RIGHT] = NULL;
}

void
cn_split_node_stats_dump(
    struct cn_compaction_work *w,
    const struct cn_tree_node *node,
    const char                *pos)
{
    const struct cn_node_stats *ns;

    if (!node)
        return;

    ns = &node->tn_ns;

    log_info(
        "job=%u cnid=%lu nodeid=%lu node=%s "
        "kvsets=%u keys=%lu "
        "hblks=%u kblks=%u vblks=%u "
        "alen=%lu",
        sts_job_id_get(&w->cw_job), w->cw_tree->cnid, node->tn_nodeid, pos,
        cn_ns_kvsets(ns), cn_ns_keys(ns),
        cn_ns_hblks(ns), cn_ns_kblks(ns), cn_ns_vblks(ns),
        cn_ns_alen(ns));
}
