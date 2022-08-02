/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <hse_util/element_source.h>
#include <hse_util/event_counter.h>
#include <error/merr.h>
#include <hse_util/assert.h>
#include <hse_util/keycmp.h>
#include <hse_util/logging.h>
#include <hse_util/list.h>

#include <hse_ikvdb/kvset_view.h>
#include <hse_ikvdb/cndb.h>

#include "cn_tree.h"
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
    bool eof;
    uint32_t offset;
};

struct forward_wbt_leaf_iterator {
    struct kvset *ks;
    struct element_source es;
    bool eof;
    struct {
        uint32_t kblk_idx;
        uint32_t leaf_idx;
    } offset;
};

static bool
reverse_kblk_iterator_next(struct element_source *source, void **data)
{
    struct reverse_kblk_iterator *iter = container_of(source, struct reverse_kblk_iterator, es);

    INVARIANT(source);
    INVARIANT(data);

    if (iter->eof)
        return false;

    assert(iter->offset < iter->ks->ks_st.kst_kblks);

    *data = &iter->ks->ks_kblks[iter->offset];

    if (iter->offset == 0) {
        iter->eof = true;
    } else {
        iter->offset--;
    }

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
    iter->eof = false;
    iter->offset = ks->ks_st.kst_kblks - 1;
    iter->es = es_make(reverse_kblk_iterator_next, NULL, NULL);
}

static int
kblk_compare(const void *const a, const void *const b)
{
    const struct kvset_kblk *kblk_a = a, *kblk_b = b;

    INVARIANT(a);
    INVARIANT(b);

    /* Return the kblock with the largest min key. */
    return -1 * keycmp(kblk_a->kb_koff_min, kblk_a->kb_klen_min, kblk_b->kb_koff_min,
        kblk_b->kb_klen_min);
}

static merr_t
find_inflection_point(
    const struct cn_tree_node *const node,
    uint64_t *const seen_kvlen,
    uint32_t *const offsets)
{
    merr_t err;
    struct bin_heap2 *bh;
    struct kvset_list_entry *le;
    struct kvset_kblk *kblk;
    struct reverse_kblk_iterator *iters;
    struct element_source **srcs;
    void *buf = NULL;
    uint64_t num_kvsets;
    uint64_t total_kvlen = 0;
    uint64_t kvset_idx = 0;
    uint64_t kvlen = 0;

    INVARIANT(node);
    INVARIANT(seen_kvlen);
    INVARIANT(offsets);

    num_kvsets = cn_ns_kvsets(&node->tn_ns);

    err = bin_heap2_create(num_kvsets, kblk_compare, &bh);
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

    list_for_each_entry(le, &node->tn_kvset_list, le_link) {
        struct kvset_metrics metrics;
        struct reverse_kblk_iterator *iter = &iters[kvset_idx];

        kvset_get_metrics(le->le_kvset, &metrics);

        total_kvlen += metrics.tot_key_bytes + metrics.tot_val_bytes;

        reverse_kblk_iterator_init(iter, le->le_kvset);

        srcs[kvset_idx] = &(iter)->es;

        kvset_idx++;
    }

    assert(kvset_idx == num_kvsets);

    err = bin_heap2_prepare(bh, num_kvsets, srcs);
    if (ev(err))
        goto out;

    while (bin_heap2_pop(bh, (void **)&kblk)) {
        kvlen += kblk->kb_metrics.tot_key_bytes + kblk->kb_metrics.tot_val_bytes;
        if (kvlen >= total_kvlen / 2)
            break;
    }

    *seen_kvlen = kvlen;

    /* Gather the offsets we ended at for each kvset. These will seed the
     * starting positions of the element sources in the next bin heap.
     */
    for (uint64_t i = 0; i < num_kvsets; i++)
        offsets[i] = iters[i].offset;

out:
    free(buf);
    bin_heap2_destroy(bh);

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

    if (iter->eof)
        return false;

    assert(iter->offset.kblk_idx < iter->ks->ks_st.kst_kblks);

    kblk = &iter->ks->ks_kblks[iter->offset.kblk_idx];
    desc = &kblk->kb_wbt_desc;

    assert(iter->offset.leaf_idx < desc->wbd_leaf_cnt);

    *data = kblk->kb_kblk_desc.map_base + desc->wbd_first_page * PAGE_SIZE +
        iter->offset.leaf_idx * WBT_NODE_SIZE;

    assert(((struct wbt_node_hdr_omf *)(*data))->wbn_magic == WBT_LFE_NODE_MAGIC);

    if (iter->offset.leaf_idx == desc->wbd_leaf_cnt - 1) {
        iter->offset.kblk_idx++;
        iter->offset.leaf_idx = 0;
        if (iter->offset.kblk_idx == iter->ks->ks_st.kst_kblks)
            iter->eof = true;
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
    INVARIANT(kblk_idx < ks->ks_st.kst_kblks);

    iter->ks = ks;
    iter->eof = false;
    /* Using prefix decrement in next, so this is fine */
    iter->offset.kblk_idx = kblk_idx;
    iter->offset.leaf_idx = 0;
    iter->es = es_make(forward_wbt_leaf_iterator_next, NULL, NULL);
}

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
    const struct cn_tree_node *const tnode,
    uint64_t seen_kvlen,
    const uint32_t *const offsets,
    void *const key_buf,
    const size_t key_buf_sz,
    unsigned int *const key_len)
{
    merr_t err;
    struct bin_heap2 *bh;
    struct kvset_list_entry *le;
    uint64_t num_kvsets;
    struct forward_wbt_leaf_iterator *iters;
    struct element_source **srcs;
    const struct wbt_lfe_omf *lfe;
    struct wbt_node_hdr_omf *wnode;
    struct key_obj key;
    void *buf = NULL;
    uint64_t total_kvlen = 0;
    uint64_t kvset_idx = 0;

    INVARIANT(tnode);
    INVARIANT(offsets);
    INVARIANT(key_buf);
    INVARIANT(key_buf_sz > 0);
    INVARIANT(key_len);

    num_kvsets = cn_ns_kvsets(&tnode->tn_ns);

    err = bin_heap2_create(num_kvsets, wbt_leaf_compare, &bh);
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

    list_for_each_entry(le, &tnode->tn_kvset_list, le_link) {
        struct kvset_metrics metrics;
        struct forward_wbt_leaf_iterator *iter = &iters[kvset_idx];

        kvset_get_metrics(le->le_kvset, &metrics);

        total_kvlen += metrics.tot_key_bytes + metrics.tot_val_bytes;

        forward_wbt_leaf_iterator_init(iter, le->le_kvset, offsets[kvset_idx]);

        srcs[kvset_idx] = &(iter)->es;

        kvset_idx++;
    }

    assert(seen_kvlen >= total_kvlen / 2);
    assert(kvset_idx == num_kvsets);

    err = bin_heap2_prepare(bh, num_kvsets, srcs);
    if (ev(err))
        goto out;

    while (bin_heap2_pop(bh, (void **)&wnode)) {
        seen_kvlen -= omf_wbn_kvlen(wnode);
        if (seen_kvlen <= (total_kvlen / 2))
            break;
    }

    assert(omf_wbn_num_keys(wnode) > 0);

    /* Get first leaf node entry */
    lfe = wbt_lfe(wnode, 0);
    wbt_node_pfx(wnode, &key.ko_pfx, &key.ko_pfx_len);
    wbt_lfe_key(wnode, lfe, &key.ko_sfx, &key.ko_sfx_len);

    key_obj_copy(key_buf, key_buf_sz, key_len, &key);
    assert(*key_len <= HSE_KVS_KEY_LEN_MAX);

out:
    free(buf);
    bin_heap2_destroy(bh);

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

    err = find_inflection_point(node, &kvlen, offsets);
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
    for (int i = LEFT; i <= RIGHT; i++) {
        blk_list_free(&result->ks[i].blks->kblks);
        blk_list_free(&result->ks[i].blks->vblks);
        blk_list_free(result->ks[i].blks_commit);
    }

    blk_list_free(result->blks_purge);
}

merr_t
cn_split(struct cn_compaction_work *w)
{
    struct kvset_list_entry *le;
    struct key_obj split_kobj;
    struct cndb *cndb;
    merr_t err;
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

    for (i = 0, le = list_first_entry(&w->cw_node->tn_kvset_list, typeof(*le), le_link);
         i < w->cw_kvset_cnt;
         i++, le = list_next_entry(le, le_link)) {

        struct kvset *ks = le->le_kvset;
        struct kvset_split_res result = { 0 };

        kvset_split_res_init(w, &result, i);

        err = kvset_split(ks, &split_kobj, &result);
        if (err) {
            kvset_split_res_free(ks, &result);
            return err;
        }

        for (int k = LEFT; k <= RIGHT; k++) {
            uint idx = (k == LEFT ? i : i + w->cw_kvset_cnt);

            if (result.ks[k].blks->hblk.bk_blkid != 0) {
                w->cw_kvsetidv[idx] = cndb_kvsetid_mint(cndb);
                w->cw_split.dgen[idx] = ks->ks_dgen;
            }
        }
    }

    return 0;
}

static bool
check_valid_kvsets(const struct cn_compaction_work *w, bool left)
{
    uint start, end;

    if (left) {
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
    for (int i = LEFT; i <= RIGHT; i++) {
        nodev[i] = NULL;

        if (!check_valid_kvsets(w, i == LEFT))
            continue;

        if (i == LEFT) {
            struct cn_tree *tree = w->cw_tree;

            nodeidv[i] = cndb_nodeid_mint(cn_tree_get_cndb(w->cw_tree));

            nodev[i] = cn_node_alloc(tree, nodeidv[i]);
            if (!nodev[i])
                return merr(ENOMEM);

            /* Allocate a route node using the split key as its edge key.
             */
            nodev[i]->tn_route_node =
                route_node_alloc(tree->ct_route_map, nodev[i], w->cw_split.key, w->cw_split.klen);
            if (!nodev[i]->tn_route_node) {
                cn_node_free(nodev[i]);
                nodev[i] = NULL;

                return merr(ENOMEM);
            }
        } else {
            /* Use the source node as the right node */
            nodeidv[i] = w->cw_node->tn_nodeid;
            nodev[i] = w->cw_node;
        }
    }

    return 0;
}

void
cn_split_nodes_free(const struct cn_compaction_work *w, struct cn_tree_node *nodev[static 2])
{
    for (int i = LEFT; i <= RIGHT && nodev[i]; i++) {
        /* Free only the allocated left node */
        if (i == LEFT) {
            route_node_free(w->cw_tree->ct_route_map, nodev[i]->tn_route_node);
            cn_node_free(nodev[i]);
        }

        nodev[i] = NULL;
    }
}
