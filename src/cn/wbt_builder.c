/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/key_util.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/omf_kmd.h>

#include <hse/hse_limits.h>

#define MTF_MOCK_IMPL_wbt_builder
#include "wbt_builder.h"
#include "wbt_internal.h"

#define KMD_CHUNK_PAGES 256
#define KMD_CHUNK_LEN (KMD_CHUNK_PAGES * PAGE_SIZE)
#define KMD_CHUNKS (KBLOCK_MAX_SIZE / KMD_CHUNK_LEN)

/**
 * struct int_node_estimator - metadata for each level of the wb tree with
 *                             internal nodes
 * @curr_rkeys_sum: Sum of all keys in the active node
 * @curr_rkeys_cnt: Number of keys in the active node. (Doesn't include the
 *                  entry about the mandatory right edge).
 * @full_node_cnt:  Number of 'full' nodes in the level. i.e. these nodes were
 *                  frozen because there wasn't any more space for more keys.
 * @level:          level in the tree. From bottom to top.
 * @parent:         pointer to parent. Null if root.
 */
struct int_node_estimator {
    uint                       curr_rkeys_sum;
    uint                       curr_rkeys_cnt;
    uint                       full_node_cnt;
    uint                       level;
    struct int_node_estimator *parent;
};

/**
 * struct wbb - a wb tree builder (wb --> "wants to be a b-tree")
 * @nodev: vector of nodes (nodev[0] == first leaf node)
 * @nodev_len: allocated length of nodev vector
 * @nodec: number of nodes in use
 * @max_inodec: upper limit on number of internal nodes that will be needed
 * @max_pgc: max allowable size of wbtree in pages (nodes+kmd+bloom)
 * @cnode: current node
 * @cnode_key_cursor: spot for next key. Points into the staging area.
 * @cnode_nkeys: number of keys (aka, entries) in current node
 * @entries: total number of keys stored so far
 * @wbt_first_kobj: first key (aka, min key in wb tree)
 * @wbt_last_kobj: last key (aka, max key in wb tree)
 * @sum_right_keys: total length of right-most keys in all leaf nodes
 *
 * Notes:
 *   @max_pages tracks the max number of pages that can be used by the wbtree.
 *   It decreases over time as keys are added to leave space for bloom filters.
 *   Each call to the wbtree builder provides an updated value for @max_pgc.
 */
struct wbb {

    void *nodev;
    uint  nodev_len;
    uint  nodec;
    uint  max_inodec;
    uint  max_pgc;
    uint  used_pgc;

    void *cnode;

    void *cnode_key_cursor;

    uint  cnode_nkeys;
    uint  cnode_kmd_off;
    uint  cnode_pfx_len;
    uint  cnode_sumlen;
    uint  cnode_key_stage_pgc;
    uint  cnode_key_extra_cnt;
    void *cnode_first_key;
    void *cnode_key_stage;

    uint entries;

    struct key_obj wbt_first_kobj;
    struct key_obj wbt_last_kobj;

    struct iovec kmd_iov[KMD_CHUNKS];
    uint         kmd_iov_index;

    struct int_node_estimator *inode_est;
};

struct key_stage_entry_intern {
    u16 child;
    u16 klen;
    u8  kdata[];
};

struct key_stage_entry_leaf {
    u32 kmd_off;
    u16 klen;
    u8  kdata[];
};

static __always_inline uint
get_kmd_len(struct wbb *wbb)
{
    uint len = wbb->kmd_iov_index * KMD_CHUNK_LEN + wbb->kmd_iov[wbb->kmd_iov_index].iov_len;

    assert(len < KMD_CHUNK_LEN * KMD_CHUNKS);
    return len;
}

static __always_inline uint
get_kmd_pgc(struct wbb *wbb)
{
    uint pgc = (get_kmd_len(wbb) + PAGE_SIZE - 1) / PAGE_SIZE;

    assert(pgc <= KMD_CHUNK_PAGES * KMD_CHUNKS);
    return pgc;
}

uint
get_nodes_at_level(struct wbb *wbb, uint level)
{
    struct int_node_estimator *est = wbb->inode_est;

    while (est && level != est->level)
        est = est->parent;

    return est ? 1 + est->full_node_cnt : 0;
}

/**
 * max_inode_cnt() - Estimate number of internal nodes needed if we add a new
 *                   leaf node.
 *
 * @wbb:               wbt builder handle
 * @right_edge_klen:   rightmost key of the finished leaf node.
 * @estimate (output): estimated number of internal nodes.
 */
static merr_t
max_inode_cnt(struct wbb *wbb, uint right_edge_klen, uint *estimate)
{
    struct int_node_estimator *est;
    int                        cnt = 0;
    merr_t                     err;

    /* As long as there's just one leaf node, the tree doesn't need any
     * internal nodes. This happens when creating the first leaf node.
     */
    if (!right_edge_klen) {
        *estimate = 0;
        return 0;
    }

    if (!wbb->inode_est) {
        wbb->inode_est = calloc(1, sizeof(*est));
        if (ev(!wbb->inode_est))
            return merr(ENOMEM);
    }

    est = wbb->inode_est;

    /* On adding a new key from the leaf node to its parent, its ancestors
     * further up might need to be updated too. The following loop does
     * this.
     */
    while (est) {
        uint used;
        uint ine_sz = sizeof(struct wbt_ine_omf);
        uint hdr_sz = sizeof(struct wbt_node_hdr_omf);

        /* All internal nodes must have a right edge. Adding one to
         * the level's est->curr_rkeys_cnt accounts for this.
         */
        used = est->curr_rkeys_sum + ((1 + est->curr_rkeys_cnt) * ine_sz) + hdr_sz;

        /* Check if this key will prompt a new node at this level */
        if (used + ine_sz + right_edge_klen > PAGE_SIZE) {

            /* Count this key as the right edge of the current node
             * and finish the node.
             * Reset stats for the current node in anticipation of
             * a new node, and bump up the number of 'full' nodes
             * at this level.
             */
            est->curr_rkeys_sum = est->curr_rkeys_cnt = 0;
            est->full_node_cnt++;

            /* If the number of nodes at this level grows beyond 1,
             * this level needs a parent. If one doesn't exist,
             * create it.
             */
            if (!est->parent) {
                assert(est->full_node_cnt == 1);

                est->parent = calloc(1, sizeof(*est));
                if (ev(!est->parent)) {
                    err = merr(ENOMEM);
                    goto err_exit;
                }

                est->parent->level = est->level + 1;
            }

        } else {
            /* There is enough space in the current node for this
             * key. Count the key and stop proceeding up the tree.
             *
             * [HSE_REVISIT] right_edge_klen is the full key's
             * length. This is excessive since we pull out the
             * longest common prefix.
             */
            est->curr_rkeys_sum += right_edge_klen;
            est->curr_rkeys_cnt++;
            break;
        }

        cnt += est->full_node_cnt + 1; /* +1 for active node */

        est = est->parent;
    }

    /* Rest of the list doesn't need any updates. Simply count nodes at
     * each level up to the root.
     */
    while (est) {
        cnt += est->full_node_cnt + 1; /* +1 for active node */

        est = est->parent;
    }

    /* Pad node count in case of faulty estimation (see NFSE-4058) */
    *estimate = cnt + 20;
    return 0;

err_exit:
    est = wbb->inode_est;

    while (est) {
        struct int_node_estimator *next = est->parent;

        free(est);
        est = next;
    }

    wbb->inode_est = 0;

    return err;
}

static struct wbt_node_hdr_omf *
_new_node(struct wbb *wbb)
{
    wbb->cnode = wbb->nodev + wbb->nodec * PAGE_SIZE;
    wbb->cnode_key_cursor = wbb->cnode_key_stage;
    wbb->cnode_pfx_len = 0;
    wbb->cnode_sumlen = 0;
    wbb->cnode_kmd_off = get_kmd_len(wbb);
    wbb->cnode_nkeys = 0;
    wbb->cnode_key_extra_cnt = 0;

    memset(wbb->cnode, 0, PAGE_SIZE);
    wbb->nodec += 1;

    return wbb->cnode;
}

static merr_t
_new_leaf_node(struct wbb *wbb, uint right_edge_klen)
{
    struct wbt_node_hdr_omf *node_hdr;
    uint                     max_inodec = 0;
    uint                     used_pgc;
    merr_t                   err;

    /* Space calculation must account for:
     * - current page use + one more leaf node + change in the number of
     *   internal nodes cannot exceed max_pgc.
     * - cannot exceed nodev array len (note: at this point
     *   nodec only accounts for internal nodes).
     */
    err = max_inode_cnt(wbb, right_edge_klen, &max_inodec);
    if (ev(err))
        return err;

    used_pgc = wbb->used_pgc + 1 + max_inodec - wbb->max_inodec;
    if (used_pgc > wbb->max_pgc || wbb->nodec + max_inodec >= wbb->nodev_len)
        return merr(ENOSPC); /* not a hard error */

    wbb->used_pgc = used_pgc;
    wbb->max_inodec = max_inodec;

    node_hdr = _new_node(wbb);
    omf_set_wbn_magic(node_hdr, WBT_LFE_NODE_MAGIC);
    omf_set_wbn_num_keys(node_hdr, 0);
    omf_set_wbn_kmd(node_hdr, wbb->cnode_kmd_off);

    return 0;
}

static int
_new_int_node(struct wbb *wbb)
{
    struct wbt_node_hdr_omf *node_hdr;

    /* Different space calculation than for leaf nodes.  Simply
     * verify against max_pgc and nodev array len.
     */
    if (wbb->used_pgc >= wbb->max_pgc || wbb->nodec >= wbb->nodev_len)
        return merr(ev(EBUG));

    wbb->used_pgc++;

    node_hdr = _new_node(wbb);

    omf_set_wbn_magic(node_hdr, WBT_INE_NODE_MAGIC);
    omf_set_wbn_num_keys(node_hdr, 0);
    omf_set_wbn_kmd(node_hdr, 0);

    return 0;
}

static inline struct wbt_node_hdr_omf *
wbb_get_node(struct wbb *wbb, uint node_number)
{
    struct wbt_node_hdr_omf *nodep;

    assert(node_number < wbb->nodec);

    nodep = (struct wbt_node_hdr_omf *)(PAGE_SIZE * node_number + wbb->nodev);

    assert(
        omf_wbn_magic(nodep) == WBT_INE_NODE_MAGIC || omf_wbn_magic(nodep) == WBT_LFE_NODE_MAGIC);

    return nodep;
}

static void
rightmost_leaf_max_key(struct wbb *wbb, uint node, struct key_obj *ko)
{
    struct wbt_node_hdr_omf *nodep;
    struct wbt_ine_omf *     ine;
    struct wbt_lfe_omf *     lfe;

    /* Walk tree to rightmost leaf that is a child of 'node', unless
     * 'node' is a leaf, in which case just initialize 'nodep'.
     */
    while (1) {
        nodep = wbb_get_node(wbb, node);
        if (omf_wbn_magic(nodep) == WBT_LFE_NODE_MAGIC)
            break;

        ine = wbt_ine(nodep, omf_wbn_num_keys(nodep));

        /* internal node numbers decrease as levels increase.
         * the following assert ensures progress in this loop.
         */
        assert(omf_ine_left_child(ine) < node);

        node = omf_ine_left_child(ine);
    }

    assert(omf_wbn_num_keys(nodep) > 0);

    lfe = wbt_lfe(nodep, omf_wbn_num_keys(nodep) - 1);
    wbt_lfe_key(nodep, lfe, &ko->ko_sfx, &ko->ko_sfx_len);
    wbt_node_pfx(nodep, &ko->ko_pfx, &ko->ko_pfx_len);
}

/* Close out the node - Write out node_hdr, prefix, INEs and key suffixes.
 */
static void
wbt_inner_publish(struct wbb *wbb, uint last_child)
{
    struct wbt_node_hdr_omf *node_hdr = wbb->cnode;

    size_t              pfx_len = wbb->cnode_pfx_len;
    struct wbt_ine_omf *entry; /* (out) current key entry ptr */
    void *              sfxp;  /* (out) current suffix ptr */
    int                 i;

    struct key_stage_entry_intern *kin = wbb->cnode_key_stage;

    omf_set_wbn_num_keys(node_hdr, wbb->cnode_nkeys);
    omf_set_wbn_pfx_len(node_hdr, pfx_len);

    /* Use the first key to write out the prefix. */
    if (pfx_len) {
        void *pfxp = wbb->cnode + sizeof(*node_hdr);

        assert(pfx_len <= kin->klen);
        memcpy(pfxp, kin->kdata, pfx_len);
    }

    entry = wbb->cnode + sizeof(*node_hdr) + pfx_len;
    sfxp = wbb->cnode + PAGE_SIZE;

    for (i = 0; i < wbb->cnode_nkeys; i++) {
        u16 sfx_len = kin->klen - pfx_len;

        sfxp -= sfx_len;
        memcpy(sfxp, kin->kdata + pfx_len, sfx_len);
        omf_set_ine_koff(entry, sfxp - wbb->cnode);
        omf_set_ine_left_child(entry, kin->child);

        assert((void *)kin >= wbb->cnode_key_stage);
        assert((void *)kin < wbb->cnode_key_stage + (wbb->cnode_key_stage_pgc * PAGE_SIZE));
        assert((void *)entry < sfxp);

        entry++;
        kin = (void *)kin + sizeof(*kin) + kin->klen;
    }

    /* should have space for this last entry */
    assert((void *)(entry) <= sfxp);

    /* Create rightmost edge entry -- yes, it uses 'ine_left_child' member.
     */
    omf_set_ine_koff(entry, 0);
    omf_set_ine_left_child(entry, last_child);
}

/**
 * wbb_lcp_len() - Compute lcp of ko and keys currently in the staging area
 * @wbb: wbtree builder
 * @ko:  new key (object) being added
 */
static int
wbb_lcp_len(struct wbb *wbb, const struct key_obj *ko)
{
    uint new_pfx_len, old_pfx_len;

    if (wbb->cnode_nkeys == 0)
        return key_obj_len(ko);

    old_pfx_len = wbb->cnode_pfx_len;
    if (old_pfx_len < ko->ko_pfx_len)
        return memlcp(wbb->cnode_first_key, ko->ko_pfx, old_pfx_len);

    /* old_pfx_len >= ko->ko_pfx_len */
    new_pfx_len = memlcp(wbb->cnode_first_key, ko->ko_pfx, ko->ko_pfx_len);
    if (new_pfx_len == ko->ko_pfx_len) {
        void *p = wbb->cnode_first_key + new_pfx_len;
        uint  cmplen = old_pfx_len - new_pfx_len;

        assert(old_pfx_len >= new_pfx_len);
        new_pfx_len += memlcp(p, ko->ko_sfx, cmplen);
    }

    return new_pfx_len;
}

static merr_t
_add_int_node_entry(struct wbb *wbb, uint child, bool last_entry)
{
    struct key_obj ko;
    uint           klen;
    merr_t         err;
    uint           space;
    uint           new_pfx_len;
    void *         end;

    struct key_stage_entry_intern *kst_int;

    /* Get rightmost key (pfx and sfx) from the child. */
    rightmost_leaf_max_key(wbb, child, &ko);

    if (wbb->cnode == NULL) {
        err = _new_int_node(wbb);
        if (err) {
            hse_elog(HSE_ERR "wbtree: DATALOSS: cannot add int node: @@e", err);
            assert(false); /* HSE_REVISIT: remove before flight */
            return err;
        }
    }

    /* calculate ptr to entry and key */
    klen = key_obj_len(&ko);

    assert(klen);

    /* Track longest pfx_len here because we need the length to calculate
     * total space consumed so far in the node.
     *
     * Do not update wbb->cnode_pfx_len until we're sure the
     * change in the lcp will not overflow the node.
     */
    new_pfx_len = wbb_lcp_len(wbb, &ko);
    assert(new_pfx_len <= klen);

    wbb->cnode_sumlen += klen;

    /* Leave room for an extra ine. */
    space = sizeof(struct wbt_node_hdr_omf) + new_pfx_len +
            ((wbb->cnode_nkeys + 2) * sizeof(struct wbt_ine_omf)) + wbb->cnode_sumlen -
            ((wbb->cnode_nkeys + 1) * new_pfx_len);

    /*
     * Every internal node has a special entry in slot [num_keys]
     * that has a reference to a child node but doesn't have a key.
     * This entry represents the "rightmost" edge from the internal
     * node.
     *
     * If (1) 'child' is the last node at its level, or (2) we have
     * no more space for key, or (3) we've hit the max keys per node,
     * then create the "rightmost" edge entry.
     */
    if (last_entry || space > PAGE_SIZE) {
        /*
         * Ideally, nodes should have have at least one entry
         * with a key.  But we're not creating balanced trees
         * yet, and we could end up all but one child being
         * referenced from previous nodes at this level, which
         * forces a node to have only the "rightmost" edge
         * entry.  So, skip this assert:
         *
         *     assert(wbb->cnode_nkeys > 0);
         */

        wbt_inner_publish(wbb, child);

        /* force new node on next entry */
        wbb->cnode = 0;
        return 0;
    }

    wbb->cnode_pfx_len = new_pfx_len;

    /* [HSE_REVISIT] Refactor the following code that grows the staging area
     * and remove duplicated logic.
     */

    /* Grow the staging area, if necessary */
    end = wbb->cnode_key_stage + (wbb->cnode_key_stage_pgc * PAGE_SIZE);
    if (unlikely(wbb->cnode_key_cursor + sizeof(*kst_int) + klen > end)) {
        void *                         mem;
        uint                           off, new_pgc = 2 * wbb->cnode_key_stage_pgc;
        struct key_stage_entry_intern *first;

        off = wbb->cnode_key_cursor - wbb->cnode_key_stage;
        if (new_pgc > 16)
            new_pgc = wbb->cnode_key_stage_pgc + 16;

        mem = malloc(new_pgc * PAGE_SIZE);
        if (ev(!mem))
            return merr(ENOMEM);

        memcpy(mem, wbb->cnode_key_stage, off);
        free(wbb->cnode_key_stage);

        wbb->cnode_key_stage_pgc = new_pgc;
        wbb->cnode_key_stage = mem;
        wbb->cnode_key_cursor = wbb->cnode_key_stage + off;

        first = mem;
        wbb->cnode_first_key = first->kdata;
    }

    kst_int = (void *)wbb->cnode_key_cursor;
    kst_int->child = child;
    kst_int->klen = klen;
    memcpy(kst_int->kdata, ko.ko_pfx, ko.ko_pfx_len);
    memcpy(kst_int->kdata + ko.ko_pfx_len, ko.ko_sfx, ko.ko_sfx_len);

    if (wbb->cnode_nkeys == 0)
        wbb->cnode_first_key = kst_int->kdata;

    wbb->cnode_key_cursor += sizeof(*kst_int) + klen;
    ++wbb->cnode_nkeys;

    return 0;
}

static merr_t
_make_internal_nodes(
    struct wbb *wbb,
    uint        first_leaf_node,
    uint        num_leaf_nodes,
    uint *      root_node_out)
{
    merr_t err;
    uint   first_node = first_leaf_node;
    uint   num_nodes = num_leaf_nodes;
    uint   i;
    uint   levels = 0;
    bool   last_entry;

    uint progress_check __maybe_unused;

    wbb->cnode = 0; /* forces new node */

    /* If there is more than one node at the current level, then for each
     * node at this level, add a single entry to a node in the parent level
     * (_add_int_node_entry creates new nodes in the parent as needed).
     *
     * Additionally, at each level with internal nodes, compare number of
     * nodes actually added at the level with the estimate. The internal
     * node estimate should be off (overestimate) by at most 1.
     */
    while (num_nodes > 1) {

/* [HSE_REVISIT] Restore this assert once the internal node
         * estimator is fixed.
         */
#if 0
        assert(num_nodes == num_leaf_nodes ||
               get_nodes_at_level(wbb, levels - 1) - num_nodes < 2);
#endif

        progress_check = num_nodes;
        for (i = 0; i < num_nodes; i++) {
            last_entry = i + 1 == num_nodes;
            err = _add_int_node_entry(wbb, i + first_node, last_entry);
            if (ev(err))
                return err;
        }

        /*
         * Make the parent level that was just created the new
         * current level and start from top to create more
         * parent levels as needed.
         */
        first_node += num_nodes;
        assert(wbb->nodec > first_node);
        num_nodes = wbb->nodec - first_node;

        /*
         * Sanity check: num_nodes must decrease each iteration
         * or else the logic is wrong and we risk an infinite
         * loop.
         */
        assert(num_nodes < progress_check);
        levels++;
    }

    /*
     * The last node is the root.  This may end up being a leaf
     * node, which is fine -- the lookup code works on single-node
     * trees where the root is a leaf.
     */
    assert(wbb->nodec > 0);
    *root_node_out = wbb->nodec - 1;
    return 0;
}

static merr_t
wbb_kmd_append(struct wbb *wbb, const void *data, uint dlen, bool copy)
{
    uint          bytes;
    uint          ix = wbb->kmd_iov_index;
    struct iovec *iov = wbb->kmd_iov + ix;

    while (dlen > 0) {
        if (ix >= NELEM(wbb->kmd_iov))
            return merr(ev(ENOMEM));
        if (!iov->iov_base) {
            iov->iov_len = 0;
            iov->iov_base = alloc_page_aligned(KMD_CHUNK_LEN, GFP_KERNEL);
            if (!iov->iov_base)
                return merr(ev(ENOMEM));
        }
        bytes = dlen < KMD_CHUNK_LEN - iov->iov_len ? dlen : KMD_CHUNK_LEN - iov->iov_len;
        if (copy) {
            memcpy(iov->iov_base + iov->iov_len, data, bytes);
            iov->iov_len += bytes;
            wbb->kmd_iov_index = ix;
        }
        dlen -= bytes;
        data += bytes;
        ix++;
        iov++;
    }

    return 0;
}

uint
wbb_entries(struct wbb *wbb)
{
    return wbb->entries + wbb->cnode_nkeys;
}

/* Close out the node - Write out node_hdr, prefix, LFEs and key suffixes.
 */
static void
wbt_leaf_publish(struct wbb *wbb)
{
    struct wbt_node_hdr_omf *node_hdr = wbb->cnode;

    size_t              pfx_len = wbb->cnode_pfx_len;
    struct wbt_lfe_omf *entry; /* (out) current key entry ptr */
    void *              sfxp;  /* (out) current suffix ptr */
    int                 i;

    struct key_stage_entry_leaf *kin = wbb->cnode_key_stage;

    omf_set_wbn_num_keys(node_hdr, wbb->cnode_nkeys);
    omf_set_wbn_pfx_len(node_hdr, pfx_len);

    /* Use the first key to write out the prefix. */
    if (pfx_len) {
        void *pfxp = wbb->cnode + sizeof(*node_hdr);

        assert(pfx_len <= kin->klen);
        memcpy(pfxp, kin->kdata, pfx_len);
    }

    entry = wbb->cnode + sizeof(*node_hdr) + pfx_len;
    sfxp = wbb->cnode + PAGE_SIZE;

    for (i = 0; i < wbb->cnode_nkeys; i++) {
        u16  sfx_len = kin->klen - pfx_len;
        uint key_extra = kin->kmd_off < U16_MAX ? 0 : 4;

        sfxp -= sfx_len + key_extra;
        assert((void *)entry < sfxp);

        if (key_extra) {
            /* kmdoff is too large for u16 */
            omf_set_lfe_kmd(entry, U16_MAX);
            *(u32 *)(sfxp) = cpu_to_le32(kin->kmd_off);
        } else {
            omf_set_lfe_kmd(entry, (u16)(kin->kmd_off));
        }

        assert((void *)kin >= wbb->cnode_key_stage);
        assert((void *)kin < wbb->cnode_key_stage + (wbb->cnode_key_stage_pgc * PAGE_SIZE));

        memcpy(sfxp + key_extra, kin->kdata + pfx_len, sfx_len);
        omf_set_lfe_koff(entry, sfxp - wbb->cnode);

        /* Store last key. */
        wbb->wbt_last_kobj.ko_pfx = wbb->cnode + sizeof(*node_hdr);
        wbb->wbt_last_kobj.ko_pfx_len = pfx_len;
        wbb->wbt_last_kobj.ko_sfx = sfxp + key_extra;
        wbb->wbt_last_kobj.ko_sfx_len = sfx_len;

        assert(pfx_len + sfx_len <= HSE_KVS_KLEN_MAX);

        /* Store first key. */
        if (!wbb->entries)
            wbb->wbt_first_kobj = wbb->wbt_last_kobj;

        entry++;
        kin = (void *)kin + sizeof(*kin) + kin->klen;
        wbb->entries++;
    }
}

merr_t
wbb_add_entry(
    struct wbb *          wbb,
    const struct key_obj *kobj,
    uint                  nvals,
    const void *          key_kmd,
    uint                  key_kmd_len,
    uint                  max_pgc,
    uint *                wbt_pgc,
    bool *                added)
{
    merr_t err;
    uint   kmd_pgc;
    uint   entry_kmd_off;
    uint   key_extra;
    size_t space, encoded_cnt_len;
    char   encoded_cnt[4]; /* large enough to hold kmd encoded count */
    size_t new_pfx_len;
    void * end;
    uint   klen = key_obj_len(kobj);

    struct key_stage_entry_leaf *kst_leaf;

    *added = false;

    if (*wbt_pgc > max_pgc || nvals > HG32_1024M_MAX || key_kmd_len == 0) {
        assert(0);
        return merr(ev(EBUG));
    }

    /* Track longest pfx_len here because we need the length to calculate
     * total space consumed so far in the node.
     */
    new_pfx_len = wbb_lcp_len(wbb, kobj);
    assert(new_pfx_len <= klen);

    /* entry_kmd_off will be saved in the "lfe" for this key */
    entry_kmd_off = get_kmd_len(wbb);
    if (entry_kmd_off < wbb->cnode_kmd_off) {
        assert(0);
        return merr(ev(EBUG));
    }
    key_extra = entry_kmd_off - wbb->cnode_kmd_off >= U16_MAX ? 4 : 0;
    if (key_extra)
        ++wbb->cnode_key_extra_cnt;

    encoded_cnt_len = 0;
    kmd_set_count(encoded_cnt, &encoded_cnt_len, nvals);

    /* Calculate size of wbtree after adding key metadata.
     * Save max_pgc and used_pgc for use deeper in the call stack.
     */
    kmd_pgc = (entry_kmd_off + encoded_cnt_len + key_kmd_len + PAGE_SIZE - 1) / PAGE_SIZE;
    wbb->max_pgc = max_pgc;
    wbb->used_pgc = wbb->nodec + wbb->max_inodec + kmd_pgc;
    if (wbb->used_pgc > wbb->max_pgc)
        return 0; /* not an error */

    /* Reserve space for kmd */
    err = wbb_kmd_append(wbb, NULL, encoded_cnt_len + key_kmd_len, false);
    if (ev(err))
        return err;

    wbb->cnode_sumlen += klen;

    /* Create a new node if space exceeds PAGE_SIZE */
    space = sizeof(struct wbt_node_hdr_omf) + new_pfx_len +
            ((wbb->cnode_nkeys + 1) * sizeof(struct wbt_lfe_omf)) + wbb->cnode_sumlen +
            (sizeof(u32) * wbb->cnode_key_extra_cnt) - ((wbb->cnode_nkeys + 1) * new_pfx_len);

    if (space > PAGE_SIZE) {

        /* close out current node */
        wbt_leaf_publish(wbb);

        /* new node allocate fail --> out of space (not error) */
        err = _new_leaf_node(wbb, key_obj_len(&wbb->wbt_last_kobj));
        if (err) {
            if (ev(merr_errno(err) != ENOSPC)) {
                assert(0);
                return err;
            }

            return 0;
        }

        assert(wbb->cnode_nkeys == 0);
        assert(wbb->cnode_sumlen == 0);

        wbb->cnode_pfx_len = klen;
        wbb->cnode_sumlen += klen;
        key_extra = 0; /* reset key_extra */
    } else {
        wbb->cnode_pfx_len = new_pfx_len;
    }

    assert(new_pfx_len <= wbb->cnode_pfx_len);

    /* Copy kmd into iovec. Should not fail b/c space has been reserved. */
    if (wbb_kmd_append(wbb, encoded_cnt, encoded_cnt_len, true) ||
        wbb_kmd_append(wbb, key_kmd, key_kmd_len, true)) {
        assert(0);
        return merr(ev(EBUG));
    }

    /* Commit the new entry
     * - move key cursor back, move entry cursor forward
     * - save key offset in LFE
     * - save kmd offset in LFE or w/ key if too big for LFE
     * - copy key into node
     * - update first/last keys
     */
    /* Get the key's kmd offset within the node's kmd region. */
    entry_kmd_off -= wbb->cnode_kmd_off;

    assert(wbb->cnode_key_cursor >= wbb->cnode_key_stage);
    assert(wbb->cnode_key_cursor <= wbb->cnode_key_stage + (wbb->cnode_key_stage_pgc * PAGE_SIZE));

    /* Grow the staging area, if necessary */
    end = wbb->cnode_key_stage + (wbb->cnode_key_stage_pgc * PAGE_SIZE);
    if (unlikely(wbb->cnode_key_cursor + sizeof(*kst_leaf) + klen > end)) {
        void *                       mem;
        uint                         off, new_pgc = 2 * wbb->cnode_key_stage_pgc;
        struct key_stage_entry_leaf *first;

        off = wbb->cnode_key_cursor - wbb->cnode_key_stage;
        if (new_pgc > 16)
            new_pgc = wbb->cnode_key_stage_pgc + 16;

        mem = malloc(new_pgc * PAGE_SIZE);
        if (ev(!mem))
            return merr(ENOMEM);

        memcpy(mem, wbb->cnode_key_stage, off);
        free(wbb->cnode_key_stage);

        wbb->cnode_key_stage_pgc = new_pgc;
        wbb->cnode_key_stage = mem;
        wbb->cnode_key_cursor = wbb->cnode_key_stage + off;

        first = mem;
        wbb->cnode_first_key = first->kdata;
    }

    /* Add kmd, klen and kdata to the staging area. */
    kst_leaf = wbb->cnode_key_cursor;
    kst_leaf->kmd_off = entry_kmd_off;
    kst_leaf->klen = klen;

    if (kobj->ko_pfx)
        memcpy(kst_leaf->kdata, kobj->ko_pfx, kobj->ko_pfx_len);

    memcpy(kst_leaf->kdata + kobj->ko_pfx_len, kobj->ko_sfx, kobj->ko_sfx_len);

    wbb->cnode_key_cursor += sizeof(*kst_leaf) + klen;

    if (wbb->cnode_nkeys == 0)
        wbb->cnode_first_key = kst_leaf->kdata;

    wbb->cnode_nkeys++;

    *wbt_pgc = wbb->nodec + wbb->max_inodec + get_kmd_pgc(wbb);
    *added = true;
    return 0;
}

void
wbb_hdr_init(struct wbb *wbb, struct wbt_hdr_omf *hdr)
{
    omf_set_wbt_magic(hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(hdr, WBT_TREE_VERSION);
}

merr_t
wbb_freeze(
    struct wbb *        wbb,
    struct wbt_hdr_omf *hdr,
    uint                max_pgc,
    uint *              wbt_pgc, /* in/out */
    struct iovec *      iov,     /* in/out */
    uint                iov_max,
    uint *              iov_cnt) /* out */
{
    merr_t err;
    uint   first_leaf_node, num_leaf_nodes, root_node;
    uint   i, kmd_pgc;

    assert(*wbt_pgc <= max_pgc);
    if (!(*wbt_pgc <= max_pgc))
        return merr(ev(EBUG));

    assert(wbb->nodec > 0);
    if (!(wbb->nodec > 0))
        return merr(ev(EBUG));

    kmd_pgc = get_kmd_pgc(wbb);
    wbb->used_pgc = wbb->nodec + kmd_pgc;
    wbb->max_pgc = max_pgc;

    assert(wbb->used_pgc <= max_pgc);
    if (!(wbb->used_pgc <= max_pgc))
        return merr(ev(EBUG));

    /* write node header in the leaf node that was in progress */
    assert(wbb->cnode_nkeys <= U16_MAX);
    wbt_leaf_publish(wbb);

    /* get num_leaf_nodes now, b/c wbb->nodec
     * will increase as internal nodes are built.
     */
    first_leaf_node = 0;
    num_leaf_nodes = wbb->nodec;

    err = _make_internal_nodes(wbb, first_leaf_node, num_leaf_nodes, &root_node);
    if (ev(err))
        return err;

    /* Recheck total page count after creating internal nodes.
     * This assert can fail with kblocks larger than 256MB (which is
     * beyond the current limit).
     */
    assert(wbb->used_pgc <= U16_MAX);

    /* format the wbtree header */
    memset(hdr, 0, sizeof(*hdr));
    omf_set_wbt_magic(hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(hdr, WBT_TREE_VERSION);
    omf_set_wbt_leaf(hdr, first_leaf_node);
    omf_set_wbt_leaf_cnt(hdr, num_leaf_nodes);
    omf_set_wbt_root(hdr, root_node);
    omf_set_wbt_kmd_pgc(hdr, kmd_pgc);

    assert(iov_max >= KMD_CHUNKS + 1);

    iov[0].iov_base = wbb->nodev;
    iov[0].iov_len = wbb->nodec * PAGE_SIZE;
    for (i = 0; i <= wbb->kmd_iov_index; i++) {
        size_t len = wbb->kmd_iov[i].iov_len;
        size_t padded_len = PAGE_ALIGN(len);

        memset(wbb->kmd_iov[i].iov_base + wbb->kmd_iov[i].iov_len, 0, padded_len - len);
        iov[i + 1].iov_base = wbb->kmd_iov[i].iov_base;
        iov[i + 1].iov_len = padded_len;
    }

    /* +1 for nodes, kmd_iov_index+1 for kmd */
    *iov_cnt = wbb->kmd_iov_index + 2;
    *wbt_pgc = wbb->used_pgc;

    return 0;
}

void
wbb_init(struct wbb *wbb, void *nodev, uint max_pgc, uint *wbt_pgc)
{
    void *kst, *iov_base[KMD_CHUNKS];
    uint  kst_pgc;
    uint  i;

    for (i = 0; i < KMD_CHUNKS; i++)
        iov_base[i] = wbb->kmd_iov[i].iov_base;

    kst = wbb->cnode_key_stage;
    kst_pgc = wbb->cnode_key_stage_pgc;

    memset(wbb, 0, sizeof(*wbb));

    wbb->max_pgc = max_pgc;
    wbb->nodev_len = max_pgc;
    wbb->nodev = nodev;
    wbb->cnode_key_stage = kst;
    wbb->cnode_key_stage_pgc = kst_pgc;

    _new_leaf_node(wbb, 0);

    for (i = 0; i < KMD_CHUNKS; i++)
        wbb->kmd_iov[i].iov_base = iov_base[i];

    *wbt_pgc = wbb->nodec;
}

merr_t
wbb_create(
    struct wbb **wbb_out,
    uint         max_pgc,
    uint *       wbt_pgc /* in/out */
    )
{
    struct wbb *wbb;
    void *      nodev;

    assert(WBB_FREEZE_IOV_MAX >= KMD_CHUNKS);

    /* insist on something to work with... */
    if (max_pgc < 8)
        return merr(ev(EINVAL));

    wbb = calloc(1, sizeof(*wbb));
    if (!wbb)
        return merr(ev(ENOMEM));

    wbb->cnode_key_stage_pgc = 2;
    wbb->cnode_key_stage = malloc(wbb->cnode_key_stage_pgc * PAGE_SIZE);
    if (ev(!wbb->cnode_key_stage)) {
        free(wbb);
        return merr(ENOMEM);
    }

    nodev = alloc_page_aligned(max_pgc * PAGE_SIZE, GFP_KERNEL);
    if (ev(!nodev)) {
        free(wbb->cnode_key_stage);
        free(wbb);
        return merr(ENOMEM);
    }

    wbb_init(wbb, nodev, max_pgc, wbt_pgc);

    *wbb_out = wbb;
    return 0;
}

void
wbb_reset(struct wbb *wbb, uint *wbt_pgc)
{
    struct int_node_estimator *est = wbb->inode_est;

    wbb->inode_est = 0;
    wbb_init(wbb, wbb->nodev, wbb->nodev_len, wbt_pgc);

    while (est) {
        struct int_node_estimator *next = est->parent;

        free(est);
        est = next;
    }
}

void
wbb_destroy(struct wbb *wbb)
{
    uint i;

    if (wbb) {
        struct int_node_estimator *est = wbb->inode_est;

        while (est) {
            struct int_node_estimator *next = est->parent;

            free(est);
            est = next;
        }

        for (i = 0; i < KMD_CHUNKS; i++)
            free_aligned(wbb->kmd_iov[i].iov_base);
        free_aligned(wbb->nodev);
        free(wbb->cnode_key_stage);
        free(wbb);
    }
}

void
wbb_min_max_keys(struct wbb *wbb, struct key_obj **first_kobj, struct key_obj **last_kobj)
{
    *first_kobj = &wbb->wbt_first_kobj;
    *last_kobj = &wbb->wbt_last_kobj;
}

uint
wbb_page_cnt_get(struct wbb *wbb)
{
    return wbb->used_pgc;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "wbt_builder_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
