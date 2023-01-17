/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/util/platform.h>
#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/page.h>
#include <hse/util/vlb.h>
#include <hse/util/event_counter.h>
#include <hse/util/key_util.h>

#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/omf_kmd.h>

#include <hse/limits.h>

#define MTF_MOCK_IMPL_wbt_builder
#include "wbt_builder.h"
#include "wbt_reader.h"
#include "wbt_internal.h"
#include "intern_builder.h"

#define KMD_CHUNK_PAGES 256
#define KMD_CHUNK_LEN (KMD_CHUNK_PAGES * PAGE_SIZE)
#define KMD_CHUNKS (KBLOCK_MAX_SIZE / KMD_CHUNK_LEN)

/**
 * struct wbb - a wb tree builder (wb --> "wants to be a b-tree")
 * @nodev: vector of nodes (nodev[0] == first leaf node)
 * @nodev_len: allocated length of nodev vector
 * @lnodec: number of nodes in use
 * @max_inodec: upper limit on number of internal nodes that will be needed
 * @max_pgc: max allowable size of wbtree in pages (nodes+kmd+bloom)
 * @cnode: current node
 * @cnode_key_cursor:     insertion point into staging buffer for next key
 * @cnode_key_stage_base: staging buffer base address
 * @cnode_key_stage_end:  staging buffer end address
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
    uint  lnodec;
    uint  inodec;
    uint  max_inodec;
    uint  max_pgc;
    uint  used_pgc;
    uint64_t total_kvlen;
    bool  finalized;

    void *cnode;

    void *cnode_key_cursor;
    void *cnode_key_stage_base;
    void *cnode_key_stage_end;

    uint32_t cnode_kmd_off;
    uint64_t cnode_kvlen;
    uint16_t cnode_nkeys;
    uint16_t cnode_pfx_len;
    uint  cnode_sumlen;
    uint  cnode_key_stage_pgc;
    uint  cnode_key_extra_cnt;
    void *cnode_first_key;
    void *cnode_last_key;
    uint16_t cnode_first_klen;
    uint16_t cnode_last_klen;

    struct intern_builder *ibldr;

    struct key_obj wbt_first_kobj;
    struct key_obj wbt_last_kobj;

    uint entries;

    uint         kmd_iov_index;
    struct iovec kmd_iov[KMD_CHUNKS + 1];
};

struct key_stage_entry_leaf {
    uint32_t kmd_off;
    uint16_t klen;
    uint8_t  kdata[] HSE_ALIGNED(4);
};

static HSE_ALWAYS_INLINE size_t
get_kst_sz(size_t klen)
{
    klen += sizeof(struct key_stage_entry_leaf);

    return roundup(klen, alignof(struct key_stage_entry_leaf));
}

static HSE_ALWAYS_INLINE uint
get_kmd_len(struct wbb *wbb)
{
    uint len = wbb->kmd_iov_index * KMD_CHUNK_LEN + wbb->kmd_iov[wbb->kmd_iov_index].iov_len;

    assert(len < KMD_CHUNK_LEN * KMD_CHUNKS);
    return len;
}

static HSE_ALWAYS_INLINE uint
get_kmd_pgc(struct wbb *wbb)
{
    uint pgc = (get_kmd_len(wbb) + PAGE_SIZE - 1) / PAGE_SIZE;

    assert(pgc <= KMD_CHUNK_PAGES * KMD_CHUNKS);
    return pgc;
}

uint
wbb_max_inodec_get(struct wbb *wbb)
{
    return wbb ? wbb->max_inodec : 0;
}

uint
wbb_kmd_pgc_get(struct wbb *wbb)
{
    return wbb ? get_kmd_pgc(wbb) : 0;
}

static struct wbt_node_hdr_omf *
_new_node(struct wbb *wbb)
{
    wbb->cnode = wbb->nodev + wbb->lnodec * PAGE_SIZE;
    wbb->cnode_key_cursor = wbb->cnode_key_stage_base;
    wbb->cnode_pfx_len = 0;
    wbb->cnode_sumlen = 0;
    wbb->cnode_kmd_off = get_kmd_len(wbb);
    wbb->cnode_nkeys = 0;
    wbb->cnode_key_extra_cnt = 0;
    wbb->cnode_kvlen = 0;

    memset(wbb->cnode, 0, WBT_NODE_SIZE);
    wbb->lnodec += 1;

    return wbb->cnode;
}

static merr_t
_new_leaf_node(struct wbb *wbb, struct key_obj *right_edge)
{
    struct wbt_node_hdr_omf *node_hdr;
    uint                     max_inodec = 0;
    merr_t                   err;

    /* Get number of pages required if the current key is added to the internal
     * nodes. Do not add the key yet.
     */
    err = ib_key_add(wbb->ibldr, right_edge, &max_inodec, true);
    if (ev(err))
        return err;

    wbb->used_pgc = wbb->used_pgc + 1 + max_inodec - wbb->max_inodec;
    wbb->max_inodec = max_inodec;

    node_hdr = _new_node(wbb);
    omf_set_wbn_magic(node_hdr, WBT_LFE_NODE_MAGIC);
    omf_set_wbn_num_keys(node_hdr, 0);
    omf_set_wbn_kmd(node_hdr, wbb->cnode_kmd_off);
    omf_set_wbn_kvlen(node_hdr, 0);

    return 0;
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

    if (old_pfx_len < 1)
        return 0;

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
wbb_kmd_append(struct wbb *wbb, const void *data, uint dlen, bool copy)
{
    uint          bytes;
    uint          ix = wbb->kmd_iov_index;
    struct iovec *iov = wbb->kmd_iov + ix;

    while (dlen > 0) {
        if (ev(ix >= NELEM(wbb->kmd_iov)))
            return merr(ENOMEM);
        if (!iov->iov_base) {
            iov->iov_len = 0;
            iov->iov_base = vlb_alloc(KMD_CHUNK_LEN);
            if (ev(!iov->iov_base))
                return merr(ENOMEM);
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

uint64_t
wbb_kvlen(const struct wbb *wbb)
{
    /* This metric isn't accurate until the tree is finalized.
     */
    assert(wbb->finalized);
    return wbb->total_kvlen;
}

uint
wbb_entries(const struct wbb *wbb)
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

    struct key_stage_entry_leaf *kin = wbb->cnode_key_stage_base;

    wbb->cnode_kvlen += WBT_NODE_SIZE;

    omf_set_wbn_num_keys(node_hdr, wbb->cnode_nkeys);
    omf_set_wbn_pfx_len(node_hdr, pfx_len);
    omf_set_wbn_kvlen(node_hdr, wbb->cnode_kvlen);

    wbb->total_kvlen += wbb->cnode_kvlen;

    /* Use the first key to write out the prefix. */
    if (pfx_len) {
        void *pfxp = wbb->cnode + sizeof(*node_hdr);

        assert(pfx_len <= kin->klen);
        memcpy(pfxp, kin->kdata, pfx_len);
    }

    entry = wbb->cnode + sizeof(*node_hdr) + pfx_len;
    sfxp = wbb->cnode + PAGE_SIZE;

    for (i = 0; i < wbb->cnode_nkeys; i++) {
        uint16_t sfx_len = kin->klen - pfx_len;
        uint key_extra = kin->kmd_off < UINT16_MAX ? 0 : 4;

        sfxp -= sfx_len + key_extra;
        assert((void *)entry < sfxp);

        if (key_extra) {
            /* kmdoff is too large for u16 */
            omf_set_lfe_kmd(entry, UINT16_MAX);
            *(uint32_t *)sfxp = cpu_to_omf32(kin->kmd_off);
        } else {
            omf_set_lfe_kmd(entry, (uint16_t)(kin->kmd_off));
        }

        assert((void *)kin >= wbb->cnode_key_stage_base);
        assert((void *)kin < wbb->cnode_key_stage_end);

        memcpy(sfxp + key_extra, kin->kdata + pfx_len, sfx_len);
        omf_set_lfe_koff(entry, sfxp - wbb->cnode);

        /* Store last key. */
        wbb->wbt_last_kobj.ko_pfx = wbb->cnode + sizeof(*node_hdr);
        wbb->wbt_last_kobj.ko_pfx_len = pfx_len;
        wbb->wbt_last_kobj.ko_sfx = sfxp + key_extra;
        wbb->wbt_last_kobj.ko_sfx_len = sfx_len;

        assert(pfx_len + sfx_len <= HSE_KVS_KEY_LEN_MAX);

        /* Store first key. */
        if (!wbb->entries)
            wbb->wbt_first_kobj = wbb->wbt_last_kobj;

        entry++;
        kin = (void *)kin + get_kst_sz(kin->klen);
        wbb->entries++;
    }
}

merr_t
wbb_add_entry(
    struct wbb *          wbb,
    const struct key_obj *kobj,
    uint                  kmd_entries,
    uint64_t              vblk_om_vlen,
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
    uint   klen = key_obj_len(kobj);

    struct key_stage_entry_leaf *kst_leaf;

    *added = false;

    if (*wbt_pgc > max_pgc || kmd_entries > HG32_1024M_MAX || key_kmd_len == 0) {
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
    key_extra = entry_kmd_off - wbb->cnode_kmd_off >= UINT16_MAX ? 4 : 0;
    if (key_extra)
        ++wbb->cnode_key_extra_cnt;

    encoded_cnt_len = 0;
    kmd_set_count(encoded_cnt, &encoded_cnt_len, kmd_entries);

    /* Calculate size of wbtree after adding key metadata.
     * Save max_pgc and used_pgc for use deeper in the call stack.
     */
    kmd_pgc = (entry_kmd_off + encoded_cnt_len + key_kmd_len + PAGE_SIZE - 1) / PAGE_SIZE;
    wbb->max_pgc = max_pgc;
    wbb->used_pgc = wbb->lnodec + wbb->max_inodec + kmd_pgc;
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
            (sizeof(uint32_t) * wbb->cnode_key_extra_cnt) - ((wbb->cnode_nkeys + 1) * new_pfx_len);

    if (space > PAGE_SIZE) {
        /* close out current node */
        wbt_leaf_publish(wbb);

        /* new node allocate fail --> out of space (not error) */
        err = _new_leaf_node(wbb, &wbb->wbt_last_kobj);
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

    assert(wbb->cnode_key_cursor >= wbb->cnode_key_stage_base);
    assert(wbb->cnode_key_cursor <= wbb->cnode_key_stage_end);

    /* Grow the staging area, if necessary */
    if (wbb->cnode_key_stage_end - wbb->cnode_key_cursor < get_kst_sz(klen)) {
        void *                       mem;
        uint                         off, new_pgc;
        struct key_stage_entry_leaf *first;

        new_pgc = wbb->cnode_key_stage_pgc ? wbb->cnode_key_stage_pgc * 2 : 8;
        if (new_pgc > 16)
            new_pgc = wbb->cnode_key_stage_pgc + 16;

        mem = malloc(new_pgc * PAGE_SIZE);
        if (ev(!mem))
            return merr(ENOMEM);

        off = wbb->cnode_key_cursor - wbb->cnode_key_stage_base;
        if (off > 0) {
            memcpy(mem, wbb->cnode_key_stage_base, off);
            free(wbb->cnode_key_stage_base);
        }

        wbb->cnode_key_stage_pgc = new_pgc;
        wbb->cnode_key_stage_base = mem;
        wbb->cnode_key_stage_end = wbb->cnode_key_stage_base + new_pgc * PAGE_SIZE;
        wbb->cnode_key_cursor = wbb->cnode_key_stage_base + off;

        first = wbb->cnode_key_stage_base;
        wbb->cnode_first_key = first->kdata;
    }

    /* Add kmd, klen and kdata to the staging area. */
    kst_leaf = wbb->cnode_key_cursor;
    kst_leaf->kmd_off = entry_kmd_off;
    kst_leaf->klen = klen;

    if (kobj->ko_pfx)
        memcpy(kst_leaf->kdata, kobj->ko_pfx, kobj->ko_pfx_len);

    memcpy(kst_leaf->kdata + kobj->ko_pfx_len, kobj->ko_sfx, kobj->ko_sfx_len);

    wbb->cnode_key_cursor += get_kst_sz(klen);

    if (wbb->cnode_nkeys == 0) {
        wbb->cnode_first_key = kst_leaf->kdata;
        wbb->cnode_first_klen = klen;
    }

    wbb->cnode_last_key = kst_leaf->kdata;
    wbb->cnode_last_klen = klen;

    wbb->cnode_nkeys++;
    wbb->cnode_kvlen += key_kmd_len + vblk_om_vlen;

    *wbt_pgc = wbb->lnodec + wbb->max_inodec + get_kmd_pgc(wbb);
    *added = true;
    return 0;
}

void
wbb_hdr_init(struct wbt_hdr_omf *hdr)
{
    omf_set_wbt_magic(hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(hdr, WBT_TREE_VERSION);
}

void
wbb_hdr_set(struct wbt_hdr_omf *hdr, struct wbt_desc *desc)
{
    memset(hdr, 0, sizeof(*hdr));
    omf_set_wbt_magic(hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(hdr, desc->wbd_version);
    omf_set_wbt_leaf(hdr, desc->wbd_leaf);
    omf_set_wbt_leaf_cnt(hdr, desc->wbd_leaf_cnt);
    omf_set_wbt_root(hdr, desc->wbd_root);
    omf_set_wbt_kmd_pgc(hdr, desc->wbd_kmd_pgc);
}

merr_t
wbb_freeze(
    struct wbb *        wbb,
    struct wbt_hdr_omf *hdr,
    uint                max_pgc,
    uint *              wbt_pgc, /* in/out */
    struct iovec *      iov,     /* in/out */
    uint                iov_max,
    uint *              iov_cnt_out) /* out */
{
    uint first_leaf_node, num_leaf_nodes, root_node;
    uint i, kmd_pgc;
    uint iov_cnt = 0;

    assert(*wbt_pgc <= max_pgc);
    if (!(*wbt_pgc <= max_pgc))
        return merr(ev(EBUG));

    assert(wbb->lnodec > 0);
    if (!(wbb->lnodec > 0))
        return merr(ev(EBUG));

    kmd_pgc = get_kmd_pgc(wbb);
    wbb->used_pgc = wbb->lnodec + kmd_pgc;
    wbb->max_pgc = max_pgc;

    assert(wbb->used_pgc <= max_pgc);
    if (!(wbb->used_pgc <= max_pgc))
        return merr(ev(EBUG));

    /* write node header in the leaf node that was in progress */
    assert(wbb->cnode_nkeys <= UINT16_MAX);
    wbt_leaf_publish(wbb);

    /* get num_leaf_nodes now, b/c wbb->lnodec
     * will increase as internal nodes are built.
     */
    first_leaf_node = 0;
    num_leaf_nodes = wbb->lnodec;

    /* Close out current internal nodes and update child offsets. */
    ib_child_update(wbb->ibldr, num_leaf_nodes);

    iov[0].iov_base = wbb->nodev;
    iov[0].iov_len = num_leaf_nodes * PAGE_SIZE;

    root_node = wbb->lnodec + wbb->max_inodec - 1;
    wbb->used_pgc += wbb->max_inodec;

    iov_cnt += 1 + ib_iovec_construct(wbb->ibldr, &iov[1]);

    /* Recheck total page count after creating internal nodes.
     * This assert can fail with kblocks larger than 256MB (which is
     * beyond the current limit).
     */
    assert(wbb->used_pgc <= UINT16_MAX);

    /* format the wbtree header */
    memset(hdr, 0, sizeof(*hdr));
    omf_set_wbt_magic(hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(hdr, WBT_TREE_VERSION);
    omf_set_wbt_leaf(hdr, first_leaf_node);
    omf_set_wbt_leaf_cnt(hdr, num_leaf_nodes);
    omf_set_wbt_root(hdr, root_node);
    omf_set_wbt_kmd_pgc(hdr, kmd_pgc);

    for (i = 0; i <= wbb->kmd_iov_index; i++) {
        size_t len = wbb->kmd_iov[i].iov_len;
        size_t padded_len = PAGE_ALIGN(len);

        memset(wbb->kmd_iov[i].iov_base + wbb->kmd_iov[i].iov_len, 0, padded_len - len);
        iov[i + iov_cnt].iov_base = wbb->kmd_iov[i].iov_base;
        iov[i + iov_cnt].iov_len = padded_len;
    }

    iov_cnt += wbb->kmd_iov_index + 1; /* KMD iov */
    assert(iov_cnt == 1 + wbb->max_inodec + wbb->kmd_iov_index + 1);

    *iov_cnt_out = iov_cnt;
    *wbt_pgc = wbb->used_pgc;

    wbb->finalized = true;

    return 0;
}

merr_t
wbb_init(struct wbb *wbb, void *nodev, uint max_pgc, uint *wbt_pgc)
{
    void  *kst_base, *kst_end, *iov_base[KMD_CHUNKS + 1];
    struct intern_builder *ibldr;
    uint   kst_pgc;
    uint   i;
    merr_t err;

    /* Save state that persists across "init" */
    ibldr = wbb->ibldr;
    kst_base = wbb->cnode_key_stage_base;
    kst_end = wbb->cnode_key_stage_end;
    kst_pgc = wbb->cnode_key_stage_pgc;
    for (i = 0; wbb->kmd_iov[i].iov_base; i++)
        iov_base[i] = wbb->kmd_iov[i].iov_base;
    iov_base[i] = NULL;

    /* Reset */
    memset(wbb, 0, sizeof(*wbb));

    /* Restore */
    wbb->cnode_key_stage_base = kst_base;
    wbb->cnode_key_stage_end = kst_end;
    wbb->cnode_key_stage_pgc = kst_pgc;
    for (i = 0; iov_base[i]; i++)
        wbb->kmd_iov[i].iov_base = iov_base[i];

    /* Init new params */
    wbb->max_pgc = max_pgc;
    wbb->nodev_len = max_pgc;
    wbb->nodev = nodev;
    wbb->inodec = max_pgc;

    err = _new_leaf_node(wbb, 0);
    if (err)
        return err;

    wbb->ibldr = ibldr;
    if (!wbb->ibldr) {
        wbb->ibldr = ib_create(wbb);
        if (ev(!wbb->ibldr))
            return merr(ENOMEM);
    }

    *wbt_pgc = wbb->lnodec;

    return 0;
}

merr_t
wbb_create(
    struct wbb **wbb_out,
    uint         max_pgc,
    uint *       wbt_pgc /* in/out */
    )
{
    struct wbb *wbb;
    void *nodev;
    merr_t err;

    /* insist on something to work with... */
    if (ev(max_pgc < 8))
        return merr(EINVAL);

    wbb = calloc(1, sizeof(*wbb));
    if (ev(!wbb))
        return merr(ENOMEM);

    nodev = aligned_alloc(PAGE_SIZE, max_pgc * PAGE_SIZE);
    if (ev(!nodev)) {
        free(wbb);
        return merr(ENOMEM);
    }

    err = wbb_init(wbb, nodev, max_pgc, wbt_pgc);
    if (ev(err)) {
        free(nodev);
        free(wbb);
        return err;
    }

    *wbb_out = wbb;

    return 0;
}

void *
wbb_inode_get_page(struct wbb *wbb)
{
    if (ev(!wbb))
        return NULL;

    assert(wbb->inodec > 0);

    wbb->inodec--;
    assert(wbb->inodec > wbb->lnodec);
    if (wbb->inodec <= wbb->lnodec)
        return NULL;

    return wbb->nodev + PAGE_SIZE * wbb->inodec;
}

bool
wbb_inode_has_space(struct wbb *wbb, uint inode_cnt)
{
    uint used_pgc;

    if (ev(!wbb))
        return false;

    used_pgc = wbb->used_pgc + 1 + inode_cnt - wbb->max_inodec;
    if (used_pgc > wbb->max_pgc || wbb->lnodec + inode_cnt >= wbb->nodev_len)
        return false;

    return true;
}

void
wbb_reset(struct wbb *wbb, uint *wbt_pgc)
{
    merr_t err;

    ib_reset(wbb->ibldr);

    /* [HSE_REVISIT] Inform caller if wbb_init() fails as the wbb is invalid.
     */
    err = wbb_init(wbb, wbb->nodev, wbb->nodev_len, wbt_pgc);
    if (err)
        abort();
}

void
wbb_destroy(struct wbb *wbb)
{
    uint i;

    if (wbb) {
        ib_destroy(wbb->ibldr);

        for (i = 0; wbb->kmd_iov[i].iov_base; i++)
            vlb_free(wbb->kmd_iov[i].iov_base, KMD_CHUNK_LEN);
        free(wbb->nodev);
        free(wbb->cnode_key_stage_base);
        free(wbb);
    }
}

void
wbb_min_max_keys(struct wbb *wbb, struct key_obj *first_kobj, struct key_obj *last_kobj)
{
    if (wbb->finalized) {
        *first_kobj = wbb->wbt_first_kobj;
        *last_kobj = wbb->wbt_last_kobj;
    } else {
        assert(wbb->cnode_nkeys > 0);

        if (wbb->entries == 0)
            key2kobj(first_kobj, wbb->cnode_first_key, wbb->cnode_first_klen);
        else
            *first_kobj = wbb->wbt_first_kobj;

        key2kobj(last_kobj, wbb->cnode_last_key, wbb->cnode_last_klen);
    }
}

uint
wbb_page_cnt_get(struct wbb *wbb)
{
    return wbb->used_pgc;
}

#if HSE_MOCKING
#include "wbt_builder_ut_impl.i"
#endif /* HSE_MOCKING */
