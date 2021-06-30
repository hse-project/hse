/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/mman.h>
#include <hse_util/keycmp.h>

#include <hse/hse_limits.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/omf_kmd.h>

#include "wbt_internal.h"
#include "omf.h"
#include "kvs_mblk_desc.h"
#include "kblock_reader.h"

#include "wbt_reader.h"
#include "wbt_reader_v5.h"

static void
wbti_get_page(struct wbti *self, u32 node_idx)
{
    size_t mblock_offset;

    assert(node_idx != self->node_idx || self->node == NULL);

    mblock_offset = PAGE_SIZE * (node_idx + self->wbd->wbd_first_page);
    self->node = (struct wbt_node_hdr_omf *)(self->kbd->map_base + mblock_offset);

    assert(omf_wbn_magic(self->node) == WBT_LFE_NODE_MAGIC);

    self->lfe_idx = -1;
    self->node_idx = node_idx;
}

static int
wbtr_seek_page(
    const struct kvs_mblk_desc *kbd,
    const struct wbt_desc *     wbd,
    const void *                kt_data,
    uint                        kt_len,
    uint                        lcp)
{
    struct wbt_node_hdr_omf *node;
    int                      j, cmp, node_num;
    uint                     cmplen;
    size_t                   pg;

    /* pull struct derefs out of the loop */
    uint  first_page = wbd->wbd_first_page;
    void *map_base = kbd->map_base;

    /* search from root */
    node_num = wbd->wbd_root;

    /* prefetch root node header */
    __builtin_prefetch(map_base + (first_page + wbd->wbd_root) * PAGE_SIZE);

    assert(0 <= node_num && node_num < wbd->wbd_n_pages);
    pg = first_page + node_num;
    node = map_base + pg * PAGE_SIZE;

    while (omf_wbn_magic(node) == WBT_INE_NODE_MAGIC) {
        struct wbt_ine_omf *ine;

        int first = 0;
        int last = omf_wbn_num_keys(node) - 1;

        const void *node_pfx;
        uint        node_pfx_len;

        const void *kdata;
        uint        klen;

        wbt_node_pfx(node, &node_pfx, &node_pfx_len);

        /* Check if key's prefix lies within this node's range.
         * If the prefix doesn't match, redirect to
         *  1. first's child if key's pfx is smaller than the node's
         *  2. last's child if key's pfx is larger than the node's
         */
        cmplen = min_t(uint, node_pfx_len, kt_len);
        cmp = keycmp(kt_data, cmplen, node_pfx, cmplen);
        if (cmp) {
            if (cmp > 0)
                first = last + 1; /* go right */

            goto navigate;
        }

        /* prefetch first node in binary search */
        __builtin_prefetch(wbt_ine(node, (first + last) / 2));

        /* binary search over key suffixes in node to find
         * the child edge to follow
         */
        while (first <= last) {
            j = (first + last) / 2;
            ine = wbt_ine(node, j);
            wbt_ine_key(node, ine, &kdata, &klen);

            cmp = keycmp(kt_data + cmplen, kt_len - cmplen, kdata, klen);
            if (cmp < 0)
                last = j - 1; /* kt_data < kdata */
            else if (cmp > 0)
                first = j + 1; /* kt_data > kdata */
            else {
                first = j; /* kt_data == kdata */
                break;
            }
        }

    navigate:
        /* follow edge indicated by 'first' */
        assert(first <= omf_wbn_num_keys(node));
        ine = wbt_ine(node, first);

        assert(omf_ine_left_child(ine) < node_num);
        node_num = omf_ine_left_child(ine);

        assert(0 <= node_num && node_num < wbd->wbd_n_pages);
        pg = first_page + node_num;
        node = map_base + pg * PAGE_SIZE;
        __builtin_prefetch(node);
    }

    return node_num;
}

/*
 * Actions after prefix compare:
 *
 * Definitions.
 * sfx_search:  Whether or not to perform a binary search over the key suffixes
 *              in the node.
 * position:    Where to position the iterator at the end of this call.
 * node_pfx_len: length of the node's lcp.
 * klen:        key length
 * cmp:         Whether key is less than (-1), greater than (+1) or equal (0)
 *              to the node prefix. Comparing the first n bytes, where n is
 *              min(klen, node_pfx_len).
 * start:       Beginning of the node.
 * first:       Wherever 'first' points after a suffix search.
 *
 * case 1: this is a cursor create (positioning prefix).
 *
 * case 1.1: klen < node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |    No      |  start   |
 *             | -1  |    No      |  EOF     |
 *             | +1  |    No      |  EOF     |
 *             +-----+------------+----------+
 *
 * case 1.2: klen >= node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |   Yes      |  first-1 |
 *             | -1  |    No      |  EOF     |
 *             | +1  |    No      |  EOF     |
 *             +-----+------------+----------+
 *
 * case 2: this is a cursor seek.
 *
 * case 2.1: klen < node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |    No      |  start   |
 *             | -1  |    No      |  start   |
 *             | +1  |    No      |  EOF     |
 *             +-----+------------+----------+
 *
 * case 2.2: klen >= node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |   Yes      |  first-1 |
 *             | -1  |    No      |  start   |
 *             | +1  |    No      |  EOF     |
 *             +-----+------------+----------+
 */
static bool
wbti_seek_fwd(struct wbti *self, struct kvs_ktuple *kt)
{
    struct wbt_node_hdr_omf *node;
    int                      j, cmp, node_num;
    int                      first, last, lfe_eof;
    size_t                   pg;
    const void *             kdata, *kt_data;
    uint                     klen, kt_len, cmplen;
    struct wbt_lfe_omf *     lfe;
    struct kvs_mblk_desc *   kbd = self->kbd;
    struct wbt_desc *        wbd = self->wbd;

    bool create = kt->kt_len < 0;
    bool sfx_search;

    const void *node_pfx;
    uint        node_pfx_len;

    if (self->node_idx == NODE_EOF)
        return false;

    kt_data = kt->kt_data;
    kt_len = abs(kt->kt_len);

    node_num = wbtr_seek_page(kbd, wbd, kt_data, kt_len, 0);
    wbti_get_page(self, node_num);

    assert(0 <= node_num && node_num < wbd->wbd_n_pages);
    pg = wbd->wbd_first_page + node_num;
    node = kbd->map_base + pg * PAGE_SIZE;

    /* at leaf */
    assert(omf_wbn_magic(node) == WBT_LFE_NODE_MAGIC);

    /* binary search over keys in node */
    first = 0;
    last = lfe_eof = omf_wbn_num_keys(node) - 1;

    wbt_node_pfx(node, &node_pfx, &node_pfx_len);

    cmplen = min_t(size_t, node_pfx_len, kt_len);
    cmp = keycmp(kt->kt_data, cmplen, node_pfx, cmplen);

    if (kt_len < node_pfx_len) {
        sfx_search = false;
        if (create)
            self->lfe_idx = cmp ? lfe_eof : first - 1;
        else
            self->lfe_idx = cmp > 0 ? lfe_eof : first - 1;
    } else {
        sfx_search = !cmp;
        self->lfe_idx = lfe_eof;
        if (!create && cmp < 0)
            self->lfe_idx = first - 1;

        kt_data += node_pfx_len;
        kt_len -= node_pfx_len;
    }

    if (!sfx_search)
        goto skip_search;

    /* prefetch first node in binary search */
    __builtin_prefetch(wbt_lfe(node, (first + last) / 2));

    while (first <= last) {
        j = (first + last) / 2;
        lfe = wbt_lfe(node, j);
        wbt_lfe_key(node, lfe, &kdata, &klen);

        cmp = keycmp(kt_data, kt_len, kdata, klen);
        if (cmp < 0) {
            last = j - 1;
        } else if (cmp > 0) {
            first = j + 1;
        } else {
            /* Found key */
            self->lfe_idx = j - 1;
            return true;
        }
    }

    /* We didn't find an exact match, follow edge indicated by 'first'.
     * If this is a cursor seek then position the cursor to the next key.
     */
    if (!create)
        self->lfe_idx = first - 1;

skip_search:

    if (!create)
        return true; /* cursor seek */

    /* It wasn't a seek, must be a cursor create.  Compare with
     * the prefix of the best match to determine if found.
     */
    lfe = wbt_lfe(node, first);
    wbt_lfe_key(node, lfe, &kdata, &klen);

    if (sfx_search) {
        cmp = keycmp_prefix(kt_data, kt_len, kdata, klen);
        if (!cmp)
            self->lfe_idx = first - 1; /* found pfx key */
    }

    return !cmp;
}

/*
 * Actions after prefix compare:
 *
 * This is very similar to forward seek, with a few changes:
 *    - Swap '-1' and '+1' in cmp
 *    - Replace 'first-1' with 'last+1'
 *    - 'start' is now the end of the node (start of a reverse iteration)
 *
 * Definitions.
 * sfx_search:  Whether or not to perform a binary search over the key suffixes
 *              in the node.
 * position:    Where to position the iterator at the end of this call.
 * node_pfx_len: length of the node's lcp.
 * klen:        key length
 * cmp:         Whether key is less than (-1), greater than (+1) or equal (0)
 *              to the node prefix. Comparing the first n bytes, where n is
 *              min(klen, node_pfx_len).
 * start:       Beginning of the node.
 * last:        Wherever 'last' points after a suffix search.
 *
 * case 1: this is a cursor create (positioning prefix).
 *
 * case 1.1: klen < node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |    No      |  start   |
 *             | -1  |    No      |  EOF     |
 *             | +1  |    No      |  EOF     |
 *             +-----+------------+----------+
 *
 * case 1.2: klen >= node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |   Yes      |  last+1  |
 *             | -1  |    No      |  EOF     |
 *             | +1  |    No      |  EOF     |
 *             +-----+------------+----------+
 *
 * case 2: this is a cursor seek.
 *
 * case 2.1: klen < node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |    No      |  start   |
 *             | -1  |    No      |  EOF     |
 *             | +1  |    No      |  start   |
 *             +-----+------------+----------+
 *
 * case 2.2: klen >= node_pfx_len
 *             +-----+------------+----------+
 *             | cmp | sfx_search | position |
 *             +-----+------------+----------+
 *             |  0  |   Yes      |  last+1  |
 *             | -1  |    No      |  EOF     |
 *             | +1  |    No      |  start   |
 *             +-----+------------+----------+
 *
 *
 * A special case during cursor create:
 *
 * Even for reverse cursor seeks, wbtr_seek_page() is used to arrive at a leaf
 * node. The way wbtree nodes are laid out (rightmost key tracks child, not the
 * leftmost) combined with the search key format (padded with 0xff) means that
 * it's possible that under certain situations this function will lead us to a
 * node that is one higher than the correct target node and we'll need to check
 * the previous node.
 *
 * Consider two leaf nodes lnode N and N+1:
 *
 *  lnode N          lnode N+1
 * -----+-----+    +-----+-----
 *  ... | ab9 |    | ad3 | ...
 * -----+-----+    +-----+-----
 *
 * Say we're creating a cursor over prefix 'ab'. Since the prefix is padded
 * with 0xff for the full length, wbtr_seek_page() will have positioned
 * node_num at lnode N+1. But there's no key with prefix 'ab' in this node. In
 * this case, compare prefix 'ab' with the last key of the previous node
 * (lnode N).
 */
static bool
wbti_seek_rev(struct wbti *self, struct kvs_ktuple *kt)
{
    struct wbt_node_hdr_omf *node;
    int                      cmp, node_num;
    int                      first, last, lfe_eof;
    size_t                   pg;
    const void *             kdata, *kt_data;
    uint                     klen, kt_len, cmplen;
    struct wbt_lfe_omf *     lfe;
    struct kvs_mblk_desc *   kbd = self->kbd;
    struct wbt_desc *        wbd = self->wbd;
    bool                     create = kt->kt_len < 0;
    bool                     sfx_search;
    const void *             node_pfx;
    uint                     node_pfx_len;

    int dbg_nrepeat HSE_MAYBE_UNUSED;

    if (self->node_idx == NODE_EOF)
        return false;

    /* Exploit the fact that kt->kt_data is padded with 0xff if this is a
     * cursor create.
     */
    kt_data = kt->kt_data;
    kt_len = abs(kt->kt_len);
    if (create)
        kt_len = HSE_KVS_KEY_LEN_MAX;

    node_num = wbtr_seek_page(kbd, wbd, kt_data, kt_len, 0);
    dbg_nrepeat = 0;

repeat:
    wbti_get_page(self, node_num);

    assert(0 <= node_num && node_num < wbd->wbd_n_pages);
    pg = wbd->wbd_first_page + node_num;
    node = kbd->map_base + pg * PAGE_SIZE;

    /* at leaf */
    assert(omf_wbn_magic(node) == WBT_LFE_NODE_MAGIC);

    /* binary search over keys in node */
    lfe_eof = first = 0;
    last = omf_wbn_num_keys(node) - 1;

    wbt_node_pfx(node, &node_pfx, &node_pfx_len);
    cmplen = min_t(size_t, node_pfx_len, abs(kt->kt_len));
    cmp = keycmp(kt->kt_data, cmplen, node_pfx, cmplen);

    if (abs(kt->kt_len) < node_pfx_len) {
        sfx_search = false;
        if (create)
            self->lfe_idx = cmp ? lfe_eof : last + 1;
        else
            self->lfe_idx = cmp < 0 ? lfe_eof : last + 1;
    } else {
        sfx_search = !cmp;
        self->lfe_idx = lfe_eof;

        if (create)
            self->lfe_idx = cmp ? lfe_eof : last + 1;
        else
            self->lfe_idx = cmp < 0 ? lfe_eof : last + 1;

        kt_data += node_pfx_len;
        kt_len -= node_pfx_len;
    }

    /* Check previous node if necessary. */
    if (HSE_UNLIKELY(create && cmp < 0 && node_num > 0)) {
        node_num--;
        dbg_nrepeat++;
        goto repeat;
    }

    if (!sfx_search)
        goto skip_search;

    /* prefetch first node in binary search */
    __builtin_prefetch(wbt_lfe(node, (first + last) / 2));

    while (first <= last) {
        int j = (first + last) / 2;

        lfe = wbt_lfe(node, j);
        wbt_lfe_key(node, lfe, &kdata, &klen);

        cmp = keycmp(kt_data, kt_len, kdata, klen);
        if (cmp < 0) {
            last = j - 1;
        } else if (cmp > 0) {
            first = j + 1;
        } else {
            /* Found key */
            self->lfe_idx = j + 1;
            return true;
        }
    }

    /* Check previous node if cursor prefix is smaller than the current
     * node.
     */
    if (HSE_UNLIKELY(create && !first && node_num > 0)) {
        node_num--;
        dbg_nrepeat++;
        goto repeat;
    }

skip_search:

    /* We didn't find an exact match, follow edge indicated by 'last'.
     * If this is a cursor seek then position the cursor to the next key.
     */
    if (!create) {
        /* Need to retreat: next iteration should find this. This
         * works even if lfe_idx is 0 before the decrement because
         * wbti_next() increments/decrements lfe_idx right off the bat.
         */
        if (sfx_search)
            self->lfe_idx = last + 1;

        return true; /* cursor seek */
    }

    /* It wasn't a seek, must be a cursor create.  Compare with
     * the prefix of the best match to determine if found.
     */

    lfe = wbt_lfe(node, last);
    wbt_lfe_key(node, lfe, &kdata, &klen);

    if (sfx_search) {
        kt_data = kt->kt_data + node_pfx_len;
        kt_len = abs(kt->kt_len) - node_pfx_len;

        cmp = keycmp_prefix(kt_data, kt_len, kdata, klen);
        if (!cmp)
            self->lfe_idx = last + 1; /* found pfx key */
    }

    return !cmp;
}

bool
wbti5_seek(struct wbti *self, struct kvs_ktuple *seek)
{
    if (HSE_UNLIKELY(!self->wbd->wbd_n_pages))
        return false;

    return self->reverse ? wbti_seek_rev(self, seek) : wbti_seek_fwd(self, seek);
}

static void
wbti_node_prev(struct wbti *self)
{
    if (self->node_idx > 0)
        wbti_get_page(self, self->node_idx - 1);
    else
        self->node_idx = NODE_EOF;

    self->lfe_idx = omf_wbn_num_keys(self->node) - 1;
}

static void
wbti_node_advance(struct wbti *self)
{
    u32 max_idx = self->wbd->wbd_leaf + self->wbd->wbd_leaf_cnt;

    if (self->node_idx + 1 < max_idx) {
        wbti_get_page(self, self->node_idx + 1);

        if (self->node_idx + 2 < max_idx)
            __builtin_prefetch(self->node + PAGE_SIZE);
    } else {
        self->node_idx = NODE_EOF;
    }
    self->lfe_idx = 0;
}

static bool
wbti_next_fwd(struct wbti *self, const void **kdata, uint *klen, const void **kmd)
{
    struct wbt_lfe_omf *lfe;
    size_t              off;

    u64 seq HSE_MAYBE_UNUSED;
    uint cnt HSE_MAYBE_UNUSED;

    if (self->node_idx == NODE_EOF)
        return false;

    /* Advance the iterator, stepping to the next node if necessary */
    self->lfe_idx++;
    if (self->lfe_idx == omf_wbn_num_keys(self->node)) {
        wbti_node_advance(self);
        if (self->node_idx == NODE_EOF)
            return false;
    }

    /* Reference the correct leaf node entry */
    assert(self->node != NULL);
    assert(self->lfe_idx < omf_wbn_num_keys(self->node));
    lfe = wbt_lfe(self->node, self->lfe_idx);

    /* Set outputs */
    wbt_lfe_key(self->node, lfe, kdata, klen);
    __builtin_prefetch(*kdata);
    off = wbt_lfe_kmd(self->node, lfe);
    assert(off < self->wbd->wbd_kmd_pgc * PAGE_SIZE);
    *kmd = self->kmd + off;

    return true;
}

static bool
wbti_next_rev(struct wbti *self, const void **kdata, uint *klen, const void **kmd)
{
    struct wbt_lfe_omf *lfe;
    size_t              off;

    u64 seq HSE_MAYBE_UNUSED;
    uint cnt HSE_MAYBE_UNUSED;

    if (self->node_idx == NODE_EOF)
        return false;

    /* Decrement entry idx, stepping to the previous node if necessary */
    self->lfe_idx--;
    if (self->lfe_idx == (uint)-1) {
        wbti_node_prev(self);
        if (self->node_idx == NODE_EOF)
            return false;
    }

    /* Reference the correct leaf node entry */
    assert(self->node != NULL);
    assert(self->lfe_idx < omf_wbn_num_keys(self->node));
    lfe = wbt_lfe(self->node, self->lfe_idx);

    /* Set outputs */
    wbt_lfe_key(self->node, lfe, kdata, klen);
    off = wbt_lfe_kmd(self->node, lfe);
    assert(off < self->wbd->wbd_kmd_pgc * PAGE_SIZE);
    *kmd = self->kmd + off;

    return true;
}

bool
wbti5_next(struct wbti *self, const void **kdata, uint *klen, const void **kmd)
{
    return self->reverse ? wbti_next_rev(self, kdata, klen, kmd)
                         : wbti_next_fwd(self, kdata, klen, kmd);
}

void
wbti5_reset(
    struct wbti *         self,
    struct kvs_mblk_desc *kbd,
    struct wbt_desc *     desc,
    struct kvs_ktuple *   seek,
    bool                  reverse,
    bool                  cache)
{
    /* self is not zeroed out so be sure to initialize all fields.
     */
    self->wbd = desc;
    self->kbd = kbd;
    self->node = NULL;
    self->kmd = kbd->map_base + PAGE_SIZE * (self->wbd->wbd_first_page + self->wbd->wbd_root + 1);

    self->node_idx = 0;
    self->lfe_idx = 0;
    self->reverse = reverse;

    if (seek) {
        if (!wbti5_seek(self, seek))
            self->node_idx = NODE_EOF;
    } else {
        wbti_get_page(self, reverse ? desc->wbd_leaf_cnt - 1 : 0);

        if (reverse) {
            self->lfe_idx = omf_wbn_num_keys(self->node);
            self->node_idx = desc->wbd_leaf + desc->wbd_leaf_cnt - 1;
        }
    }
}

merr_t
wbtr5_read_vref(
    const struct kvs_mblk_desc *kbd,
    const struct wbt_desc *     wbd,
    const struct kvs_ktuple *   kt,
    uint                        lcp,
    u64                         seq,
    enum key_lookup_res *       lookup_res,
    struct kvs_vtuple_ref *     vref)
{
    struct wbt_node_hdr_omf *node;
    int                      j, cmp, node_num;
    int                      first, last;
    size_t                   pg;
    const void *             kdata, *kt_data;
    uint                     klen, kt_len;
    struct wbt_lfe_omf *     lfe;

    const void *node_pfx;
    uint        node_pfx_len;

    kt_data = kt->kt_data;
    kt_len = kt->kt_len;

    assert(kt->kt_len > 0);

    if (HSE_UNLIKELY(!wbd->wbd_n_pages))
        goto done;

    node_num = wbtr_seek_page(kbd, wbd, kt_data, kt_len, 0);

    assert(0 <= node_num && node_num < wbd->wbd_n_pages);
    pg = wbd->wbd_first_page + node_num;
    node = kbd->map_base + pg * PAGE_SIZE;

    /* at leaf */
    assert(omf_wbn_magic(node) == WBT_LFE_NODE_MAGIC);

    /* binary search over keys in node */
    first = 0;
    last = omf_wbn_num_keys(node) - 1;

    wbt_node_pfx(node, &node_pfx, &node_pfx_len);

    if (kt_len < node_pfx_len)
        goto done;

    cmp = keycmp(kt->kt_data, node_pfx_len, node_pfx, node_pfx_len);
    if (cmp)
        goto done; /* prefix didn't match; key not found */

    /* prefetch first node in binary search */
    __builtin_prefetch(wbt_lfe(node, (first + last) / 2));

    kt_data += node_pfx_len;
    kt_len -= node_pfx_len;

    while (first <= last) {
        j = (first + last) / 2;
        lfe = wbt_lfe(node, j);
        wbt_lfe_key(node, lfe, &kdata, &klen); /* sfx */

        cmp = keycmp(kt_data, kt_len, kdata, klen);
        if (cmp < 0)
            last = j - 1;
        else if (cmp > 0)
            first = j + 1;
        else {
            /* Found key */
            void * kmd;
            size_t off;
            u64    vseq;
            uint   nvals;

            kmd = kbd->map_base + PAGE_SIZE * (wbd->wbd_first_page + wbd->wbd_root + 1);

            off = wbt_lfe_kmd(node, lfe);
            assert(off < wbd->wbd_kmd_pgc * PAGE_SIZE);
            nvals = kmd_count(kmd, &off);
            assert(nvals > 0);
            while (nvals--) {
                wbt_read_kmd_vref(kmd, &off, &vseq, vref);
                assert(off <= wbd->wbd_kmd_pgc * PAGE_SIZE);
                if (seq >= vseq) {
                    vref->vr_seq = vseq;
                    if (vref->vr_type == vtype_tomb)
                        *lookup_res = FOUND_TMB;
                    else if (vref->vr_type == vtype_ptomb)
                        *lookup_res = FOUND_PTMB;
                    else
                        *lookup_res = FOUND_VAL;

                    return 0;
                }
            }
            break;
        }
    }
done:
    /* Not finding the key is *not* an error. */
    *lookup_res = NOT_FOUND;
    return 0;
}
