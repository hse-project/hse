/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/mman.h>

#include <hse/hse_limits.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/omf_kmd.h>

#include "omf.h"
#include "kvs_mblk_desc.h"
#include "kblock_reader.h"

#include "wbt_internal.h"
#include "wbt_reader.h"

#include "wbt_reader_v4.h"

static void
wbti_get_page(struct wbti *self, u32 node_idx)
{
    size_t mblock_offset;

    assert(node_idx != self->node_idx || self->node == NULL);

    mblock_offset = PAGE_SIZE * (node_idx + self->wbd->wbd_first_page);
    self->node = (struct wbt4_node_hdr_omf *)(self->kbd->map_base + mblock_offset);

    assert(omf_wbn4_magic(self->node) == WBT_LFE_NODE_MAGIC);

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
    struct wbt4_node_hdr_omf *node;
    int                       j, cmp, node_num;
    size_t                    pg;

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

    assert(kt_len >= lcp);

    kt_data += lcp;
    kt_len -= lcp;

    while (omf_wbn4_magic(node) == WBT_INE_NODE_MAGIC) {
        struct wbt_ine_omf *ine;

        int         first = 0;
        int         last = omf_wbn4_num_keys(node) - 1;
        const void *kdata;
        uint        klen;

        /* prefetch first node in binary search */
        __builtin_prefetch(wbt4_ine(node, (first + last) / 2));

        /* binary search over keys in node to find
         * the child edge to follow
         */
        while (first <= last) {
            j = (first + last) / 2;
            ine = wbt4_ine(node, j);
            wbt4_ine_key(node, ine, &kdata, &klen);
            assert(klen >= lcp);

            cmp = keycmp(kt_data, kt_len, kdata + lcp, klen - lcp);
            if (cmp < 0)
                last = j - 1; /* kt_data < kdata */
            else if (cmp > 0)
                first = j + 1; /* kt_data > kdata */
            else {
                first = j; /* kt_data == kdata */
                break;
            }
        }

        /* follow edge indicated by 'first' */
        assert(first <= omf_wbn4_num_keys(node));
        ine = wbt4_ine(node, first);

        assert(omf_ine_left_child(ine) < node_num);
        node_num = omf_ine_left_child(ine);

        assert(0 <= node_num && node_num < wbd->wbd_n_pages);
        pg = first_page + node_num;
        node = map_base + pg * PAGE_SIZE;
        __builtin_prefetch(node);
    }

    return node_num;
}

static bool
wbti_seek_fwd(struct wbti *self, struct kvs_ktuple *kt)
{
    struct wbt4_node_hdr_omf *node;
    int                       j, cmp, node_num;
    int                       first, last;
    size_t                    pg;
    const void *              kdata, *kt_data;
    uint                      klen, kt_len;
    struct wbt_lfe_omf *      lfe;
    struct kvs_mblk_desc *    kbd = self->kbd;
    struct wbt_desc *         wbd = self->wbd;

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
    assert(omf_wbn4_magic(node) == WBT_LFE_NODE_MAGIC);

    /* binary search over keys in node */
    first = 0;
    last = omf_wbn4_num_keys(node) - 1;

    /* prefetch first node in binary search */
    __builtin_prefetch(wbt4_lfe(node, (first + last) / 2));

    while (first <= last) {
        j = (first + last) / 2;
        lfe = wbt4_lfe(node, j);
        wbt4_lfe_key(node, lfe, &kdata, &klen);

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
    if (kt->kt_len >= 0) {
        self->lfe_idx = first - 1;
        return true; /* cursor seek */
    }

    /* It wasn't a seek, must be a cursor create.  Compare with
     * the prefix of the best match to determine if found.
     */
    lfe = wbt4_lfe(node, first);
    wbt4_lfe_key(node, lfe, &kdata, &klen);

    cmp = keycmp_prefix(kt_data, kt_len, kdata, klen);
    if (!cmp)
        self->lfe_idx = first - 1; /* found pfx key */

    return !cmp;
}

static bool
wbti_seek_rev(struct wbti *self, struct kvs_ktuple *kt)
{
    struct wbt4_node_hdr_omf *node;
    int                       cmp, node_num;
    int                       first, last;
    size_t                    pg;
    const void *              kdata, *kt_data;
    uint                      klen, kt_len;
    struct wbt_lfe_omf *      lfe;
    struct kvs_mblk_desc *    kbd = self->kbd;
    struct wbt_desc *         wbd = self->wbd;

    if (self->node_idx == NODE_EOF)
        return false;

    /* Exploit the fact that kt->kt_data is padded with 0xff if this is a
     * cursor create.
     */
    kt_data = kt->kt_data;
    kt_len = abs(kt->kt_len);
    if (kt->kt_len < 0)
        kt_len = HSE_KVS_KLEN_MAX;

    node_num = wbtr_seek_page(kbd, wbd, kt_data, kt_len, 0);
    wbti_get_page(self, node_num);

    assert(0 <= node_num && node_num < wbd->wbd_n_pages);
    pg = wbd->wbd_first_page + node_num;
    node = kbd->map_base + pg * PAGE_SIZE;

    /* at leaf */
    assert(omf_wbn4_magic(node) == WBT_LFE_NODE_MAGIC);

    /* binary search over keys in node */
    first = 0;
    last = omf_wbn4_num_keys(node) - 1;

    /* prefetch first node in binary search */
    __builtin_prefetch(wbt4_lfe(node, (first + last) / 2));

    while (first <= last) {
        int j = (first + last) / 2;

        lfe = wbt4_lfe(node, j);
        wbt4_lfe_key(node, lfe, &kdata, &klen);

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

    /* We didn't find an exact match, follow edge indicated by 'last'.
     * If this is a cursor seek then position the cursor to the next key.
     */
    if (kt->kt_len > 0) {
        /* Need to retreat: next iteration should find this. This
         * works even if lfe_idx is 0 before the decrement because
         * wbti_next() increments/decrements lfe_idx right off the bat.
         */
        self->lfe_idx = last + 1;
        return true; /* cursor seek */
    }

    /* It wasn't a seek, must be a cursor create.  Compare with
     * the prefix of the best match to determine if found.
     */
    if (unlikely(last < 0)) {
        /*
         * Consider two leaf nodes lnode N and N+1:
         *
         *  lnode N          lnode N+1
         * -----+-----+    +-----+-----
         *  ... | ab9 |    | ad3 | ...
         * -----+-----+    +-----+-----
         *
         * Say this is a cursor over prefix ab. Then the above code
         * searches through lnode N+1, and will end with last=-1.
         * In this case, compare prefix 'ab' with the last key of the
         * previous node (lnode N).
         */

        assert(node_num > 0);

        wbti_get_page(self, node_num - 1);
        assert(0 <= node_num && node_num < wbd->wbd_n_pages);
        pg = wbd->wbd_first_page + node_num;
        node = kbd->map_base + pg * PAGE_SIZE;
        last = omf_wbn4_num_keys(node) - 1;
    }

    lfe = wbt4_lfe(node, last);
    wbt4_lfe_key(node, lfe, &kdata, &klen);

    cmp = keycmp_prefix(kt_data, abs(kt->kt_len), kdata, klen);
    if (!cmp)
        self->lfe_idx = last + 1; /* found pfx key */

    return !cmp;
}

bool
wbti4_seek(struct wbti *self, struct kvs_ktuple *seek)
{
    return self->reverse ? wbti_seek_rev(self, seek) : wbti_seek_fwd(self, seek);
}

static void
wbti_node_prev(struct wbti *self)
{
    if (self->node_idx > 0)
        wbti_get_page(self, self->node_idx - 1);
    else
        self->node_idx = NODE_EOF;

    self->lfe_idx = omf_wbn4_num_keys(self->node) - 1;
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

    u64 seq __maybe_unused;
    uint cnt __maybe_unused;

    if (self->node_idx == NODE_EOF)
        return false;

    /* Advance the iterator, stepping to the next node if necessary */
    self->lfe_idx++;
    if (self->lfe_idx == omf_wbn4_num_keys(self->node)) {
        wbti_node_advance(self);
        if (self->node_idx == NODE_EOF)
            return false;
    }

    /* Reference the correct leaf node entry */
    assert(self->node != NULL);
    assert(self->lfe_idx < omf_wbn4_num_keys(self->node));
    lfe = wbt4_lfe(self->node, self->lfe_idx);

    /* Set outputs */
    wbt4_lfe_key(self->node, lfe, kdata, klen);
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

    u64 seq __maybe_unused;
    uint cnt __maybe_unused;

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
    assert(self->lfe_idx < omf_wbn4_num_keys(self->node));
    lfe = wbt4_lfe(self->node, self->lfe_idx);

    /* Set outputs */
    wbt4_lfe_key(self->node, lfe, kdata, klen);
    off = wbt_lfe_kmd(self->node, lfe);
    assert(off < self->wbd->wbd_kmd_pgc * PAGE_SIZE);
    *kmd = self->kmd + off;

    return true;
}

bool
wbti4_next(struct wbti *self, const void **kdata, uint *klen, const void **kmd)
{
    return self->reverse ? wbti_next_rev(self, kdata, klen, kmd)
                         : wbti_next_fwd(self, kdata, klen, kmd);
}

void
wbti4_reset(
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

    if (cache)
        kbr_madvise_wbt_leaf_nodes(kbd, desc, MADV_NORMAL);

    if (seek) {
        if (!wbti4_seek(self, seek))
            self->node_idx = NODE_EOF;
    } else {
        wbti_get_page(self, reverse ? desc->wbd_leaf_cnt - 1 : 0);

        if (reverse) {
            self->lfe_idx = omf_wbn4_num_keys(self->node);
            self->node_idx = desc->wbd_leaf + desc->wbd_leaf_cnt - 1;
        }
    }
}

merr_t
wbtr4_read_vref(
    const struct kvs_mblk_desc *kbd,
    const struct wbt_desc *     wbd,
    const struct kvs_ktuple *   kt,
    uint                        lcp,
    u64                         seq,
    enum key_lookup_res *       lookup_res,
    struct kvs_vtuple_ref *     vref)
{
    struct wbt4_node_hdr_omf *node;
    int                       j, cmp, node_num;
    int                       first, last;
    size_t                    pg;
    const void *              kdata, *kt_data;
    uint                      klen, kt_len;
    struct wbt_lfe_omf *      lfe;

    kt_data = kt->kt_data;
    kt_len = kt->kt_len;

    assert(kt->kt_len > 0);

    node_num = wbtr_seek_page(kbd, wbd, kt_data, kt_len, lcp);

    assert(0 <= node_num && node_num < wbd->wbd_n_pages);
    pg = wbd->wbd_first_page + node_num;
    node = kbd->map_base + pg * PAGE_SIZE;

    /* at leaf */
    assert(omf_wbn4_magic(node) == WBT_LFE_NODE_MAGIC);

    /* binary search over keys in node */
    first = 0;
    last = omf_wbn4_num_keys(node) - 1;

    assert(kt_len >= lcp);

    /* The caller ensures that if (lcp > 0) then every key
     * in this kblock shares a common prefix with the target
     * key that is at least lcp bytes long.
     */
    kt_data += lcp;
    kt_len -= lcp;

    while (first <= last) {
        j = (first + last) / 2;
        lfe = wbt4_lfe(node, j);
        wbt4_lfe_key(node, lfe, &kdata, &klen);

        assert(klen >= lcp);

        cmp = keycmp(kt_data, kt_len, kdata + lcp, klen - lcp);
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

    /* Not finding the key is *not* an error. */
    *lookup_res = NOT_FOUND;
    return 0;
}
