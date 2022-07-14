/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_WBT_READER_H
#define HSE_KVS_CN_WBT_READER_H

#include <hse_util/inttypes.h>
#include <hse_util/key_util.h>

#include <hse_ikvdb/tuple.h>

struct kvs_mblk_desc;
struct mpool;
struct wbt_hdr_omf;
struct kvset_vgroup_map;

/* MTF_MOCK_DECL(wbt_reader) */

#define NODE_EOF ((u32)-1)

/**
 * struct wbt_desc - a descriptor for accessing a KBLOCK's WBT
 * @wbd_first_page: offset, in pages, from start of MBLOCK to WBT data region
 * @wbd_n_pages: size of data region in pages
 * @wbd_root: root node's page number (@wbd_root < @wbd_n_pages)
 * @wbd_leaf: first leaf node (@wbd_leaf < @wbd_n_pages)
 * @wbd_leaf_cnt: number of leaf nodes
 * @wbd_kmd_pgc: size of key-metadata region in pages
 *
 * When a KBLOCK is opened for reading, the @wbt_hdr_omf struct is read from
 * media and the relevant information is stored in a @wbt_desc struct.
 *
 * Notes:
 *  - @wbt_first_page and @wbt_n_pages are in units of 4K pages.
 *    So, if @wbt_first_page=2 and @wbt_n_pages=3, then the WBT
 *    data region occupies pages 2,3 and 4 -- which maps
 *    to bytes 2*4096 to 5*4096-1 (end of page 4).
 */
struct wbt_desc {
    uint32_t wbd_first_page;
    uint32_t wbd_n_pages;
    uint16_t wbd_root;
    uint16_t wbd_leaf;
    uint16_t wbd_leaf_cnt;
    uint16_t wbd_kmd_pgc;
    uint16_t wbd_version;
};

struct wbti {
    struct wbt_desc *wbd; /* MUST BE FIRST */
    const void *base;
    const struct wbt_node_hdr_omf *node;
    const void *kmd;
    uint32_t node_idx;
    uint32_t lfe_idx;

    bool reverse;
};

/**
 * wbtr_read_vref() - Read the metadata data for the value associated with key
 * @base: base address of the block
 * @wbd: wbtree descriptor
 * @kt: key to search for
 * @lcp: longest common prefix common to %kt and all keys in the kblock
 * @lookup_res: (output) one of NOT_FOUND, FOUND_VAL,
 *              or FOUND_TMB (tombstone)
 * @vref: (output) value metadata if found
 */
/* MTF_MOCK */
merr_t
wbtr_read_vref(
    const void *base,
    const struct wbt_desc *wbd,
    const struct kvs_ktuple *kt,
    uint lcp,
    u64 seq,
    enum key_lookup_res *lookup_res,
    struct kvset_vgroup_map *vgmap,
    struct kvs_vtuple_ref *vref);

merr_t
wbti_alloc(struct wbti **wbti_out);

/**
 * wbti_reset() - Reset the fields of a wbtree iterator.
 * @wbti: wbt iterator
 * @base: base address of the block
 * @wbd:  wbtree descriptor
 * @seek: if set, first key in iterator
 * @reverse: whether to iterate backwards
 * @cache: whether to cache wbt node values
 */
void
wbti_reset(
    struct wbti *self,
    const void *base,
    struct wbt_desc *desc,
    struct kvs_ktuple *seek,
    bool reverse,
    bool cache);

/**
 * wbti_create() - Create a wbtree iterator
 * @wbti: (output) newly constructed iterator
 * @base: base address of the block
 * @wbd:  wbtree descriptor
 * @seek: if set, first key in iterator
 * @reverse: whether to iterate backwards
 * @cache: whether to cache wbt node values
 */
/* MTF_MOCK */
merr_t
wbti_create(
    struct wbti **wbti,
    const void *base,
    struct wbt_desc *wbd,
    struct kvs_ktuple *seek,
    bool reverse,
    bool cache);

/**
 * wbti_destroy() - Destroy a wbtree iterator. Does not
 *       destroy or otherwise modify any other objects.
 * @wbti: iterator to destroy
 */
/* MTF_MOCK */
void
wbti_destroy(struct wbti *wbti);

/**
 * wbti_prefix() - Get the current wbt node's longest common prefix
 * @self:   wbt iterator handle
 * @pfx:    (out) longest common prefix
 * @pfx_len: (out) length of @pfx
 */
/* MTF_MOCK */
void
wbti_prefix(struct wbti *self, const void **pfx, uint *pfx_len);

/**
 * wbti_next() - Retrieve the next entry in the WBT
 * @wbti:  iterator
 * @kdata: (output) key data
 * @klen:  (output) length of key
 * @kmd:   (output) key metadata
 *
 * Returns: false if EOF (outputs not valid), true otherwise (outputs valid).
 */
/* MTF_MOCK */
bool
wbti_next(struct wbti *wbti, const void **kdata, uint *klen, const void **kmd);

/* MTF_MOCK */
void
wbt_read_kmd_vref(
    const void *kmd,
    struct kvset_vgroup_map *vgmap,
    size_t *off,
    u64 *seq,
    struct kvs_vtuple_ref *vref);

merr_t
wbti_init(void);
void
wbti_fini(void);

/* MTF_MOCK */
merr_t
wbtr_read_desc(const struct wbt_hdr_omf *wbt_hdr, struct wbt_desc *desc);

#if HSE_MOCKING
#include "wbt_reader_ut.h"
#endif /* HSE_MOCKING */

#endif
