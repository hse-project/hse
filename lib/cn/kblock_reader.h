/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KBLOCK_READER_H
#define HSE_KVS_CN_KBLOCK_READER_H

#include <stdint.h>

#include <hse/ikvdb/tuple.h>

struct cn;
struct bloom_desc;
struct wbt_desc;
struct kvs_mblk_desc;

struct kblk_metrics {
    uint32_t num_keys;
    uint32_t num_tombstones;
    uint64_t tot_key_bytes;
    uint64_t tot_val_bytes;
    uint64_t tot_kvlen;
    uint64_t tot_vused_bytes;
    uint32_t tot_wbt_pages;
    uint32_t tot_blm_pages;
};

struct kblock_desc {
    struct cn *cn;
    struct kvs_mblk_desc *kd_mbd;
    struct wbt_desc *kd_wbd;
};

/**
 * kbr_read_wbt_region_desc() - Read the WBT region descriptor for
 *                          the given KBLOCK ID.
 * @kblock_desc:    KVBLOCK_DESC for KBLOCK to read
 * @wbt_rgn_desc:   (output) WBT descriptor
 */
merr_t
kbr_read_wbt_region_desc(struct kvs_mblk_desc *kblock_desc, struct wbt_desc *wbt_rgn_desc);

/**
 * kbr_read_blm_region_desc() - Read the Bloom filter region
 *                          descriptor for the given KBLOCK ID.
 * @kblock_desc:    KVBLOCK_DESC for KBLOCK to read
 * @blm_rgn_desc:   (output) bloom region descriptor
 * @kblock_id:      KBLOCK ID for KBLOCK to read
 */
merr_t
kbr_read_blm_region_desc(struct kvs_mblk_desc *kblock_desc, struct bloom_desc *blm_desc);

/**
 * kbr_read_metrics() - Read kblock header to obtain metrics.
 *
 * @kblock_desc:    KVBLOCK_DESC for KBLOCK to read
 * @metrics:        (output) metrics saved here
 */
merr_t
kbr_read_metrics(struct kvs_mblk_desc *kblock_desc, struct kblk_metrics *metrics);

/**
 * kbr_madvise_wbt_leaf_nodes() - advise about caching of wbtree leaf nodes
 */
void
kbr_madvise_wbt_leaf_nodes(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc, int advice);

/**
 * kbr_madvise_wbt_int_nodes() - advise about caching of wbtree internal modes
 */
void
kbr_madvise_wbt_int_nodes(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc, int advice);

/**
 * kbr_madvise_kmd() - advise about caching of key meta-data region
 */
void
kbr_madvise_kmd(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc, int advice);

/**
 * kbr_madvise_bloom() - advise about caching of bloom filter
 */
void
kbr_madvise_bloom(struct kvs_mblk_desc *kblkdesc, struct bloom_desc *desc, int advice);

#endif
