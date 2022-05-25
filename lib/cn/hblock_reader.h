/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CN_HBLOCK_READER_H
#define CN_HBLOCK_READER_H

/* MTF_MOCK_DECL(hblock_reader) */

#include <stdint.h>

#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

struct kvs_mblk_desc;
struct mblock_props;
struct mpool;
struct mpool_mcache_map;
struct wbt_desc;

struct hblk_metrics {
    size_t hm_size;
    uint32_t hm_nptombs;
};

/**
 * Advise about caching of wbtree internal modes
 *
 * @param hblk_desc hblock descriptor
 * @param wbt_desc WBTree descriptor
 * @param advice advice flag
 */
void
hbr_madvise_wbt_int_nodes(
    struct kvs_mblk_desc *hblk_desc,
    struct wbt_desc *wbt_desc, int advice) HSE_NONNULL(1, 2);

/**
 * Advise about caching of wbtree leaf nodes
 *
 * @param hblk_desc hblock descriptor
 * @param wbt_desc WBTree descriptor
 * @param advice advice flag
 */
void
hbr_madvise_wbt_leaf_nodes(
    struct kvs_mblk_desc *hblk_desc,
    struct wbt_desc *wbt_desc,
    int advice) HSE_NONNULL(1, 2);

/**
 * Advise about caching of key meta-data region
 *
 * @param hblk_desc hblock descriptor
 * @param wbt_desc WBTree descriptor
 * @param advice advice flag
 */
void
hbr_madvise_kmd(
    struct kvs_mblk_desc *hblk_desc,
    struct wbt_desc *wbt_desc,
    int advice) HSE_NONNULL(1, 2);

/**
 * Get the mblock descriptor for the given mblock.
 *
 * @param mpool mpool containing the mblock
 * @param map mcache
 * @param props properties of the mblock
 * @param blkid mblock id referencing the mblock
 * @param[in,out] mblk_desc mblock descriptor
 */
merr_t
hbr_read_desc(
    struct mpool *mpool,
    struct mpool_mcache_map *map,
    struct mblock_props *props,
    uint64_t blkid,
    struct kvs_mblk_desc *mblk_desc) HSE_NONNULL(1, 2, 3, 5);

/**
 * Read various metrics about an hblock.
 *
 * @param hblk_desc hblock descriptor
 * @param[in,out] metrics hblock metrics
 */
merr_t
hbr_read_metrics(struct kvs_mblk_desc *hblk_desc, struct hblk_metrics *metrics) HSE_NONNULL(1, 2);

/**
 * Read the prefix tombstone tree region descriptor for the given hblock.
 *
 * @param mblk_desc mblock descriptor
 * @param[in,out] wbt_desc WBT descriptor
 */
merr_t
hbr_read_ptree_region_desc(
    struct kvs_mblk_desc *mblk_desc,
    struct wbt_desc *wbt_desc) HSE_NONNULL(1, 2);

/**
 * Read the seqno range from the header.
 *
 * @param mblk_desc mblock descriptor
 * @param[out] seqno_min Minimum sequence number
 * @param[out] seqno_max Maximum sequence number
 */
merr_t
hbr_read_seqno_range(
    struct kvs_mblk_desc *mblk_desc,
    uint64_t *seqno_min,
    uint64_t *seqno_max) HSE_NONNULL(1, 2, 3);

#if HSE_MOCKING
#include "hblock_reader_ut.h"
#endif /* HSE_MOCKING */

#endif /* CN_HBLOCK_READER_H */
