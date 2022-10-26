/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CN_HBLOCK_READER_H
#define CN_HBLOCK_READER_H

/* MTF_MOCK_DECL(hblock_reader) */

#include <stdint.h>

#include <hse/util/compiler.h>
#include <hse/error/merr.h>

struct kvs_mblk_desc;
struct wbt_desc;
struct vgmap;

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

/**
 * Return the vgroup count from the header.
 *
 * @param hbd hblock descriptor
 * @param[out] nvgroups number of vgroups
 */
merr_t
hbr_read_vgroup_cnt(const struct kvs_mblk_desc *hbd, uint32_t *nvgroups);

/**
 * Return the vgroup map from the header.
 *
 * @param hbd hblock descriptor
 * @param[out] vgmap vgroup map
 * @param[out] use_vgmap set if vgmap contains non-zero index adjust for any of the vgroups
 */
merr_t
hbr_read_vgroup_map(const struct kvs_mblk_desc *hbd, struct vgmap *vgmap, bool *use_vgmap);

/**
 * Return the ptree region from the hblock.
 *
 * @param hbd hblock descriptor
 * @param ptd ptree descriptor
 * @param[out] ptree start of ptree region
 * @param[out] ptree_pgc number of ptree pages
 */
void
hbr_read_ptree(
    const struct kvs_mblk_desc *hbd,
    const struct wbt_desc      *ptd,
    uint8_t                   **ptree,
    uint32_t                   *ptree_pgc);

#if HSE_MOCKING
#include "hblock_reader_ut.h"
#endif /* HSE_MOCKING */

#endif /* CN_HBLOCK_READER_H */
