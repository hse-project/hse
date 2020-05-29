/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_VBLOCK_BUILDER_H
#define HSE_KVS_CN_VBLOCK_BUILDER_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

#include <hse_util/perfc.h>

struct cn;
struct vblock_builder;
struct blk_list;
struct kvs_rparams;
struct cn_merge_stats;

enum mp_media_classp;

/* MTF_MOCK_DECL(vblock_builder) */

/**
 * vbb_create() - Create a vblock builder
 * @bld_out: builder handle (output)
 * @cn: cn in which vblocks will be created
 * @pc: perf counters
 * @flags: kvset builder flags
 */
/* MTF_MOCK */
merr_t
vbb_create(
    struct vblock_builder **bld_out,
    struct cn *             cn,
    struct perfc_set *      pc,
    u64                     vgroup,
    uint                    flags);

/**
 * vbb_destroy() - Destroy a vblock builder
 * @bld:  bld handle
 *
 * Deletes all uncommitted vblocks.
 */
/* MTF_MOCK */
void
vbb_destroy(struct vblock_builder *bld);

/**
 * vbb_add_entry() - Store a value in a vblock.
 * @bld:  builder handle
 * @vdata, @vlen: value to add to vblock
 & @vbidout: The id of vblock that holds value
 * @vbidxout: index of the vblock that holds the added value
 * @vboffout: offset of value into vblock
 */
/* MTF_MOCK */
merr_t
vbb_add_entry(
    struct vblock_builder *bld,
    const void *           vdata,
    uint                   vlen,
    u64 *                  vbidout,
    uint *                 vbidxout,
    uint *                 vboffout);

/* MTF_MOCK */
merr_t
vbb_finish(struct vblock_builder *bld, struct blk_list *vblks);

/* MTF_MOCK */
size_t
vbb_estimate_alen(struct cn *cn, size_t wlen, enum mp_media_classp mclass);

/**
 * vbb_flush_entry() - Writes vblock contents into media
 * @bld:  builder handle
 */
merr_t
vbb_flush_entry(struct vblock_builder *bld);

bool
vbb_verify_entry(struct vblock_builder *bld, u32 vbidx, u64 blkid, u64 blkoff, u32 vlen);

void
vbb_get_vblocks(struct vblock_builder *bld, struct blk_list *vblks);

merr_t
vbb_add_entry_ext(
    struct vblock_builder *bld,
    const void *           vdata,
    uint                   vlen,
    bool                   wait,
    u8                     index,
    u64 *                  vbidout,
    uint *                 vbidxout,
    uint *                 vboffout);

merr_t
vbb_finish_entry(struct vblock_builder *bld, u8 index);

void
vbb_remove_unused_vblocks(struct vblock_builder *bld);

u32
vbb_get_blk_count(struct vblock_builder *bld);

u32
vbb_get_blk_count_committed(struct vblock_builder *bld);

u32
vbb_vblock_hdr_len(void);

merr_t
vbb_blk_list_merge(struct vblock_builder *dst, struct vblock_builder *src, struct blk_list *vblks);

void
vbb_set_mclass(struct vblock_builder *bld, enum mp_media_classp mclass);

enum mp_media_classp
vbb_get_mclass(struct vblock_builder *bld);

void
vbb_set_merge_stats(struct vblock_builder *bld, struct cn_merge_stats *stats);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "vblock_builder_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
