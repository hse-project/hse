/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_BUILDER_INT_H
#define HSE_KVS_CN_KVSET_BUILDER_INT_H

#include <hse/limits.h>

#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_util/perfc.h>

#include "cn_metrics.h"
#include "hblock_builder.h"
#include "kblock_builder.h"

struct cn;


/* A staging buffer for holding a single key's metadata.
 */
struct kmd_info {
    uint8_t *kmd;     // allocated buffer
    uint kmd_size;    // size of allocated buffer
    size_t kmd_used;  // length of valid data in buffer
};

/* kvset builder object
 *
 * A kvset builder creates hblocks, kblocks and vblocks that make up a kvset.
 * The primary outputs of a build operation are the mblock IDs for the header
 * mblock (hblock), one or more key mblocks (kblocks), and zero or more value
 * blocks (vblocks).
 */
struct kvset_builder {
    struct cn *cn;               // pointer to cn struct

    struct hblock_builder *hbb;  // hblock builder
    uint64_t hblk_id;            // hblock id

    struct kblock_builder *kbb;  // kblock builder
    struct blk_list kblk_list;   // list of kblock ids

    struct vblock_builder *vbb;  // vblock builder
    struct blk_list vblk_list;   // list of vblock ids

    struct vgmap *vgmap;

    uint64_t seqno_max; // max seqno present in new kvset
    uint64_t seqno_min; // min seqno present in new kvset
    uint64_t vused;     // sum of len of all values in new kvset
    uint64_t vtotal;    // sum of written lengths of all vblocks (excluding vblock footer)

    uint64_t seqno_prev;       // for sanity checks while building kvsets
    uint64_t seqno_prev_ptomb; // for sanity checks while building kvsets

    struct kmd_info kblk_kmd;  // staging buffer for kblk key metadata
    struct kmd_info hblk_kmd;  // staging buffer for hblk key metadata

    struct key_stats key_stats;    // stats about current key and its values
    struct cn_merge_stats mstats;  // stats about the builder's merge operation

    // for capped KVS only
    uint8_t  last_ptomb[HSE_KVS_PFX_LEN_MAX]; // copy of largest ptomb seen (for capped KVS)
    uint32_t last_ptlen;                      // length of last_ptomb
    uint64_t last_ptseq;                      // seqno of last_ptomb
};

#endif
