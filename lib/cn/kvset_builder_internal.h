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

struct kmd_info {
    uint8_t *kmd;
    uint kmd_size;
    size_t kmd_used;
};

/**
 * struct kvset_builder - context for holding the results of a merge operation
 * @cn:              pointer to cn struct
 * @hbb:             hblock builder (creates a single hblock)
 * @hblk:            singular hblock
 * @kbb:             kblock builder (creates multiple kblocks)
 * @kblk_list:       list of kblock ids allocated by @kbb
 * @vbb:             vblock builder (creates multiple vblocks)
 * @vblk_list:       list of vblock ids allocated by @vbb
 * @seqno_max:       max seqno present in output kvset
 * @seqno_min:       min seqno present in output kvset
 * @vused:           sum of vlen of all selected values
 * @kblk_kmd:        kmd info about the main wbtree
 * @hblk_kmd:        kmd info about the ptomb wbtree
 * @key_stats:       stats regarding the current key being added
 * @last_ptomb:      last (largest) ptomb seen while building kvset. Tracked
 *                   only if cn is a capped.
 * @last_ptlen:      length of @last_ptomb
 * @vblk_baseidx:    base index used for coalescing multiple vblock builders
 *
 * This struct contains the output kvset when merging multiple input kvsets
 * into one output kvset.  It is used for ingest, compaction and spill.  When
 * used for spill, there is one of these structs for each child (i.e., one for
 * each output kvset).
 */
struct kvset_builder {
    struct cn *cn;

    struct hblock_builder *hbb;
    struct kvs_block hblk;

    struct kblock_builder *kbb;
    struct blk_list kblk_list;

    struct vblock_builder *vbb;
    struct blk_list vblk_list;

    uint64_t seqno_max;
    uint64_t seqno_min;

    /* vused feeds into tree compaction logic.
     * Modify with care.
     */
    uint64_t vused;

    /* state related to current key and its values */
    struct kmd_info kblk_kmd;
    struct kmd_info hblk_kmd;


    struct key_stats key_stats;
    struct cn_merge_stats mstats;

    unsigned int vgroups;
    uint8_t  last_ptomb[HSE_KVS_PFX_LEN_MAX];
    uint32_t last_ptlen;
    uint64_t last_ptseq;
};
#endif
