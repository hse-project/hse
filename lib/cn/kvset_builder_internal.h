/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_BUILDER_INT_H
#define HSE_KVS_CN_KVSET_BUILDER_INT_H

#include <hse_util/perfc.h>
#include <hse_ikvdb/mclass_policy.h>

#include "cn_metrics.h"

struct cn;

struct kmd_info {
    u8 *   kmd;
    uint   kmd_size;
    size_t kmd_used;
};

/**
 * struct kvset_builder - context for holding the results of a merge operation
 * @cn:              pointer to cn struct
 * @kbb:             kblock builder (creates multiple kblocks)
 * @kblk_list:       list of kblock ids allocated by @kbb
 * @vbb:             vblock builder (creates multiple vblocks)
 * @vblk_list:       list of vblock ids allocated by @vbb
 * @seqno_max:       max seqno present in output kvset
 * @seqno_min:       min seqno present in output kvset
 * @vused:           sum of vlen of all selected values
 * @main:            kmd info about the main wbtree
 * @sec:             kmd info about the ptomb wbtree
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

    struct kblock_builder *kbb;
    struct blk_list        kblk_list;

    struct vblock_builder *vbb;
    struct blk_list        vblk_list;

    u64 seqno_max;
    u64 seqno_min;

    /* vused feeds into tree compaction logic.
     * Modify with care.
     */
    u64 vused;

    /* state related to current key and its values */
    struct kmd_info main;
    struct kmd_info sec;

    struct kbb_key_stats  key_stats;
    struct cn_merge_stats mstats;

    u8  last_ptomb[HSE_KVS_MAX_PFXLEN];
    u32 last_ptlen;
    u64 last_ptseq;
    u32 vblk_baseidx;
};
#endif
