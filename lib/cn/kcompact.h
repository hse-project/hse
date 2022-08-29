/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
  */

#ifndef HSE_KVS_CN_COMPACT_H
#define HSE_KVS_CN_COMPACT_H

/* MTF_MOCK_DECL(kcompact) */

#include <stdint.h>

#include <hse/error/merr.h>

struct cn_compaction_work;

/* Maps vblock refs for k-compaction
 *
 * This structure is used during k-compaction to map the vr_index
 * in kvs_vtuple_ref into the new target vr_index in the larger kvset.
 *
 * Example:
 * 4 origin kvsets: {k0,v0,v1} {k1,v0} {k2,v0,v1,v2} {k3,v0,v1}
 * blkv:            [v0,v1,v2,v3,v4,v5,v6,v7]
 * map:             [0,2,3,6]
 * blkc, mapc:      8,4
 * If the value for a key is in v4, that key's lfe_vbidx is 1.
 * The k-compacted key will have a new lfe_vbidx of 4:
 *      map[2] + original lfe_vbidx -- that is 3 + 1 = 4
 *
 * For backwards-compat, a full vblock has 0 waste, and 0 used.
 * Once k-compacted, used and waste are set to non-zero.
 *
 * Wasted space is calculated as ratio of waste / (used+waste).
 * Examples:
 * used 0,    waste 0,    ratio:   0 / 1   = 0
 * used 100M, waste 0,    ratio:   0 / 100 = 0
 * used 100M, waste 100M, ratio: 100 / 200 = .50
 * used 100M, waste 200M, ratio: 200 / 300 = .67
 * used 100M, waste 300M, ratio: 300 / 400 = .75
 * used 20M,  waste 300M, ratio: 300 / 320 = .94
 */
struct kvset_vblk_map {
    uint64_t         *vbm_blkv;  // vector of vblock ids
    uint32_t         *vbm_map;   // map of offsets from src vr_index to new vr_index in target
    uint32_t          vbm_blkc;  // number of entries in blkv
    uint32_t          vbm_mapc;  // number of entries in map[]
    uint64_t          vbm_used;  // total bytes of used vblock space
    uint64_t          vbm_waste; // total bytes of un-used vblock space
    uint64_t          vbm_tot;   // total bytes of all values in vblock space
};

/* Perform a k-compact operation
 */
/* MTF_MOCK */
merr_t
cn_kcompact(struct cn_compaction_work *w);

#if HSE_MOCKING
#include "kcompact_ut.h"
#endif /* HSE_MOCKING */

#endif
