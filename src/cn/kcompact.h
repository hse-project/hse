/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
  */

#ifndef HSE_KVS_CN_COMPACT_H
#define HSE_KVS_CN_COMPACT_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

struct cn_compaction_work;

/* MTF_MOCK_DECL(kcompact) */

/**
 * struct kvset_vblk_map - maps vblock refs for k-compaction
 * @vbm_blkv:   vector of vblock ids
 * @vbm_blkc:   number of entries in blkv
 * @vbm_map:    map of offsets from src vr_index to new vr_index in target
 * @vbm_mapc:   number of entries in map[]
 * @vbm_used:   total bytes of used vblock space
 * @vbm_waste:  total bytes of un-used vblock space
 * @vbm_tot:    total bytes of all values in vblock space
 *
 * This structure is used during k-compaction to map the vr_index
 * in kvs_vtuple_ref into the new target vr_index in the larger kvset.
 *
 * Example:
 * 4 origin kvsets: {k0,v0,v1} {k1,v2} {k2,v3,v4,v5} {k3,v6,v7}
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
    struct kvs_block *vbm_blkv;
    u32               vbm_blkc;
    u32 *             vbm_map;
    u32               vbm_mapc;
    u64               vbm_used;
    u64               vbm_waste;
    u64               vbm_tot;
};

/**
 * cn_kcompact - Build kvsets as part of a k-compact operation
 */
/* MTF_MOCK */
merr_t
cn_kcompact(struct cn_compaction_work *w);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "kcompact_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
