/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_BLK_LIST_H
#define HSE_IKVDB_BLK_LIST_H

#include <inttypes.h>

struct blk_list {
    uint64_t *blks;
    uint32_t n_alloc;
    uint32_t n_blks;
};

struct kvset_mblocks {
    uint64_t hblk_id;
    struct blk_list kblks;
    struct blk_list vblks;
    uint64_t bl_vtotal;
    uint64_t bl_vused;
    uint64_t bl_seqno_max;
    uint64_t bl_seqno_min;

    void *bl_last_ptomb;
    uint32_t bl_last_ptlen;
    uint64_t bl_last_ptseq;
};

#endif
