/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_BLK_LIST_H
#define HSE_IKVDB_BLK_LIST_H

#include <hse_util/inttypes.h>

/**
 * struct kvs_block - information about a mblock in a blk_list
 * @bk_blkid:  mblock id
 * @bk_handle: mblock handle
 * @bk_needs_commit:  valid only when part of c1 external vblock builder
 * @bk_valid:         valid only when part of c1 external vblock builder
 */
struct kvs_block {
    u64  bk_blkid;
    bool bk_needs_commit;
    bool bk_valid;
};

struct blk_list {
    struct kvs_block *blks;
    u32               n_blks;
    u32               n_alloc;
};

struct kvset_mblocks {
    struct blk_list kblks;
    struct blk_list vblks;
    u64             bl_vused;
    u64             bl_seqno_max;
    u64             bl_seqno_min;

    void *bl_last_ptomb;
    u32   bl_last_ptlen;
    u64   bl_last_ptseq;
};

#endif
