/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_BLK_LIST_H
#define HSE_KVS_CN_BLK_LIST_H

#include <hse_util/inttypes.h>
#include <hse/error/merr.h>

/* MTF_MOCK_DECL(blk_list) */

struct blk_list;
struct kvs_block;
struct mblock_props;
struct mpool;

#define BLK_LIST_PRE_ALLOC 64

/* MTF_MOCK */
merr_t
delete_mblock(struct mpool *mp, uint64_t mbid);

/* MTF_MOCK */
void
delete_mblocks(struct mpool *mp, struct blk_list *blk);

/* MTF_MOCK */
merr_t
commit_mblock(struct mpool *mp, uint64_t mbid);

/* MTF_MOCK */
merr_t
commit_mblocks(struct mpool *mp, struct blk_list *blk);

/* MTF_MOCK */
void
blk_list_init(struct blk_list *blkl);

/* MTF_MOCK */
merr_t
blk_list_append(struct blk_list *blks, u64 blkid);

/* MTF_MOCK */
void
blk_list_free(struct blk_list *blks);

#if HSE_MOCKING
#include "blk_list_ut.h"
#endif

#endif
