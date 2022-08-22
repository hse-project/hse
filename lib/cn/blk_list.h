/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_BLK_LIST_H
#define HSE_KVS_CN_BLK_LIST_H

#include <hse_util/inttypes.h>
#include <hse/error/merr.h>

struct blk_list;
struct kvs_block;
struct mblock_props;
struct mpool;

#define BLK_LIST_PRE_ALLOC 64

merr_t
delete_mblock(struct mpool *mp, struct kvs_block *blk);

void
delete_mblocks(struct mpool *mp, struct blk_list *blk);

merr_t
commit_mblock(struct mpool *mp, struct kvs_block *blk);

merr_t
commit_mblocks(struct mpool *mp, struct blk_list *blk);

void
blk_list_init(struct blk_list *blkl);

merr_t
blk_list_append(struct blk_list *blks, u64 blkid);

merr_t
blk_list_append_ext(struct blk_list *blks, u64 blkid, bool valid, bool needs_commit);

void
blk_list_free(struct blk_list *blks);

#endif
