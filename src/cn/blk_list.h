/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_BLK_LIST_H
#define HSE_KVS_CN_BLK_LIST_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>

#include <hse_ikvdb/blk_list.h>

struct mpool;
struct mblock_props;

#define BLK_LIST_PRE_ALLOC 64

merr_t
abort_mblock(struct mpool *dataset, struct kvs_block *blk);

void
abort_mblocks(struct mpool *dataset, struct blk_list *blks);

merr_t
delete_mblock(struct mpool *dataset, struct kvs_block *blk);

merr_t
commit_mblock(struct mpool *dataset, struct kvs_block *blk);

void
blk_list_init(struct blk_list *blkl);

merr_t
blk_list_append(struct blk_list *blks, u64 blkid);

merr_t
blk_list_append_ext(struct blk_list *blks, u64 blkid, bool valid, bool needs_commit);

void
blk_list_free(struct blk_list *blks);

#endif
