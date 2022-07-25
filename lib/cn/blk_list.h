/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVS_CN_BLK_LIST_H
#define HSE_KVS_CN_BLK_LIST_H

#include <stdint.h>

#include <hse/error/merr.h>

struct blk_list;
struct kvs_block;
struct mblock_props;
struct mpool;

#define BLK_LIST_PRE_ALLOC 64

void
delete_mblock(struct mpool *mp, uint64_t mbid) HSE_MOCK;

void
delete_mblocks(struct mpool *mp, struct blk_list *blk) HSE_MOCK;

merr_t
commit_mblock(struct mpool *mp, uint64_t mbid) HSE_MOCK;

merr_t
commit_mblocks(struct mpool *mp, struct blk_list *blk) HSE_MOCK;

void
blk_list_init(struct blk_list *blkl) HSE_MOCK;

merr_t
blk_list_append(struct blk_list *blks, uint64_t blkid) HSE_MOCK;

void
blk_list_free(struct blk_list *blks) HSE_MOCK;

#if HSE_MOCKING
#include "blk_list_ut.h"
#endif

#endif
