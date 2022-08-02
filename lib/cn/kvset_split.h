/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_SPLIT_H
#define HSE_KVS_CN_KVSET_SPLIT_H

#include <error/merr.h>
#include <hse_ikvdb/blk_list.h>
#include <hse_util/inttypes.h>
#include <hse_util/hlog.h>
#include <hse_util/key_util.h>

#include "kblock_reader.h"
#include "wbt_reader.h"
#include "cn_tree.h"
#include "hblock_reader.h"
#include "hblock_builder.h"

struct kvset;

enum split_side { LEFT = 0, RIGHT = 1 };

/**
 * struct kvset_split_res - split output
 */
struct kvset_split_res {
    struct {
        struct kvset_mblocks *blks;        /* kblocks, vblocks and the hblock */
        struct vgmap        **vgmap;       /* vgroup map */
        struct blk_list      *blks_commit; /* list of mblocks in the target kvsets to commit */
    } ks[2];

    struct blk_list          *blks_purge;  /* list of mblocks in the source kvset to delete */
};

/**
 * kvset_split() - split kblocks, vblocks and the hblock of a given kvset
 * @ks:         kvset handle
 * @split_kobj: split key object
 * @result:     split result (output)
 */
merr_t
kvset_split(
    struct kvset           *ks,
    const struct key_obj   *split_kobj,
    struct kvset_split_res *result);

#endif /* HSE_KVS_CN_KVSET_SPLIT_H */
