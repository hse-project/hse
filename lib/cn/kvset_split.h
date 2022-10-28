/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_SPLIT_H
#define HSE_KVS_CN_KVSET_SPLIT_H

#include <hse/error/merr.h>
#include <hse/ikvdb/blk_list.h>
#include <hse/util/inttypes.h>
#include <hse/util/hlog.h>
#include <hse/util/key_util.h>

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
 * struct kvset_split_wargs - split work args
 *
 * @work:       work struct
 * @ks:         kvset handle
 * @split_kobj: split key object
 * @pc:         perfc_set handle
 * @err:        return status of this split work
 * @inflightp:  ptr to count of inflight requests
 * @result:     split result (output)
 */
struct kvset_split_wargs {
    struct work_struct     work;
    struct kvset          *ks;
    struct key_obj        *split_kobj;
    struct perfc_set      *pc;
    merr_t                 err;
    atomic_uint           *inflightp;
    struct kvset_split_res result;
};

/**
 * kvset_split_worker() - worker function that splits a given kvset
 *
 * @work: split work struct
 */
void
kvset_split_worker(struct work_struct *work);

#endif /* HSE_KVS_CN_KVSET_SPLIT_H */
