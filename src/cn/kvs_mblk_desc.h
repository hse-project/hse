/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_MBLK_DESC_H
#define HSE_KVS_MBLK_DESC_H

#include <hse_util/inttypes.h>

struct mpool_mcache_map;
struct mpool;

struct kvs_mblk_desc {
    void *                   map_base; /* base address of mcache map */
    struct mpool_mcache_map *map;      /* mcache map */
    u32                      map_idx;  /* index of mblk in map */
    struct mpool *           ds;       /* mpool dataset */
    u64                      mb_id;    /* mblock id */
};

#endif
