/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_MBLK_DESC_H
#define HSE_KVS_MBLK_DESC_H

#include <stdint.h>

#include <hse/types.h>

struct mpool_mcache_map;
struct mpool;

struct kvs_mblk_desc {
    void *                   map_base; /* base address of mcache map */
    struct mpool_mcache_map *map;      /* mcache map */
    uint32_t                 map_idx;  /* index of mblk in map */
    enum hse_mclass          mclass;   /* media class */
    struct mpool *           ds;       /* mpool dataset */
    uint64_t                 mbid;    /* mblock id */
};

#endif
