/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_VIEW_H
#define HSE_KVS_CN_KVSET_VIEW_H

#include <hse_util/table.h>

#include <hse_ikvdb/cn_node_loc.h>

struct cn;
struct kvset;

struct kvset_metrics {
    u32 num_keys;
    u32 num_tombstones;
    u32 num_kblocks;
    u32 num_vblocks;
    u64 tot_key_bytes;
    u64 tot_val_bytes;
    u32 tot_wbt_pages;
    u32 tot_blm_pages;
    u16 compc;
    u32 vgroups;
};

/* MTF_MOCK_DECL(kvset_view) */

/* MTF_MOCK */
void
kvset_get_metrics(struct kvset *kvset, struct kvset_metrics *metrics);

/**
 * kvset_get_num_kblocks() - Get number of kblocks in kvset
 */
/* MTF_MOCK */
u32
kvset_get_num_kblocks(struct kvset *kvset);

/**
 * kvset_get_num_vblocks() - Get number of vblocks in kvset
 */
/* MTF_MOCK */
u32
kvset_get_num_vblocks(struct kvset *kvset);

/**
 * kvset_get_nth_kblock_id() - Get mblock id of the nth kblock in kvset
 */
/* MTF_MOCK */
u64
kvset_get_nth_kblock_id(struct kvset *kvset, u32 index);

/**
 * kvset_get_nth_vblock_id() - Get mblock id of the nth vblock in kvset
 */
/* MTF_MOCK */
u64
kvset_get_nth_vblock_id(struct kvset *kvset, u32 index);

/* MTF_MOCK */
u64
kvset_get_dgen(struct kvset *kvset);

/* MTF_MOCK */
u64
kvset_get_seqno_max(struct kvset *kvset);

struct kvset_view {
    struct kvset *     kvset;
    struct cn_node_loc node_loc;
};

#if HSE_MOCKING
#include "kvset_view_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_KVS_CN_KVSET_VIEW_H */
