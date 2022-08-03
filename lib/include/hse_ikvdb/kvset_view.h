/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_VIEW_H
#define HSE_KVS_CN_KVSET_VIEW_H

#include <hse_util/table.h>

struct cn;
struct kvset;

struct kvset_metrics {
    uint32_t num_keys;
    uint32_t num_tombstones;
    uint32_t nptombs;
    uint32_t num_hblocks; /* this should always be one */
    uint32_t num_kblocks;
    uint32_t num_vblocks;
    uint64_t header_bytes;
    uint64_t tot_key_bytes;
    uint64_t tot_val_bytes;
    uint64_t tot_vused_bytes;
    uint32_t tot_wbt_pages;
    uint32_t tot_blm_pages;
    uint32_t compc;
    uint16_t rule;
    uint16_t vgroups;
};

/* MTF_MOCK_DECL(kvset_view) */

/* MTF_MOCK */
void
kvset_get_metrics(struct kvset *kvset, struct kvset_metrics *metrics);

/**
 * Return the mblock ID of the hblock
 *
 * @param ks kvset
 */
/* MTF_MOCK */
uint64_t
kvset_get_hblock_id(struct kvset *ks);

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
uint64_t
kvset_get_nodeid(const struct kvset *kvset);

/* MTF_MOCK */
u64
kvset_get_dgen(struct kvset *kvset);

/* MTF_MOCK */
u64
kvset_get_seqno_max(struct kvset *kvset);

struct kvset_view {
    struct kvset *kvset;
    uint64_t      nodeid;
    uint          eklen;
    char          ekbuf[44]; /* 64 - offsetof(struct kvset_view, ekbuf) */
};

#if HSE_MOCKING
#include "kvset_view_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_KVS_CN_KVSET_VIEW_H */
