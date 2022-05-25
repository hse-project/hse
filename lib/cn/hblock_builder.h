/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CN_HBLOCK_BUILDER_H
#define CN_HBLOCK_BUILDER_H

/* MTF_MOCK_DECL(hblock_builder) */

#include <stdint.h>

#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

enum hse_mclass_policy_age;
struct cn;
struct hblock_builder;
struct hlog;
struct key_obj;
struct kvs_block;
struct key_stats;

/* MTF_MOCK */
merr_t
hbb_add_ptomb(
    struct hblock_builder *bld,
    const struct key_obj *kobj,
    const void *kmd,
    unsigned int kmd_len,
    struct key_stats *stats);

/* MTF_MOCK */
merr_t
hbb_create(struct hblock_builder **bld_out, const struct cn *cn);

/* MTF_MOCK */
void
hbb_destroy(struct hblock_builder *bld);

/* MTF_MOCK */
merr_t
hbb_finish(
    struct hblock_builder *bld,
    struct kvs_block *blkl,
    uint64_t min_seqno,
    uint64_t max_seqno,
    uint32_t num_kblocks,
    uint32_t num_vblocks,
    uint32_t num_vgroups,
    const uint8_t *hlog);

merr_t
hbb_set_agegroup(struct hblock_builder *bld, enum hse_mclass_policy_age age) HSE_NONNULL(1);

#if HSE_MOCKING
#include "hblock_builder_ut.h"
#endif /* HSE_MOCKING */

#endif /* CN_HBLOCK_BUILDER_H */
