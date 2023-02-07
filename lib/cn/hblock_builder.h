/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef CN_HBLOCK_BUILDER_H
#define CN_HBLOCK_BUILDER_H

/* MTF_MOCK_DECL(hblock_builder) */

#include <stdint.h>

#include <hse/util/compiler.h>
#include <hse/error/merr.h>

enum hse_mclass_policy_age;
struct cn;
struct hblock_builder;
struct hlog;
struct key_obj;
struct kvs_block;
struct key_stats;
struct vgmap;
struct perfc_set;
struct wbt_desc;

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
hbb_create(struct hblock_builder **bld_out, const struct cn *cn, struct perfc_set *pc);

/* MTF_MOCK */
void
hbb_destroy(struct hblock_builder *bld);

/* MTF_MOCK */
merr_t
hbb_finish(
    struct hblock_builder *bld,
    uint64_t              *hblk_id_out,
    const struct vgmap    *vgmap,
    struct key_obj        *min_pfxp,
    struct key_obj        *max_pfxp,
    const uint64_t         min_seqno,
    const uint64_t         max_seqno,
    const uint32_t         num_kblocks,
    const uint32_t         num_vblocks,
    const uint32_t         num_ptombs,
    const uint8_t         *hlog,
    const uint8_t         *ptree,
    struct wbt_desc       *ptree_desc,
    uint32_t               ptree_pgc);

merr_t
hbb_set_agegroup(struct hblock_builder *bld, enum hse_mclass_policy_age age) HSE_NONNULL(1);

uint32_t
hbb_get_nptombs(const struct hblock_builder *bld);

#if HSE_MOCKING
#include "hblock_builder_ut.h"
#endif /* HSE_MOCKING */

#endif /* CN_HBLOCK_BUILDER_H */
