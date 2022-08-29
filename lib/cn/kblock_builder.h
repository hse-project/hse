/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KBLOCK_BUILDER_H
#define HSE_KVS_CN_KBLOCK_BUILDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <hse/error/merr.h>

#include <hse/util/perfc.h>
#include <hse/util/key_util.h>

struct cn;
struct cn_merge_stats;
struct blk_list;
struct kblock_builder;
struct kblock_desc;
struct key_stats;
struct kvs_rparams;
struct wbti;

enum hse_mclass;
enum hse_mclass_policy_age;

/* MTF_MOCK_DECL(kblock_builder) */

/**
 * DOC: kblock builder lifecycle
 *
 * 1. Create with kbb_create().
 *
 * 2. Repeatedly invoke kbb_add_entry() and/or kbb_is_empty() as needed.  The
 *    kblock builder object will allocate and write kblocks as needed.

 * 3. To abort, call kbb_destroy() at any time.  This will free all internal
 *    resources and abort any kblocks allocated during calls to
 *    kbb_add_entry().

 * 4. To finish, call kbb_finish(), which will allocate and write the final
 *    kblock and return a list of IDs for all kblocks that have been allocated
 *    and written but not committed since the kblock builder was created with
 *    kbb_create().
 *
 * 5. It is up to the caller to abort or commit the kblocks whose IDs are
 *    returned by kbb_finish().
 */

/**
 * kbb_create() - Create a kblock builder
 * @builder_out: builder handle (output)
 * @cn: cn in which kblocks will be created
 * @pc: perf counters
 */
/* MTF_MOCK */
merr_t
kbb_create(struct kblock_builder **bld_out, struct cn *cn, struct perfc_set *pc);

/**
 * kbb_destroy() - Destroy a kblock builder
 * @bld: builder handle
 *
 * Frees all resources and aborts all mblocks allocated internally
 * since kbb_create().
 */
/* MTF_MOCK */
void
kbb_destroy(struct kblock_builder *bld);

/**
 * kbb_add_entry() - Store a key and a value reference in a kblock.
 * @bld: builder handle
 * @kobj: key to add to kblock
 * @kmd, @kmd_len: omf-encoded key metadata
 * @stats: REQUIRED info about key and values being added
 *
 * Add an entry to an in-memory kblock image.  If the image is full, an mblock
 * is allocated, the image is written to it, a new image is created, and the
 * entry is added to the new image.
 *
 * Note: the mblock is allocated and written, but not committed.
 */
/* MTF_MOCK */
merr_t
kbb_add_entry(
    struct kblock_builder *bld,
    const struct key_obj * kobj,
    const void *           kmd,
    uint                   kmd_len,
    struct key_stats *     stats);

/**
 * kbb_finish() - ensure all kblocks have been written to media and
 *            are ready to be committed.
 * @bld: builder handle
 * @klbks: (output) list of mblock IDs
 *
 * Return:
 * Upon successful return:
 *  (1) Caller owns struct blk_list.
 *  (2) Caller must invoke 'blk_list_free()' with @kblks.
 *  (3) Caller owns all mblocks whose IDs are in @kblks.
 *  (4) Caller must abort or commit all mblocks it owns as a result
 *      of calling kbb_finish().
 *  (5) If @kblks is an empty list, then no entries were added and
 *      no mblocks were allocated.
 *
 * Upon failure, the only vaild action is to call kbb_destroy().
 */
/* MTF_MOCK */
merr_t
kbb_finish(struct kblock_builder *bld, struct blk_list *kblks);

/* MTF_MOCK */
size_t
kbb_estimate_alen(struct cn *cn, size_t wlen, enum hse_mclass mclass);

const uint8_t *
kbb_get_composite_hlog(const struct kblock_builder *bld);

merr_t
kbb_set_agegroup(struct kblock_builder *bld, enum hse_mclass_policy_age age);

void
kbb_set_merge_stats(struct kblock_builder *bld, struct cn_merge_stats *stats);

/* MTF_MOCK */
bool
kbb_is_empty(struct kblock_builder *bld);

void
kbb_curr_kblk_min_max_keys(
    struct kblock_builder *bld,
    struct key_obj        *min_kobj,
    struct key_obj        *max_kobj);

#if HSE_MOCKING
#include "kblock_builder_ut.h"
#endif /* HSE_MOCKING */

#endif
