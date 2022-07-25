/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_IKVS_KVSET_BUILDER_H
#define HSE_IKVS_KVSET_BUILDER_H

#include <hse/error/merr.h>
#include <hse/ikvdb/blk_list.h>
#include <hse/ikvdb/mclass_policy.h>
#include <hse/ikvdb/omf_kmd.h>
#include <hse/ikvdb/tuple.h>
#include <hse/mpool/mpool.h>
#include <hse/util/atomic.h>

struct cn;
struct kvset_builder;
struct kvs_rparams;
struct perfc_set;
struct cn_merge_stats;
struct vgmap;

struct key_stats {
    uint nvals;
    uint ntombs;
    uint nptombs;
    uint64_t tot_vlen;
    uint64_t tot_vused;
};

merr_t
kvset_builder_create(
    struct kvset_builder **builder_out,
    struct cn *cn,
    struct perfc_set *pc,
    uint64_t vgroup) HSE_MOCK;

merr_t
kvset_builder_get_mblocks(struct kvset_builder *builder, struct kvset_mblocks *mblocks) HSE_MOCK;

/**
 * kvset_builder_add_key() - start a new kvset entry
 * @builder: kvset builder object
 * @ko:      key object to be associated with new entry
 *
 * kvset_builder_add_key() and kvset_builder_add_val() are used to
 * add entries to kvset builders.  An entry is single key and a set of values
 * (or tombstones) with distinct sequence numbers.
 *
 * To add an entry to a builder, call kvset_builder_add_val() to add each
 * value associated with the key, then call kvset_builder_add_key() to add
 * actual key.  Successive calls to kvset_builder_add_val() must have strictly
 * decreasing sequence numbers (see the assert() in the example below).
 *
 * Example:
 *
 *   for (i = 0; !err && i < nvals; i++) {
 *       assert(i == 0 || seq[i] > seq[i-1]);
 *       err = kvset_builder_add_val(bld, seq[i], vdata[i], vlen[i]);
 *   }
 *   err = kvset_builder_add_key(bld, kobj);
 *
 * Notes:
 *   - Prefix tombstones and regular tombstones are represented as special
 *     pointer values.  See kvset_builder_add_val() for details.
 *   - There is no function to "finish" an entry (the entry is finished when
 *     kvset_builder_add_val() has been called @nvals times).
 */
merr_t
kvset_builder_add_key(struct kvset_builder *builder, const struct key_obj *ko) HSE_MOCK;

merr_t
kvset_builder_add_val(
    struct kvset_builder *self,
    const struct key_obj *kobj,
    const void *vdata,
    uint vlen,
    uint64_t seq,
    uint complen) HSE_MOCK;

merr_t
kvset_builder_add_vref(
    struct kvset_builder *self,
    uint64_t seq,
    uint vbidx,
    uint vboff,
    uint vlen,
    uint complen) HSE_MOCK;

merr_t
kvset_builder_add_nonval(struct kvset_builder *self, uint64_t seq, enum kmd_vtype vtype) HSE_MOCK;

void
kvset_builder_adopt_vblocks(
    struct kvset_builder *self,
    size_t num_vblocks,
    uint64_t *vblock_ids,
    uint64_t vtotal,
    struct vgmap *vgmap) HSE_MOCK;

void
kvset_builder_destroy(struct kvset_builder *builder) HSE_MOCK;

void
kvset_mblocks_destroy(struct kvset_mblocks *kvset) HSE_MOCK;

merr_t
kvset_builder_set_agegroup(struct kvset_builder *self, enum hse_mclass_policy_age age) HSE_MOCK;

void
kvset_builder_set_merge_stats(struct kvset_builder *self, struct cn_merge_stats *stats) HSE_MOCK;

#if HSE_MOCKING
#include "kvset_builder_ut.h"
#endif /* HSE_MOCKING */

#endif
