/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_KVSET_BUILDER_H
#define HSE_IKVS_KVSET_BUILDER_H

#include <hse_util/hse_err.h>
#include <hse_util/atomic.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/omf_kmd.h>

#include <mpool/mpool.h>

struct cn;
struct kvset_builder;
struct kvs_rparams;
struct perfc_set;
struct c1_bonsai_vbldr;
struct cn_merge_stats;

#define KVSET_BUILDER_FLAGS_NONE (0)
#define KVSET_BUILDER_FLAGS_SPARE (1u << 0)
#define KVSET_BUILDER_FLAGS_EXT (1u << 1)     /* from c1, to cn root node */
#define KVSET_BUILDER_FLAGS_INGEST (1u << 2)  /* from c0 or c1, to cn root node */

/* MTF_MOCK_DECL(kvset_builder) */
/* MTF_MOCK */
merr_t
kvset_builder_create(
    struct kvset_builder **builder_out,
    struct cn *            cn,
    struct perfc_set *     pc,
    u64                    vgroup,
    uint                   flags);

/* MTF_MOCK */
merr_t
kvset_builder_get_mblocks(struct kvset_builder *builder, struct kvset_mblocks *mblocks);

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
/* MTF_MOCK */
merr_t
kvset_builder_add_key(struct kvset_builder *builder, const struct key_obj *ko);

/**
 * kvset_builder_add_val() - add a value or a tombstone to a kvset entry
 * @builder: kvset builder object
 * @seq: sequence number of value or tombstone
 * @vdata: pointer to value, or a special tombstone pointer
 * @vlen: length of value
 * @vbldr: vbldr which is already created
 *
 * See kvset_builder_add_key().
 *
 * Special cases for tombstones:
 *
 *   - If @vdata == %HSE_CORE_TOMB_PFX:
 *        Then a prefix tombstone is added and @vlen is ignored.
 *
 *   - If @vdata == %HSE_CORE_TOMB_REG:
 *        Then a regular tombstone is added and @vlen is ignored.
 *
 *   - If @vdata == NULL or @vlen == 0:
 *        Then a zero-length value is added.
 *
 *   - Otherwise, and regular value is added.
 */
/* MTF_MOCK */
merr_t
kvset_builder_add_val(
    struct kvset_builder *  self,
    u64                     seq,
    const void *            vdata,
    uint                    vlen,
    struct c1_bonsai_vbldr *vbldr);

/* MTF_MOCK */
merr_t
kvset_builder_add_vref(struct kvset_builder *self, u64 seq, uint vbidx, uint vboff, uint vlen);

/* MTF_MOCK */
merr_t
kvset_builder_add_nonval(struct kvset_builder *self, u64 seq, enum kmd_vtype vtype);

/* MTF_MOCK */
void
kvset_builder_destroy(struct kvset_builder *builder);

/* MTF_MOCK */
void
kvset_mblocks_destroy(struct kvset_mblocks *kvset);

/* MTF_MOCK */
merr_t
kvset_builder_flush_vblock(struct kvset_builder *self);

/* MTF_MOCK */
merr_t
kvset_builder_add_val_ext(
    struct kvset_builder *self,
    u64                   seq,
    const void *          vdata,
    uint                  vlen,
    bool                  wait,
    u8                    index,
    u64 *                 vbidout,
    uint *                vbidxout,
    uint *                vboffout);

/* MTF_MOCK */
void
kvset_builder_get_c0c1vstat(struct kvset_builder *self, u64 *c0_vlen, u64 *c1_vlen);

/* MTF_MOCK */
merr_t
kvset_builder_finish_vblock(struct kvset_builder *self, u8 index);

/* MTF_MOCK */
void
kvset_builder_remove_unused_vblocks(struct kvset_builder *self);

/* MTF_MOCK */
u32
kvset_builder_vblock_hdr_len(void);

/* MTF_MOCK */
u32
kvset_builder_get_committed_vblock_count(struct kvset_builder *self);

/* MTF_MOCK */
merr_t
kvset_builder_merge_vblocks(struct kvset_builder *dst, struct kvset_builder *src);

/* MTF_MOCK */
void
kvset_builder_set_mclass_kvblk(
    struct kvset_builder *self,
    enum mp_media_classp  kblk_mclass,
    enum mp_media_classp  vblk_mclass);

/* MTF_MOCK */
void
kvset_builder_set_mclass(struct kvset_builder *self, enum mp_media_classp mclass);

/* MTF_MOCK */
void
kvset_builder_set_merge_stats(struct kvset_builder *self, struct cn_merge_stats *stats);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "kvset_builder_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
