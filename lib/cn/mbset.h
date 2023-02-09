/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_MBSET_H
#define HSE_KVDB_CN_MBSET_H

#include <stdint.h>

#include <hse/mpool/mpool.h>
#include <hse/util/atomic.h>
#include <hse/util/platform.h>

#include "cn/kvs_mblk_desc.h"

struct mpool;
struct mblock_props;
struct mbset;

/* MTF_MOCK_DECL(mbset) */

typedef void
mbset_callback(void *rock, bool mblock_delete_error);

typedef merr_t
mbset_udata_init_fn(const struct kvs_mblk_desc *mblk, void *rock);

/*
 * A ref counted set of mblocks
 *
 * An "mbset" is a set of vblocks owned by a single kvset and
 * possibly referenced by multiple kvsets (e.g., after k-compaction).
 */
struct mbset {
    struct kvs_mblk_desc *mbs_mblkv;
    uint64_t mbs_alen;
    uint64_t mbs_wlen;
    uint mbs_mblkc;
    atomic_int mbs_ref;
    struct mpool *mbs_mp;
    mbset_callback *mbs_callback;
    void *mbs_callback_rock;
    void *mbs_udata;
    uint mbs_udata_sz;
    bool mbs_del;
};

/* MTF_MOCK */
merr_t
mbset_create(
    struct mpool *ds,
    uint idc,
    uint64_t *idv,
    size_t udata_sz,
    mbset_udata_init_fn udata_init_fn,
    struct mbset **handle);

/* MTF_MOCK */
struct mbset *
mbset_get_ref(struct mbset *self);

/* MTF_MOCK */
void
mbset_put_ref(struct mbset *self);

/* MTF_MOCK */
void
mbset_set_callback(struct mbset *self, mbset_callback *callback, void *rock);

/* MTF_MOCK */
void
mbset_set_delete_flag(struct mbset *self);

static HSE_ALWAYS_INLINE struct mpool *
mbset_get_mp(const struct mbset *self)
{
    return self->mbs_mp;
}

static HSE_ALWAYS_INLINE uint64_t
mbset_get_wlen(const struct mbset *self)
{
    return self->mbs_wlen;
}

static HSE_ALWAYS_INLINE uint64_t
mbset_get_alen(const struct mbset *self)
{
    return self->mbs_alen;
}

static HSE_ALWAYS_INLINE uint64_t
mbset_get_mbid(const struct mbset *self, uint blk_num)
{
    bool valid = blk_num < self->mbs_mblkc;

    assert(valid);
    return valid ? self->mbs_mblkv[blk_num].mbid : 0;
}

static HSE_ALWAYS_INLINE uint
mbset_get_blkc(const struct mbset *self)
{
    return self->mbs_mblkc;
}

static HSE_ALWAYS_INLINE void *
mbset_get_udata(const struct mbset *self, uint blk_num)
{
    bool valid = blk_num < self->mbs_mblkc;

    assert(valid);
    return (valid && self->mbs_udata_sz ? self->mbs_udata + self->mbs_udata_sz * blk_num : 0);
}

#if HSE_MOCKING
#include "mbset_ut.h"
#endif /* HSE_MOCKING */

#endif
