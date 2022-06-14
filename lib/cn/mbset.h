/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_MBSET_H
#define HSE_KVDB_CN_MBSET_H

#include <hse_util/platform.h>
#include <hse_util/atomic.h>

#include <mpool/mpool.h>

struct mpool_mcache_map;
struct mpool;
struct mblock_props;
struct mbset;

#define MBSET_FLAGS_CAPPED (0x0001)
#define MBSET_FLAGS_VBLK_ROOT (0x0002)

/* MTF_MOCK_DECL(mbset) */

typedef void
mbset_callback(void *rock, bool mblock_delete_error);

typedef merr_t
mbset_udata_init_fn(
    struct mbset *       mbs,
    uint                 bnum,
    uint *               argcp,
    u64 *                argv,
    struct mblock_props *props,
    void *               rock);

/**
 * struct mbset - a ref counted set of mblocks
 * @mbs_map:  mcache map handle
 * @mbs_idv:  vector of mblock object ids
 * @mbs_idc:  mblock count, length of @mbs_idv
 * @mbs_ref:  reference count
 * @mbs_mp:   mpool handle
 * @mbs_del:  if true, delete mblocks in destructor
 * @mbs_alen: sum of mblock allocated lengths
 * @mbs_wlen: sum of mblock written lengths
 *
 * An "mbset" is a set of kblocks (or vblocks) owned by a single kvset and
 * possibly referenced by multiple kvsets (e.g., after k-compaction).
 */
struct mbset {
    struct mpool_mcache_map  *mbs_map;
    u64 *                     mbs_idv;
    u64                       mbs_alen;
    u64                       mbs_wlen;
    uint                      mbs_idc;
    struct mpool *            mbs_mp;
    atomic_int                mbs_ref;
    mbset_callback *          mbs_callback;
    void *                    mbs_callback_rock;
    void *                    mbs_udata;
    uint                      mbs_udata_sz;
    bool                      mbs_del;
};

/* MTF_MOCK */
merr_t
mbset_create(
    struct mpool *      ds,
    uint                idc,
    u64 *               idv,
    size_t              udata_sz,
    mbset_udata_init_fn udata_init_fn,
    uint                flags,
    struct mbset **     handle);

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
mbset_apply(struct mbset *self, mbset_udata_init_fn fn, uint *argcp, u64 *argv);

/* MTF_MOCK */
void
mbset_set_delete_flag(struct mbset *self);

/* MTF_MOCK */
void
mbset_madvise(struct mbset *self, int advise);

static HSE_ALWAYS_INLINE struct mpool *
mbset_get_mp(struct mbset *self)
{
    return self->mbs_mp;
}

static HSE_ALWAYS_INLINE u64
mbset_get_wlen(struct mbset *self)
{
    return self->mbs_wlen;
}

static HSE_ALWAYS_INLINE u64
mbset_get_alen(struct mbset *self)
{
    return self->mbs_alen;
}

static HSE_ALWAYS_INLINE struct mpool_mcache_map *
mbset_get_map(struct mbset *self)
{
    return self->mbs_map;
}

static HSE_ALWAYS_INLINE u64
mbset_get_mbid(struct mbset *self, uint blk_num)
{
    bool valid = blk_num < self->mbs_idc;

    assert(valid);
    return valid ? self->mbs_idv[blk_num] : 0;
}

static HSE_ALWAYS_INLINE uint
mbset_get_blkc(struct mbset *self)
{
    return self->mbs_idc;
}

static HSE_ALWAYS_INLINE void *
mbset_get_udata(struct mbset *self, uint blk_num)
{
    bool valid = blk_num < self->mbs_idc;

    assert(valid);
    return (valid && self->mbs_udata_sz ? self->mbs_udata + self->mbs_udata_sz * blk_num : 0);
}

#if HSE_MOCKING
#include "mbset_ut.h"
#endif /* HSE_MOCKING */

#endif
