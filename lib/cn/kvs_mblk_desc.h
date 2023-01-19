/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_MBLK_DESC_H
#define HSE_MBLK_DESC_H

#include <assert.h>
#include <inttypes.h>

#include <hse/types.h>

#include <hse/error/merr.h>
#include <hse/util/page.h>

/* MTF_MOCK_DECL(mblk_desc) */

struct mpool;

/* Mblock descriptor */
struct kvs_mblk_desc {
    void *map_base;      // memory mapped address of mblock
    uint64_t mbid;       // mblock id
    uint16_t alen_pages; // allocated length of mblock, in 4K pages
    uint16_t wlen_pages; // written length of mblock, in 4K pages
    uint16_t ra_pages;   // max readahead pages
    uint8_t mclass;      // media class
};

static_assert(
    HSE_MCLASS_MAX <= UINT8_MAX,
    "struct kvs_mblk_desc member mclass too small to hold enum hse_mclass");

/* Map an mblock and initialize an mblock descriptor.
 */
/* MTF_MOCK */
merr_t
mblk_mmap(struct mpool *mp, uint64_t mbid, struct kvs_mblk_desc *md_out);

/* Unmap an mblock.
 */
/* MTF_MOCK */
merr_t
mblk_munmap(struct mpool *mp, struct kvs_mblk_desc *md);

/* MTF_MOCK */
merr_t
mblk_madvise_pages(const struct kvs_mblk_desc *md, size_t pg, size_t pg_cnt, int advice);

static inline enum hse_mclass
mblk_mclass(const struct kvs_mblk_desc *d)
{
    return d->mclass;
}

static inline uint64_t
mblk_alen(const struct kvs_mblk_desc *d)
{
    return d->alen_pages * PAGE_SIZE;
}

static inline uint64_t
mblk_wlen(const struct kvs_mblk_desc *d)
{
    return d->wlen_pages * PAGE_SIZE;
}

#ifdef HSE_MOCKING
#include "kvs_mblk_desc_ut.h"
#endif

#endif
