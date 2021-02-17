/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
/*
 * Storage manager interface for HSE
 */

#ifndef HSE_MPOOL2_H
#define HSE_MPOOL2_H

struct mpool;
struct mpool_params;

int64_t
mpool_params_get2(struct mpool *mp, struct mpool_params *params);

int64_t
mpool_params_set2(struct mpool *mp, struct mpool_params *params);

uint64_t
mpool_mblock_alloc2(
    struct mpool        *mp,
    enum mp_media_classp mclass,
    uint64_t            *mbid,
    struct mblock_props *props);

uint64_t
mpool_mblock_write2(struct mpool *mp, uint64_t mbid, const struct iovec *iov, int iovc, off_t off);

#endif /* HSE_MPOOL2_H */
