/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MCLASS_H
#define MPOOL_MCLASS_H

#include <dirent.h>

#include <hse_util/hse_err.h>

#include <mpool/mpool_structs.h>

#define MCLASS_MAX (1 << 2) /* 2-bit for mclass-id */

struct media_class;
struct mblock_fset;
struct mpool;

enum mclass_id {
    MCID_INVALID = 0,
    MCID_CAPACITY = 1,
    MCID_STAGING = 2,
};

struct mclass_params {
    size_t  fszmax;
    size_t  mblocksz;
    u8      filecnt;
    char    path[PATH_MAX];
};

/**
 * mclass_open() - open the specified mclass
 *
 * @mp:     mpool handle
 * @mclass: media class
 * @params: mclass params
 * @flags:  open flags
 *
 * @handle(output): mclass handle
 */
merr_t
mclass_open(
    struct mpool         *mp,
    enum mp_media_classp  mclass,
    struct mclass_params *params,
    int                   flags,
    struct media_class  **handle);

/**
 * mclass_close() - close an mclass
 *
 * @mc: mclass handle
 */
merr_t
mclass_close(struct media_class *mc);

/**
 * mclass_destroy() - destroy an mclass
 *
 * @mc: mclass handle
 */
void
mclass_destroy(struct media_class *mc);

/**
 * mclass_id() - get mclass id
 *
 * @mc: mclass handle
 */
int
mclass_id(struct media_class *mc);

/**
 * mclass_dpath() - get directory path
 *
 * @mc: mclass handle
 */
const char *
mclass_dpath(struct media_class *mc);

/**
 * mclass_dirfd() - get mclass directory fd
 *
 * @mc: mclass handle
 */
int
mclass_dirfd(struct media_class *mc);

struct mblock_fset *
mclass_fset(struct media_class *mc);

enum mclass_id
mclass_to_mcid(enum mp_media_classp mclass);

enum mp_media_classp
mcid_to_mclass(enum mclass_id mcid);

size_t
mclass_mblocksz(struct media_class *mc);

void
mclass_mblocksz_set(struct media_class *mc, size_t mblocksz);

merr_t
mclass_stats_get(struct media_class *mc, struct mpool_mclass_stats *stats);

#endif /* MPOOL_MCLASS_H */
