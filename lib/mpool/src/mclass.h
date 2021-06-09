/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MCLASS_H
#define MPOOL_MCLASS_H

#include <dirent.h>

#include <hse_util/hse_err.h>

#include <mpool/mpool_structs.h>

#define MCLASS_MAX         (1 << 2) /* 2-bit for mclass-id */
#define MP_DESTROY_THREADS 8

struct media_class;
struct mblock_fset;
struct mpool;
struct workqueue_struct;

/**
 * enum mclass_id - media class ID
 */
enum mclass_id {
    MCID_INVALID = 0,
    MCID_CAPACITY = 1,
    MCID_STAGING = 2,
};

/**
 * struct mclass_params - media class params passed at mclass open
 *
 * @fszmax:   max file size
 * @mblocksz: mblock size
 * @filecnt:  number of files in an mclass fileset
 * @path:     mclass storage path
 */
struct mclass_params {
    size_t fszmax;
    size_t mblocksz;
    u8     filecnt;
    char   path[PATH_MAX];
};

/**
 * mclass_open() - open the specified mclass
 *
 * @mclass: media class
 * @params: mclass params
 * @flags:  open flags
 * @handle: mclass handle (output)
 */
merr_t
mclass_open(
    enum mpool_mclass     mclass,
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
mclass_destroy(struct media_class *mc, struct workqueue_struct *wq);

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

/**
 * mclass_fset() - get mblock fileset handle
 *
 * @mc: mclass handle
 */
struct mblock_fset *
mclass_fset(struct media_class *mc);

/**
 * mclass_to_mcid() - convert mclass to mclass ID
 *
 * @mclass: media class
 */
enum mclass_id
mclass_to_mcid(enum mpool_mclass mclass);

/**
 * mcid_to_mclass() - convert mclass ID to mclass
 *
 * @mcid: media class ID
 */
enum mpool_mclass
mcid_to_mclass(enum mclass_id mcid);

/**
 * mclass_mblocksz_get() - get mblock size
 *
 * @mc: mclass handle
 */
size_t
mclass_mblocksz_get(struct media_class *mc);

/**
 * mclass_mblocksz_set() - set mblock size
 *
 * @mc:       mclass handle
 * @mblocksz: mblock size
 */
void
mclass_mblocksz_set(struct media_class *mc, size_t mblocksz);

/**
 * mclass_stats_get() - get media class stats
 *
 * @mc:    mclass handle
 * @stats: mclass stats (output)
 */
merr_t
mclass_stats_get(struct media_class *mc, struct mpool_mclass_stats *stats);

#endif /* MPOOL_MCLASS_H */
