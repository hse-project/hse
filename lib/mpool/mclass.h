/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MCLASS_H
#define MPOOL_MCLASS_H

#include <dirent.h>

#include <hse_util/hse_err.h>

#include <mpool/mpool_internal.h>

#define MCLASS_MAX (1 << 2) /* 2-bit for mclass-id */

struct media_class;
struct mblock_fset;
struct mpool;

enum mclass_id {
    MCID_INVALID = 0,
    MCID_CAPACITY = 1,
    MCID_STAGING = 2,
};

/**
 * mclass_open() - open the specified mclass
 *
 * @mp:    mpool handle
 * @mcid:  mclass ID
 * @dpath: mclass directory path
 * @flags: open flags
 *
 * @handle(output): mclass handle
 */
merr_t
mclass_open(
    struct mpool        *mp,
    enum mp_media_classp mclass,
    const char          *dpath,
    uint8_t              fcnt,
    int                  flags,
    struct media_class **handle);

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

merr_t
mclass_params_set(struct media_class *mc, const char *key, const char *val, size_t len);

merr_t
mclass_params_get(struct media_class *mc, const char *key, char *val, size_t len);

merr_t
mclass_params_remove(struct media_class *mc);

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

#endif /* MPOOL_MCLASS_H */
