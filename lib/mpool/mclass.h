/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MCLASS_H
#define MPOOL_MCLASS_H

#include <dirent.h>

#include <hse_util/hse_err.h>

#define MCLASS_MAX              (1 << 2)    /* 2-bit for mclass-id */

struct mblock_fset;
struct mpool;

enum mclass_id {
	MCID_CAPACITY = 0,
	MCID_STAGING  = 1,
	MCID_MAX      = 2,
};

/**
 * struct media_class - represents a mclass instance
 *
 * @dirp:  mclass directory stream
 * @mbfsp: mblock fileset handle
 * @mcid:  mclass ID (persisted in mblock/mdc metadata)
 * @dpath: mclass directory path
 */
struct media_class {
	DIR                    *dirp;
	struct mblock_fset     *mbfsp;
	enum mclass_id          mcid;
	char                    dpath[PATH_MAX];
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
    enum mclass_id       mcid,
    const char          *dpath,
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

#endif /* MPOOL_MCLASS_H */
