/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MCLASS_H
#define MPOOL_MCLASS_H

#include <dirent.h>

#include <error/merr.h>

#include <mpool/mpool_structs.h>

#define MCLASS_MAX         (1 << 2) /* 2-bit for mclass-id */
#define MP_DESTROY_THREADS 8

struct media_class;
struct mblock_fset;
struct mpool;
struct workqueue_struct;
struct io_ops;

/**
 * enum mclass_id - media class ID
 */
enum mclass_id {
    MCID_INVALID = 0,
    MCID_CAPACITY = 1,
    MCID_STAGING = 2,
    MCID_PMEM = 3,
};

/**
 * struct mclass_params - mclass params
 *
 * @fmaxsz:   max file size
 * @mblocksz: mblock size
 * @filecnt:  number of files in an mclass fileset
 * @path:     storage path
 */
struct mclass_params {
    size_t  fmaxsz;
    size_t  mblocksz;
    uint8_t filecnt;
    char    path[PATH_MAX];
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
    enum hse_mclass           mclass,
    const struct mclass_params *params,
    int                         flags,
    struct media_class **       handle);

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
 * @path: mclass path
 * @wq:   destroy wq
 */
int
mclass_destroy(const char *path, struct workqueue_struct *wq);

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

/** @brief Get the user-given path.
 *
 * @param mc: Media class handle.
 *
 * @returns User-given path (pre-realpath(3)).
 */
const char *
mclass_upath(const struct media_class *mc);

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
 * mclass_supports_directio() - check directio support
 *
 * @mc: mclass handle
 */
bool
mclass_supports_directio(struct media_class *mc);

/**
 * mclass_to_mcid() - convert mclass to mclass ID
 *
 * @mclass: media class
 */
enum mclass_id
mclass_to_mcid(enum hse_mclass mclass);

/**
 * mcid_to_mclass() - convert mclass ID to mclass
 *
 * @mcid: media class ID
 */
enum hse_mclass
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
 * mclass_gclose_set() - set graceful close
 *
 * @mc:       mclass handle
 */
void
mclass_gclose_set(struct media_class *mc);

/**
 * mclass_gclose_get() - get graceful close value
 *
 * @mc:       mclass handle
 */
bool
mclass_gclose_get(struct media_class *mc);

/**
 * mclass_io_ops_set() -  set io ops for the specified mclass
 *
 * @mclass: mclass enum
 * @io:     io_ops (output)
 */
void
mclass_io_ops_set(enum hse_mclass mclass, struct io_ops *io);

/**
 * mclass_info_get() - get media class info
 *
 * @mc: mclass handle
 * @info: mclass info (output)
 */
merr_t
mclass_info_get(struct media_class *mc, struct hse_mclass_info *info);

/** @brief Get properties of a media class.
 *
 * @param mc: Media class.
 * @param props: Media class properties.
 */
void
mclass_props_get(struct media_class *mc, struct mpool_mclass_props *props);

/**
 * mclass_ftw() - walk mclass files matching prefix and invoke callback for each file
 *
 * @mc:     mclass handle
 * @prefix: file prefix
 * @cb:     instance of struct mpool_file_cb
 */
merr_t
mclass_ftw(struct media_class *mc, const char *prefix, struct mpool_file_cb *cb);

/**
 * mclass_files_exist() - check for existence of media class files
 *
 * @path: mclass path
 */
bool
mclass_files_exist(const char *path);

#endif /* MPOOL_MCLASS_H */
