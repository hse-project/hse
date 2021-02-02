/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MBLOCK_FILE_H
#define MPOOL_MBLOCK_FILE_H

#include <hse_util/hse_err.h>

#define MBLOCK_FILE_SIZE_MAX     (1ULL << 11) /* In GiB */

struct mblock_mmap;
struct mblock_smap;
struct mblock_fset;
struct io_ops;

/**
 * struct mblock_file - mblock file handle (one per file)
 *
 * @mbfsp: reference to the fileset handle
 * @smap:  space map
 * @mmap:  mblock map
 * @io:    io handle for sync/async rw ops
 *
 * maxsz: maximum file size (2TiB with 16-bit block offset)
 *
 * meta_soff: start offset in the fset meta file
 * meta_len:  length of the metadata region for this file
 *
 * fd:   file handle
 * name: file name
 *
 */
struct mblock_file {
	struct mblock_fset     *mbfsp;
	struct mblock_smap     *smap;
	struct mblock_map      *mmap;
	struct io_ops          *io;

	size_t                  maxsz;

	off_t                   meta_soff;
	size_t                  meta_len;

	int                     fd;
	char                    name[32];
};

/**
 * mblock_file_open() - open an mblock file
 *
 * @fs:    mblock fileset handle
 * @dirfd: mclass directory fd
 * @name:  file name
 * @flags: open flags
 * @handle(output): mblock file handle
 *
 */
merr_t
mblock_file_open(
    struct mblock_fset  *mbfsp,
    int                  dirfd,
    char                *name,
    int                  flags,
    struct mblock_file **handle);

/**
 * mblock_file_close() - close an mblock file
 *
 * @mbfp: mblock file handle
 */
void
mblock_file_close(struct mblock_file *mbfp);

/**
 * mblock_allocv() - allocate a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidc: count of objects to allocate
 *
 * @mbidv (output): vector of mblock ids
 */
merr_t
mblock_allocv(struct mblock_file *mbfp, int mbidc, uint64_t *mbidv);

/**
 * mblock_commitv() - commit a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_commitv(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_abortv() - abort a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_abortv(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_destroyv() - destroy a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_destroyv(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_read() - read an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 * @offset: offset
 */
merr_t
mblock_read(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc,
	    off_t offset);

/**
 * mblock_write() - write an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 * @offset: offset
 */
merr_t
mblock_write(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc,
	     off_t offset);

#endif /* MPOOL_MBLOCK_FILE_H */

