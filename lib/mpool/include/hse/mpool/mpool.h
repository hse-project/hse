/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef MPOOL_H
#define MPOOL_H

#include <stdbool.h>
#include <stdlib.h>

#include <hse/mpool/mpool_structs.h>

#include <hse/error/merr.h>

struct mpool;            /* opaque mpool handle */
struct mpool_mdc;        /* opaque MDC (metadata container) handle */
struct mpool_file;       /* opaque mpool file handle */
struct iovec;

/* MTF_MOCK_DECL(mpool) */

/*
 * Mpool Administrative APIs...
 */

/**
 * mpool_create() - Create an mpool
 *
 * @home:      kvdb home
 * @cparams:   mpool cparams
 */
/* MTF_MOCK */
merr_t
mpool_create(const char *home, const struct mpool_cparams *cparams);


/**
 * mpool_cparams_defaults() - Init default mpool cparams
 *
 * @cparams: mpool cparams (output)
 */
/* MTF_MOCK */
void
mpool_cparams_defaults(struct mpool_cparams *cparams);

/**
 * mpool_mclass_add() - Add a media class to the mpool
 *
 * @mclass   enum hse_mclass, cannot be HSE_MCLASS_CAPACITY
 * @cparams: mpool cparams
 */
/* MTF_MOCK */
merr_t
mpool_mclass_add(enum hse_mclass mclass, const struct mpool_cparams *cparams);

/**
 * mpool_mclass_destroy() - Destroy the specified mclass (used only during error path cleanup)
 *
 * @mclass   enum hse_mclass, cannot be HSE_MCLASS_CAPACITY
 * @dparams: mpool dparams
 */
/* MTF_MOCK */
void
mpool_mclass_destroy(enum hse_mclass mclass, const struct mpool_dparams *dparams);

/**
 * mpool_open() - Open an mpool
 *
 * @home:    kvdb home
 * @rparams: mpool rparams
 * @flags:   open flags
 * @handle:  mpool handle (output)
 *
 * Flags are limited to a subset of flags allowed by open(2):
 * O_CREAT, O_RDONLY, O_WRONLY, and O_RDWR.
 */
/* MTF_MOCK */
merr_t
mpool_open(
    const char                 *home,
    const struct mpool_rparams *rparams,
    uint32_t                    flags,
    struct mpool              **handle);

/**
 * mpool_close() - Close an mpool
 *
 * @mp: mpool handle
 */
/* MTF_MOCK */
merr_t
mpool_close(struct mpool *mp);

/**
 * mpool_destroy() - Destroy an mpool
 *
 * @home:    kvdb home
 * @dparams: mpool dparams
 */
/* MTF_MOCK */
merr_t
mpool_destroy(const char *home, const struct mpool_dparams *dparams);

/**
 * mpool_mclass_props_get() - get properties of the specified media class
 *
 * @mp:     mpool descriptor
 * @mclass: input media mclass
 * @props:  media class props (output)
 *
 * Returns: 0 for success
 *          non-zero(err): merr_errno(err) == ENOENT if the specified mclass is not present
 */
/* MTF_MOCK */
merr_t
mpool_mclass_props_get(
    struct mpool *             mp,
    enum hse_mclass          mclass,
    struct mpool_mclass_props *props);

/**
 * mpool_mclass_info_get() - get info of the specified media class
 *
 * @mp: mpool descriptor
 * @mclass: input media mclass
 * @info: media class info (output)
 *
 * Returns: 0 for success
 *          non-zero(err): merr_errno(err) == ENOENT if the specified mclass is not present
 */
/* MTF_MOCK */
merr_t
mpool_mclass_info_get(struct mpool *mp, enum hse_mclass mclass, struct hse_mclass_info *info);

/**
 * mpool_mclass_ftw() - walk files in 'mclass' and invoke cb for each file matching 'prefix'
 *
 * @mp:     mpool descriptor
 * @mclass: enum hse_mclass
 * @prefix: file prefix
 * @cb:     instance of struct mpool_file_cb
 */
merr_t
mpool_mclass_ftw(
    struct mpool         *mp,
    enum hse_mclass     mclass,
    const char           *prefix,
    struct mpool_file_cb *cb);

/** @brief Check if a media class is configured.
 *
 * @param mp: Mpool.
 * @param mclass: Media class.
 *
 * @returns true if configured, false if not.
 */
/* MTF_MOCK */
bool
mpool_mclass_is_configured(struct mpool *mp, enum hse_mclass mclass);

/**
 * mpool_props_get() - get mpool properties
 *
 * @mp:    mpool handle
 * @props: mpool props
 */
/* MTF_MOCK */
merr_t
mpool_props_get(struct mpool *mp, struct mpool_props *props);

/**
 * mpool_info_get() - Get mpool information.
 *
 * @mp: mpool handle
 * @stats: mpool info (output)
 */
merr_t
mpool_info_get(struct mpool *mp, struct mpool_info *stats);

/*
 * Mpool Data Manager APIs
 */

/******************************** MDC APIs ************************************/

/**
 * mpool_mdc_alloc() - Alloc an MDC
 *
 * @mp:       mpool handle
 * @magic:    MDC magic
 * @capacity: capacity (bytes)
 * @mclass:   media class
 * @logid1:   logid 1 (output)
 * @logid2:   logid 2 (output)
 */
/* MTF_MOCK */
merr_t
mpool_mdc_alloc(
    struct mpool *    mp,
    uint32_t          magic,
    size_t            capacity,
    enum hse_mclass mclass,
    uint64_t *        logid1,
    uint64_t *        logid2);

/**
 * mpool_mdc_commit() - Commit an MDC
 *
 * @mp:     mpool handle
 * @logid1: logid 1
 * @logid2: logid 2
 */
/* MTF_MOCK */
merr_t
mpool_mdc_commit(struct mpool *mp, uint64_t logid1, uint64_t logid2);

/**
 * mpool_mdc_abort() - Abort an MDC
 *
 * @mp:     mpool handle
 * @logid1: logid 1
 * @logid2: logid 2
 */
merr_t
mpool_mdc_abort(struct mpool *mp, uint64_t logid1, uint64_t logid2);

/**
 * mpool_mdc_delete() - Delete an MDC
 *
 * @mp:     mpool handle
 * @logid1: logid 1
 * @logid2: logid 2
 */
/* MTF_MOCK */
merr_t
mpool_mdc_delete(struct mpool *mp, uint64_t logid1, uint64_t logid2);

/**
 * mpool_mdc_open() - Open MDC by OIDs
 *
 * @mp:     mpool handle
 * @logid1: logid 1
 * @logid2: logid 2
 * @rdonly: read-only open
 * @handle: MDC handle (output)
 */
/* MTF_MOCK */
merr_t
mpool_mdc_open(
    struct mpool      *mp,
    uint64_t           logid1,
    uint64_t           logid2,
    bool               rdonly,
    struct mpool_mdc **handle);

/**
 * mpool_mdc_close() - Close MDC
 *
 * @mdc: MDC handle
 */
/* MTF_MOCK */
merr_t
mpool_mdc_close(struct mpool_mdc *mdc);

/**
 * mpool_mdc_rewind() - Rewind MDC to first record
 *
 * @mdc: MDC handle
 */
/* MTF_MOCK */
merr_t
mpool_mdc_rewind(struct mpool_mdc *mdc);

/**
 * mpool_mdc_read() - Read next record from MDC
 *
 * @mdc:   MDC handle
 * @data:  buffer to receive data
 * @len:   length of supplied buffer
 * @rdlen: number of bytes read (output)
 *
 * Return: If merr_errno() of the return value is EOVERFLOW, then the receive buffer
 *         "data" is too small and must be resized according to the value returned in
 *         "rdlen".
 */
/* MTF_MOCK */
merr_t
mpool_mdc_read(struct mpool_mdc *mdc, void *data, size_t len, size_t *rdlen);

/**
 * mpool_mdc_append() - append record to MDC
 *
 * @mdc:  MDC handle
 * @data: data to write
 * @len:  length of data
 * @sync: flag to defer return until IO is complete
 */
/* MTF_MOCK */
merr_t
mpool_mdc_append(struct mpool_mdc *mdc, void *data, size_t len, bool sync);
/**
 * mpool_mdc_cstart() - Initiate MDC compaction
 *
 * @mdc: MDC handle
 */
/* MTF_MOCK */
merr_t
mpool_mdc_cstart(struct mpool_mdc *mdc);

/**
 * mpool_mdc_cend() - End MDC compactions
 *
 * @mdc: MDC handle
 */
/* MTF_MOCK */
merr_t
mpool_mdc_cend(struct mpool_mdc *mdc);

/**
 * mpool_mdc_sync() - Sync the specified MDC
 *
 * @mdc: MDC handle
 */
/* MTF_MOCK */
merr_t
mpool_mdc_sync(struct mpool_mdc *mdc);

/**
 * mpool_mdc_usage() - Return mdc statistics
 *
 * @mdc:       MDC handle
 * @size:      MDC size
 * @allocated: Number of bytes allocated
 * @used:      Number of bytest used (includes overhead)
 */
/* MTF_MOCK */
merr_t
mpool_mdc_usage(struct mpool_mdc *mdc, uint64_t *size, uint64_t *allocated, uint64_t *used);

/******************************** MBLOCK APIs ************************************/

/**
 * mpool_mblock_alloc() - allocate an mblock
 *
 * @mp:     mpool
 * @mclass: media class
 * @flags:  mblock alloc flags
 * @mbid:   mblock object ID (output)
 * @props:  properties of new mblock (output) - will be returned if the ptr is non-NULL
 *
 * Return: %0 on success, <%0 on error
 */
/* MTF_MOCK */
merr_t
mpool_mblock_alloc(
    struct mpool *       mp,
    enum hse_mclass      mclass,
    uint32_t             flags,
    uint64_t *           mbid,
    struct mblock_props *props);

/**
 * mpool_mblock_commit() - commit an mblock
 *
 * @mp:   mpool
 * @mbid: mblock object ID
 *
 * Return: %0 on success, <%0 on error
 */
/* MTF_MOCK */
merr_t
mpool_mblock_commit(struct mpool *mp, uint64_t mbid);

/**
 * mpool_mblock_delete() - delete an committed mblock
 *
 * @mp:   mpool
 * @mbid: mblock object ID
 *
 * Return: %0 on success, <%0 on error
 */
/* MTF_MOCK */
merr_t
mpool_mblock_delete(struct mpool *mp, uint64_t mbid);

/**
 * mpool_mblock_props_get() - get properties of an mblock
 *
 * @mp:    mpool
 * @mbid:  mblock ojbect ID
 * @props: mblock properties (output)
 *
 * Return: %0 on success, <%0 on error
 */
/* MTF_MOCK */
merr_t
mpool_mblock_props_get(struct mpool *mp, uint64_t mbid, struct mblock_props *props);

/**
 * mpool_mblock_write() - write data to an mblock synchronously
 *
 * @mp:      mpool
 * @mbid:    mblock object ID
 * @iov:     iovec containing data to be written
 * @iov_cnt: iovec count
 *
 * Return: %0 on success, <%0 on error
 */
/* MTF_MOCK */
merr_t
mpool_mblock_write(struct mpool *mp, uint64_t mbid, const struct iovec *iov, int iovc);

/**
 * mpool_mblock_read() - read data from an mblock
 *
 * @mp:      mpool
 * @mbid:    mblock object ID
 * @iov:     iovec for output data
 * @iov_cnt: length of iov[]
 * @offset:  PAGE aligned offset into the mblock
 *
 * Return:
 * * On failure: <%0  - -ERRNO
 * * On success: >=%0 - number of bytes read
 */
/* MTF_MOCK */
merr_t
mpool_mblock_read(struct mpool *mp, uint64_t mbid, const struct iovec *iov, int iovc, off_t offset);

/**
 * mpool_mblock_clone() - clone the specified mblock
 *
 * @mp:       mpool
 * @mbid:     mblock object ID to clone from
 * @off:      start offset to clone from/to in the source/target mblock IDs
 * @len:      number of bytes to clone
 * @mbid_out: target mblock id (output)
 *
 * Requirements on `off' and `len':
 * - off must not be less than 0
 * - off and len must be page aligned
 * - len == 0 implies a clone of the entire source mblock from 'off' up to its written length
 * - off + len must not be greater than the mblock write length
 *
 * For the target mblock:
 * - is uncommitted
 * - write_len == off + len
 * - allocated_len >= write_len
 *
 * Notes:
 * - If off > 0 or len < source mblock's write_length then reading the target mblock from
 *   an offset range not covered by this clone operation returns zeroes
 *
 * Return: %0 on success, <%0 on error
 */
merr_t
mpool_mblock_clone(struct mpool *mp, uint64_t mbid, off_t off, size_t len, uint64_t *mbid_out);

/**
 * mpool_mblock_punch() - Punch a hole into the specified region of a committed mblock
 *
 * @mp:   mpool
 * @mbid: mblock object ID to punch
 * @off:  start offset
 * @len:  number of bytes to punch
 *
 * Requirements on `off' and `len':
 * - off must not be less than 0
 * - off and len must be page aligned
 * - len == 0 implies a punch of the entire mblock from 'off' up to its written length
 * - off + len must not be greater than wlen
 *
 * Notes:
 * - Reading an mblock from the punched region returns zeroes
 * - The mblock's wlen property is updated when the punched region covers the tail end of
 *   the mblock's written length
 * - The mblock's alen property is calculated on the fly by using the lseek(HOLE/DATA)
 *   technique, so it accounts for the punched regions in an mblock
 *
 * Return: %0 on success, <%0 on error
 */
merr_t
mpool_mblock_punch(struct mpool *mp, uint64_t mbid, off_t off, size_t len);

/**
 * mpool_mblock_mmap() - memory map an mblock in the virtual address space of the calling process
 *
 * @mp:       mpool
 * @mbid:     mblock id
 * @addr_out: mapped address (output)
 */
merr_t
mpool_mblock_mmap(struct mpool *mp, uint64_t mbid, const void **addr_out);

/**
 * mpool_mblock_munmap() - unmap an mblock
 *
 * @mp:   mpool
 * @mbid: mblock id
 */
merr_t
mpool_mblock_munmap(struct mpool *mp, uint64_t mbid);

/**
 * An mpool_file is a simple wrapper around mpool to manage files in a specified
 * mpool and media class.
 */

/**
 * mpool_file_open() - Open a file in the specified mpool and mclass
 *
 * @mp:     mpool handle
 * @mclass: which mclass the file belongs to
 * @name:   name of the file
 * @flags:  open(2) flags
 * @handle: mpool file handle (output)
 *
 * Return: %0 on success, merr_t on failure
 */
merr_t
mpool_file_open(
    struct mpool       *mp,
    enum hse_mclass   mclass,
    const char         *name,
    int                 flags,
    size_t              capacity,
    bool                sparse,
    struct mpool_file **handle);

/**
 * mpool_file_close() - Close an mpool file
 *
 * @file: mpool file handle
 */
merr_t
mpool_file_close(struct mpool_file *file);

/**
 * mpool_file_destroy() - Destroy an mpool file
 *
 * @mp:     mpool handle
 * @mclass: media class
 * @name:   file name
 */
merr_t
mpool_file_destroy(struct mpool *mp, enum hse_mclass mclass, const char *name);

/**
 * mpool_file_read() - Read an mpool file
 *
 * @file:   mpool file handle
 * @offset: read offset
 * @buf:    read buffer
 * @buflen: buffer len
 * @rdlen:  bytes read (output)
 */
merr_t
mpool_file_read(struct mpool_file *file, off_t offset, char *buf, size_t buflen, size_t *rdlen);

/**
 * mpool_file_write() - Write an mpool file
 *
 * @file:   mpool file handle
 * @offset: write offset
 * @buf:    write buffer
 * @buflen: buffer len
 * @wrlen:  bytes written (output)
 */
merr_t
mpool_file_write(
    struct mpool_file *file,
    off_t              offset,
    const char        *buf,
    size_t             buflen,
    size_t            *wrlen);

/**
 * mpool_file_sync() - Sync mpool file
 *
 * @file:   mpool file handle
 */
merr_t
mpool_file_sync(struct mpool_file *file);

/**
 * mpool_file_mmap() - mmap the given file
 *
 * @file:     mpool file handle
 * @read_only:   read-only
 * @addr_out: mapped addr
 */
merr_t
mpool_file_mmap(struct mpool_file *file, bool read_only, int advice, char **addr_out);

/**
 * mpool_file_size() - get mpool file size
 *
 * @file: mpool file handle
 */
size_t
mpool_file_size(struct mpool_file *file);

/**
 * mpool_mcpath_is_fsdax() - is the mclass path on a DAX filesystem
 *
 * @dpath: media class path
 * @isdax: return true if dax (output)
 */
merr_t
mpool_mcpath_is_fsdax(const char *path, bool *isdax);


#if HSE_MOCKING
#include "mpool_ut.h"
#endif /* HSE_MOCKING */

#endif /* MPOOL_H */
