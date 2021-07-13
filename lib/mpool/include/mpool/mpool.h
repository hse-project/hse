/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_H
#define MPOOL_H

#include <mpool/mpool_structs.h>

#include <hse_util/hse_err.h>

#define MPOOL_CAPACITY_MCLASS_DEFAULT_PATH "capacity"

struct mpool;            /* opaque mpool handle */
struct mpool_mdc;        /* opaque MDC (metadata container) handle */
struct mpool_mcache_map; /* opaque mcache map handle */
struct mpool_file;       /* opaque mpool file handle */

/* MTF_MOCK_DECL(mpool) */

/*
 * Mpool Administrative APIs...
 */

/**
 * mpool_create() - Create an mpool
 *
 * @name:   kvdb home
 * @params: mpool cparams
 */
/* MTF_MOCK */
merr_t
mpool_create(const char *home, const struct mpool_cparams *params);

/**
 * mpool_mclass_add() - Add a media class to the mpool
 *
 * @name:   kvdb home
 * @mclass  mclass id
 * @params: mpool cparams
 */
merr_t
mpool_mclass_add(
    const char *                home,
    enum mpool_mclass           mclass,
    const struct mpool_cparams *params);

/**
 * mpool_open() - Open an mpool
 *
 * @home: mpool home
 * @params: mpool rparams
 * @flags:  open flags
 * @mp:     mpool handle (output)
 *
 * Flags are limited to a subset of flags allowed by open(2):
 * O_CREAT, O_RDONLY, O_WRONLY, and O_RDWR.
 */
/* MTF_MOCK */
merr_t
mpool_open(
    const char                 *home,
    const struct mpool_rparams *params,
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
 * @name:   mpool name
 * @params: mpool dparams
 */
/* MTF_MOCK */
merr_t
mpool_destroy(const char *name, const struct mpool_dparams *params);

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
    enum mpool_mclass          mclass,
    struct mpool_mclass_props *props);

/**
 * mpool_mclass_stats_get() - get storage stats of the specified media class
 *
 * @mp:     mpool descriptor
 * @mclass: input media mclass
 * @stats:  media class storage stats (output)
 *
 * Returns: 0 for success
 *          non-zero(err): merr_errno(err) == ENOENT if the specified mclass is not present
 */
/* MTF_MOCK */
merr_t
mpool_mclass_stats_get(
    struct mpool *             mp,
    enum mpool_mclass          mclass,
    struct mpool_mclass_stats *stats);

/**
 * mpool_mclass_ftw() - walk files in 'mclass' and invoke cb for each file matching 'prefix'
 *
 * @mp:     mpool descriptor
 * @mclass: enum mpool_mclass
 * @prefix: file prefix
 * @cb:     instance of struct mpool_file_cb
 */
merr_t
mpool_mclass_ftw(
    struct mpool         *mp,
    enum mpool_mclass     mclass,
    const char           *prefix,
    struct mpool_file_cb *cb);

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
 * mpool_stats_get() - Get mpool storage stats
 *
 * @mp:    mpool handle
 * @stats: mpool stats (output)
 */
merr_t
mpool_stats_get(struct mpool *mp, struct mpool_stats *stats);

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
    enum mpool_mclass mclass,
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
 * mpool_mdc_rootid_get() - Retrieve mpool root MDC OIDs
 *
 * @logid1: logid 1
 * @logid2: logid 2
 */
/* MTF_MOCK */
merr_t
mpool_mdc_rootid_get(uint64_t *logid1, uint64_t *logid2);


/**
 * mpool_mdc_root_open() - Open root MDC
 *
 * @home:   kvdb home
 * @logid1: logid 1
 * @logid2: logid 2
 * @handle: MDC handle (output)
 */
/* MTF_MOCK */
merr_t
mpool_mdc_root_open(const char *home, uint64_t logid1, uint64_t logid2, struct mpool_mdc **handle);

/**
 * mpool_mdc_root_create() - initialize the root MDC
 *
 * @home: kvdb home
 */
/* MTF_MOCK */
merr_t
mpool_mdc_root_create(const char *home);

/**
 * mpool_mdc_root_destroy() - Destroy root MDC
 *
 * @home:   kvdb home
 * @logid1: logid 1
 * @logid2: logid 2
 */
/* MTF_MOCK */
merr_t
mpool_mdc_root_destroy(const char *home, uint64_t logid1, uint64_t logid2);

/**
 * mpool_mdc_open() - Open MDC by OIDs
 *
 * @mp:     mpool handle
 * @logid1: logid 1
 * @logid2: logid 2
 * @handle: MDC handle (output)
 */
/* MTF_MOCK */
merr_t
mpool_mdc_open(struct mpool *mp, uint64_t logid1, uint64_t logid2, struct mpool_mdc **handle);

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
merr_t
mpool_mdc_sync(struct mpool_mdc *mdc);

/**
 * mpool_mdc_usage() - Return mdc statistics
 *
 * @mdc:       MDC handle
 * @allocated: Number of bytes allocated
 * @used:      Number of bytest used (includes overhead)
 */
/* MTF_MOCK */
merr_t
mpool_mdc_usage(struct mpool_mdc *mdc, uint64_t *allocated, uint64_t *used);

/******************************** MBLOCK APIs ************************************/

/**
 * mpool_mblock_alloc() - allocate an mblock
 *
 * @mp:     mpool
 * @mclass: media class
 * @mbid:   mblock object ID (output)
 * @props:  properties of new mblock (output) - will be returned if the ptr is non-NULL
 *
 * Return: %0 on success, <%0 on error
 */
/* MTF_MOCK */
merr_t
mpool_mblock_alloc(
    struct mpool *       mp,
    enum mpool_mclass    mclass,
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
 * mpool_mblock_abort() - abort an mblock
 *
 * @mp:   mpool
 * @mbid: mblock object ID
 *
 * mblock must have been allocated but not yet committed.
 *
 * Return: %0 on success, <%0 on error
 */
/* MTF_MOCK */
merr_t
mpool_mblock_abort(struct mpool *mp, uint64_t mbid);

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

/******************************** MCACHE APIs ************************************/

/**
 * mpool_mcache_madvise() - Give advice about use of memory
 *
 * @map:    mcache map handle
 * @mbidx:  logical mblock number in mcache map
 * @offset: offset into the mblock specified by mbidx
 * @length: see madvise(2)
 * @advice: see madvise(2)
 *
 * Like madvise(2), but for mcache maps.
 *
 * Note that one can address the entire map (including holes) by
 * specifying zero for %mbidx, zero for %offset, and %SIZE_MAX for
 * %length.  In general, %SIZE_MAX may always be specified for %length,
 * in which case it addresses the map from the given mbidx based offset
 * to the end of the map.
 */
/* MTF_MOCK */
merr_t
mpool_mcache_madvise(
    struct mpool_mcache_map *map,
    uint32_t                 mbidx,
    off_t                    offset,
    size_t                   length,
    int                      advice);

/**
 * mpool_mcache_getbase() - Get the base address of a memory-mapped mblock in an mcache map
 *
 * @map:   mcache map handle
 * @mbidx: mcache map mblock index
 *
 * If the pages of an mcache map are contiguous in memory (as is the case in
 * user-space), return the the base address of the mapped mblock.  If the
 * pages are not contiguous, return NULL.
 */
/* MTF_MOCK */
void *
mpool_mcache_getbase(struct mpool_mcache_map *map, const uint32_t mbidx);

/**
 * mpool_mcache_getpages() - Get a vector of pages from a single mblock
 *
 * @map:     mcache map handle
 * @pagec:   page count (len of @pagev array)
 * @mbidx:   mcache map mblock index
 * @offsetv: vector of page offsets into objects/mblocks
 * @pagev:   vector of pointers to pages (output)
 *
 * mbidx is an index into the mbidv[] vector that was given to mpool_mcache_create().
 *
 * Return: %0 on success, merr_t on failure
 */
/* MTF_MOCK */
merr_t
mpool_mcache_getpages(
    struct mpool_mcache_map *map,
    const uint32_t           pagec,
    const uint32_t           mbidx,
    const off_t              offsetv[],
    void *                   pagev[]);

/**
 * mpool_mcache_mmap() - Create an mcache map
 *
 * @mp:    handle for the mpool
 * @mbidc: mblock ID count
 * @mbidv: vector of mblock IDs
 * @mapp:  pointer to (opaque) mpool_mcache_map ptr
 *
 * Create an mcache map for the list of given mblock IDs and returns a handle to it via *mapp.
 */
/* MTF_MOCK */
merr_t
mpool_mcache_mmap(struct mpool *mp, size_t mbidc, uint64_t *mbidv, struct mpool_mcache_map **mapp);

/**
 * mpool_mcache_munmap() - munmap an mcache mmap
 *
 * @map:
 */
/* MTF_MOCK */
void
mpool_mcache_munmap(struct mpool_mcache_map *map);

/**
 * mpool_mcache_purge() - Purge map (NOT SUPPORTED)
 *
 * @map: mcache map handle
 * @mp:  mp mpool
 */
/* MTF_MOCK */
merr_t
mpool_mcache_purge(struct mpool_mcache_map *map, const struct mpool *mp);

/**
 * mpool_mcache_mincore() - Get VSS and RSS for the mcache map (NOT SUPPORTED)
 *
 * @map:  mcache map handle
 * @mp:   mpool handle
 * @rssp: ptr to count of resident pages in the map
 * @vssp: ptr to count of virtual pages in the map
 *
 * Get the virtual and resident set sizes (in pages count)
 * for the given mcache map.
 */
/* MTF_MOCK */
merr_t
mpool_mcache_mincore(
    struct mpool_mcache_map *map,
    const struct mpool *     mp,
    size_t *                 rssp,
    size_t *                 vssp);

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
    enum mpool_mclass   mclass,
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
mpool_file_destroy(struct mpool *mp, enum mpool_mclass mclass, const char *name);

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
 * @rdonly:   read-only
 * @addr_out: mapped addr
 */
merr_t
mpool_file_mmap(struct mpool_file *file, bool rdonly, int advice, char **addr_out);

/**
 * mpool_file_size() - get mpool file size
 *
 * @file: mpool file handle
 */
size_t
mpool_file_size(struct mpool_file *file);

#if HSE_MOCKING
#include "mpool_ut.h"
#endif /* HSE_MOCKING */

#endif /* MPOOL_H */
