/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MBLOCK_FILE_H
#define MPOOL_MBLOCK_FILE_H

#include <hse_util/hse_err.h>

#include "mclass.h"

#define MBID_FILEID_BITS (8)
#define MBID_MCID_BITS   (2)
#define MBID_BLOCK_BITS  (16)

#define MBLOCK_SIZE_MB    (32)
#define MBLOCK_SIZE_BYTES (MBLOCK_SIZE_MB << 20)
#define MBLOCK_SIZE_SHIFT (25)

#define MBLOCK_DATA_FILE_PFX "mblock-data"
#define MBLOCK_OPT_WRITE_SZ  (128 << 10)

#define MBLOCK_FILE_SIZE_MAX ((1ULL << MBID_BLOCK_BITS) << MBLOCK_SIZE_SHIFT)

/**
 * Mblock ID in-memory layout
 *
 * Bit-range    #Bits       Field
 * ---------    -----    -----------
 *  [63..32]     32      Uniquifier
 *  [31..24]      8      File ID
 *  [23..22]      2      Mclass ID
 *  [21..16]      6      Reserved
 *  [15..0]      16      Block offset
 */

#define MBID_UNIQ_SHIFT   (32)
#define MBID_FILEID_SHIFT (24)
#define MBID_MCID_SHIFT   (22)
#define MBID_RSVD_SHIFT   (16)

#define MBID_UNIQ_MASK   (0xffffffff00000000)
#define MBID_FILEID_MASK (0x00000000ff000000)
#define MBID_MCID_MASK   (0x0000000000c00000)
#define MBID_RSVD_MASK   (0x00000000003f0000)
#define MBID_BLOCK_MASK  (0x000000000000ffff)

struct mblock_mmap;
struct mblock_rgnmap;
struct mblock_fset;
struct mblock_file;
struct io_ops;

/**
 * struct mblock_filehdr - mblock file header stored in metadata file
 *
 * @uniq:   last persisted uniquifier
 * @fileid: file identifier
 * @rsvd1:
 * @rsvd2:
 */
struct mblock_filehdr {
    uint32_t uniq;
    uint8_t  fileid;
    uint8_t  rsvd1;
    uint16_t rsvd2;
};

/**
 * struct mblock_file_params - mblock file params
 *
 * @fszmax:   max file size
 * @mblocksz: mblock size
 * @fileid:   file identifier
 */
struct mblock_file_params {
    size_t fszmax;
    size_t mblocksz;
    int    fileid;
};

/**
 * struct mblock_file_stats - mblock file stats
 *
 * @allocated: allocated bytes
 * @used:      used bytes
 * @mbcnt:     mblock count
 */
struct mblock_file_stats {
    uint64_t allocated;
    uint64_t used;
    uint32_t mbcnt;
};

static __always_inline inline int
file_id(uint64_t mbid)
{
    return (mbid & MBID_FILEID_MASK) >> MBID_FILEID_SHIFT;
}

static __always_inline int
file_index(uint64_t mbid)
{
    return file_id(mbid) - 1;
}

static __always_inline enum mclass_id
mclassid(uint64_t mbid)
{
    return (mbid & MBID_MCID_MASK) >> MBID_MCID_SHIFT;
}

/**
 * mblock_file_open() - open an mblock file
 *
 * @mbfsp:     mblock fileset handle
 * @mc:        media class handle
 * @params:    mblock file params
 * @flags:     open flags
 * @meta_addr: mapped region in the mclass metadata file for this file
 * @handle:    mblock file handle (output)
 *
 */
merr_t
mblock_file_open(
    struct mblock_fset        *mbfsp,
    struct media_class        *mc,
    struct mblock_file_params *params,
    int                        flags,
    char                      *meta_addr,
    struct mblock_file       **handle);

/**
 * mblock_file_close() - close an mblock file
 *
 * @mbfp: mblock file handle
 */
void
mblock_file_close(struct mblock_file *mbfp);

/**
 * mblock_file_alloc() - allocate a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidc: count of objects to allocate
 * @mbidv: vector of mblock ids (output)
 */
merr_t
mblock_file_alloc(struct mblock_file *mbfp, int mbidc, uint64_t *mbidv);

/**
 * mblock_file_commit() - commit a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_file_commit(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_file_abort() - abort a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_file_abort(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_file_delete() - destroy a vector of mblock objects
 *
 * @mbfp:  mblock file handle
 * @mbidv  vector of mblock ids
 * @mbidc: count of mblock ids
 */
merr_t
mblock_file_delete(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc);

/**
 * mblock_file_read() - read an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 * @off:    offset
 */
merr_t
mblock_file_read(
    struct mblock_file *mbfp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off);

/**
 * mblock_file_write() - write an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 */
merr_t
mblock_file_write(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc);

/**
 * mblock_file_find() - test mblock's existence and return write length.
 *
 * @mbfp:  mblock file handle
 * @mbidv: vector of mblock ids
 * @mbidc: count of mblock ids
 * @wlen:  write length (output)
 */
merr_t
mblock_file_find(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, uint32_t *wlen);

/**
 * mblock_file_meta_len() - return meta length to track objects in an mblock file
 *
 * @fszmax:   max file size
 * @mblocksz: mblock size
 */
size_t
mblock_file_meta_len(size_t fszmax, size_t mblocksz);

/**
 * mblock_file_map_getbase() - get the mapped address and wlen for the specified mblock
 *
 * @mbfp:     mblock file handle
 * @mbid:     mblock id
 * @addr_out: mapped addr (output)
 * @wlen:     write length (output)
 */
merr_t
mblock_file_map_getbase(struct mblock_file *mbfp, uint64_t mbid, char **addr_out, uint32_t *wlen);

/**
 * mblock_file_unmap() - unmap the given mblock id
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 */
merr_t
mblock_file_unmap(struct mblock_file *mbfp, uint64_t mbid);

/**
 * mblock_file_stats_get() - get mblock file stats
 *
 * @mbfp:  mblock file handle
 * @stats: mblock file stats (output)
 */
merr_t
mblock_file_stats_get(struct mblock_file *mbfp, struct mblock_file_stats *stats);

#endif /* MPOOL_MBLOCK_FILE_H */
