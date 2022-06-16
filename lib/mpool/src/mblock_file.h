/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MBLOCK_FILE_H
#define MPOOL_MBLOCK_FILE_H

#include <rbtree.h>
#include <hse_util/hse_err.h>

#include "mclass.h"

/* clang-format off */

#define MBID_FILEID_BITS       (8)
#define MBID_MCID_BITS         (2)
#define MBID_BLOCK_BITS        (16)

#define MBLOCK_FILE_PFX        "mblock"

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

/*
 * The most significant bit of wlen (both in-memory and on-media) indicates whether an mblock
 * is pre-allocated (1) or not (0).
 */
#define MBLOCK_WLEN_PREALLOC_SHIFT (31)
#define MBLOCK_WLEN_MASK           (0x7fffffffU)


_Static_assert(((1 << MBID_FILEID_BITS) - 1) == (MPOOL_MCLASS_FILECNT_MAX),
	       "MBID_FILEID_BITS and MPOOL_MCLASS_FILECNT_MAX mismatch");

/* clang-format on */

struct mblock_mmap;
struct mblock_rgnmap;
struct mblock_fset;
struct mblock_file;
struct kmem_cache;
struct io_ops;

/**
 * struct mblock_filehdr - mblock file header stored in metadata file
 *
 * @uniq:   last persisted uniquifier
 * @fileid: file identifier
 */
struct mblock_filehdr {
    uint32_t uniq;
    uint8_t  fileid;
};

/**
 * struct mblock_file_params - mblock file params
 *
 * @rmcache:     region map cache
 * @metaio:      io backend to use for metadata operations
 * @meta_addr:   start of memory-mapped region in the metadata file
 * @meta_ugaddr: start of memory-mapped region in the target metadata file (for upgrade)
 * @fszmax:      max file size
 * @mblocksz:    mblock size
 * @fileid:      file identifier
 * @gclose:      was mpool gracefully closed in the prior instance
 */
struct mblock_file_params {
    struct kmem_cache *rmcache;
    struct io_ops     *metaio;
    char  *meta_addr;
    char  *meta_ugaddr;
    size_t fszmax;
    size_t mblocksz;
    int    fileid;
    bool   gclose;
};

/**
 * struct mblock_file_info - mblock file info
 *
 * @allocated: allocated bytes
 * @used:      used bytes
 * @mbcnt:     mblock count
 */
struct mblock_file_info {
    uint64_t allocated;
    uint64_t used;
};

/**
 * struct mblock_file_mbinfo - mblock info
 *
 * @fd:   mblock file descriptor
 * @off:  file offset at which the mblock of interest is allocated from
 * @wlen: number of bytes written to the mblock of interest
 */
struct mblock_file_mbinfo {
    int fd;
    off_t off;
    size_t wlen;
};

/**
 * struct mblock_rgn -
 *
 * @rgn_node:  rb-tree linkage
 * @rgn_start: first available key
 * @rgn_end:   last available key (not inclusive)
 */
struct mblock_rgn {
    struct rb_node rgn_node;
    uint32_t       rgn_start;
    uint32_t       rgn_end;
};

/**
 * struct mblock_oid_info -
 *
 * @mb_oid:  mblock OID
 * @mb_wlen: mblock write length
 */
struct mblock_oid_info {
    uint64_t mb_oid;
    uint32_t mb_wlen;
};

static HSE_ALWAYS_INLINE int
file_id(uint64_t mbid)
{
    return (mbid & MBID_FILEID_MASK) >> MBID_FILEID_SHIFT;
}

static HSE_ALWAYS_INLINE int
file_index(uint64_t mbid)
{
    return file_id(mbid) - 1;
}

static HSE_ALWAYS_INLINE enum mclass_id
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
 * @version:   on-media mblock meta header version
 * @handle:    mblock file handle (output)
 *
 */
merr_t
mblock_file_open(
    struct mblock_fset        *mbfsp,
    struct media_class        *mc,
    struct mblock_file_params *params,
    int                        flags,
    uint32_t                   version,
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
 * @flags: mblock alloc flags
 * @mbidc: count of objects to allocate
 * @mbidv: vector of mblock ids (output)
 */
merr_t
mblock_file_alloc(struct mblock_file *mbfp, uint32_t flags, int mbidc, uint64_t *mbidv);

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
 * mblock_read() - read an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 * @off:    offset
 */
merr_t
mblock_read(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc, off_t off);

/**
 * mblock_write() - write an mblock object
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 * @iov:    iovec ptr
 * @iovc:   iov count
 */
merr_t
mblock_write(struct mblock_file *mbfp, uint64_t mbid, const struct iovec *iov, int iovc);

/**
 * mblock_file_find() - test mblock's existence and return props
 *
 * @mbfp:  mblock file handle
 * @mbidv: vector of mblock ids
 * @mbidc: count of mblock ids
 * @props: mblock props
 */
merr_t
mblock_file_find(struct mblock_file *mbfp, uint64_t *mbidv, int mbidc, struct mblock_props *props);

/**
 * mblock_file_meta_len() - return meta length to track objects in an mblock file
 *
 * @fszmax:   max file size
 * @mblocksz: mblock size
 * @version:  mblock meta header version
 */
size_t
mblock_file_meta_len(size_t fszmax, size_t mblocksz, uint32_t version);

/**
 * mblock_map_getbase() - get the mapped address and wlen for the specified mblock
 *
 * @mbfp:     mblock file handle
 * @mbid:     mblock id
 * @addr_out: mapped addr (output)
 * @wlen:     write length (output)
 */
merr_t
mblock_map_getbase(struct mblock_file *mbfp, uint64_t mbid, char **addr_out, uint32_t *wlen);

/**
 * mblock_unmap() - unmap the given mblock id
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock id
 */
merr_t
mblock_unmap(struct mblock_file *mbfp, uint64_t mbid);

/**
 * mblock_file_info_get() - get mblock file info
 *
 * @mbfp:  mblock file handle
 * @info: mblock file info (output)
 */
merr_t
mblock_file_info_get(const struct mblock_file *mbfp, struct mblock_file_info *info);

/**
 * mblock_info_get() - get an mblock info from the mblock data file
 *
 * @mbfp:   mblock file handle
 * @mbid:   mblock ID
 * @mbinfo: mblock info (output)
 */
merr_t
mblock_info_get(struct mblock_file *mbfp, uint64_t mbid, struct mblock_file_mbinfo *mbinfo);

/**
 * mblock_wlen_set() - set the write length of an mblock (used by mblock clone)
 *
 * @mbfp:     mblock file handle
 * @mbid:     mblock ID
 * @wlen:     write length
 * @prealloc: preallocated mblock?
 */
void
mblock_wlen_set(struct mblock_file *mbfp, uint64_t mbid, uint32_t wlen, bool prealloc);

#endif /* MPOOL_MBLOCK_FILE_H */
