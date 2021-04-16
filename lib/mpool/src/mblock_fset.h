/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MBLOCK_FSET_H
#define MPOOL_MBLOCK_FSET_H

#include <hse_util/hse_err.h>

#include "mblock_file.h"

#define MBLOCK_METAHDR_VERSION 1
#define MBLOCK_METAHDR_MAGIC   0xffaaccee

#define MBLOCK_FSET_FILES_MAX     (1 << MBID_FILEID_BITS)
#define MBLOCK_FSET_FILES_DEFAULT 32

struct mblock_file;
struct mblock_fset;

/**
 * struct mblock_metahdr - mblock meta header
 * stored at offset 0 in the metadata file which is one per media class
 *
 * @vers:      header version
 * @magic:     header magic
 * @fszmax_gb: max file size in GB
 * @mblksz_mb: mblock size in MB
 * @mcid:      mclass ID
 * @fcnt:      no. of data files per mclass
 * @blkbits:   no. of bits to track blocks allocated per file
 * @mcbits:    no. of bits to track media class
 */
struct mblock_metahdr {
    uint32_t vers;
    uint32_t magic;
    uint32_t fszmax_gb;
    uint16_t mblksz_mb;
    uint8_t  mcid;
    uint8_t  fcnt;
    uint8_t  blkbits;
    uint8_t  mcbits;
};

/**
 * mblock_fset_open() - open an mblock fileset
 *
 * @mc:     media class handle
 * @fcnt:   no. of mblock data file in the specified mclass
 * @fszmax: max file size
 * @flags:  open flags
 * @mbfsp:  mblock fileset handle (output)
 */
merr_t
mblock_fset_open(
    struct media_class  *mc,
    uint8_t              fcnt,
    size_t               fszmax,
    int                  flags,
    struct mblock_fset **mbfsp);

/**
 * mblock_fset_close() - close an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 */
void
mblock_fset_close(struct mblock_fset *mbfsp);

/**
 * mblock_fset_remove() - remove an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 */
void
mblock_fset_remove(struct mblock_fset *mbfsp);

/**
 * mblock_fset_alloc() - allocate object from an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 * @mbidc: mblock count (support only mbidc == 1)
 * @mbidv: mblock id (output)
 */
merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, int mbidc, uint64_t *mbidv);

/**
 * mblock_fset_commit() - commit mblocks
 *
 * @mbfsp: mblock fileset handle
 * @mbidv: mblock id
 * @mbidc: mblock count (support only mbidc == 1)
 */
merr_t
mblock_fset_commit(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc);

/**
 * mblock_fset_abort() - abort mblocks
 *
 * @mbfsp: mblock fileset handle
 * @mbidv: mblock id
 * @mbidc: mblock count (support only mbidc == 1)
 */
merr_t
mblock_fset_abort(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc);

/**
 * mblock_fset_delete() - delete mblocks
 *
 * @mbfsp: mblock fileset handle
 * @mbidv: mblock id
 * @mbidc: mblock count (support only mbidc == 1)
 */
merr_t
mblock_fset_delete(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc);

/**
 * mblock_fset_write() - write an mblock
 *
 * @mbfsp: mblock fileset handle
 * @mbid:  mblock id
 * @iov:   iovec ptr
 * @iovc:  iovec cnt
 */
merr_t
mblock_fset_write(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc);

/**
 * mblock_fset_read() - read an mblock
 *
 * @mbfsp: mblock fileset handle
 * @mbid:  mblock id
 * @iov:   iovec ptr
 * @iovc:  iovec cnt
 * @off:   offset to read from
 */
merr_t
mblock_fset_read(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off);

/**
 * mblock_fset_find() - find an mblock and return write length
 *
 * @mbfsp: mblock fileset handle
 * @mbidv: mblock id
 * @mbidc: mblock count (support only mbidc == 1)
 * @wlen:  write length of the specifid mblock (output)
 */
merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc, uint32_t *wlen);

/**
 * mblock_fset_getbase() - get the mapped address of the specified mblock
 *
 * @mbfsp:    mblock fileset handle
 * @mbid:     mblock id
 * @addr_out: mapped addr (output)
 * @wlen:     write length of the specifid mblock (output)
 */
merr_t
mblock_fset_map_getbase(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    char              **addr_out,
    uint32_t           *wlen);

/**
 * mblock_fset_unmap() - unmap the specified mblock
 *
 * @mbfsp: mblock fileset handle
 * @mbid:  mblock id
 */
merr_t
mblock_fset_unmap(
    struct mblock_fset *mbfsp,
    uint64_t            mbid);

/**
 * mblock_fset_stats_get() - retrieve stats of an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 * @stats: stats (output)
 */
merr_t
mblock_fset_stats_get(struct mblock_fset *mbfsp, struct mpool_mclass_stats *stats);

#endif /* MPOOL_MBLOCK_FSET_H */
