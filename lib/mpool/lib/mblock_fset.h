/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MBLOCK_FSET_H
#define MPOOL_MBLOCK_FSET_H

#include <sys/uio.h>

#include <hse/error/merr.h>

#include "mblock_file.h"

/* clang-format off */

#define MBLOCK_METAHDR_MAGIC       (0xffaacceeU)

/* clang-format on */

struct mblock_file;
struct mblock_fset;

/**
 * struct mblock_metahdr - mblock meta header
 * stored at offset 0 in the metadata file which is one per media class
 *
 * @vers:    header version
 * @magic:   header magic
 * @fszmax:  max file size in bytes
 * @mblksz:  mblock size in bytes
 * @mcid:    mclass ID
 * @fcnt:    no. of data files per mclass
 * @blkbits: no. of bits to track blocks allocated per file
 * @mcbits:  no. of bits to track media class
 * @gclose:  was mpool closed gracefully in the previous instantiation
 */
struct mblock_metahdr {
    uint32_t vers;
    uint32_t magic;
    uint64_t fszmax;
    uint64_t mblksz;
    uint8_t  mcid;
    uint8_t  fcnt;
    uint8_t  blkbits;
    uint8_t  mcbits;
    bool     gclose;
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
 * mblock_fset_alloc() - allocate object from an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 * @flags: mblock alloc flags
 * @mbidc: mblock count (support only mbidc == 1)
 * @mbidv: mblock id (output)
 */
merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, uint32_t flags, int mbidc, uint64_t *mbidv);

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
mblock_fset_write(struct mblock_fset *mbfsp, uint64_t mbid, const struct iovec *iov, int iovc);

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
 * mblock_fset_find() - find an mblock and return props
 *
 * @mbfsp: mblock fileset handle
 * @mbidv: mblock id
 * @mbidc: mblock count (support only mbidc == 1)
 * @props: mblock props (output)
 */
merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc, struct mblock_props *props);

/**
 * mblock_fset_getbase() - get the mapped address of the specified mblock
 *
 * @mbfsp:    mblock fileset handle
 * @mbid:     mblock id
 * @addr_out: mapped addr (output)
 * @wlen:     write length of the specifid mblock (output)
 */
merr_t
mblock_fset_map_getbase(struct mblock_fset *mbfsp, uint64_t mbid, char **addr_out, uint32_t *wlen);

/**
 * mblock_fset_unmap() - unmap the specified mblock
 *
 * @mbfsp: mblock fileset handle
 * @mbid:  mblock id
 */
merr_t
mblock_fset_unmap(struct mblock_fset *mbfsp, uint64_t mbid);

/**
 * mblock_fset_info_get() - retrieve info of an mblock fileset
 *
 * @mbfsp: mblock fileset handle
 * @info: info (output)
 */
merr_t
mblock_fset_info_get(struct mblock_fset *mbfsp, struct hse_mclass_info *info);

/** @brief Get file count.
 *
 * @param mbfsp: mblock fileset handle.
 *
 * @returns File count.
 */
uint8_t
mblock_fset_filecnt_get(const struct mblock_fset *mbfsp);

/** @brief Get file max size.
 *
 * @param mbfsp: mblock fileset handle.
 *
 * @returns File max size.
 */
size_t
mblock_fset_fmaxsz_get(const struct mblock_fset *const mbfsp);

/**
 * mblock_fset_clone() - clone an mblock
 *
 * @mbfsp:    mblock fileset handle
 * @mbid:     source mblock id
 * @off:      start offset to clone from/to in the source/target mblock IDs
 * @len:      number of bytes to clone
 * @mbid_out: target mblock id (output)
 */
merr_t
mblock_fset_clone(
    struct mblock_fset *mbfsp,
    uint64_t            src_mbid,
    off_t               off,
    size_t              len,
    uint64_t           *mbid_out);

/**
 * mblock_fset_punch() - punch an mblock
 *
 * @mbfsp: mblock fileset handle
 * @mbid:  mblock id
 * @off:   start offset
 * @len:   number of bytes to punch
 */
merr_t
mblock_fset_punch(struct mblock_fset *mbfsp, uint64_t mbid, off_t off, size_t len);

#endif /* MPOOL_MBLOCK_FSET_H */
