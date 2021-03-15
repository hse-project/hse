/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
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
 * @mc:             media class handle
 * @flags:          open flags
 * @mbfsp (output): mblock fileset handle
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

merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, int mbidc, uint64_t *mbidv);

merr_t
mblock_fset_commit(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc);

merr_t
mblock_fset_abort(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc);

merr_t
mblock_fset_delete(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc);

merr_t
mblock_fset_write(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc);

merr_t
mblock_fset_read(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off);

merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc, uint32_t *wlen);

merr_t
mblock_fset_map_getbase(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    char              **addr_out,
    uint32_t           *wlen);

merr_t
mblock_fset_unmap(
    struct mblock_fset *mbfsp,
    uint64_t            mbid);

#endif /* MPOOL_MBLOCK_FSET_H */
