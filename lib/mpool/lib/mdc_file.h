/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef MPOOL_MDC_FILE_H
#define MPOOL_MDC_FILE_H

#include <stdint.h>
#include <stdio.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/omf_version.h>

#include "mclass.h"

#define MDC_LOGHDR_MAGIC  (0xdeadbeefU)
#define MDC_LOGHDR_LEN    (4096)
#define MDC_RA_BYTES      (128u << KB_SHIFT)
#define MDC_EXTEND_FACTOR (8)
#define MDC_FILE_PFX      "mdc"

struct mpool_mdc;
struct mdc_file;

/**
 * struct mdc_loghdr - MDC file header
 *
 * @vers:  MDC file version
 * @magic: MDC file magic
 * @gen:   generation
 * @crc:   header CRC
 */
struct mdc_loghdr {
    uint32_t vers;
    uint32_t magic;
    uint64_t gen;
    uint32_t crc;
};

/**
 * struct mdc_rechdr - MDC record header
 *
 * @size: record length
 * @crc:  record CRC
 */
struct mdc_rechdr {
    uint64_t size;
    uint32_t crc;
};

static inline uint64_t
logid_make(uint8_t fid, enum mclass_id mcid, uint32_t magic)
{
    return (uint64_t)fid << 34 | (uint64_t)mcid << 32 | magic;
}

static inline uint32_t
logid_magic(uint64_t logid)
{
    return logid & UINT_MAX;
}

static inline uint8_t
logid_mcid(uint64_t logid)
{
    return (logid >> 32) & 3;
}

static inline enum hse_mclass
logid_mclass(uint64_t logid)
{
    return mcid_to_mclass(logid_mcid(logid));
}

static inline uint8_t
logid_fid(uint64_t logid)
{
    return (logid >> 34) & 1;
}

static inline bool
logids_valid(uint64_t logid1, uint64_t logid2)
{
    return (
        logid1 != logid2 && logid_magic(logid1) == logid_magic(logid2) &&
        logid_fid(logid1) + 1 == logid_fid(logid2) && logid_mcid(logid1) == logid_mcid(logid2));
}

static inline void
mdc_filename_gen(char *buf, size_t buflen, uint64_t logid)
{
    snprintf(buf, buflen, "%s-%lx", MDC_FILE_PFX, logid);
}

/**
 * mdc_file_create() - create an MDC file
 *
 * @dirfd:    directory fd
 * @name:     MDC file name
 * @flags:    file creation flags
 * @mode:     file creation mode
 * @mclass:   media class used for MDC file
 * @capacity: capacity (bytes)
 */
merr_t
mdc_file_create(
    int dirfd,
    const char *name,
    int flags,
    int mode,
    enum hse_mclass mclass,
    size_t capacity);

/**
 * mdc_file_destroy() - destroy an MDC file
 *
 * @dirfd: directory fd
 * @name: MDC file name
 */
merr_t
mdc_file_destroy(int dirfd, const char *name);

/**
 * mdc_file_commit() - commit an MDC file
 *
 * @dirfd: directory fd
 * @name: MDC file name
 */
merr_t
mdc_file_commit(int dirfd, const char *name);

/**
 * mdc_file_open() - open an MDC file
 *
 * @mdc:    mdc handle
 * @dirfd:  directory fd
 * @name:   MDC file name
 * @logid:  MDC file id
 * @rdonly: read-only open
 * @gen:    MDC file gen (output)
 * @handle: MDC file handle (output)
 */
merr_t
mdc_file_open(
    struct mpool_mdc *mdc,
    int dirfd,
    const char *name,
    uint64_t logid,
    bool rdonly,
    bool gclose,
    uint64_t *gen,
    struct mdc_file **handle);

/**
 * mdc_file_close() - close an MDC file
 *
 * @mfp: mdc file handle
 */
merr_t
mdc_file_close(struct mdc_file *mfp);

/**
 * mdc_file_erase() - erase an MDC file
 *
 * @mfp:    mdc file handle
 * @newgen: new mdc file generation
 */
merr_t
mdc_file_erase(struct mdc_file *mfp, uint64_t newgen);

/**
 * mdc_file_gen() - retrieve gen of an mdc file
 *
 * @mfp: mdc file handle
 * @gen: mdc file generation (output)
 */
merr_t
mdc_file_gen(struct mdc_file *mfp, uint64_t *gen);

/**
 * mdc_file_exists() - check whether an MDC file exists
 *
 * @dirfd:  directory fd
 * @name1:  MDC file name 1
 * @name2:  MDC file name 2
 * @exist:  whether MDC file exists? (output)
 */
merr_t
mdc_file_exists(int dirfd, const char *name1, const char *name2, bool *exist);

/**
 * mdc_file_sync() - sync an MDC file
 *
 * @mfp: mdc file handle
 */
merr_t
mdc_file_sync(struct mdc_file *mfp);

/**
 * mdc_file_rewind() - rewind an MDC file
 *
 * @mfp: mdc file handle
 */
merr_t
mdc_file_rewind(struct mdc_file *mfp);

/**
 * mdc_file_stats() - get stats of an MDC file
 *
 * @mfp:       mdc file handle
 * @size:      mdc file size
 * @allocated: allocated space in bytes (output)
 * @used:      used space in bytes (output)
 *
 */
merr_t
mdc_file_stats(struct mdc_file *mfp, uint64_t *size, uint64_t *allocated, uint64_t *used);

/**
 * mdc_file_read() - read an MDC file
 *
 * @mfp:    mdc file handle
 * @data:   buffer
 * @len:    buffer length
 * @verify: enable/disable CRC verification during read
 * @rdlen:  read length (output)
 */
merr_t
mdc_file_read(struct mdc_file *mfp, void *data, size_t len, bool verify, size_t *rdlen);

/**
 * mdc_file_append() - append an MDC file
 *
 * @mfp:  mdc file handle
 * @data: buffer
 * @len:  buffer length
 * @sync: sync or async append
 */
merr_t
mdc_file_append(struct mdc_file *mfp, void *data, size_t len, bool sync);

#endif /* MPOOL_MDC_FILE_H */
