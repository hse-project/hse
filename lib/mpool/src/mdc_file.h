/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_MDC_FILE_H
#define MPOOL_MDC_FILE_H

#include <stdio.h>

#include <hse_util/hse_err.h>

#include "mclass.h"

#define MDC_LOGHDR_MAGIC   ((u32)0xdeadbeef)
#define MDC_LOGHDR_VERSION ((u32)1)
#define MDC_LOGHDR_LEN     (4096)
#define MDC_RA_BYTES       (128 << 10)
#define MDC_EXTEND_FACTOR  (8)

struct mpool_mdc;
struct mdc_file;

struct mdc_loghdr {
    uint32_t vers;
    uint32_t magic;
    uint64_t gen;
    uint32_t rsvd;
    uint32_t crc;
};

struct mdc_rechdr {
    uint64_t size;
    uint32_t crc;
};

merr_t
mdc_file_create(int dirfd, uint64_t logid, int flags, int mode, size_t capacity);

merr_t
mdc_file_destroy(int dirfd, uint64_t logid);

merr_t
mdc_file_commit(int dirfd, uint64_t logid);

merr_t
mdc_file_open(struct mpool_mdc *mdc, uint64_t logid, uint64_t *gen, struct mdc_file **handle);

merr_t
mdc_file_close(struct mdc_file *mfp);

merr_t
mdc_file_erase(struct mdc_file *mfp, uint64_t newgen);

merr_t
mdc_file_gen(struct mdc_file *mfp, uint64_t *gen);

merr_t
mdc_file_exists(int dirfd, uint64_t logid1, uint64_t logid2, bool *exist);

merr_t
mdc_file_sync(struct mdc_file *mfp);

merr_t
mdc_file_rewind(struct mdc_file *mfp);

merr_t
mdc_file_usage(struct mdc_file *mfp, size_t *usage);

merr_t
mdc_file_read(struct mdc_file *mfp, void *data, size_t len, size_t *rdlen, bool verify);

merr_t
mdc_file_append(struct mdc_file *mfp, void *data, size_t len, bool sync);

static inline uint64_t
logid_make(u8 fid, enum mclass_id mcid, uint32_t magic)
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

static inline uint8_t
logid_fid(uint64_t logid)
{
    return (logid >> 34) & 1;
}

static inline bool
logids_valid(uint64_t logid1, uint64_t logid2)
{
    return (logid1 != logid2 &&
            logid_magic(logid1) == logid_magic(logid2) &&
            logid_fid(logid1) + 1 == logid_fid(logid2) &&
            logid_mcid(logid1) == logid_mcid(logid2));
}

static inline void
mdc_filename_gen(char *buf, size_t buflen, uint64_t logid)
{
    snprintf(buf, buflen, "%s-%lx", "mdc", logid);
}

#endif /* MPOOL_MDC_FILE_H */
