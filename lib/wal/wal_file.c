/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>

#include "wal.h"
#include "wal_file.h"

struct wal_file {
    struct wal        *wal;
    struct mpool_file *mpf;

    uint64_t dgen;
    off_t    roff;
    off_t    woff;

    int      fileid;
    char     name[PATH_MAX];
};

merr_t
wal_file_create(
    struct wal        *wal,
    enum mpool_mclass  mclass,
    size_t             capacity,
    uint64_t           dgen,
    int                fileid)
{
    merr_t err;
    char name[PATH_MAX];

    if (!wal)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", "wal", dgen, fileid);

    err = mpool_file_create(wal->mp, mclass, name, capacity, true);
    if (err)
        return err;

    return 0;
}

merr_t
wal_file_destroy(struct wal *wal, enum mpool_mclass mclass, uint64_t dgen, int fileid)
{
    char name[PATH_MAX];

    if (!wal)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", "wal", dgen, fileid);

    return mpool_file_destroy(wal->mp, mclass, name);
}

merr_t
wal_file_open(
    struct wal        *wal,
    enum mpool_mclass  mclass,
    uint64_t           dgen,
    int                fileid,
    struct wal_file  **handle)
{
    struct wal_file   *walf;
    struct mpool_file *file;
    merr_t err;
    char name[PATH_MAX];

    if (!wal)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", "wal", dgen, fileid);

    err = mpool_file_open(wal->mp, mclass, name, O_RDWR, &file);
    if (err)
        return err;

    walf = calloc(1, sizeof(*walf));
    if (!walf) {
        mpool_file_close(file);
        return merr(ENOMEM);
    }

    walf->wal = wal;
    walf->mpf = file;
    walf->dgen = dgen;
    walf->fileid = fileid;
    walf->roff = 0;
    walf->woff = 0;

    return 0;
}

merr_t
wal_file_close(struct wal_file *walf)
{
    merr_t err;

    if (!walf)
        return merr(EINVAL);

    err = mpool_file_close(walf->mpf);
    if (err)
        return err;

    free(walf);

    return 0;
}

merr_t
wal_file_read(struct wal_file *walf, char *buf, size_t buflen)
{
    merr_t err;
    size_t rdlen;

    if (!walf)
        return merr(EINVAL);

    err = mpool_file_read(walf->mpf, walf->roff, buf, buflen, &rdlen);
    if (err)
        return err;

    walf->roff += rdlen;

    return 0;
}

merr_t
wal_file_write(struct wal_file *walf, const char *buf, size_t buflen)
{
    merr_t err;

    if (!walf)
        return merr(EINVAL);

    err = mpool_file_write(walf->mpf, walf->woff, buf, buflen);
    if (err)
        return err;

    walf->woff += buflen;

    return 0;
}
