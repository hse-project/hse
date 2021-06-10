/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_FILE_H
#define WAL_FILE_H

#include <hse_util/hse_err.h>

#include <mpool/mpool.h>

struct wal;
struct wal_file;


merr_t
wal_file_open(
    struct mpool      *mp,
    enum mpool_mclass  mclass,
    uint64_t           dgen,
    int                fileid,
    size_t             capacity,
    struct wal_file  **handle);

merr_t
wal_file_close(struct wal_file *walf);

void
wal_file_get(struct wal_file *walf);

void
wal_file_put(struct wal_file *walf);

merr_t
wal_file_destroy(struct mpool *mp, enum mpool_mclass mclass, uint64_t dgen, int fileid);

merr_t
wal_file_read(struct wal_file *walf, char *buf, size_t buflen);

merr_t
wal_file_write(struct wal_file *walf, const char *buf, size_t buflen);

#endif /* WAL_FILE_H */
