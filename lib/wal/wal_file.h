/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_FILE_H
#define WAL_FILE_H

#include <hse_util/hse_err.h>

#include <mpool/mpool.h>

struct wal;
struct wal_fileset;
struct wal_file;

struct wal_fileset *
wal_fileset_open(struct mpool *mp, enum mpool_mclass mclass, size_t capacity, u32 magic, u32 vers);

void
wal_fileset_close(struct wal_fileset *wfset, u64 ingestseq, u64 ingestgen, u64 txhorizon);

merr_t
wal_file_open(struct wal_fileset *wfset, uint64_t gen, int fileid, struct wal_file **handle);

merr_t
wal_file_close(struct wal_file *walf);

void
wal_file_get(struct wal_file *walf);

void
wal_file_put(struct wal_file *walf);

merr_t
wal_file_destroy(struct wal_fileset *wfset, uint64_t gen, int fileid);

merr_t
wal_file_read(struct wal_file *walf, char *buf, size_t len);

merr_t
wal_file_write(struct wal_file *wfile, const char *buf, size_t len);

void
wal_file_minmax_update(struct wal_file *wfile, struct wal_minmax_info *info);

merr_t
wal_fileset_reclaim(struct wal_fileset *wfset, u64 seqno, u64 gen, u64 txhorizon, bool closing);

merr_t
wal_file_complete(struct wal_fileset *wfset, struct wal_file *wfile);

#endif /* WAL_FILE_H */
