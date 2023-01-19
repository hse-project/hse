/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_FILE_H
#define WAL_FILE_H

#include <hse/error/merr.h>
#include <hse/mpool/mpool.h>

struct wal;
struct wal_fileset;
struct wal_file;
struct wal_replay_gen_info;
struct wal_replay_info;

struct wal_fileset *
wal_fileset_open(
    struct mpool *mp,
    enum hse_mclass mclass,
    size_t capacity,
    uint32_t magic,
    uint32_t vers);

void
wal_fileset_close(
    struct wal_fileset *wfset,
    uint64_t ingestseq,
    uint64_t ingestgen,
    uint64_t txhorizon);

void
wal_fileset_mclass_set(struct wal_fileset *wfset, enum hse_mclass mclass);

void
wal_fileset_version_set(struct wal_fileset *wfset, uint32_t version);

void
wal_fileset_flags_set(struct wal_fileset *wfset, uint32_t flags);

merr_t
wal_file_open(
    struct wal_fileset *wfset,
    uint64_t gen,
    int fileid,
    bool replay,
    struct wal_file **handle);

merr_t
wal_file_close(struct wal_file *walf);

merr_t
wal_file_get(struct wal_file *walf);

void
wal_file_put(struct wal_file *walf);

merr_t
wal_file_destroy(struct wal_fileset *wfset, uint64_t gen, int fileid);

merr_t
wal_file_read(struct wal_file *walf, char *buf, size_t len);

merr_t
wal_file_write(struct wal_file *wfile, char *buf, size_t len, bool bufwrap);

void
wal_file_minmax_update(struct wal_file *wfile, struct wal_minmax_info *info);

merr_t
wal_fileset_reclaim(
    struct wal_fileset *wfset,
    uint64_t seqno,
    uint64_t gen,
    uint64_t txhorizon,
    bool closing);

merr_t
wal_file_complete(struct wal_fileset *wfset, struct wal_file *wfile);

merr_t
wal_fileset_replay(
    struct wal_fileset *wfset,
    struct wal_replay_info *rinfo,
    uint32_t *cnt_out,
    struct wal_replay_gen_info **rginfo_out);

void
wal_fileset_replay_free(struct wal_fileset *wfset, bool failed);

#endif /* WAL_FILE_H */
