/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_IO_H
#define WAL_IO_H

struct wal_io;
struct wal_fileset;
struct wal_iocb;

merr_t
wal_io_enqueue(
    struct wal_io          *io,
    char                   *buf,
    u64                     len,
    u64                     gen,
    struct wal_minmax_info *info,
    bool                    bufwrap,
    bool                    gendone);

struct wal_io *
wal_io_create(
    struct wal_fileset *wfset,
    uint                index,
    atomic64_t         *doff,
    struct wal_iocb    *iocb);

void
wal_io_destroy(struct wal_io *io);

merr_t
wal_io_init(u32 threads);

void
wal_io_fini();

#endif /* WAL_IO_H */
