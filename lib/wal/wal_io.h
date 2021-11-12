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
    uint64_t                len,
    uint64_t                gen,
    struct wal_minmax_info *info,
    bool                    bufwrap);

struct wal_io *
wal_io_create(
    struct wal_fileset *wfset,
    uint32_t            index,
    atomic_ulong       *doff,
    struct wal_iocb    *iocb);

void
wal_io_destroy(struct wal_io *io);

merr_t
wal_io_init(uint32_t threads);

void
wal_io_fini();

#endif /* WAL_IO_H */
