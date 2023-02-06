/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef WAL_BUFFER_H
#define WAL_BUFFER_H

#include <stdint.h>
#include <stdatomic.h>

#include <hse/error/merr.h>
#include <hse/util/compiler.h>

struct wal_fileset;
struct wal_bufset;
struct wal_buffer;
struct wal_iocb;
struct wal_flush_stats;

struct wal_bufset *
wal_bufset_open(
    struct wal_fileset *wfset,
    size_t              bufsz,
    uint32_t            dur_bytes,
    atomic_ulong       *ingestgen,
    struct wal_iocb    *iocb);

void
wal_bufset_close(struct wal_bufset *wbs);

void *
wal_bufset_alloc(
    struct wal_bufset *wbs,
    size_t             len,
    uint64_t          *offout,
    uint32_t          *wbidx,
    int64_t           *cookie);

void
wal_bufset_finish(
    struct wal_bufset *wbs,
    uint32_t           wbidx,
    size_t             len,
    uint64_t           gen,
    uint64_t           endoff);

void
wal_bufset_reclaim(struct wal_bufset *wbs, uint64_t gen);

merr_t
wal_bufset_flush(struct wal_bufset *wbs, struct wal_flush_stats *wbfsp);

uint32_t
wal_bufset_durcnt(struct wal_bufset *wbs, uint32_t offc, uint64_t *offv);

uint32_t
wal_bufset_curoff(struct wal_bufset *wbs, uint32_t offc, uint64_t *offv);

uint32_t
wal_bufset_flushoff(struct wal_bufset *wbs, uint32_t offc, uint64_t *offv);

uint32_t
wal_bufset_genoff(struct wal_bufset *wbs, uint64_t gen, uint32_t offc, uint64_t *offv);

#endif /* WAL_BUFFER_H */
