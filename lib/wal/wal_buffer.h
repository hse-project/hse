/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_BUFFER_H
#define WAL_BUFFER_H

struct wal_fileset;
struct wal_bufset;
struct wal_buffer;

struct wal_bufset *
wal_bufset_open(struct wal_fileset *wfset, atomic64_t *ingestgen);

void
wal_bufset_close(struct wal_bufset *wbs);

void *
wal_bufset_alloc(struct wal_bufset *wbs, size_t len, u64 *offout, uint *wbidx);

void
wal_bufset_finish(struct wal_bufset *wbs, uint wbidx, size_t len, uint64_t gen);

void
wal_bufset_reclaim(struct wal_bufset *wbs, uint64_t gen);

merr_t
wal_bufset_flush(struct wal_bufset *wbs);

#endif /* WAL_BUFFER_H */
