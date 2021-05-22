/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_BUFFER_H
#define WAL_BUFFER_H

struct wal_buffer;

struct wal_buffer *
wal_buffer_create(void);

void
wal_buffer_destroy(struct wal_buffer *wbuf);

void *
wal_buffer_alloc(struct wal_buffer *wbuf, size_t len);

#endif /* WAL_BUFFER_H */
