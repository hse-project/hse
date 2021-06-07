/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_BUFFER_H
#define WAL_BUFFER_H

struct wal_buffer;

struct wal_buffer *
wal_buffer_create(struct wal *wal);

void
wal_buffer_destroy(struct wal_buffer *wbuf);

void *
wal_buffer_alloc(struct wal_buffer *wbuf, size_t len);

uint
wal_active_buf_cnt(void);

merr_t
wal_buffer_flush(struct wal_buffer *wbuf, struct workqueue_struct *wq);

#endif /* WAL_BUFFER_H */
