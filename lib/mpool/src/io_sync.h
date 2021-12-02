/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_IO_SYNC_H
#define MPOOL_IO_SYNC_H

#include <hse_util/hse_err.h>

struct iovec;

merr_t
io_sync_read(
    const void         *src_adr,
    int                 src_fd,
    off_t               off,
    const struct iovec *iov,
    int                 iovcnt,
    int                 flags,
    size_t             *rdlen);

merr_t
io_sync_write(
    void               *dst_addr,
    int                 dst_fd,
    off_t               off,
    const struct iovec *iov,
    int                 iovcnt,
    int                 flags,
    size_t             *wrlen);

#endif /* MPOOL_IO_SYNC_H */
