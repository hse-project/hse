/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_IO_H
#define MPOOL_IO_H

#include <hse_util/hse_err.h>

/**
 * struct io_ops - io operations to be implemented by different IO backends
 *
 * read:  read IO
 * write: write IO
 */
struct io_ops {
    merr_t
        (*read)(int fd, off_t off, const struct iovec *iov, int iovcnt, int flags, size_t *rdlen);
    merr_t
        (*write)(int fd, off_t off, const struct iovec *iov, int iovcnt, int flags, size_t *wrlen);
};

/* sync backend */
extern const struct io_ops io_sync_ops;

#endif /* MPOOL_IO_H */
