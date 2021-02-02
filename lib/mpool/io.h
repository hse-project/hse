/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_IO_H
#define MPOOL_IO_H

#include <hse_util/hse_err.h>

struct io_ops {
	merr_t (*read)(int fd, off_t off, const struct iovec *iov, int iovcnt, int flags);
	merr_t (*write)(int fd, off_t off, const struct iovec *iov, int iovcnt, int flags);
};

extern const struct io_ops io_sync_ops;

#endif /* MPOOL_IO_H */

