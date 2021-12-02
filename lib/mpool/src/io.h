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
    merr_t (*read)(const void *src_addr, int src_fd, off_t off, const struct iovec *iov,
		   int iovcnt, int flags, size_t *rdlen);
    merr_t (*write)(void *dst_addr, int dst_fd, off_t off, const struct iovec *iov,
		    int iovcnt, int flags, size_t *wrlen);
    merr_t (*mmap)(void **addr, size_t len, int prot, int flags, int fd, off_t offset);
    merr_t (*munmap)(void *addr, size_t len);
    merr_t (*msync)(void *addr, size_t len, int flags);
};

/* sync backend */
extern const struct io_ops io_sync_ops;

/* pmem backend */
#ifdef HAVE_PMEM
extern const struct io_ops io_pmem_ops;
#endif /* HAVE_PMEM */

#endif /* MPOOL_IO_H */
