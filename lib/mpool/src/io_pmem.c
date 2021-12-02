/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/base.h>
#include <hse_util/mman.h>
#include <hse_util/assert.h>
#include <hse_util/page.h>

#include "io.h"
#include "io_sync.h"

#include <libpmem.h>

merr_t
io_pmem_read(
    const void         *src_addr,
    int                 src_fd,
    off_t               off,
    const struct iovec *iov,
    int                 iovcnt,
    int                 flags,
    size_t             *rdlen)
{
    size_t tlen = 0;
    int    i;

    if (!src_addr)
        return io_sync_read(src_addr, src_fd, off, iov, iovcnt, flags, rdlen);

    for (i = 0; i < iovcnt; i++) {
        size_t len = iov[i].iov_len;

        if (len > 0) {
            memcpy(iov[i].iov_base, src_addr, len);
            src_addr += len;
            tlen += len;
        }
    }

    if (rdlen)
        *rdlen = tlen;

    return 0;
}

merr_t
io_pmem_write(
    void               *dst_addr,
    int                 dst_fd,
    off_t               off,
    const struct iovec *iov,
    int                 iovcnt,
    int                 flags,
    size_t             *wrlen)
{
    size_t tlen = 0;
    int    i;

    if (!dst_addr)
        return io_sync_write(dst_addr, dst_fd, off, iov, iovcnt, flags, wrlen);

    for (i = 0; i < iovcnt; i++) {
        size_t len = iov[i].iov_len;

        if (len > 0) {
            pmem_memcpy_nodrain(dst_addr, (const void *)iov[i].iov_base, len);
            dst_addr += len;
            tlen += len;
        }
    }
    pmem_drain(); /* drain HW buffers */

    if (wrlen)
        *wrlen = tlen;

    return 0;
}

merr_t
io_pmem_mmap(void **addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    void *addrout;

    INVARIANT(addr);

    flags |= (MAP_SHARED_VALIDATE | MAP_SYNC);

    addrout = mmap(*addr, len, prot, flags, fd, offset);
    if (addrout == MAP_FAILED)
        return merr(errno);

    *addr = addrout;

    return 0;
}

merr_t
io_pmem_munmap(void *addr, size_t len)
{
    int rc;

    INVARIANT(addr);

    rc = munmap(addr, len);

    return (rc == -1) ? merr(errno) : 0;
}

merr_t
io_pmem_msync(void *addr, size_t len, int flags)
{
    pmem_persist(addr, len);

    return 0;
}

const struct io_ops io_pmem_ops = {
    .read = io_pmem_read,
    .write = io_pmem_write,
    .mmap = io_pmem_mmap,
    .munmap = io_pmem_munmap,
    .msync = io_pmem_msync,
};
