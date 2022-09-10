/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef IOV_MAX
#include <sys/uio.h>

#ifdef __IOV_MAX
#define IOV_MAX __IOV_MAX
#endif
#endif

#ifndef IOV_MAX
/* This is for IOV_MAX */
#define __need_IOV_MAX /* This way stdio_lim.h defines IOV_MAX */
#include <bits/stdio_lim.h>
#endif

#ifndef IOV_MAX
#error "Neither __IOV_MAX nor IOV_MAX is defined"
#endif

#include <sys/mman.h>

#include <hse_util/minmax.h>
#include <hse_util/event_counter.h>
#include <hse_util/assert.h>
#include <hse_util/page.h>

#include "io.h"

static size_t
iolen(const struct iovec *iov, int cnt)
{
    size_t len = 0;

    while (cnt-- > 0)
        len += iov[cnt].iov_len;

    return len;
}

merr_t
io_sync_read(
    int                 src_fd,
    off_t               off,
    const struct iovec *iov,
    int                 iovcnt,
    int                 flags,
    size_t             *rdlen)
{
    const struct iovec *curiov;
    int left;
    off_t start;

    curiov = iov;
    left = iovcnt;
    start = off;

    while (left > 0) {
        ssize_t cc;
        size_t len;
        int    cnt;

        cnt = min_t(int, left, IOV_MAX);

        len = iolen(curiov, cnt);

        /* Pass flags to preadv2(). Not available on fc25. */
        cc = preadv(src_fd, curiov, cnt, off);
        if (cc != len) {
            if (cc == -1)
                return merr(errno);
            ev(1);
            off += cc;
            goto out;
        }

        off += cc;
        left -= cnt;
        curiov += cnt;
    }

out:
    if (rdlen)
        *rdlen = off - start;

    return 0;
}

merr_t
io_sync_write(
    int                 dst_fd,
    off_t               off,
    const struct iovec *iov,
    int                 iovcnt,
    int                 flags,
    size_t             *wrlen)
{
    const struct iovec *curiov;
    int left;
    off_t start;

    curiov = iov;
    left = iovcnt;
    start = off;

    while (left > 0) {
        size_t cc, len;
        int    cnt;

        cnt = min_t(int, left, IOV_MAX);

        len = iolen(curiov, cnt);

        /* Pass flags to pwritev2(). Not available on fc25. */
        cc = pwritev(dst_fd, curiov, cnt, off);
        if (cc != len) {
            if (cc == -1)
                return merr(errno);
            ev(1);
            off += cc;
            goto out;
        }

        off += cc;
        left -= cnt;
        curiov += cnt;
    }

out:
    if (wrlen)
        *wrlen = off - start;

    return 0;
}

merr_t
io_sync_mmap(void **addr, size_t len, int prot, int flags, int fd, off_t offset)
{
    void *addrout;

    INVARIANT(addr);

    addrout = mmap(*addr, len, prot, flags, fd, offset);
    if (addrout == MAP_FAILED)
        return merr(errno);

    *addr = addrout;

    return 0;
}

merr_t
io_sync_munmap(void *addr, size_t len)
{
    int rc;

    INVARIANT(addr);

    rc = munmap(addr, len);

    return (rc == -1) ? merr(errno) : 0;
}

merr_t
io_sync_msync(void *addr, size_t len, int flags)
{
    int rc;

    INVARIANT(addr);

    addr = (void *)((uintptr_t)addr & PAGE_MASK);
    len = PAGE_ALIGN(len);

    rc = msync(addr, len, flags);

    return (rc == -1) ? merr(errno) : 0;
}

merr_t
io_sync_clone(int src_fd, off_t src_off, int tgt_fd, off_t tgt_off, size_t len, int flags)
{
    size_t left = len, cc;
    off_t cur_soff = src_off, cur_toff = tgt_off;

    do {
        cc = copy_file_range(src_fd, &cur_soff, tgt_fd, &cur_toff, len, 0);
        if (cc == -1)
            return merr(errno);

        left -= cc;

        /* copy_file_range() automatically adjusts `cur_soff' and `cur_toff' with the
         * number of bytes copied. Below check verifies that this is infact the case.
         */
        if ((left + (cur_soff - src_off) != len) || (left + (cur_toff - tgt_off) != len))
            return merr(EBUG);

    } while (left > 0 && cc > 0);

    assert(left == 0);

    return left > 0 ? merr(EIO) : 0;
}

const struct io_ops io_sync_ops = {
    .read = io_sync_read,
    .write = io_sync_write,
    .mmap = io_sync_mmap,
    .munmap = io_sync_munmap,
    .msync = io_sync_msync,
    .clone = io_sync_clone,
};
