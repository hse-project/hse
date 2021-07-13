/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <fcntl.h>
#include <sys/mman.h>

#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/string.h>

#include "mpool_internal.h"
#include "mclass.h"
#include "io.h"

struct mpool_file {
    struct mpool       *mp;
    struct media_class *mc;
    struct io_ops       io;
    char  *addr;
    size_t size;
    int    fd;
    char   name[PATH_MAX];
};

/* Forward Decls. */
static merr_t
mpool_file_unmap(struct mpool_file *file);

merr_t
mpool_file_open(
    struct mpool       *mp,
    enum mpool_mclass   mclass,
    const char         *name,
    int                 flags,
    size_t              capacity,
    bool                sparse,
    struct mpool_file **handle)
{
    struct mpool_file  *mfp;
    struct media_class *mc;
    int    dirfd, fd, rc;
    merr_t err;
    bool create = false;

    if (!mp || !name || mclass > MP_MED_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    dirfd = mclass_dirfd(mc);
    rc = faccessat(dirfd, name, F_OK, 0);
    if (rc == -1 && errno == ENOENT) {
        create = true;
        rc = 0;
    }

    flags &= (O_RDWR | O_RDONLY | O_WRONLY | O_CREAT | O_DIRECT | O_SYNC);
    if (create)
        flags |= (O_CREAT | O_EXCL);

    fd = openat(dirfd, name, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    if (create) {
        if (!sparse) {
            rc = posix_fallocate(fd, 0, capacity);
            ev(rc);
        }
        if (sparse || rc < 0) {
            rc = ftruncate(fd, capacity);
            ev(rc);
        }
    }

    mfp = calloc(1, sizeof(*mfp));
    if (!mfp) {
        err = merr(ENOMEM);
        goto errout;
    }

    mfp->mp = mp;
    mfp->mc = mc;
    mfp->fd = fd;
    mfp->io = io_sync_ops;
    strlcpy(mfp->name, name, sizeof(mfp->name));

    *handle = mfp;

    return 0;

errout:
    close(fd);
    if (create)
        unlinkat(dirfd, name, 0);

    return err;
}

merr_t
mpool_file_close(struct mpool_file *file)
{
    merr_t err;

    if (!file)
        return merr(EINVAL);

    err = mpool_file_unmap(file);
    ev(err);

    close(file->fd);
    free(file);

    return 0;
}

merr_t
mpool_file_destroy(struct mpool *mp, enum mpool_mclass mclass, const char *name)
{
    struct media_class *mc;
    int  dirfd, rc;

    if (!mp || !name || mclass > MP_MED_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);
    dirfd = mclass_dirfd(mc);

    rc = unlinkat(dirfd, name, 0);
    if (rc < 0)
        return merr(errno);

    return 0;
}

merr_t
mpool_file_read(struct mpool_file *file, off_t offset, char *buf, size_t buflen, size_t *rdlen)
{
    struct iovec iov;
    merr_t err;

    if (!file || !buf)
        return merr(EINVAL);

    iov.iov_base = buf;
    iov.iov_len = buflen;

    err = file->io.read(file->fd, offset, (const struct iovec *)&iov, 1, 0, rdlen);
    if (err)
        return err;

    return 0;
}

merr_t
mpool_file_write(
    struct mpool_file *file,
    off_t              offset,
    const char        *buf,
    size_t             buflen,
    size_t            *wrlen)
{
    struct iovec iov;
    merr_t err;

    if (!file || !buf)
        return merr(EINVAL);

    iov.iov_base = (char *)buf;
    iov.iov_len = buflen;

    err = file->io.write(file->fd, offset, (const struct iovec *)&iov, 1, 0, wrlen);
    if (err)
        return err;

    return 0;
}

merr_t
mpool_file_sync(struct mpool_file *file)
{
    int rc;

    rc = fsync(file->fd);
    if (rc)
        return merr(errno);

    return 0;
}

size_t
mpool_file_size(struct mpool_file *file)
{
    struct stat st;
    int rc;

    rc = fstat(file->fd, &st);
    if (rc == -1)
        return 0;

    return st.st_size;
}

merr_t
mpool_file_mmap(struct mpool_file *file, bool rdonly, int advice, char **addr_out)
{
    char *addr;
    int prot, rc;
    size_t sz;

    if (!file)
        return merr(EINVAL);

    sz = mpool_file_size(file);
    prot = rdonly ? PROT_READ : PROT_READ | PROT_WRITE;

    addr = mmap(NULL, sz, prot, MAP_SHARED, file->fd, 0);
    if (addr == MAP_FAILED)
        return merr(errno);

    file->addr = addr;
    file->size = sz;

    if (advice != 0) {
        rc = madvise(addr, sz, advice);
        ev(rc);
    }

    if (addr_out)
        *addr_out = addr;

    return 0;
}

static merr_t
mpool_file_unmap(struct mpool_file *file)
{
    int rc;

    if (!file->addr)
        return 0;

    rc = munmap(file->addr, file->size);
    if (rc == -1)
        return merr(errno);

    return 0;
}
