
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <fcntl.h>

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
    int    fd;
    char   name[PATH_MAX];
};

merr_t
mpool_file_create(
    struct mpool       *mp,
    enum mpool_mclass   mclass,
    const char         *name,
    size_t              capacity,
    bool                sparse)
{
    struct media_class *mc;
    int    dirfd, rc, fd, flags;
    merr_t err = 0;

    if (!mp || !name || mclass > MP_MED_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    flags = O_CREAT | O_EXCL | O_RDWR;

    dirfd = mclass_dirfd(mc);
    fd = openat(dirfd, name, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    if (!sparse) {
        rc = fallocate(fd, 0, 0, capacity);
        ev(rc);
    }

    /* TODO: handle file-systems that do not support prealloc */
    if (sparse || rc < 0)
        rc = ftruncate(fd, capacity);

    if (rc < 0)
        err = merr(errno);

    close(fd);

    if (err)
        unlinkat(dirfd, name, 0);

    return err;
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
mpool_file_open(
    struct mpool       *mp,
    enum mpool_mclass   mclass,
    const char         *name,
    int                 flags,
    struct mpool_file **handle)
{
    struct mpool_file  *mfp;
    struct media_class *mc;
    int    dirfd, fd;
    merr_t err;

    if (!mp || !name || mclass > MP_MED_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    dirfd = mclass_dirfd(mc);
    fd = openat(dirfd, name, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    mfp = calloc(1, sizeof(*mfp));
    if (!mfp) {
        close(fd);
        return merr(ENOMEM);
    }

    mfp->mp = mp;
    mfp->mc = mc;
    mfp->fd = fd;
    mfp->io = io_sync_ops;
    strlcpy(mfp->name, name, sizeof(mfp->name));

    *handle = mfp;

    return 0;
}

merr_t
mpool_file_close(struct mpool_file *file)
{
    if (!file)
        return merr(EINVAL);

    close(file->fd);
    free(file);

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
mpool_file_write(struct mpool_file *file, off_t offset, const char *buf, size_t buflen)
{
    struct iovec iov;
    merr_t err;

    if (!file || !buf)
        return merr(EINVAL);

    iov.iov_base = (char *)buf;
    iov.iov_len = buflen;

    err = file->io.write(file->fd, offset, (const struct iovec *)&iov, 1, 0);
    if (err)
        return err;

    return 0;
}
