/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ftw.h>

#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include "mclass.h"
#include "mblock_fset.h"

static merr_t
mclass_lockfile_acq(int dirfd)
{
    int fd;

    fd = openat(dirfd, ".lockfile", O_CREAT | O_EXCL | O_SYNC, S_IRUSR | S_IWUSR);
    if (ev(fd < 0)) {
        assert(errno == EEXIST);
        return merr(EBUSY);
    }

    close(fd);

    return 0;
}

static void
mclass_lockfile_rel(int dirfd)
{
    unlinkat(dirfd, ".lockfile", 0);
}

merr_t
mclass_open(struct mpool *mp, enum mclass_id mcid, const char *dpath, struct media_class **handle)
{
    struct media_class *mc;

    DIR    *dirp;
    merr_t  err;

    if (ev(!mp || !dpath || !handle || mcid >= MCID_MAX))
        return merr(EINVAL);

    dirp = opendir(dpath);
    if (!dirp) {
        err = merr(errno);
        hse_elog(HSE_ERR "Opening mclass dir %s failed: @@e", err, dpath);
        return err;
    }

    if (mcid == MCID_CAPACITY) {
        err = mclass_lockfile_acq(dirfd(dirp));
        if (ev(err))
            goto err_exit2;
    }

    mc = calloc(1, sizeof(*mc));
    if (ev(!mc)) {
        err = merr(ENOMEM);
        goto err_exit2;
    }

    mc->dirp = dirp;
    mc->mcid = mcid;

    strlcpy(mc->dpath, dpath, sizeof(mc->dpath));

    err = mblock_fset_open(mc, &mc->mbfsp);
    if (err) {
        hse_elog(HSE_ERR "Opening data files failed, mcid %d: @@e", err, mcid);
        goto err_exit1;
    }

    *handle = mc;

    return 0;

err_exit1:
    free(mc);

err_exit2:
    closedir(dirp);

    return err;
}

merr_t
mclass_close(struct media_class *mc)
{
    if (ev(!mc))
        return merr(EINVAL);

    mblock_fset_close(mc->mbfsp);

    if (mc->mcid == MCID_CAPACITY)
        mclass_lockfile_rel(dirfd(mc->dirp));

    closedir(mc->dirp);

    free(mc);

    return 0;
}

void
mclass_destroy(struct media_class *mc)
{
    if (ev(!mc))
        return;

    mblock_fset_remove(mc->mbfsp);

    if (mc->mcid == MCID_CAPACITY)
        mclass_lockfile_rel(dirfd(mc->dirp));

    closedir(mc->dirp);

    free(mc);
}

merr_t
mclass_params_set(struct media_class *mc, const char *key, const char *val, size_t len)
{
    int fd, dirfd;
    ssize_t cc;
    merr_t err=0;

    dirfd = mclass_dirfd(mc);

    fd = openat(dirfd, key, O_CREAT | O_RDWR | O_SYNC | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return merr(errno);

    cc = pwrite(fd, val, len, 0);
    if (cc != len) {
        err = merr(errno);
        goto errout;
    }

errout:
    close(fd);

    return err;
}

merr_t
mclass_params_get(struct media_class *mc, const char *key, char *val, size_t len)
{
    int fd, dirfd;
    ssize_t cc;
    merr_t err=0;

    dirfd = mclass_dirfd(mc);

    fd = openat(dirfd, key, O_RDONLY);
    if (fd < 0)
        return merr(errno);

    cc = pread(fd, val, len, 0);
    if (cc < 0) {
        err = merr(errno);
        goto errout;
    }

errout:
    close(fd);

    return err;
}

int
mclass_id(struct media_class *mc)
{
    return mc->mcid;
}

int
mclass_dirfd(struct media_class *mc)
{
    return dirfd(mc->dirp);
}

const char *
mclass_dpath(struct media_class *mc)
{
    return mc->dpath;
}
