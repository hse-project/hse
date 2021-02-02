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
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>

#include "mclass.h"
#include "mblock_file.h"

merr_t
mblock_file_open(
    struct mblock_fset  *mbfsp,
    int                  dirfd,
    char                *name,
    int                  flags,
    struct mblock_file **handle)
{
    struct mblock_file *mbfp;

    int fd, rc;
    merr_t err;

    if (ev(!mbfsp || !name || !handle))
        return merr(EINVAL);

    mbfp = calloc(1, sizeof(*mbfp));
    if (ev(!mbfp))
        return merr(ENOMEM);

    mbfp->mbfsp = mbfsp;
    mbfp->maxsz = MBLOCK_FILE_SIZE_MAX;
    strlcpy(mbfp->name, name, sizeof(mbfp->name));

    if (flags == 0 || !(flags & (O_RDWR | O_RDONLY | O_WRONLY)))
        flags |= O_RDWR;

    flags &= O_RDWR | O_RDONLY | O_WRONLY | O_CREAT;

    if (flags & O_CREAT)
        flags |= O_EXCL;

    fd = openat(dirfd, name, flags | O_DIRECT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "open/create data file failed, file name %s: @@e", err, name);
        goto err_exit;
    }

    /* ftruncate to the maximum size to make it a sparse file */
    rc = ftruncate(fd, MBLOCK_FILE_SIZE_MAX << 30);
    if (rc < 0) {
        err = merr(errno);
        close(fd);
        hse_elog(HSE_ERR "Truncating data file failed, file name %s: @@e", err, name);
        goto err_exit;
    }

    mbfp->fd = fd;

    *handle = mbfp;

    return 0;

err_exit:
    free(mbfp);

    return err;
}

void
mblock_file_close(struct mblock_file *mbfp)
{
    if (!mbfp)
        return;

    close(mbfp->fd);

    free(mbfp);
}
