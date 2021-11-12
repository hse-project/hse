/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_dax

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/dax.h>

#if defined(MAP_SYNC) && defined(MAP_SHARED_VALIDATE)
#include <dirent.h>
#include <sys/mman.h>
#else
#include <mntent.h>
#endif

merr_t
dax_path_is_fsdax(const char *path, bool *isdax)
{
    merr_t err = 0;
    int rc;

#if defined(MAP_SYNC) && defined(MAP_SHARED_VALIDATE)

    DIR *dirp;
    int fddir, fd;
    char *addr;
    const int fsize = 4 * PAGE_SIZE;
    const char *fname = "hse-dax-test";

    if (!path || !isdax)
        return merr(EINVAL);

    *isdax = false;

    dirp = opendir(path);
    if (!dirp)
        return merr(errno);

    fddir = dirfd(dirp);
    fd = openat(fddir, fname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        goto out;
    }

    rc = posix_fallocate(fd, 0, fsize);
    if (rc < 0) {
        err = merr(rc);
        goto out;
    }

    addr = mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE | MAP_SYNC, fd, 0);
    if (addr == MAP_FAILED) {
        if (merr_errno(errno) == ENOTSUP)
            err = 0; /* ENOTSUP indicates a non-dax range */
        goto out;
    }
    munmap(addr, fsize);

    *isdax = true;

out:
    if (fd >= 0)
        close(fd);
    unlinkat(fddir, fname, 0);
    if (dirp)
        closedir(dirp);

    return err;

#else

    struct mntent *entry;
    struct stat sbuf;
    const char *mnttab = "/etc/mtab";
    FILE *fp;
    dev_t pathdev;

    if (!path || !isdax)
        return merr(EINVAL);

    *isdax = false;

    rc = stat(path, &sbuf);
    if (rc == -1)
        return merr(errno);
    pathdev = sbuf.st_dev;

    fp = fopen(mnttab, "r");
    if (!fp)
        return merr(errno);

    while ((entry = getmntent(fp))) {
        rc = stat(entry->mnt_dir, &sbuf);
        if (rc == -1) {
            err = merr(errno);
            break;
        }

        if (pathdev == sbuf.st_dev) { /* same FS as path */
            char *daxopt, *end;
            char daxval[16];
            int  n;

            daxopt = strstr(entry->mnt_opts, "dax");
            if (!daxopt)
                break;

            end = strchr(daxopt, ',');
            if (end)
                *end = '\0';

            n = sscanf(daxopt, "dax=%s", daxval);
            if (n == 1) {
                if (strcmp(daxval, "always") == 0)
                    *isdax = true;
                /* TODO: Handle dax=inode */
            }
            break;
        }
    }

    fclose(fp);

    return err;

#endif
}

#if HSE_MOCKING
#include "dax_ut_impl.i"
#endif /* HSE_MOCKING */
