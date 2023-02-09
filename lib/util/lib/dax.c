/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#define MTF_MOCK_IMPL_dax

#include "build_config.h"

#include <stdio.h>

#include <sys/stat.h>

#ifdef HAVE_PMEM
#include <libpmem.h>
#include <limits.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/types.h>
#endif

#include <hse/error/merr.h>
#include <hse/util/dax.h>
#include <hse/util/page.h>
#include <hse/util/platform.h>

merr_t
dax_path_is_fsdax(const char *path, bool *isdax)
{
#ifdef HAVE_PMEM

    char buf[PATH_MAX + 16];
    const char *fname = "hse-dax-test";
    const size_t fsize = 4 << 20;
    void *addr;
    size_t n;
    int is_pmem = 0;

    if (!path || !isdax)
        return merr(EINVAL);

    *isdax = false;

    n = snprintf(buf, sizeof(buf), "%s%s%s", path, path[strlen(path) - 1] == '/' ? "" : "/", fname);
    if (n >= sizeof(buf))
        return merr(ENAMETOOLONG);

    addr = pmem_map_file(buf, fsize, PMEM_FILE_CREATE, S_IRUSR | S_IWUSR, NULL, &is_pmem);
    if (!addr)
        return merr(errno);

    pmem_unmap(addr, fsize);

    *isdax = (is_pmem > 0);

    remove(buf);

    return 0;

#else

    DIR *dirp;
    int fddir, fd, rc;
    char *addr;
    const int fsize = 4 * PAGE_SIZE;
    const char *fname = "hse-dax-test";
    merr_t err = 0;

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

#endif /* HAVE_PMEM */
}

#if HSE_MOCKING
#include "dax_ut_impl.i"
#endif /* HSE_MOCKING */
