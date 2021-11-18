/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <bsd/string.h>

#include <hse_util/storage.h>

#include <mtf/common.h>
#include <mpool/mpool.h>

#include "common.h"

extern char home[PATH_MAX];

char capacity_path[PATH_MAX];
char staging_path[PATH_MAX];
char pmem_path[PATH_MAX];

struct mpool_cparams tcparams;
struct mpool_rparams trparams;
struct mpool_dparams tdparams;

static int
remove_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    return remove(path);
}

int
mpool_test_pre(struct mtf_test_info *ti)
{
    int rc = 0;

    setup_mclass(MP_MED_CAPACITY);

    return rc;
}

int
mpool_test_post(struct mtf_test_info *ti)
{
    int rc;

    rc = nftw(capacity_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    rc = nftw(staging_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    rc = nftw(pmem_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    unset_mclass(MP_MED_CAPACITY);
    unset_mclass(MP_MED_STAGING);
    unset_mclass(MP_MED_PMEM);

    return 0;
}

int
mpool_collection_pre(struct mtf_test_info *ti)
{
    int rc = 0;
    size_t n;

    n = snprintf(capacity_path, sizeof(capacity_path), "%s/capacity", home);
    if (n >= sizeof(capacity_path))
        return ENAMETOOLONG;
    n = snprintf(staging_path, sizeof(staging_path), "%s/staging", home);
    if (n >= sizeof(staging_path))
        return ENAMETOOLONG;
    n = snprintf(pmem_path, sizeof(pmem_path), "%s/pmem", home);
    if (n >= sizeof(pmem_path))
        return ENAMETOOLONG;

    rc = nftw(capacity_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    rc = nftw(staging_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    rc = nftw(pmem_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    rc = make_capacity_path();
    if (rc == -1)
        return errno;

    rc = make_staging_path();
    if (rc == -1)
        return errno;

    rc = make_pmem_path();
    if (rc == -1)
        return errno;

    mpool_cparams_defaults(&tcparams);

    return 0;
}

int
make_capacity_path(void)
{
    return mkdir(capacity_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
}

int
make_staging_path(void)
{
    return mkdir(staging_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
}

int
make_pmem_path(void)
{
    return mkdir(pmem_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
}

int
remove_capacity_path(void)
{
    return nftw(capacity_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
}

int
remove_staging_path(void)
{
    return nftw(staging_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
}

int
remove_pmem_path(void)
{
    return nftw(pmem_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
}

void
unset_mclass(const enum mpool_mclass mc)
{
    memset(tcparams.mclass[mc].path, 0, sizeof(tcparams.mclass[mc].path));
    memset(trparams.mclass[mc].path, 0, sizeof(tcparams.mclass[mc].path));
    memset(tdparams.mclass[mc].path, 0, sizeof(tcparams.mclass[mc].path));
}

void
setup_mclass(const enum mpool_mclass mc)
{
    const char *path = (mc == MP_MED_CAPACITY) ? capacity_path :
        (mc == MP_MED_STAGING ? staging_path : pmem_path);

    strlcpy(tcparams.mclass[mc].path, path, sizeof(tcparams.mclass[mc].path));
    strlcpy(trparams.mclass[mc].path, path, sizeof(trparams.mclass[mc].path));
    strlcpy(tdparams.mclass[mc].path, path, sizeof(tdparams.mclass[mc].path));
}
