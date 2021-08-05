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

#include <hse_ut/common.h>
#include <mpool/mpool_structs.h>

#include "common.h"

extern char home[PATH_MAX];

char capacity_path[PATH_MAX];
char staging_path[PATH_MAX];

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

    unset_mclass(MP_MED_CAPACITY);
    unset_mclass(MP_MED_STAGING);

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

    rc = nftw(capacity_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    rc = nftw(staging_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
    if (rc && errno != ENOENT) {
        return errno;
    }

    rc = make_capacity_path();
    if (rc == -1)
        return errno;

    rc = make_staging_path();
    if (rc == -1)
        return errno;

    return 0;
}

int
make_staging_path(void)
{
    return mkdir(staging_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
}

int
make_capacity_path(void)
{
    return mkdir(capacity_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
}

int
remove_staging_path(void)
{
    return nftw(staging_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
}

int
remove_capacity_path(void)
{
    return nftw(capacity_path, remove_cb, 4, FTW_DEPTH | FTW_PHYS);
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
    /* [HSE_REVISIT]: When mpool gets refactored to mpool_cparams/mpool_rparams,
     * use the default constants.
     */
    const char *path = mc == MP_MED_CAPACITY ? capacity_path : staging_path;

    strlcpy(tcparams.mclass[mc].path, path, sizeof(tcparams.mclass[mc].path));
    tcparams.mclass[mc].fmaxsz = 2048 * GB;
    tcparams.mclass[mc].filecnt = 32;
    tcparams.mclass[mc].mblocksz = 32 * MB;

    strlcpy(trparams.mclass[mc].path, path, sizeof(trparams.mclass[mc].path));

    strlcpy(tdparams.mclass[mc].path, path, sizeof(tdparams.mclass[mc].path));
}
