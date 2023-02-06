/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <bsd/string.h>

#include <hse/util/storage.h>

#include <hse/test/mtf/common.h>
#include <hse/test/mtf/framework.h>
#include <hse/mpool/mpool.h>

#include "common.h"

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

    setup_mclass(HSE_MCLASS_CAPACITY);

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

    unset_mclass(HSE_MCLASS_CAPACITY);
    unset_mclass(HSE_MCLASS_STAGING);
    unset_mclass(HSE_MCLASS_PMEM);

    return 0;
}

int
mpool_collection_pre(struct mtf_test_info *ti)
{
    int rc = 0;
    size_t n;

    n = snprintf(capacity_path, sizeof(capacity_path), "%s/capacity", mtf_kvdb_home);
    if (n >= sizeof(capacity_path))
        return ENAMETOOLONG;
    n = snprintf(staging_path, sizeof(staging_path), "%s/staging", mtf_kvdb_home);
    if (n >= sizeof(staging_path))
        return ENAMETOOLONG;
    n = snprintf(pmem_path, sizeof(pmem_path), "%s/pmem", mtf_kvdb_home);
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
unset_mclass(const enum hse_mclass mc)
{
    memset(tcparams.mclass[mc].path, 0, sizeof(tcparams.mclass[mc].path));
    memset(trparams.mclass[mc].path, 0, sizeof(tcparams.mclass[mc].path));
    memset(tdparams.mclass[mc].path, 0, sizeof(tcparams.mclass[mc].path));
}

void
setup_mclass_with_params(const enum hse_mclass mc, uint8_t fcnt, uint32_t mbsz, uint64_t fmaxsz)
{
    const char *path = (mc == HSE_MCLASS_CAPACITY) ? capacity_path :
        (mc == HSE_MCLASS_STAGING ? staging_path : pmem_path);

    strlcpy(tcparams.mclass[mc].path, path, sizeof(tcparams.mclass[mc].path));
    strlcpy(trparams.mclass[mc].path, path, sizeof(trparams.mclass[mc].path));
    strlcpy(tdparams.mclass[mc].path, path, sizeof(tdparams.mclass[mc].path));

    tcparams.mclass[mc].filecnt = fcnt;
    tcparams.mclass[mc].mblocksz = mbsz;
    tcparams.mclass[mc].fmaxsz = fmaxsz;
}

void
setup_mclass(const enum hse_mclass mc)
{
    setup_mclass_with_params(mc, MPOOL_MCLASS_FILECNT_DEFAULT, MPOOL_MBLOCK_SIZE_DEFAULT,
                             MPOOL_MCLASS_FILESZ_DEFAULT);
}

uint64_t
allocated_bytes_summation(const struct mpool_info *const info)
{
    uint64_t sum = 0;

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        sum += info->mclass[i].mi_allocated_bytes;

    return sum;
}

uint64_t
used_bytes_summation(const struct mpool_info *const info)
{
    uint64_t sum = 0;

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        sum += info->mclass[i].mi_used_bytes;

    return sum;
}
