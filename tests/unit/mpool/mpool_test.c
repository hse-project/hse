/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include "common.h"

#include <mpool/mpool.h>
#include <mpool_internal.h>
#include <mclass.h>

MTF_BEGIN_UTEST_COLLECTION_PREPOST(mpool_test, mpool_test_pre, mpool_test_post)

MTF_DEFINE_UTEST(mpool_test, mpool_ocd_test)
{
    struct mpool      *mp, *mp1;
    struct mpool_stats stats = {};
    struct mpool_props mprops = {};
    struct dirent     *d;

    char   staging_path[PATH_MAX];
    merr_t err;
    int    rc, entry;
    DIR   *dirp;

    err = mpool_open(NULL, NULL, 0, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open("mp1", NULL, 0, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open("mp1", NULL, 0, &mp);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_create("mp1", NULL);
    ASSERT_EQ(0, err);

    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_create("mp1", NULL);
    ASSERT_EQ(EEXIST, merr_errno(err));

    err = mpool_open("mp1", NULL, O_RDONLY, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_props_get(NULL, &mprops);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_props_get(mp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_props_get(mp, &mprops);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(32, mprops.mp_mblocksz[MP_MED_CAPACITY]);
    ASSERT_EQ(30, mprops.mp_vma_size_max);

    err = mpool_stats_get(NULL, &stats);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_stats_get(mp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, (64 << 20L));
    ASSERT_LT(stats.mps_used, (64 << 20L));
    ASSERT_EQ(0, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(storage_path, stats.mps_path[MP_MED_CAPACITY], strlen(storage_path)));
    ASSERT_EQ(0, strlen(stats.mps_path[MP_MED_STAGING]));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);
    mpool_destroy(NULL, NULL);

    unsetenv("HSE_STORAGE_PATH");
    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    setenv("HSE_STORAGE_PATH", (const char *)storage_path, 1);
    setenv("HSE_STAGING_PATH", (const char *)storage_path, 1);
    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));
    unsetenv("HSE_STAGING_PATH");
    mpool_destroy("mp1", NULL);

    err = mpool_create("mp1", NULL);
    ASSERT_EQ(0, err);

    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    strlcpy(staging_path, storage_path, sizeof(staging_path));
    strlcat(staging_path, "/staging", sizeof(staging_path) - strlen(staging_path));
    setenv("HSE_STAGING_PATH", (const char *)staging_path, 1);

    err = mpool_mclass_add("mp1", MP_MED_STAGING, NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    rc = mkdir(staging_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
    ASSERT_EQ(0, rc);

    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(ENOENT, merr_errno(err));

    dirp = opendir(staging_path);
    ASSERT_NE(dirp, NULL);

    entry = 0;
    while ((d = readdir(dirp)) != NULL)
        entry++;
    ASSERT_EQ(2, entry);

    rewinddir(dirp);

    err = mpool_mclass_add("mp1", MP_MED_STAGING, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, (64 << 20L) * 2); /* 2 media classes */
    ASSERT_LT(stats.mps_used, (64 << 20L) * 2);
    ASSERT_EQ(0, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(storage_path, stats.mps_path[MP_MED_CAPACITY], strlen(storage_path)));
    ASSERT_EQ(0, strncmp(staging_path, stats.mps_path[MP_MED_STAGING], strlen(staging_path)));

    entry = 0;
    while ((d = readdir(dirp)) != NULL && entry < 3)
        entry++;
    ASSERT_GT(entry, 2);

    closedir(dirp);

    err = mpool_open("mp1", NULL, O_RDWR, &mp1);
    ASSERT_EQ(EBUSY, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);
    mpool_destroy("mp1", NULL);

    unsetenv("HSE_STAGING_PATH");
    setenv("HSE_STORAGE_PATH", (const char *)storage_path, 1);
}

MTF_DEFINE_UTEST(mpool_test, mclass_test)
{
    struct mpool             *mp;
    struct mpool_mclass_props props = {};
    struct mpool_mclass_stats stats = {};
    struct media_class       *mc;
    merr_t                    err;
    int                       mcid, fd, i, rc;
    const char               *pathp;
    size_t                    mbsz;
    struct mblock_fset       *fsetp;

    err = mpool_create("mp1", NULL);
    ASSERT_EQ(0, err);

    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mclass_props_get(NULL, MP_MED_CAPACITY, &props);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_props_get(mp, MP_MED_CAPACITY, NULL);
    ASSERT_EQ(0, err);

    err = mpool_mclass_props_get(mp, MP_MED_COUNT, &props);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_props_get(mp, MP_MED_STAGING, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mclass_props_get(mp, MP_MED_CAPACITY, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(32, props.mc_mblocksz);

    err = mpool_mclass_stats_get(NULL, MP_MED_CAPACITY, &stats);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_stats_get(mp, MP_MED_COUNT, &stats);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_stats_get(mp, MP_MED_STAGING, &stats);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mclass_stats_get(mp, MP_MED_CAPACITY, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mclass_stats_get(mp, MP_MED_CAPACITY, &stats);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_LT(stats.mcs_allocated, (64 << 20L));
    ASSERT_LT(stats.mcs_used, (64 << 20L));
    ASSERT_EQ(0, stats.mcs_mblock_cnt);
    ASSERT_EQ(0, strncmp(storage_path, stats.mcs_path, strlen(storage_path)));

    mc = mpool_mclass_handle(NULL, MP_MED_CAPACITY);
    ASSERT_EQ(NULL, mc);

    mc = mpool_mclass_handle(mp, MP_MED_COUNT);
    ASSERT_EQ(NULL, mc);

    mc = mpool_mclass_handle(mp, MP_MED_CAPACITY);
    ASSERT_NE(NULL, mc);

    mcid = mclass_id(NULL);
    ASSERT_EQ(mcid, MCID_INVALID);

    mcid = mclass_id(mc);
    ASSERT_EQ(mcid, MP_MED_CAPACITY + 1);

    fd = mclass_dirfd(NULL);
    ASSERT_EQ(fd, -1);

    fd = mclass_dirfd(mc);
    ASSERT_GT(fd, 0);

    pathp = mclass_dpath(NULL);
    ASSERT_EQ(pathp, NULL);

    pathp = mclass_dpath(mc);
    rc = strcmp(pathp, storage_path);
    ASSERT_EQ(0, rc);

    fsetp = mclass_fset(NULL);
    ASSERT_EQ(fsetp, NULL);

    fsetp = mclass_fset(mc);
    ASSERT_NE(fsetp, NULL);

    mbsz = mclass_mblocksz_get(NULL);
    ASSERT_EQ(mbsz, 0);

    mbsz = mclass_mblocksz_get(mc);
    ASSERT_EQ(32 << 20, mbsz);

    mclass_mblocksz_set(NULL, 64 << 20);
    mbsz = mclass_mblocksz_get(mc);
    ASSERT_EQ(32 << 20, mbsz);

    mclass_mblocksz_set(mc, 64 << 20);
    mbsz = mclass_mblocksz_get(mc);
    ASSERT_EQ(64 << 20, mbsz);

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        ASSERT_EQ(i + 1, mclass_to_mcid(i));
        ASSERT_EQ(i, mcid_to_mclass(i + 1));
    }

    err = mclass_stats_get(NULL, &stats);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mclass_stats_get(mc, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    ASSERT_EQ(MCID_INVALID, mclass_to_mcid(i));
    ASSERT_EQ(MP_MED_INVALID, mcid_to_mclass(i + 1));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);
    mpool_destroy("mp1", NULL);
}

MTF_END_UTEST_COLLECTION(mpool_test);
