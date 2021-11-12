/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>

#include <mtf/framework.h>
#include <mock/api.h>

#include <mpool/mpool.h>
#include <mpool_internal.h>
#include <mclass.h>

#include "common.h"

MTF_BEGIN_UTEST_COLLECTION_PRE(mpool_test, mpool_collection_pre)

MTF_DEFINE_UTEST_PREPOST(mpool_test, mpool_ocd_test, mpool_test_pre, mpool_test_post)
{
    struct mpool *mp;
    struct mpool_stats  stats = {};
    struct mpool_props  mprops = {};
    struct dirent      *d;

    merr_t  err;
    int     rc, entry;
    DIR    *dirp;
    bool    exists;

    err = mpool_open(home, &trparams, 0, &mp);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_create(home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_create(home, &tcparams);
    ASSERT_EQ(EEXIST, merr_errno(err));

    err = mpool_open(home, &trparams, O_RDONLY, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_open(home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_props_get(NULL, &mprops);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_props_get(mp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_props_get(mp, &mprops);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(32, mprops.mp_mblocksz[MP_MED_CAPACITY]);

    err = mpool_stats_get(NULL, &stats);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_stats_get(mp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, (64 << 20L));
    ASSERT_LT(stats.mps_used, (64 << 20L));
    ASSERT_EQ(0, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(capacity_path, stats.mps_path[MP_MED_CAPACITY], sizeof(capacity_path)));
    ASSERT_EQ(0, strlen(stats.mps_path[MP_MED_STAGING]));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    exists = mclass_files_exist(tcparams.mclass[MP_MED_CAPACITY].path);
    ASSERT_EQ(true, exists);

    mpool_destroy(home, &tdparams);

    exists = mclass_files_exist(tcparams.mclass[MP_MED_CAPACITY].path);
    ASSERT_EQ(false, exists);

#if 0
    err = mpool_create(home, &tcparams);
    ASSERT_EQ(0, err);

    const char *same_paths[] = { capacity_path, capacity_path };
    err = mpool_open(home, same_paths, O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    mpool_destroy(home, &tdparams);
#endif

    setup_mclass(MP_MED_STAGING);

    err = mpool_create(home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(home, &trparams, O_CREAT | O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open(home, &trparams, O_EXCL | O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open(home, &trparams, O_CREAT | O_EXCL | O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open(home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    rc = remove_staging_path();
    ASSERT_EQ(0, rc);

    err = mpool_mclass_add(MP_MED_STAGING, &tcparams);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_open(home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(ENOENT, merr_errno(err));

    rc = make_staging_path();
    ASSERT_EQ(0, rc);

    dirp = opendir(staging_path);
    ASSERT_NE(dirp, NULL);

    entry = 0;
    while ((d = readdir(dirp)) != NULL)
        entry++;
    ASSERT_EQ(2, entry);

    rewinddir(dirp);

    err = mpool_mclass_add(MP_MED_STAGING, &tcparams);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open(home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, (64 << 20L) * 2); /* 2 media classes */
    ASSERT_LT(stats.mps_used, (64 << 20L) * 2);
    ASSERT_EQ(0, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(capacity_path, stats.mps_path[MP_MED_CAPACITY], sizeof(capacity_path)));
    ASSERT_EQ(0, strncmp(staging_path, stats.mps_path[MP_MED_STAGING], sizeof(staging_path)));

    entry = 0;
    while ((d = readdir(dirp)) != NULL && entry < 3)
        entry++;
    ASSERT_GT(entry, 2);

    closedir(dirp);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(home, &tdparams);
}

MTF_DEFINE_UTEST_PREPOST(mpool_test, mclass_test, mpool_test_pre, mpool_test_post)
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

    err = mpool_create(home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(home, &trparams, O_RDWR, &mp);
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
    ASSERT_EQ(0, strncmp(capacity_path, stats.mcs_path, sizeof(capacity_path)));

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
    rc = strcmp(pathp, capacity_path);
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

    ASSERT_EQ(MCID_INVALID, mclass_to_mcid(i));
    ASSERT_EQ(MP_MED_INVALID, mcid_to_mclass(i + 1));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(home, &tdparams);
}

MTF_END_UTEST_COLLECTION(mpool_test);
