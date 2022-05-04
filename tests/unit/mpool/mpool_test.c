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
#include <mblock_fset.h>

#include "common.h"

MTF_BEGIN_UTEST_COLLECTION_PRE(mpool_test, mpool_collection_pre)

static merr_t
mpool_filecnt_test(uint8_t filecnt)
{
    merr_t err;

    setup_mclass_with_params(HSE_MCLASS_CAPACITY, filecnt, MPOOL_MBLOCK_SIZE_DEFAULT,
                             MPOOL_MCLASS_FILESZ_DEFAULT);
    make_capacity_path();

    setup_mclass_with_params(HSE_MCLASS_STAGING, filecnt, MPOOL_MBLOCK_SIZE_DEFAULT,
                             MPOOL_MCLASS_FILESZ_DEFAULT);
    make_staging_path();

    err = mpool_create(mtf_kvdb_home, &tcparams);
    if (!err)
        err = mpool_destroy(mtf_kvdb_home, &tdparams);

    return err;
}

static merr_t
mpool_filesz_test(uint32_t mblocksz, uint64_t fszmax)
{
    merr_t err;

    setup_mclass_with_params(HSE_MCLASS_CAPACITY, MPOOL_MCLASS_FILECNT_DEFAULT, mblocksz, fszmax);
    make_capacity_path();

    setup_mclass_with_params(HSE_MCLASS_STAGING, MPOOL_MCLASS_FILECNT_DEFAULT, mblocksz, fszmax);
    make_staging_path();

    err = mpool_create(mtf_kvdb_home, &tcparams);
    if (!err)
        err = mpool_destroy(mtf_kvdb_home, &tdparams);

    return err;
}

MTF_DEFINE_UTEST_PREPOST(mpool_test, mpool_ocd_test, mpool_test_pre, mpool_test_post)
{
    struct mpool *      mp;
    struct mpool_info  info = {};
    struct mpool_props mprops = {};
    struct dirent *    d;

    merr_t err;
    int    rc, entry;
    DIR *  dirp;
    bool   exists;

    err = mpool_open(mtf_kvdb_home, &trparams, 0, &mp);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(EEXIST, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDONLY, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_props_get(NULL, &mprops);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_props_get(mp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_props_get(mp, &mprops);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(MPOOL_MBLOCK_SIZE_DEFAULT, mprops.mclass[HSE_MCLASS_CAPACITY].mc_mblocksz);

    err = mpool_info_get(NULL, &info);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_info_get(mp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, err);
    ASSERT_LT(allocated_bytes_summation(&info), (70ul << MB_SHIFT));
    ASSERT_LT(used_bytes_summation(&info), (70ul << MB_SHIFT));
    ASSERT_EQ(
        0, strncmp(capacity_path, info.mclass[HSE_MCLASS_CAPACITY].mi_path, sizeof(capacity_path)));
    ASSERT_EQ(0, strlen(info.mclass[HSE_MCLASS_STAGING].mi_path));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    exists = mclass_files_exist(tcparams.mclass[HSE_MCLASS_CAPACITY].path);
    ASSERT_EQ(true, exists);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    exists = mclass_files_exist(tcparams.mclass[HSE_MCLASS_CAPACITY].path);
    ASSERT_EQ(false, exists);

    setup_mclass(HSE_MCLASS_STAGING);

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_CREAT | O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_EXCL | O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_CREAT | O_EXCL | O_RDWR, &mp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    rc = remove_staging_path();
    ASSERT_EQ(0, rc);

    err = mpool_mclass_add(HSE_MCLASS_STAGING, &tcparams);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
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

    err = mpool_mclass_add(HSE_MCLASS_STAGING, &tcparams);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, err);
    ASSERT_LT(allocated_bytes_summation(&info), (70ul << MB_SHIFT) * 2); /* 2 media classes */
    ASSERT_LT(used_bytes_summation(&info), (70ul << MB_SHIFT) * 2);
    ASSERT_EQ(
        0, strncmp(capacity_path, info.mclass[HSE_MCLASS_CAPACITY].mi_path, sizeof(capacity_path)));
    ASSERT_EQ(0, strncmp(staging_path, info.mclass[HSE_MCLASS_STAGING].mi_path, sizeof(staging_path)));

    entry = 0;
    while ((d = readdir(dirp)) != NULL && entry < 3)
        entry++;
    ASSERT_GT(entry, 2);

    closedir(dirp);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    err = mpool_filecnt_test(MPOOL_MCLASS_FILECNT_MAX);
    ASSERT_EQ(0, err);

    err = mpool_filecnt_test(MPOOL_MCLASS_FILECNT_MAX - 1);
    ASSERT_EQ(0, err);

    err = mpool_filecnt_test(MPOOL_MCLASS_FILECNT_MIN);
    ASSERT_EQ(0, err);

    err = mpool_filesz_test(MPOOL_MBLOCK_SIZE_MIN, MPOOL_MCLASS_FILESZ_MIN);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(mpool_test, mclass_test, mpool_test_pre, mpool_test_post)
{
    struct mpool *            mp;
    struct mpool_mclass_props props = {};
    struct hse_mclass_info    info = {};
    struct media_class*       mc;
    merr_t                    err;
    int                       mcid, fd, i, rc;
    const char *              pathp;
    size_t                    mbsz;
    struct mblock_fset *      fsetp;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mclass_props_get(NULL, HSE_MCLASS_CAPACITY, &props);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_props_get(mp, HSE_MCLASS_CAPACITY, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_props_get(mp, HSE_MCLASS_COUNT, &props);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_props_get(mp, HSE_MCLASS_STAGING, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mclass_props_get(mp, HSE_MCLASS_CAPACITY, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(MPOOL_MBLOCK_SIZE_DEFAULT, props.mc_mblocksz);

    err = mpool_mclass_info_get(NULL, HSE_MCLASS_CAPACITY, &info);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_info_get(mp, HSE_MCLASS_COUNT, &info);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_info_get(mp, HSE_MCLASS_STAGING, &info);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mclass_info_get(mp, HSE_MCLASS_CAPACITY, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mclass_info_get(mp, HSE_MCLASS_CAPACITY, &info);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_LT(info.mi_allocated_bytes, (70ul << MB_SHIFT));
    ASSERT_LT(info.mi_used_bytes, (70ul << MB_SHIFT));
    ASSERT_EQ(0, strncmp(capacity_path, info.mi_path, sizeof(capacity_path)));

    mc = mpool_mclass_handle(NULL, HSE_MCLASS_CAPACITY);
    ASSERT_EQ(NULL, mc);

    mc = mpool_mclass_handle(mp, HSE_MCLASS_COUNT);
    ASSERT_EQ(NULL, mc);

    mc = mpool_mclass_handle(mp, HSE_MCLASS_CAPACITY);
    ASSERT_NE(NULL, mc);

    mcid = mclass_id(NULL);
    ASSERT_EQ(mcid, MCID_INVALID);

    mcid = mclass_id(mc);
    ASSERT_EQ(mcid, HSE_MCLASS_CAPACITY + 1);

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
    ASSERT_EQ(32ul << MB_SHIFT, mbsz);

    mclass_mblocksz_set(NULL, 64ul << MB_SHIFT);
    mbsz = mclass_mblocksz_get(mc);
    ASSERT_EQ(32ul << MB_SHIFT, mbsz);

    mclass_mblocksz_set(mc, 64ul << MB_SHIFT);
    mbsz = mclass_mblocksz_get(mc);
    ASSERT_EQ(64ul << MB_SHIFT, mbsz);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        ASSERT_EQ(i + 1, mclass_to_mcid(i));
        ASSERT_EQ(i, mcid_to_mclass(i + 1));
    }

    ASSERT_EQ(MCID_INVALID, mclass_to_mcid(i));
    ASSERT_EQ(HSE_MCLASS_INVALID, mcid_to_mclass(i + 1));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);
}

MTF_DEFINE_UTEST_PREPOST(mpool_test, is_configured, mpool_test_pre, mpool_test_post)
{
    merr_t        err;
    struct mpool *mp;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (i == HSE_MCLASS_BASE) {
            ASSERT_TRUE(mpool_mclass_is_configured(mp, i));
        } else {
            ASSERT_FALSE(mpool_mclass_is_configured(mp, i));
        }
    }

    ASSERT_FALSE(mpool_mclass_is_configured(NULL, HSE_MCLASS_BASE));
    ASSERT_FALSE(mpool_mclass_is_configured(mp, HSE_MCLASS_COUNT));

    err = mpool_close(mp);
    ASSERT_EQ(0, merr_errno(err));

    mpool_destroy(mtf_kvdb_home, &tdparams);
}

MTF_END_UTEST_COLLECTION(mpool_test);
