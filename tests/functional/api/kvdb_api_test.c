/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <sys/stat.h>

#include <hse/hse.h>
#include <hse/experimental.h>

#include <mtf/framework.h>
#include <fixtures/kvdb.h>

#include <hse_util/base.h>

struct hse_kvdb *kvdb_handle;

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvdb_setup(home, 0, NULL, 0, NULL, &kvdb_handle);

    return hse_err_to_errno(err);
}

int
test_collection_teardown(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvdb_teardown(home, kvdb_handle);

    return hse_err_to_errno(err);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvdb_api_test, test_collection_setup, test_collection_teardown)

MTF_DEFINE_UTEST(kvdb_api_test, close_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_close(NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, compact_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_compact(NULL, 0);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, compact_invalid_flags)
{
    hse_err_t err;

    err = hse_kvdb_compact(kvdb_handle, 81);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, create_null_home)
{
    hse_err_t err;

    err = hse_kvdb_create(NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, create_home_zero_length)
{
    hse_err_t err;

    err = hse_kvdb_create("", 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, create_home_too_long)
{
    hse_err_t err;
    char      buf[PATH_MAX + 1];

    memset(buf, 'a', sizeof(buf));
    buf[PATH_MAX] = '\0';

    err = hse_kvdb_create(buf, 0, NULL);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, create_mismatched_paramc_paramv)
{
    hse_err_t err;

    err = hse_kvdb_create(home, 1, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, create_exists)
{
    hse_err_t err;

    /* TC: Trying to create a KVDB on an already open KVDB returns EEXIST */
    err = hse_kvdb_create(home, 0, NULL);
    ASSERT_EQ(EEXIST, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, drop_null_home)
{
    hse_err_t err;

    err = hse_kvdb_drop(NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, drop_home_zero_length)
{
    hse_err_t err;

    err = hse_kvdb_drop("");
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, drop_home_too_long)
{
    hse_err_t err;
    char      buf[PATH_MAX + 1];

    memset(buf, 'a', sizeof(buf));
    buf[PATH_MAX] = '\0';

    err = hse_kvdb_drop(buf);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, drop_open_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_drop(home);
    ASSERT_EQ(EBUSY, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, home_null_kvdb)
{
    const char *home_intro;

    home_intro = hse_kvdb_home_get(NULL);
    ASSERT_EQ(NULL, home_intro);
}

MTF_DEFINE_UTEST(kvdb_api_test, home_success)
{
    const char *home_intro;

    home_intro = hse_kvdb_home_get(kvdb_handle);
    ASSERT_STREQ(home, home_intro);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvs_names_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_kvs_names_get(NULL, NULL, (char ***)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, kvs_names_null_namev)
{
    hse_err_t err;

    err = hse_kvdb_kvs_names_get(kvdb_handle, NULL, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, kvs_name_success)
{
    hse_err_t err;
    size_t    namec;
    char    **namev;

    err = hse_kvdb_kvs_names_get(kvdb_handle, &namec, &namev);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(0, namec);
    ASSERT_EQ(NULL, namev);

    err = hse_kvdb_kvs_create(kvdb_handle, "kvs", 0, NULL);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_kvs_names_get(kvdb_handle, &namec, &namev);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(1, namec);
    ASSERT_STREQ("kvs", namev[0]);

    hse_kvdb_kvs_names_free(kvdb_handle, namev);

    err = hse_kvdb_kvs_drop(kvdb_handle, "kvs");
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_info_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_mclass_info_get(NULL, HSE_MCLASS_BASE, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_info_invalid_mclass)
{
    hse_err_t err;

    err = hse_kvdb_mclass_info_get(kvdb_handle, -1, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));

    err = hse_kvdb_mclass_info_get(kvdb_handle, HSE_MCLASS_COUNT, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_info_null_info)
{
    hse_err_t err;

    err = hse_kvdb_mclass_info_get(kvdb_handle, HSE_MCLASS_BASE, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_info_success)
{
    hse_err_t              err;
    struct hse_mclass_info info;
    char                   buf[PATH_MAX + sizeof("capacity")];

    snprintf(buf, sizeof(buf), "%s%s%s", home, home[strlen(home)] == '/' ? "" : "/", "capacity");

    err = hse_kvdb_mclass_info_get(kvdb_handle, HSE_MCLASS_CAPACITY, &info);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_STREQ(buf, info.mi_path);
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_is_configured_null_kvdb)
{
    bool configured;

    configured = hse_kvdb_mclass_is_configured(NULL, HSE_MCLASS_BASE);
    ASSERT_FALSE(configured);
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_is_configured_invalid_mclass)
{
    bool configured;

    configured = hse_kvdb_mclass_is_configured(kvdb_handle, -1);
    ASSERT_FALSE(configured);

    configured = hse_kvdb_mclass_is_configured(kvdb_handle, HSE_MCLASS_COUNT);
    ASSERT_FALSE(configured);
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_is_configured_success)
{
    bool configured;

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        configured = hse_kvdb_mclass_is_configured(kvdb_handle, i);
        ASSERT_EQ(i == HSE_MCLASS_CAPACITY, configured);
    }
}

MTF_DEFINE_UTEST(kvdb_api_test, open_null_home)
{
    hse_err_t err;

    err = hse_kvdb_open(NULL, 0, NULL, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, open_home_zero_length)
{
    hse_err_t err;

    err = hse_kvdb_open("", 0, NULL, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, open_home_too_long)
{
    hse_err_t err;
    char      buf[PATH_MAX + 1];

    memset(buf, 'a', sizeof(buf));
    buf[PATH_MAX] = '\0';

    err = hse_kvdb_open(buf, 0, NULL, (void *)-1);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, open_twice)
{
    hse_err_t err;

    err = hse_kvdb_open(home, 0, NULL, &kvdb_handle);
    ASSERT_EQ(EBUSY, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, open_mismatched_paramc_paramv)
{
    hse_err_t err;

    err = hse_kvdb_open(home, 1, NULL, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, reopen)
{
    hse_err_t err;

    err = hse_kvdb_close(kvdb_handle);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_open(home, 0, NULL, &kvdb_handle);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, param_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_param_get(NULL, "read_only", NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, param_null_param)
{
    hse_err_t err;

    err = hse_kvdb_param_get(kvdb_handle, NULL, NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, param_mismatched_buf_buf_sz)
{
    hse_err_t err;

    err = hse_kvdb_param_get(kvdb_handle, "read_only", NULL, 8, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, param_success)
{
    hse_err_t err;
    size_t    needed_sz;
    char      buf[8];

    err = hse_kvdb_param_get(kvdb_handle, "read_only", NULL, 0, &needed_sz);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(5, needed_sz);

    err = hse_kvdb_param_get(kvdb_handle, "read_only", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_STREQ("false", buf);
    ASSERT_EQ(5, needed_sz);
}

MTF_DEFINE_UTEST(kvdb_api_test, storage_add_null_home)
{
    hse_err_t err;

    err = hse_kvdb_storage_add(NULL, 1, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, storage_add_home_zero_length)
{
    hse_err_t err;

    err = hse_kvdb_storage_add("", 1, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, storage_add_zero_paramc)
{
    hse_err_t err;

    err = hse_kvdb_storage_add(home, 0, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, storage_add_null_paramv)
{
    hse_err_t err;

    err = hse_kvdb_storage_add(home, 1, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, storage_add_open)
{
    hse_err_t   err;
    const char *paramv[] = { "storage." HSE_MCLASS_STAGING_NAME ".path=staging" };

    err = hse_kvdb_storage_add(home, NELEM(paramv), paramv);
    ASSERT_EQ(EBUSY, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, storage_add_success)
{
    hse_err_t   err;
    int         rc;
    char        staging_path[2 * PATH_MAX];
    const char *paramv[] = { staging_path };

    snprintf(
        staging_path,
        sizeof(staging_path),
        "storage.%s.path=%s%s%s",
        HSE_MCLASS_STAGING_NAME,
        home,
        home[strlen(home)] == '/' ? "" : "/",
        "staging");

    rc = mkdir(
        staging_path + sizeof("storage." HSE_MCLASS_STAGING_NAME ".path=") - 1,
        S_IRGRP | S_IXGRP | S_IRWXU);
    ASSERT_EQ(0, rc);

    err = hse_kvdb_close(kvdb_handle);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_storage_add(home, NELEM(paramv), paramv);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_open(home, 0, NULL, &kvdb_handle);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, sync_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_sync(NULL, 0);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, sync_invalid_flags)
{
    hse_err_t err;

    err = hse_kvdb_sync((void *)-1, 81);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, sync_success)
{
    hse_err_t err;

    err = hse_kvdb_sync(kvdb_handle, 0);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_name_invalid_mclass)
{
    const char *name;

    name = hse_mclass_name_get(-1);
    ASSERT_EQ(NULL, name);

    name = hse_mclass_name_get(HSE_MCLASS_COUNT);
    ASSERT_EQ(NULL, name);
}

MTF_DEFINE_UTEST(kvdb_api_test, mclass_name_success)
{
    const char *name;

    name = hse_mclass_name_get(HSE_MCLASS_CAPACITY);
    ASSERT_STREQ(HSE_MCLASS_CAPACITY_NAME, name);

    name = hse_mclass_name_get(HSE_MCLASS_STAGING);
    ASSERT_STREQ(HSE_MCLASS_STAGING_NAME, name);

    name = hse_mclass_name_get(HSE_MCLASS_PMEM);
    ASSERT_STREQ(HSE_MCLASS_PMEM_NAME, name);
}

MTF_END_UTEST_COLLECTION(kvdb_api_test)
