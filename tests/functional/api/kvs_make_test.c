/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_ut/fixtures.h>
#include <errno.h>

/* Globals */
struct hse_kvdb *kvdb_handle = NULL;
struct hse_kvs * kvs_handle = NULL;

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    int rc;

    rc = mtf_kvdb_setup(lcl_ti, NULL, &kvdb_handle, 0);
    ASSERT_EQ_RET(rc, 0, -1);

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *lcl_ti)
{
    int rc;

    rc = mtf_kvdb_teardown(lcl_ti);
    ASSERT_EQ_RET(rc, 0, -1);

    return 0;
}

int
kvs_create(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = hse_kvdb_kvs_make(kvdb_handle, "new_kvs", NULL);
    ASSERT_EQ_RET(err, 0, -1);

    err = hse_kvdb_kvs_open(kvdb_handle, "new_kvs", NULL, &kvs_handle);
    ASSERT_EQ_RET(err, 0, -1);

    return 0;
}

int
kvs_destroy(struct mtf_test_info *lcl_ti)
{
    int       rc;
    hse_err_t err;

    err = hse_kvdb_kvs_close(kvs_handle);
    ASSERT_EQ_RET(err, 0, -1);

    rc = mtf_kvdb_kvs_drop_all(kvdb_handle);
    ASSERT_EQ_RET(rc, 0, -1);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvs_api_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST(kvs_api_test, kvs_nonexisting_testcase)
{
    hse_err_t       err;
    struct hse_kvs *kvs_handle = NULL;

    /* TC: A non-existing KVS cannot be opened */
    err = hse_kvdb_kvs_open(kvdb_handle, "non_existing_kvs", NULL, &kvs_handle);
    ASSERT_EQ(hse_err_to_errno(err), ENOENT);
    ASSERT_EQ(kvs_handle, NULL);

    /* TC: A non-existing KVS cannot be closed */
    err = hse_kvdb_kvs_close(NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, kvs_invalid_testcase, kvs_create, kvs_destroy)
{
    hse_err_t err;
    char      buf[16];
    char      bad_name[] = { 'k', 'v', 's', 1, 19, 0 };
    char      kvs_buf[HSE_KVS_NAME_LEN_MAX + 1];
    int       n;
    /* TC: A KVS cannot be created with special characters in the name */
    err = hse_kvdb_kvs_make(kvdb_handle, "kvdb/example", NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS cannot be created with no characters in the name */
    err = hse_kvdb_kvs_make(kvdb_handle, "", NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS cannot be created with NULL value */
    err = hse_kvdb_kvs_make(kvdb_handle, NULL, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS cannot be created with binary characters  */
    err = hse_kvdb_kvs_make(kvdb_handle, bad_name, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS can be created with less than defined max length of 32 characters in the name */

    for (int i = 0; i < HSE_KVS_NAME_LEN_MAX - 1; i++) {
        kvs_buf[i] = 'a' + (i % 26);
    }
    kvs_buf[HSE_KVS_NAME_LEN_MAX - 1] = '\000';
    err = hse_kvdb_kvs_make(kvdb_handle, kvs_buf, NULL);
    ASSERT_EQ(err, 0);

    /* TC: A KVS cannot be created with more than defined max length of 32 characters in the name */
    kvs_buf[HSE_KVS_NAME_LEN_MAX - 1] = 'x';
    kvs_buf[HSE_KVS_NAME_LEN_MAX] = '\000';
    err = hse_kvdb_kvs_make(kvdb_handle, kvs_buf, NULL);
    ASSERT_EQ(hse_err_to_errno(err), ENAMETOOLONG);

    /* TC: Two KVS cannot have same name */
    err = hse_kvdb_kvs_make(kvdb_handle, "new_kvs", NULL);
    ASSERT_EQ(hse_err_to_errno(err), EEXIST);

    /* TC: KVDB cannot have more than 256 KVS */
    for (int i = 2; i <= HSE_KVS_COUNT_MAX; i++) {
        n = snprintf(buf, sizeof(buf), "%s_%d", "new_kvs", i);
        ASSERT_LT(n, sizeof(buf));
        err = hse_kvdb_kvs_make(kvdb_handle, buf, NULL);
        if (i < HSE_KVS_COUNT_MAX) {
            ASSERT_EQ(err, 0);
        } else {
            ASSERT_EQ(hse_err_to_errno(err), EINVAL);
        }
    }
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, kvs_handle_testcase, kvs_create, kvs_destroy)
{
    hse_err_t err;
    size_t    vlen;
    char      vbuf[16];
    bool      found;

    /* TC: A handle cannot be reused until closed */
    err = hse_kvdb_kvs_open(kvdb_handle, "new_kvs", NULL, &kvs_handle);
    ASSERT_EQ(hse_err_to_errno(err), EBUSY);

    /* TC: A KVS cannot get a non-existing key value pair */
    err = hse_kvs_get(
        kvs_handle, NULL, "test_key", strlen("test_key"), &found, vbuf, sizeof(vbuf), &vlen);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(found, false);
}

MTF_END_UTEST_COLLECTION(kvs_api_test)
