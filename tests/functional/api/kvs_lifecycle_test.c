/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <fixtures/kvdb.h>
#include <fixtures/kvs.h>
#include <errno.h>

/* Globals */
struct hse_kvdb *kvdb_handle = NULL;
struct hse_kvs * kvs_handle = NULL;
const char *     kvs_name = "kvs-lifecycle-test";

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

int
kvs_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvs_setup(kvdb_handle, kvs_name, 0, NULL, 0, NULL, &kvs_handle);

    return hse_err_to_errno(err);
}

int
kvs_teardown(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvs_teardown(kvdb_handle, kvs_name, kvs_handle);

    return hse_err_to_errno(err);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvs_api, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST(kvs_api, kvs_nonexisting)
{
    hse_err_t       err;
    struct hse_kvs *kvs_handle = NULL;

    /* TC: A non-existing KVS cannot be opened */
    err = hse_kvdb_kvs_open(kvdb_handle, "non_existing_kvs", 0, NULL, &kvs_handle);
    ASSERT_EQ(hse_err_to_errno(err), ENOENT);
    ASSERT_EQ(kvs_handle, NULL);

    /* TC: A non-existing KVS cannot be closed */
    err = hse_kvdb_kvs_close(NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);
}

MTF_DEFINE_UTEST_PREPOST(kvs_api, kvs_invalid, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    char      buf[32];
    char      bad_name[] = { 'k', 'v', 's', 1, 19, 0 };
    char      kvs_buf[HSE_KVS_NAME_LEN_MAX + 1];
    int       n;

    /* TC: A KVS cannot be created with special characters in the name */
    err = hse_kvdb_kvs_create(kvdb_handle, "kvdb/example", 0, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS cannot be created with no characters in the name */
    err = hse_kvdb_kvs_create(kvdb_handle, "", 0, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS cannot be created with NULL value */
    err = hse_kvdb_kvs_create(kvdb_handle, NULL, 0, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS cannot be created with binary characters  */
    err = hse_kvdb_kvs_create(kvdb_handle, bad_name, 0, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS can be created with less than defined max length of 32 characters in the name */
    for (int i = 0; i < HSE_KVS_NAME_LEN_MAX - 1; i++) {
        kvs_buf[i] = 'a' + (i % 26);
    }
    kvs_buf[HSE_KVS_NAME_LEN_MAX - 1] = '\000';
    err = hse_kvdb_kvs_create(kvdb_handle, kvs_buf, 0, NULL);
    ASSERT_EQ(err, 0);

    /* TC: A KVS cannot be created with more than defined max length of 32 characters in the name */
    kvs_buf[HSE_KVS_NAME_LEN_MAX - 1] = 'x';
    kvs_buf[HSE_KVS_NAME_LEN_MAX] = '\000';
    err = hse_kvdb_kvs_create(kvdb_handle, kvs_buf, 0, NULL);
    ASSERT_EQ(hse_err_to_errno(err), ENAMETOOLONG);

    /* TC: Two KVS cannot have same name */
    err = hse_kvdb_kvs_create(kvdb_handle, kvs_name, 0, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EEXIST);

    /* TC: KVDB cannot have more than 256 KVS */
    for (int i = 2; i <= HSE_KVS_COUNT_MAX; i++) {
        n = snprintf(buf, sizeof(buf), "%s_%d", kvs_name, i);
        ASSERT_LT(n, sizeof(buf));
        err = hse_kvdb_kvs_create(kvdb_handle, buf, 0, NULL);
        if (i < HSE_KVS_COUNT_MAX) {
            ASSERT_EQ(err, 0);
        } else {
            ASSERT_EQ(hse_err_to_errno(err), EINVAL);
        }
    }
}

MTF_DEFINE_UTEST_PREPOST(kvs_api, kvs_valid_handle, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    size_t    vlen;
    char      vbuf[16];
    bool      found;

    /* TC: A handle cannot be reused until closed */
    err = hse_kvdb_kvs_open(kvdb_handle, kvs_name, 0, NULL, &kvs_handle);
    ASSERT_EQ(hse_err_to_errno(err), EBUSY);

    /* TC: A KVS cannot get a non-existing key value pair */
    err = hse_kvs_get(
        kvs_handle, 0, NULL, "test_key", strlen("test_key"), &found, vbuf, sizeof(vbuf), &vlen);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(found, false);
}

MTF_END_UTEST_COLLECTION(kvs_api)
