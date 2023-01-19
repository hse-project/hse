/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>

#include <mtf/framework.h>

#include <hse/experimental.h>
#include <hse/hse.h>

#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/vcomp_params.h>
#include <hse/test/fixtures/kvdb.h>
#include <hse/test/fixtures/kvs.h>
#include <hse/util/base.h>

struct hse_kvdb *kvdb_handle;
struct hse_kvs *kvs_handle;
const char *kvs_name = "kvs";

#define FILTER      "key"
#define FILTER_LEN  (sizeof(FILTER) - 1)
#define PFX         FILTER
#define PFX_LEN     FILTER_LEN
#define NUM_ENTRIES 5
#define KEY_FMT     (PFX "%d")
#define VALUE_FMT   "value%d"

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvdb_setup(mtf_kvdb_home, 0, NULL, 0, NULL, &kvdb_handle);

    return hse_err_to_errno(err);
}

int
test_collection_teardown(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvdb_teardown(mtf_kvdb_home, kvdb_handle);

    return hse_err_to_errno(err);
}

int
kvs_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    char prefix_length_param[32];
    const char *cparamv[] = { prefix_length_param };

    snprintf(prefix_length_param, sizeof(prefix_length_param), "prefix.length=%lu", PFX_LEN);

    err = fxt_kvs_setup(kvdb_handle, kvs_name, 0, NULL, NELEM(cparamv), cparamv, &kvs_handle);

    return hse_err_to_errno(err);
}

int
transactional_kvs_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    char prefix_length_param[32];
    const char *cparamv[] = { prefix_length_param };
    const char *rparamv[] = { "transactions.enabled=true" };

    snprintf(prefix_length_param, sizeof(prefix_length_param), "prefix.length=%lu", PFX_LEN);

    err = fxt_kvs_setup(
        kvdb_handle, kvs_name, NELEM(rparamv), rparamv, NELEM(cparamv), cparamv, &kvs_handle);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    return hse_err_to_errno(err);
}

int
kvs_setup_with_data(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    char prefix_length_param[32];
    const char *cparamv[] = { prefix_length_param };
    char key_buf[8], val_buf[8];

    snprintf(prefix_length_param, sizeof(prefix_length_param), "prefix.length=%lu", PFX_LEN);

    err = fxt_kvs_setup(kvdb_handle, kvs_name, 0, NULL, NELEM(cparamv), cparamv, &kvs_handle);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        int key_len;
        int val_len;

        key_len = snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        ASSERT_LT_RET(key_len, sizeof(key_buf) - 1, ENAMETOOLONG);
        ASSERT_GT_RET(key_len, 0, EBADMSG);

        val_len = snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);
        ASSERT_LT_RET(val_len, sizeof(val_buf) - 1, ENAMETOOLONG);
        ASSERT_GT_RET(val_len, 0, EBADMSG);

        err = hse_kvs_put(kvs_handle, 0, NULL, key_buf, key_len, val_buf, val_len);
        ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));
    }

    return hse_err_to_errno(err);
}

int
transactional_kvs_setup_with_data(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    char prefix_length_param[32];
    const char *cparamv[] = { prefix_length_param };
    const char *rparamv[] = { "transactions.enabled=true" };
    char key_buf[8], val_buf[8];
    struct hse_kvdb_txn *txn;

    snprintf(prefix_length_param, sizeof(prefix_length_param), "prefix.length=%lu", PFX_LEN);

    err = fxt_kvs_setup(
        kvdb_handle, kvs_name, NELEM(rparamv), rparamv, NELEM(cparamv), cparamv, &kvs_handle);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE_RET(NULL, txn, EINVAL);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        int key_len;
        int val_len;

        key_len = snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        ASSERT_LT_RET(key_len, sizeof(key_buf) - 1, ENAMETOOLONG);
        ASSERT_GT_RET(key_len, 0, EBADMSG);

        val_len = snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);
        ASSERT_LT_RET(val_len, sizeof(val_buf) - 1, ENAMETOOLONG);
        ASSERT_GT_RET(val_len, 0, EBADMSG);

        err = hse_kvs_put(kvs_handle, 0, txn, key_buf, key_len, val_buf, val_len);
        ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));
    }

    err = hse_kvdb_txn_commit(kvdb_handle, txn);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    return hse_err_to_errno(err);
}

int
kvs_teardown(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvs_teardown(kvdb_handle, kvs_name, kvs_handle);

    return hse_err_to_errno(err);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvs_api_test, test_collection_setup, test_collection_teardown)

MTF_DEFINE_UTEST(kvs_api_test, close_null_kvs)
{
    hse_err_t err;

    err = hse_kvdb_kvs_close(NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, create_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_kvs_create(NULL, "kvs", 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, create_null_name)
{
    hse_err_t err;

    err = hse_kvdb_kvs_create(kvdb_handle, NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, create_invalid_name)
{
    hse_err_t err;
    const char *namev[] = { "",  "!", "@", "#",  "$", "%", "^", "&", "*",  "(",
                            ")", "<", ">", "?",  ",", ".", "/", ":", "\"", ";",
                            "'", "{", "}", "\\", "[", "]", "|", "+", "=" };

    for (int i = 0; i < NELEM(namev); i++) {
        err = hse_kvdb_kvs_create(kvdb_handle, namev[i], 0, NULL);
        ASSERT_EQ(EINVAL, hse_err_to_errno(err));
    }
}

MTF_DEFINE_UTEST(kvs_api_test, create_mismatched_paramc_paramv)
{
    hse_err_t err;

    err = hse_kvdb_kvs_create(kvdb_handle, "kvs", 1, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, drop_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_kvs_drop(NULL, "kvs");
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, drop_null_name)
{
    hse_err_t err;

    err = hse_kvdb_kvs_drop(kvdb_handle, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, drop_invalid_name)
{
    hse_err_t err;
    const char *namev[] = { "",  "!", "@", "#",  "$", "%", "^", "&", "*",  "(",
                            ")", "<", ">", "?",  ",", ".", "/", ":", "\"", ";",
                            "'", "{", "}", "\\", "[", "]", "|", "+", "=" };

    for (int i = 0; i < NELEM(namev); i++) {
        err = hse_kvdb_kvs_drop(kvdb_handle, namev[i]);
        ASSERT_EQ(ENOENT, hse_err_to_errno(err));
    }
}

MTF_DEFINE_UTEST(kvs_api_test, open_null_kvdb)
{
    hse_err_t err;

    err = hse_kvdb_kvs_open(NULL, kvs_name, 0, NULL, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, open_null_name)
{
    hse_err_t err;

    err = hse_kvdb_kvs_open(kvdb_handle, NULL, 0, NULL, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, open_invalid_name)
{
    hse_err_t err;
    const char *namev[] = { "",  "!", "@", "#",  "$", "%", "^", "&", "*",  "(",
                            ")", "<", ">", "?",  ",", ".", "/", ":", "\"", ";",
                            "'", "{", "}", "\\", "[", "]", "|", "+", "=" };

    for (int i = 0; i < NELEM(namev); i++) {
        err = hse_kvdb_kvs_open(kvdb_handle, namev[i], 0, NULL, (void *)-1);
        ASSERT_EQ(ENOENT, hse_err_to_errno(err));
    }
}

MTF_DEFINE_UTEST(kvs_api_test, open_mismatched_paramc_paramv)
{
    hse_err_t err;

    err = hse_kvdb_kvs_open(kvdb_handle, "kvs", 1, NULL, (void *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, lifecycle_test)
{
    hse_err_t err;
    struct hse_kvs *kvs;

    err = hse_kvdb_kvs_create(kvdb_handle, __func__, 0, NULL);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_kvs_open(kvdb_handle, __func__, 0, NULL, &kvs);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_kvs_close(kvs);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_kvs_drop(kvdb_handle, __func__);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, delete_null_kvs)
{
    hse_err_t err;

    err = hse_kvs_delete(NULL, 0, NULL, (void *)-1, 1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, delete_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_delete((struct hse_kvs *)-1, ~0, NULL, (const void *)-1, 1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, delete_null_key)
{
    hse_err_t err;

    err = hse_kvs_delete((struct hse_kvs *)-1, 0, NULL, NULL, 1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, delete_key_len_too_long)
{
    hse_err_t err;

    err = hse_kvs_delete((struct hse_kvs *)-1, 0, NULL, (const void *)-1, HSE_KVS_KEY_LEN_MAX + 1);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, delete_key_len_is_0)
{
    hse_err_t err;

    err = hse_kvs_delete((struct hse_kvs *)-1, 0, NULL, (void *)-1, 0);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, delete_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t err;
    bool found;
    size_t val_len;

    err = hse_kvs_delete(kvs_handle, 0, NULL, "key0", sizeof("key0") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_get(kvs_handle, 0, NULL, "key0", sizeof("key0") - 1, &found, NULL, 0, &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_FALSE(found);
}

MTF_DEFINE_UTEST_PREPOST(
    kvs_api_test,
    delete_success_transactional,
    transactional_kvs_setup,
    kvs_teardown)
{
    hse_err_t err;
    bool found;
    size_t val_len;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err =
        hse_kvs_put(kvs_handle, 0, txn, "key0", sizeof("key0") - 1, "value0", sizeof("value0") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_get(kvs_handle, 0, txn, "key0", sizeof("key0") - 1, &found, NULL, 0, &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(found);

    err = hse_kvs_delete(kvs_handle, 0, txn, "key0", sizeof("key0") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_get(kvs_handle, 0, txn, "key0", sizeof("key0") - 1, &found, NULL, 0, &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_FALSE(found);

    err = hse_kvdb_txn_abort(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(kvs_api_test, get_null_kvs)
{
    hse_err_t err;

    err = hse_kvs_get(NULL, 0, NULL, (const void *)-1, 1, (bool *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, get_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_get(
        (struct hse_kvs *)-1, ~0, NULL, (const void *)-1, 1, (bool *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, get_null_key)
{
    hse_err_t err;

    err = hse_kvs_get((struct hse_kvs *)-1, 0, NULL, NULL, 1, (bool *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, get_null_found)
{
    hse_err_t err;

    err = hse_kvs_get((struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, NULL, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, get_null_val_len)
{
    hse_err_t err;

    err = hse_kvs_get((struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, (bool *)-1, NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, get_mismatch_valbuf_valbuf_sz)
{
    hse_err_t err;

    err = hse_kvs_get(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, (bool *)-1, NULL, 1, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, get_key_len_too_long)
{
    hse_err_t err;

    err = hse_kvs_get(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, HSE_KVS_KEY_LEN_MAX + 1, (bool *)-1, NULL, 0,
        (size_t *)-1);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, get_key_len_is_0)
{
    hse_err_t err;

    err = hse_kvs_get(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 0, (bool *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, get_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t err;
    bool found;
    char valbuf[8];
    size_t val_len;

    err = hse_kvs_get(
        kvs_handle, 0, NULL, "key0", sizeof("key0") - 1, &found, valbuf, sizeof(valbuf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(found);
    ASSERT_EQ(0, memcmp(valbuf, "value0", val_len));
}

MTF_DEFINE_UTEST_PREPOST(
    kvs_api_test,
    get_success_transactional,
    transactional_kvs_setup,
    kvs_teardown)
{
    hse_err_t err;
    bool found;
    char valbuf[8];
    size_t val_len;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err =
        hse_kvs_put(kvs_handle, 0, txn, "key0", sizeof("key0") - 1, "value0", sizeof("value0") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_get(
        kvs_handle, 0, txn, "key0", sizeof("key0") - 1, &found, valbuf, sizeof(valbuf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(found);
    ASSERT_EQ(0, memcmp(valbuf, "value0", val_len));
}

MTF_DEFINE_UTEST(kvs_api_test, name_null_kvs)
{
    const char *name;

    name = hse_kvs_name_get(NULL);
    ASSERT_EQ(NULL, name);
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, name_success, kvs_setup, kvs_teardown)
{
    const char *name;

    name = hse_kvs_name_get(kvs_handle);
    ASSERT_STREQ(kvs_name, name);
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, param_dnem, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    size_t needed_sz;
    char buf[16];

    err = hse_kvs_param_get(kvs_handle, "does.not.exist", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, param_null_kvs)
{
    hse_err_t err;

    err = hse_kvs_param_get(NULL, "transactions.enabled", NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, param_null_param)
{
    hse_err_t err;

    err = hse_kvs_param_get((struct hse_kvs *)-1, NULL, NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, param_mismatched_buf_buf_sz)
{
    hse_err_t err;

    err = hse_kvs_param_get((struct hse_kvs *)-1, "transactions.enabled", NULL, 8, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, param_success, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    size_t needed_sz;
    char buf[8];

    err = hse_kvs_param_get(kvs_handle, "transactions.enabled", NULL, 0, &needed_sz);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(5, needed_sz);

    err = hse_kvs_param_get(kvs_handle, "transactions.enabled", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_STREQ("false", buf);
    ASSERT_EQ(5, needed_sz);
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_delete_null_kvs)
{
    hse_err_t err;

    err = hse_kvs_prefix_delete(NULL, 0, NULL, PFX, PFX_LEN);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_delete_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_prefix_delete((struct hse_kvs *)-1, ~0, NULL, PFX, PFX_LEN);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_delete_null_pfx)
{
    hse_err_t err;

    err = hse_kvs_prefix_delete((struct hse_kvs *)-1, 0, NULL, NULL, 1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_delete_pfx_len_too_long)
{
    hse_err_t err;

    err = hse_kvs_prefix_delete((struct hse_kvs *)-1, 0, NULL, (void *)-1, HSE_KVS_PFX_LEN_MAX + 1);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_delete_pfx_len_is_0)
{
    hse_err_t err;

    err = hse_kvs_prefix_delete((struct hse_kvs *)-1, 0, NULL, (void *)-1, 0);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    kvs_api_test,
    prefix_delete_pfx_len_mismatch_with_kvs_cparam,
    kvs_setup,
    kvs_teardown)
{
    hse_err_t err;

    err = hse_kvs_prefix_delete(kvs_handle, 0, NULL, PFX, PFX_LEN + 1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, prefix_delete_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t err;
    char key_buf[8];
    size_t val_len;
    bool found;
    int n;

    err = hse_kvs_prefix_delete(kvs_handle, 0, NULL, PFX, PFX_LEN);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        n = snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);

        err = hse_kvs_get(kvs_handle, 0, NULL, key_buf, n, &found, NULL, 0, &val_len);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_FALSE(found);
    }
}

MTF_DEFINE_UTEST_PREPOST(
    kvs_api_test,
    prefix_delete_transactional,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t err;
    struct hse_kvdb_txn *txn;
    char key_buf[8], val_buf[8];
    size_t key_len, val_len;
    bool found;
    int n;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    key_len = snprintf(key_buf, sizeof(key_buf), KEY_FMT, NUM_ENTRIES);
    val_len = snprintf(val_buf, sizeof(val_buf), VALUE_FMT, NUM_ENTRIES);

    err = hse_kvs_put(kvs_handle, 0, txn, key_buf, key_len, val_buf, val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_prefix_delete(kvs_handle, 0, txn, PFX, PFX_LEN);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i <= NUM_ENTRIES; i++) {
        n = snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);

        err = hse_kvs_get(kvs_handle, 0, txn, key_buf, n, &found, NULL, 0, &val_len);
        if (i == NUM_ENTRIES) {
            ASSERT_TRUE(found);
        } else {
            ASSERT_FALSE(found);
        }
    }

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(kvs_api_test, put_null_kvs)
{
    hse_err_t err;

    err = hse_kvs_put(NULL, 0, NULL, (void *)-1, 1, NULL, 0);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, put_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_put((struct hse_kvs *)-1, ~0, NULL, (void *)-1, 1, NULL, 0);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, put_null_key)
{
    hse_err_t err;

    err = hse_kvs_put((struct hse_kvs *)-1, 0, NULL, NULL, 0, NULL, 0);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, put_mismatch_val_val_len)
{
    hse_err_t err;

    err = hse_kvs_put((struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, NULL, 1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, put_key_len_too_long)
{
    hse_err_t err;

    err = hse_kvs_put((struct hse_kvs *)-1, 0, NULL, (void *)-1, HSE_KVS_KEY_LEN_MAX + 1, NULL, 0);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, put_key_len_is_0)
{
    hse_err_t err;

    err = hse_kvs_put((struct hse_kvs *)-1, 0, NULL, (void *)-1, 0, NULL, 0);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, put_val_len_too_long)
{
    hse_err_t err;

    err = hse_kvs_put(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, (void *)-1, HSE_KVS_VALUE_LEN_MAX + 1);
    ASSERT_EQ(EMSGSIZE, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, put_vcomp_on, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t err;
    char buf[CN_SMALL_VALUE_THRESHOLD];

    memset(buf, 1, sizeof(buf));

    err = hse_kvs_put(kvs_handle, HSE_KVS_PUT_VCOMP_ON, NULL, "vcomp", 5, buf, sizeof(buf));
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, put_vcomp_exclusivity, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t err;
    char buf[CN_SMALL_VALUE_THRESHOLD];

    memset(buf, 1, sizeof(buf));

    err = hse_kvs_put(
        kvs_handle, HSE_KVS_PUT_VCOMP_ON | HSE_KVS_PUT_VCOMP_OFF, NULL, "vcomp", 5, buf,
        sizeof(buf));
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_null_kvs)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        NULL, 0, NULL, (void *)-1, 1, (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1,
        HSE_KVS_KEY_LEN_MAX, (size_t *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, ~0, NULL, (void *)-1, 1, (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1,
        HSE_KVS_KEY_LEN_MAX, (size_t *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_null_pfx)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, 0, NULL, NULL, 1, (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1,
        HSE_KVS_KEY_LEN_MAX, (size_t *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_null_found)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, NULL, (void *)-1, HSE_KVS_KEY_LEN_MAX,
        (size_t *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_null_val_len)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1,
        HSE_KVS_KEY_LEN_MAX, (size_t *)-1, NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_mismatched_valbuf_valbuf_sz)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1,
        HSE_KVS_KEY_LEN_MAX, (size_t *)-1, NULL, 1, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_pfx_len_is_0)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 0, (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1,
        HSE_KVS_KEY_LEN_MAX, (size_t *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_pfx_len_too_long)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, HSE_KVS_KEY_LEN_MAX + 1,
        (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1, HSE_KVS_KEY_LEN_MAX, (size_t *)-1, NULL, 0,
        (size_t *)-1);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(kvs_api_test, prefix_probe_keybuf_sz_mismatch)
{
    hse_err_t err;

    err = hse_kvs_prefix_probe(
        (struct hse_kvs *)-1, 0, NULL, (void *)-1, 1, (enum hse_kvs_pfx_probe_cnt *)-1, (void *)-1,
        HSE_KVS_KEY_LEN_MAX - 1, (size_t *)-1, NULL, 0, (size_t *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_api_test, prefix_probe_success, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    enum hse_kvs_pfx_probe_cnt found;
    char key_buf[HSE_KVS_KEY_LEN_MAX], val_buf[8];
    size_t key_len, val_len;

    err = hse_kvs_put(
        kvs_handle, 0, NULL, "key0", sizeof("key0") - 1, "value0", sizeof("value0") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_prefix_probe(
        kvs_handle, 0, NULL, PFX, PFX_LEN, &found, key_buf, sizeof(key_buf), &key_len, val_buf,
        sizeof(val_buf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(HSE_KVS_PFX_FOUND_ONE, found);
    ASSERT_EQ(0, memcmp(key_buf, "key0", key_len));
    ASSERT_EQ(0, memcmp(val_buf, "value0", val_len));

    err = hse_kvs_put(
        kvs_handle, 0, NULL, "key1", sizeof("key1") - 1, "value1", sizeof("value1") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_prefix_probe(
        kvs_handle, 0, NULL, PFX, PFX_LEN, &found, key_buf, sizeof(key_buf), &key_len, val_buf,
        sizeof(val_buf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(HSE_KVS_PFX_FOUND_MUL, found);

    if (memcmp(key_buf, "key0", key_len) == 0)
        ASSERT_EQ(0, memcmp(val_buf, "value0", val_len));
    else if (memcmp(key_buf, "key1", key_len) == 0)
        ASSERT_EQ(0, memcmp(val_buf, "value1", val_len));
    else
        ASSERT_TRUE(0);

    err = hse_kvs_prefix_probe(
        kvs_handle, 0, NULL, "xyz", sizeof("xyz") - 1, &found, key_buf, sizeof(key_buf), &key_len,
        val_buf, sizeof(val_buf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(HSE_KVS_PFX_FOUND_ZERO, found);
}

MTF_DEFINE_UTEST_PREPOST(
    kvs_api_test,
    prefix_probe_success_transactional,
    transactional_kvs_setup,
    kvs_teardown)
{
    hse_err_t err;
    enum hse_kvs_pfx_probe_cnt found;
    char key_buf[HSE_KVS_KEY_LEN_MAX], val_buf[8];
    size_t key_len, val_len;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err =
        hse_kvs_put(kvs_handle, 0, txn, "key0", sizeof("key0") - 1, "value0", sizeof("value0") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_prefix_probe(
        kvs_handle, 0, txn, PFX, PFX_LEN, &found, key_buf, sizeof(key_buf), &key_len, val_buf,
        sizeof(val_buf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(HSE_KVS_PFX_FOUND_ONE, found);
    ASSERT_EQ(0, memcmp(key_buf, "key0", key_len));
    ASSERT_EQ(0, memcmp(val_buf, "value0", val_len));

    /* By committing this transaction, we can make sure that prefix_probe() can
     * peer into persisted data and non-persisted data.
     */
    err = hse_kvdb_txn_commit(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err =
        hse_kvs_put(kvs_handle, 0, txn, "key1", sizeof("key1") - 1, "value1", sizeof("value1") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_prefix_probe(
        kvs_handle, 0, txn, PFX, PFX_LEN, &found, key_buf, sizeof(key_buf), &key_len, val_buf,
        sizeof(val_buf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(HSE_KVS_PFX_FOUND_MUL, found);

    if (memcmp(key_buf, "key0", key_len) == 0)
        ASSERT_EQ(0, memcmp(val_buf, "value0", val_len));
    else if (memcmp(key_buf, "key1", key_len) == 0)
        ASSERT_EQ(0, memcmp(val_buf, "value1", val_len));
    else
        ASSERT_TRUE(0);

    err = hse_kvs_prefix_probe(
        kvs_handle, 0, txn, "xyz", sizeof("xyz") - 1, &found, key_buf, sizeof(key_buf), &key_len,
        val_buf, sizeof(val_buf), &val_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(HSE_KVS_PFX_FOUND_ZERO, found);

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_END_UTEST_COLLECTION(kvs_api_test)
