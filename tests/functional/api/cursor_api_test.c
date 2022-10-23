/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/hse.h>

#include <mtf/framework.h>
#include <hse/test/fixtures/kvdb.h>
#include <hse/test/fixtures/kvs.h>

#include <hse_util/base.h>

struct hse_kvdb *kvdb_handle = NULL;
struct hse_kvs  *kvs_handle = NULL;
const char      *kvs_name = "kvs";

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

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    cursor_api_test,
    test_collection_setup,
    test_collection_teardown);

int
kvs_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvs_setup(kvdb_handle, kvs_name, 0, NULL, 0, NULL, &kvs_handle);

    return hse_err_to_errno(err);
}

int
transactional_kvs_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t   err;
    const char *rparamv[] = { "transactions.enabled=true" };

    err = fxt_kvs_setup(kvdb_handle, kvs_name, NELEM(rparamv), rparamv, 0, NULL, &kvs_handle);

    return hse_err_to_errno(err);
}

int
kvs_setup_with_data(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    char      key_buf[8], val_buf[8];

    err = fxt_kvs_setup(kvdb_handle, kvs_name, 0, NULL, 0, NULL, &kvs_handle);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        const int key_len = snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        ASSERT_LT_RET(key_len, sizeof(key_buf) - 1, ENAMETOOLONG);
        ASSERT_GT_RET(key_len, 0, EBADMSG);

        const int val_len = snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);
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
    hse_err_t            err;
    char                 key_buf[8], val_buf[8];
    const char          *rparamv[] = { "transactions.enabled=true" };
    struct hse_txn *txn;

    err = fxt_kvs_setup(kvdb_handle, kvs_name, NELEM(rparamv), rparamv, 0, NULL, &kvs_handle);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE_RET(NULL, txn, EINVAL);

    err = hse_txn_begin(kvdb_handle, txn);
    ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        const int key_len = snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        ASSERT_LT_RET(key_len, sizeof(key_buf) - 1, ENAMETOOLONG);
        ASSERT_GT_RET(key_len, 0, EBADMSG);

        const int val_len = snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);
        ASSERT_LT_RET(val_len, sizeof(val_buf) - 1, ENAMETOOLONG);
        ASSERT_GT_RET(val_len, 0, EBADMSG);

        err = hse_kvs_put(kvs_handle, 0, txn, key_buf, key_len, val_buf, val_len);
        ASSERT_EQ_RET(0, hse_err_to_errno(err), hse_err_to_errno(err));
    }

    err = hse_txn_commit(kvdb_handle, txn);
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

MTF_DEFINE_UTEST(cursor_api_test, create_null_kvs)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;

    err = hse_kvs_cursor_create(NULL, 0, NULL, NULL, 0, &cursor);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, create_invalid_flags)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;

    err = hse_kvs_cursor_create((struct hse_kvs *)-1, 81, NULL, NULL, 0, &cursor);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, create_mismatched_filter_filter_len)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;

    err = hse_kvs_cursor_create((struct hse_kvs *)-1, 0, NULL, NULL, 1, &cursor);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, create_filter_len_is_0, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, "does not exist", 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_LT(key_len, sizeof(key_buf) - 1);
        ASSERT_LT(val_len, sizeof(val_buf) - 1);

        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        ASSERT_EQ(0, memcmp(key_buf, key, key_len));
        ASSERT_EQ(0, memcmp(val_buf, val, val_len));

        ASSERT_FALSE(eof);

        if (i == NUM_ENTRIES - 1) {
            err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
            ASSERT_TRUE(eof);
        }
    }

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(cursor_api_test, create_null_cursor)
{
    hse_err_t err;

    err = hse_kvs_cursor_create((struct hse_kvs *)-1, 0, NULL, NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_with_null_txn_on_transactional_kvs,
    transactional_kvs_setup,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_with_invalid_txn_on_transactional_kvs,
    transactional_kvs_setup,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    struct hse_txn   *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvs_cursor_create(kvs_handle, 0, txn, NULL, 0, &cursor);
    ASSERT_EQ(EPROTO, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_with_active_txn_on_non_transactional_kvs,
    kvs_setup,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    struct hse_txn   *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_create(kvs_handle, 0, txn, NULL, 0, &cursor);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_with_active_txn_on_transactional_kvs,
    transactional_kvs_setup,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    struct hse_txn   *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_create(kvs_handle, 0, txn, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, err);

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_reverse_with_null_txn_on_non_transactional_kvs,
    kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err = hse_kvs_cursor_create(kvs_handle, HSE_CURSOR_CREATE_REV, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = NUM_ENTRIES - 1; i >= 0; i--) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_reverse_with_null_txn_on_transactional_kvs,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err = hse_kvs_cursor_create(kvs_handle, HSE_CURSOR_CREATE_REV, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = NUM_ENTRIES - 1; i >= 0; i--) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_reverse_with_active_txn_on_transactional_kvs,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];
    struct hse_txn   *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_create(kvs_handle, HSE_CURSOR_CREATE_REV, txn, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = NUM_ENTRIES - 1; i >= 0; i--) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_with_filter_and_null_txn_on_non_transactional_kvs,
    kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err =
        hse_kvs_cursor_create(kvs_handle, 0, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_with_filter_and_null_txn_on_transactional_kvs,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err =
        hse_kvs_cursor_create(kvs_handle, 0, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_with_filter_and_active_txn_on_transactional_kvs,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];
    struct hse_txn   *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err =
        hse_kvs_cursor_create(kvs_handle, 0, txn, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_reverse_with_filter_and_null_txn_on_non_transactional_kvs,
    kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err =
        hse_kvs_cursor_create(kvs_handle, HSE_CURSOR_CREATE_REV, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = NUM_ENTRIES - 1; i >= 0; i--) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_reverse_with_filter_null_txn_on_transactional_kvs,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err =
        hse_kvs_cursor_create(kvs_handle, HSE_CURSOR_CREATE_REV, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = NUM_ENTRIES - 1; i >= 0; i--) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    create_reverse_with_filter_and_active_txn_on_transactional_kvs,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];
    struct hse_txn   *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err =
        hse_kvs_cursor_create(kvs_handle, HSE_CURSOR_CREATE_REV, txn, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = NUM_ENTRIES - 1; i >= 0; i--) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(cursor_api_test, destroy_null_cursor)
{
    hse_err_t err;

    err = hse_kvs_cursor_destroy(NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_null_cursor)
{
    hse_err_t err;

    err = hse_kvs_cursor_read(
        NULL, 0, (void *)-1, (size_t *)-1, (void *)-1, (size_t *)-1, (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_cursor_read(
        (void *)-1, 81, (void *)-1, (size_t *)-1, (void *)-1, (size_t *)-1, (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_null_key)
{
    hse_err_t err;

    err = hse_kvs_cursor_read(
        (void *)-1, 0, NULL, (size_t *)-1, (void *)-1, (size_t *)-1, (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_null_key_len)
{
    hse_err_t err;

    err =
        hse_kvs_cursor_read((void *)-1, 0, (void *)-1, NULL, (void *)-1, (size_t *)-1, (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_null_val)
{
    hse_err_t err;

    err = hse_kvs_cursor_read(
        (void *)-1, 0, (void *)-1, (size_t *)-1, NULL, (size_t *)-1, (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_null_val_len)
{
    hse_err_t err;

    err =
        hse_kvs_cursor_read((void *)-1, 0, (void *)-1, (size_t *)-1, (void *)-1, NULL, (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_null_eof)
{
    hse_err_t err;

    err = hse_kvs_cursor_read(
        (void *)-1, 0, (void *)-1, (size_t *)-1, (void *)-1, (size_t *)-1, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, read_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_LT(key_len, sizeof(key_buf) - 1);
        ASSERT_LT(val_len, sizeof(val_buf) - 1);

        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        ASSERT_EQ(0, memcmp(key_buf, key, key_len));
        ASSERT_EQ(0, memcmp(val_buf, val, val_len));

        ASSERT_FALSE(eof);

        if (i == NUM_ENTRIES - 1) {
            err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
            ASSERT_TRUE(eof);
        }
    }

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    read_success_with_filter,
    kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    /* Include an entry which doesn't match the filter */
    err = hse_kvs_put(kvs_handle, 0, NULL, "ping", sizeof("ping") - 1, "pong", sizeof("pong") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_LT(key_len, sizeof(key_buf) - 1);
        ASSERT_LT(val_len, sizeof(val_buf) - 1);

        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        ASSERT_EQ(0, memcmp(key_buf, key, key_len));
        ASSERT_EQ(0, memcmp(val_buf, val, val_len));

        ASSERT_FALSE(eof);

        if (i == NUM_ENTRIES - 1) {
            err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
            ASSERT_TRUE(eof);
        }
    }

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(cursor_api_test, read_copy_null_cursor)
{
    hse_err_t err;

    err = hse_kvs_cursor_read_copy(
        NULL, 0, (void *)-1, 8, (size_t *)-1, (void *)-1, 8, (size_t *)-1, (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_copy_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_cursor_read_copy(
        (struct hse_kvs_cursor *)-1,
        81,
        (void *)-1,
        8,
        (size_t *)-1,
        (void *)-1,
        8,
        (size_t *)-1,
        (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_copy_null_keybuf)
{
    hse_err_t err;

    err = hse_kvs_cursor_read_copy(
        (struct hse_kvs_cursor *)-1,
        0,
        NULL,
        8,
        (size_t *)-1,
        (void *)-1,
        8,
        (size_t *)-1,
        (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_copy_null_key_len)
{
    hse_err_t err;

    err = hse_kvs_cursor_read_copy(
        (struct hse_kvs_cursor *)-1,
        0,
        (void *)-1,
        8,
        NULL,
        (void *)-1,
        8,
        (size_t *)-1,
        (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_copy_null_eof)
{
    hse_err_t err;

    err = hse_kvs_cursor_read_copy(
        (struct hse_kvs_cursor *)-1,
        0,
        (void *)-1,
        8,
        (size_t *)-1,
        (void *)-1,
        8,
        (size_t *)-1,
        NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, read_copy_null_valbuf_with_valbuf_sz)
{
    hse_err_t err;

    err = hse_kvs_cursor_read_copy(
        (struct hse_kvs_cursor *)-1,
        0,
        (void *)-1,
        8,
        (size_t *)-1,
        NULL,
        8,
        (size_t *)-1,
        (bool *)-1);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, read_copy_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[2][8], val_buf[2][8];

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        err = hse_kvs_cursor_read_copy(
            cursor,
            0,
            key_buf[0],
            sizeof(key_buf[0]),
            &key_len,
            val_buf[0],
            sizeof(val_buf[0]),
            &val_len,
            &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_LT(key_len, sizeof(key_buf) - 1);
        ASSERT_LT(val_len, sizeof(val_buf) - 1);

        snprintf(key_buf[1], sizeof(key_buf[1]), KEY_FMT, i);
        snprintf(val_buf[1], sizeof(val_buf[1]), VALUE_FMT, i);

        ASSERT_EQ(0, memcmp(key_buf[0], key_buf[1], key_len));
        ASSERT_EQ(0, memcmp(val_buf[0], val_buf[1], val_len));

        ASSERT_FALSE(eof);

        if (i == NUM_ENTRIES - 1) {
            err = hse_kvs_cursor_read_copy(
                cursor,
                0,
                key_buf[0],
                sizeof(key_buf[0]),
                &key_len,
                val_buf[0],
                sizeof(val_buf[0]),
                &val_len,
                &eof);
            ASSERT_TRUE(eof);
        }
    }

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    read_copy_success_with_filter,
    kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[2][8], val_buf[2][8];

    /* Include an entry which doesn't match the filter */
    err = hse_kvs_put(kvs_handle, 0, NULL, "ping", sizeof("ping") - 1, "pong", sizeof("pong") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        err = hse_kvs_cursor_read_copy(
            cursor,
            0,
            key_buf[0],
            sizeof(key_buf[0]),
            &key_len,
            val_buf[0],
            sizeof(val_buf[0]),
            &val_len,
            &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_LT(key_len, sizeof(key_buf) - 1);
        ASSERT_LT(val_len, sizeof(val_buf) - 1);

        snprintf(key_buf[1], sizeof(key_buf[1]), KEY_FMT, i);
        snprintf(val_buf[1], sizeof(val_buf[1]), VALUE_FMT, i);

        ASSERT_EQ(0, memcmp(key_buf[0], key_buf[1], key_len));
        ASSERT_EQ(0, memcmp(val_buf[0], val_buf[1], val_len));

        ASSERT_FALSE(eof);

        if (i == NUM_ENTRIES - 1) {
            err = hse_kvs_cursor_read_copy(
                cursor,
                0,
                key_buf[0],
                sizeof(key_buf[0]),
                &key_len,
                val_buf[0],
                sizeof(val_buf[0]),
                &val_len,
                &eof);
            ASSERT_TRUE(eof);
        }
    }

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(cursor_api_test, seek_null_cursor)
{
    hse_err_t err;

    err = hse_kvs_cursor_seek(NULL, 0, NULL, 0, NULL, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, seek_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_cursor_seek((struct hse_kvs_cursor *)-1, 81, NULL, 0, NULL, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, seek_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *found;
    size_t                 found_len;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_seek(cursor, 0, "key3", sizeof("key3") - 1, &found, &found_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(0, memcmp(found, "key3", sizeof("key3") - 1));

    /* Read 3x because that will move the cursor to the end */
    for (int i = 0; i < 2; i++) {
        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    seek_success_with_filter,
    kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *found;
    size_t                 found_len;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;

    /* Include an entry which doesn't match the filter */
    err = hse_kvs_put(kvs_handle, 0, NULL, "ping", sizeof("ping") - 1, "pong", sizeof("pong") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_seek(cursor, 0, "key3", sizeof("key3") - 1, &found, &found_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(0, memcmp(found, "key3", sizeof("key3") - 1));

    /* Read 3x because that will move the cursor to the end */
    for (int i = 0; i < 2; i++) {
        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, seek_range_null_cursor)
{
    hse_err_t err;

    err = hse_kvs_cursor_seek_range(NULL, 0, NULL, 0, NULL, 0, NULL, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(cursor_api_test, seek_range_invalid_flags)
{
    hse_err_t err;

    err = hse_kvs_cursor_seek_range((struct hse_kvs_cursor *)-1, 81, NULL, 0, NULL, 0, NULL, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, seek_range_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *found;
    size_t                 found_len;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_seek_range(
        cursor, 0, "key0", sizeof("key0") - 1, "key3", sizeof("key3") - 1, &found, &found_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(0, memcmp(found, "key0", found_len));

    for (int i = 0; i < 4; i++) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    seek_range_success_with_filter,
    kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *found;
    size_t                 found_len;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    char                   key_buf[8], val_buf[8];

    /* Include an entry which doesn't match the filter */
    err = hse_kvs_put(kvs_handle, 0, NULL, "ping", sizeof("ping") - 1, "pong", sizeof("pong") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    /* Include this to move the range to include the ping/pong pair */
    err = hse_kvs_put(
        kvs_handle, 0, NULL, "key5", sizeof("key5") - 1, "value5", sizeof("value5") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, FILTER, FILTER_LEN, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_seek_range(
        cursor, 0, "key3", sizeof("key3") - 1, "key5", sizeof("key5") - 1, &found, &found_len);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(0, memcmp(found, "key3", found_len));

    for (int i = 3; i <= 5; i++) {
        snprintf(key_buf, sizeof(key_buf), KEY_FMT, i);
        snprintf(val_buf, sizeof(val_buf), VALUE_FMT, i);

        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_EQ(0, memcmp(key, key_buf, key_len));
        ASSERT_EQ(0, memcmp(val, val_buf, val_len));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, update_view_null_cursor, kvs_setup, kvs_teardown)
{
    hse_err_t err;

    err = hse_kvs_cursor_update_view(NULL, 0);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, update_view_invalid_flags, kvs_setup, kvs_teardown)
{
    hse_err_t err;

    err = hse_kvs_cursor_update_view((struct hse_kvs_cursor *)-1, 81);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_api_test, update_view_success, kvs_setup_with_data, kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;

    err = hse_kvs_cursor_create(kvs_handle, 0, NULL, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    /* Exists outside the cursor view */
    err = hse_kvs_put(
        kvs_handle, 0, NULL, "key5", sizeof("key5") - 1, "value5", sizeof("value5") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_update_view(cursor, 0);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(0, memcmp(key, "key5", key_len));
    ASSERT_EQ(0, memcmp(val, "value5", val_len));
    ASSERT_FALSE(eof);

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(
    cursor_api_test,
    transactional_cursor,
    transactional_kvs_setup_with_data,
    kvs_teardown)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor;
    const void            *key, *val;
    size_t                 key_len, val_len;
    bool                   eof;
    struct hse_txn   *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_txn_begin(kvdb_handle, txn);

    err = hse_kvs_cursor_create(kvs_handle, 0, txn, NULL, 0, &cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    for (int i = 0; i < NUM_ENTRIES; i++) {
        err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
        ASSERT_EQ(0, hse_err_to_errno(err));
        ASSERT_FALSE(eof);
    }

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    /* Now that the cursor has been drained, add a KV pair using the same txn,
     * and see the pair with the cursor.
     */
    err =
        hse_kvs_put(kvs_handle, 0, txn, "key5", sizeof("key5") - 1, "value5", sizeof("value5") - 1);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(0, memcmp(key, "key5", key_len));
    ASSERT_EQ(0, memcmp(val, "value5", val_len));
    ASSERT_FALSE(eof);

    err = hse_kvs_cursor_read(cursor, 0, &key, &key_len, &val, &val_len, &eof);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_TRUE(eof);

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_EQ(0, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_END_UTEST_COLLECTION(cursor_api_test)
