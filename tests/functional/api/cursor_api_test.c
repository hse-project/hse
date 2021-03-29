/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <errno.h>

/* Globals */
struct hse_kvs *       kvs_handle = NULL;
struct hse_kvs_cursor *cursor = NULL;
const int              key_value_pairs = 5;

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t                  err;
    char *                     mpool_name;
    struct hse_kvdb *          kvdb_handle = NULL;
    const char *               kvs_name = "kvs_test";
    char                       key[16], val[16];
    struct mtf_test_coll_info *coll_info = lcl_ti->ti_coll;

    if (coll_info->tci_argc != 2)
        return -1;

    mpool_name = coll_info->tci_argv[1];

    err = hse_kvdb_open(mpool_name, NULL, &kvdb_handle);
    ASSERT_TRUE_RET(!err, -1);

    err = hse_kvdb_kvs_make(kvdb_handle, kvs_name, NULL);
    ASSERT_TRUE_RET((!err || hse_err_to_errno(err) == EEXIST), -1);

    err = hse_kvdb_kvs_open(kvdb_handle, kvs_name, NULL, &kvs_handle);
    ASSERT_TRUE_RET(!err, -1);

    for (int i = 0; i < key_value_pairs; i++) {
        snprintf(key, sizeof(key), "test_key_%02d", i);
        snprintf(val, sizeof(val), "test_value_%02d", i);

        err = hse_kvs_put(kvs_handle, NULL, key, strlen(key), val, strlen(val));
        ASSERT_TRUE_RET(!err, -1);

    }

    return EXIT_SUCCESS;
}

int
test_collection_teardown(struct mtf_test_info *lcl_ti)
{
    hse_err_t   err;
    char        key[16];

    for (int i = 0; i < key_value_pairs; i++) {
        snprintf(key, sizeof(key), "test_key_%02d", i);
        err = hse_kvs_delete(kvs_handle, NULL, key, strlen(key));
        ASSERT_TRUE_RET(!err, -1);
    }

    err = hse_kvs_cursor_destroy(cursor);
    ASSERT_TRUE_RET(!err, -1);

    return EXIT_SUCCESS;
}

int
init_cursor(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = hse_kvs_cursor_create(kvs_handle, NULL, NULL, 0, &cursor);
    ASSERT_TRUE_RET(!err, -1);

    return EXIT_SUCCESS;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    cursor_api_test,
    test_collection_setup,
    test_collection_teardown);

MTF_DEFINE_UTEST(cursor_api_test, cursor_invalid_testcase)
{
    hse_err_t   err;
    bool        eof = false;
    const void *cur_key, *cur_val;
    size_t      cur_klen, cur_vlen;

    /* TC: A cursor cannot be created without a valid KVS */
    err = hse_kvs_cursor_create(NULL, NULL, NULL, 0, &cursor);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A null cursor cannot be used to read a KVS */
    err = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);
}

MTF_DEFINE_UTEST(cursor_api_test, cursor_valid_testcase)
{
    hse_err_t              err;
    struct hse_kvs_cursor *cursor_handle = NULL;
    struct hse_kvs_cursor *duplicate_cursor_handle = NULL;

    /* TC: A cursor can be created */
    err = hse_kvs_cursor_create(kvs_handle, NULL, NULL, 0, &cursor_handle);
    ASSERT_EQ(err, 0);

    /* TC: A populated KVS returns a valid cursor */
    ASSERT_NE(cursor_handle, NULL);

    /* TC: A handle can be reused to create multiple cursors */
    err = hse_kvs_cursor_create(kvs_handle, NULL, NULL, 0, &duplicate_cursor_handle);
    ASSERT_EQ(err, 0);

    /* TC: A cursor can be destroyed */
    err = hse_kvs_cursor_destroy(cursor_handle);
    ASSERT_EQ(err, 0);

    err = hse_kvs_cursor_destroy(duplicate_cursor_handle);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PRE(cursor_api_test, cursor_read_testcase, init_cursor)
{
    hse_err_t   err;
    bool        eof = false;
    const void *cur_key, *cur_val;
    size_t      cur_klen, cur_vlen;
    int         count = 0;
    char        read_buff[16], expec_buff[16];

    /* TC: A cursor can read key value pairs in a KVS, and returns the correct key value pairs */
    while (!eof) {
        err = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
        ASSERT_EQ(err, 0);

        if (!eof) {
            snprintf(
                expec_buff,
                sizeof(expec_buff),
                "test_key_%02d",
                (count) % 100u); /* keep within limits */
            snprintf(read_buff, sizeof(read_buff), "%.*s", (int)cur_klen, (char *)cur_key);
            ASSERT_STREQ(expec_buff, read_buff);

            snprintf(expec_buff, sizeof(expec_buff), "test_value_%02d", (count++) % 100u);
            snprintf(read_buff, sizeof(read_buff), "%.*s", (int)cur_vlen, (char *)cur_val);
            ASSERT_STREQ(expec_buff, read_buff);
        }
    }
}

MTF_DEFINE_UTEST_PRE(cursor_api_test, cursor_read_changes_testcase, init_cursor)
{
    hse_err_t   err;
    bool        eof = false;
    const void *cur_key, *cur_val;
    size_t      cur_klen, cur_vlen;
    int         count = 0;

    /* TC: An existing cursor cannot see changes to the KVS */
    err = hse_kvs_put(kvs_handle, NULL, "extra_key", 9, "extra_value", 11);
    ASSERT_EQ(err, 0);

    while (!eof) {
        err = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
        ASSERT_EQ(err, 0);

        if (!eof)
            count++;
    }

    ASSERT_EQ(count, key_value_pairs);
}

MTF_DEFINE_UTEST_PRE(cursor_api_test, cursor_seek_testcase, init_cursor)
{
    hse_err_t   err;
    bool        eof = false;
    const void *cur_key, *cur_val;
    size_t      cur_klen, cur_vlen;
    char        read_buff[16];
    char *      search_key = "test_key_02";

    /* TC: A cursor can seek to a specific key */
    err = hse_kvs_cursor_seek(cursor, NULL, search_key, strlen(search_key), NULL, NULL);
    ASSERT_EQ(err, 0);

    err = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
    ASSERT_EQ(err, 0);

    snprintf(read_buff, sizeof(read_buff), "%.*s", (int)cur_klen, (char *)cur_key);
    ASSERT_STREQ(search_key, read_buff);

    /* TC: A cursor will be positioned at the first key if the specified key does not exist */
    eof = false;
    err = hse_kvs_cursor_seek(cursor, NULL, "fake_key", 8, NULL, NULL);
    ASSERT_EQ(err, 0);

    err = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
    ASSERT_EQ(err, 0);

    snprintf(read_buff, sizeof(read_buff), "%.*s", (int)cur_klen, (char *)cur_key);
    ASSERT_STREQ("test_key_00", read_buff);
}

MTF_DEFINE_UTEST_PRE(cursor_api_test, cursor_multiple_testcase, init_cursor)
{
    hse_err_t              err;
    bool                   eof = false;
    const void *           cur_key, *cur_val;
    size_t                 cur_klen, cur_vlen;
    struct hse_kvs_cursor *duplicate_cursor;
    char                   buff_1[16], buff_2[16];
    int                    count_1 = 0, count_2 = 0;

    /* TC: A KVS can have multiple cursors reading at different rates */
    err = hse_kvs_cursor_create(kvs_handle, NULL, NULL, 0, &duplicate_cursor);
    ASSERT_EQ(err, 0);

    /* Fast Cursor */
    err = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
    ASSERT_EQ(err, 0);
    err = hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
    ASSERT_EQ(err, 0);
    sprintf(buff_1, "%.*s", (int)cur_klen, (char *)cur_key);

    /* Slow Cursor */
    err =
        hse_kvs_cursor_read(duplicate_cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);
    ASSERT_EQ(err, 0);
    sprintf(buff_2, "%.*s", (int)cur_klen, (char *)cur_key);

    ASSERT_STRNE(buff_1, buff_2);

    /* TC: A KVS with multiple cursors must update each cursor explicitly */
    err = hse_kvs_cursor_create(kvs_handle, NULL, NULL, 0, &duplicate_cursor);
    ASSERT_EQ(err, 0);

    err = hse_kvs_put(kvs_handle, NULL, "extra_key", 9, "extra_value", 11);
    ASSERT_EQ(err, 0);

    err = hse_kvs_cursor_update(cursor, NULL);
    ASSERT_EQ(err, 0);

    eof = false;
    while (!eof) {
        hse_kvs_cursor_read(cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);

        if (!eof) {
            count_1++;
        }
    }

    eof = false;
    while (!eof) {
        hse_kvs_cursor_read(duplicate_cursor, NULL, &cur_key, &cur_klen, &cur_val, &cur_vlen, &eof);

        if (!eof) {
            count_2++;
        }
    }

    ASSERT_NE(count_1, count_2);
}

MTF_END_UTEST_COLLECTION(cursor_api_test)
