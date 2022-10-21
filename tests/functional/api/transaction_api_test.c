/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <unistd.h>

#include <hse/hse.h>
#include <hse_util/base.h>
#include <hse/test/fixtures/kvdb.h>
#include <hse/test/fixtures/kvs.h>

#include <mtf/framework.h>

struct hse_kvdb *kvdb_handle = NULL;
struct hse_kvs  *kvs_handle = NULL;

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    /* 5 second timeout with a 5 second delay. 5 seconds should be enough to
     * hopefully get through all the tests, while allowing the 'expired' test
     * to properly fail.
     */
    static const char *kvdb_rparamv[] = { "txn_timeout=5000", "txn_wkth_delay=5000" };
    static const char *kvs_rparamv[] = { "transactions.enabled=true" };

    hse_err_t err;

    err = fxt_kvdb_setup(mtf_kvdb_home, NELEM(kvdb_rparamv), kvdb_rparamv, 0, NULL, &kvdb_handle);
    if (err)
        return hse_err_to_errno(err);

    err = fxt_kvs_setup(kvdb_handle, "kvs", NELEM(kvs_rparamv), kvs_rparamv, 0, NULL, &kvs_handle);

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
    transaction_api_test,
    test_collection_setup,
    test_collection_teardown);

MTF_DEFINE_UTEST(transaction_api_test, alloc_null_kvdb)
{
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(NULL);

    ASSERT_EQ(NULL, txn);
}

MTF_DEFINE_UTEST(transaction_api_test, state_transitions)
{
    hse_err_t               err;
    struct hse_kvdb_txn    *txn;
    enum hse_kvdb_txn_state state;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    state = hse_kvdb_txn_state_get(kvdb_handle, txn);
    ASSERT_EQ(HSE_KVDB_TXN_INVALID, state);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    state = hse_kvdb_txn_state_get(kvdb_handle, txn);
    ASSERT_EQ(HSE_KVDB_TXN_ACTIVE, state);

    err = hse_kvdb_txn_abort(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    state = hse_kvdb_txn_state_get(kvdb_handle, txn);
    ASSERT_EQ(HSE_KVDB_TXN_ABORTED, state);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    err = hse_kvdb_txn_commit(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    state = hse_kvdb_txn_state_get(kvdb_handle, txn);
    ASSERT_EQ(HSE_KVDB_TXN_COMMITTED, state);

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(transaction_api_test, state_get_null_kvdb)
{
    struct hse_kvdb_txn    *txn;
    enum hse_kvdb_txn_state state;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    state = hse_kvdb_txn_state_get(NULL, txn);
    ASSERT_EQ(HSE_KVDB_TXN_INVALID, state);
}

MTF_DEFINE_UTEST(transaction_api_test, state_get_null_txn)
{
    enum hse_kvdb_txn_state state;

    state = hse_kvdb_txn_state_get(kvdb_handle, NULL);
    ASSERT_EQ(HSE_KVDB_TXN_INVALID, state);
}

MTF_DEFINE_UTEST(transaction_api_test, begin_null_kvdb)
{
    hse_err_t            err;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_begin(NULL, txn);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(transaction_api_test, begin_null_txn)
{
    hse_err_t err;

    err = hse_kvdb_txn_begin(kvdb_handle, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(transaction_api_test, commit_null_kvdb)
{
    hse_err_t            err;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_commit(NULL, txn);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(transaction_api_test, commit_null_txn)
{
    hse_err_t err;

    err = hse_kvdb_txn_commit(kvdb_handle, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(transaction_api_test, abort_null_kvdb)
{
    hse_err_t            err;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_abort(NULL, txn);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(transaction_api_test, abort_null_txn)
{
    hse_err_t err;

    err = hse_kvdb_txn_abort(kvdb_handle, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(transaction_api_test, commit_without_begin)
{
    hse_err_t            err;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_commit(kvdb_handle, txn);
    ASSERT_EQ(ECANCELED, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(transaction_api_test, abort_without_begin)
{
    hse_err_t            err;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_commit(kvdb_handle, txn);
    ASSERT_EQ(ECANCELED, hse_err_to_errno(err));

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(transaction_api_test, expired)
{
    hse_err_t err;
    struct hse_kvdb_txn *txn;
    enum hse_kvdb_txn_state state;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(NULL, txn);

    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(0, hse_err_to_errno(err));

    while (true) {
        bool found;
        size_t val_len;
        struct hse_kvs_cursor *cursor;
        char val_buf[HSE_KVS_VALUE_LEN_MAX];

        state = hse_kvdb_txn_state_get(kvdb_handle, txn);
        if (state != HSE_KVDB_TXN_ABORTED) {
            sleep(5);
            continue;
        }

        err = hse_kvs_cursor_create(kvs_handle, 0, txn, NULL, 0, &cursor);
        ASSERT_EQ(EPROTO, hse_err_to_errno(err));
        ASSERT_EQ(HSE_ERR_CTX_TXN_EXPIRED, hse_err_to_ctx(err));

        err = hse_kvs_put(kvs_handle, 0, txn, "test", 4, "test", 4);
        ASSERT_EQ(ECANCELED, hse_err_to_errno(err));
        ASSERT_EQ(HSE_ERR_CTX_TXN_EXPIRED, hse_err_to_ctx(err));

        err = hse_kvs_get(kvs_handle, 0, txn, "test", 4, &found, val_buf, sizeof(val_buf), &val_len);
        ASSERT_EQ(ECANCELED, hse_err_to_errno(err));
        ASSERT_EQ(HSE_ERR_CTX_TXN_EXPIRED, hse_err_to_ctx(err));

        err = hse_kvs_delete(kvs_handle, 0, txn, "test", 4);
        ASSERT_EQ(ECANCELED, hse_err_to_errno(err));
        ASSERT_EQ(HSE_ERR_CTX_TXN_EXPIRED, hse_err_to_ctx(err));

        break;
    }
}

MTF_END_UTEST_COLLECTION(transaction_api_test)
