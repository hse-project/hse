/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>

#include <hse/hse.h>
#include <hse/test/fixtures/kvdb.h>

#include <mtf/framework.h>

struct hse_kvdb *kvdb_handle = NULL;
struct hse_kvs  *kvs_handle = NULL;

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

MTF_END_UTEST_COLLECTION(transaction_api_test)
