/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_ut/fixtures.h>

/* Globals */
struct hse_kvdb *kvdb_handle = NULL;
struct hse_kvs * kvs_handle = NULL;

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    int rc;

    rc = mtf_kvdb_setup(lcl_ti, &kvdb_handle, 0);
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
setup_kvs(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    const char *paramv[] = {
        "transactions.enabled=true",
    };

    err = hse_kvdb_kvs_create(kvdb_handle, "kvs_transaction_test", 0, NULL);
    ASSERT_EQ_RET(err, 0, -1);

    err = hse_kvdb_kvs_open(kvdb_handle, "kvs_transaction_test", NELEM(paramv), paramv, &kvs_handle);
    ASSERT_EQ_RET(err, 0, -1);

    return 0;
}

int
destroy_kvs(struct mtf_test_info *lcl_ti)
{
    int       rc;
    hse_err_t err;

    err = hse_kvdb_kvs_close(kvs_handle);
    ASSERT_EQ_RET(err, 0, -1);

    rc = mtf_kvdb_kvs_drop_all(kvdb_handle);
    ASSERT_EQ_RET(rc, 0, -1);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    transaction_api_test,
    test_collection_setup,
    test_collection_teardown);

MTF_DEFINE_UTEST(transaction_api_test, transaction_invalid_testcase)
{
    hse_err_t err;

    /* TC: A transaction cannot begin without being allocated */
    err = hse_kvdb_txn_begin(kvdb_handle, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);
}

MTF_DEFINE_UTEST(transaction_api_test, transaction_valid_testcase)
{
    hse_err_t            err;
    struct hse_kvdb_txn *txn;

    /* TC: A transaction can be allocated */
    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(txn, NULL);

    /* TC: A transaction that has not begun can be aborted */
    err = hse_kvdb_txn_abort(kvdb_handle, txn);
    ASSERT_EQ(err, 0);

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST(transaction_api_test, transaction_ops_testcase)
{
    hse_err_t               err;
    struct hse_kvdb_txn *   txn;
    enum hse_kvdb_txn_state state;

    txn = hse_kvdb_txn_alloc(kvdb_handle);
    ASSERT_NE(txn, NULL);

    /* TC: An allocated transaction can begin */
    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(err, 0);

    /* TC: A transaction that has begun will return a state of HSE_KVDB_TXN_ACTIVE */
    state = hse_kvdb_txn_state_get(kvdb_handle, txn);
    ASSERT_EQ(state, HSE_KVDB_TXN_ACTIVE);

    /* TC: A transaction that has begun can be aborted */
    err = hse_kvdb_txn_abort(kvdb_handle, txn);
    ASSERT_EQ(err, 0);

    /* TC: An aborted transaction will return a state of HSE_KVDB_TXN_ABORTED */
    state = hse_kvdb_txn_state_get(kvdb_handle, txn);
    ASSERT_EQ(state, HSE_KVDB_TXN_ABORTED);

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST_PREPOST(transaction_api_test, transaction_commit_testcase, setup_kvs, destroy_kvs)
{
    bool                    found;
    char                    vbuf[16];
    size_t                  vlen;
    hse_err_t               err;
    struct hse_kvdb_txn    *txn;
    enum hse_kvdb_txn_state state;

    txn = hse_kvdb_txn_alloc(kvdb_handle);

    /* TC: A transaction that has not begun cannot be committed */
    err = hse_kvdb_txn_commit(kvdb_handle, txn);
    ASSERT_EQ(hse_err_to_errno(err), ECANCELED);

    /* TC: A transaction that has begun can be committed */
    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(err, 0);
    err = hse_kvs_put(kvs_handle, 0, txn, "test_key", 8, "test_value", 10);
    ASSERT_EQ(err, 0);

    err = hse_kvdb_txn_commit(kvdb_handle, txn);
    ASSERT_EQ(err, 0);

    /* TC: A committed transaction will have visible changes */
    err = hse_kvs_get(kvs_handle, 0, NULL, "test_key", 8, &found, vbuf, sizeof(vbuf), &vlen);
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(found);

    /* TC: A committed transaction will return a state of HSE_KVDB_TXN_COMMITTED */
    state = hse_kvdb_txn_state_get(kvdb_handle, txn);
    ASSERT_EQ(state, HSE_KVDB_TXN_COMMITTED);

    err = hse_kvdb_txn_abort(kvdb_handle, txn);
    ASSERT_EQ(err, 0);

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_DEFINE_UTEST_PREPOST(
    transaction_api_test,
    transaction_abort_commit_testcase,
    setup_kvs,
    destroy_kvs)
{
    bool                found;
    char                vbuf[16];
    size_t              vlen;
    hse_err_t           err;
    struct hse_kvdb_txn *txn;

    txn = hse_kvdb_txn_alloc(kvdb_handle);

    /* TC: An aborted transaction will not persist any changes */
    err = hse_kvdb_txn_begin(kvdb_handle, txn);
    ASSERT_EQ(err, 0);
    err = hse_kvs_put(kvs_handle, 0, txn, "test_key", 8, "test_value", 10);
    ASSERT_EQ(err, 0);

    err = hse_kvdb_txn_abort(kvdb_handle, txn);
    ASSERT_EQ(err, 0);

    err = hse_kvs_get(kvs_handle, 0, NULL, "test_key", 8, &found, vbuf, sizeof(vbuf), &vlen);
    ASSERT_EQ(err, 0);
    ASSERT_FALSE(found);

    hse_kvdb_txn_free(kvdb_handle, txn);
}

MTF_END_UTEST_COLLECTION(transaction_api_test)
