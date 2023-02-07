/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <hse/hse.h>

#include <hse/test/mtf/framework.h>
#include <hse/test/fixtures/kvdb.h>
#include <hse/test/fixtures/kvs.h>

#include <hse/util/platform.h>
#include <hse/util/base.h>

#include <unistd.h>

struct hse_kvdb *kvdb_handle = NULL;
struct hse_kvs  *kvs_handle = NULL;
const char      *kvs_name = "kvs";

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
    cursor_txn_test,
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
kvs_txn_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t   err;
    const char *rparamv[] = { "transactions.enabled=true" };

    err = fxt_kvs_setup(kvdb_handle, kvs_name, NELEM(rparamv), rparamv, 0, NULL, &kvs_handle);

    return hse_err_to_errno(err);
}

int
kvs_teardown(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;

    err = fxt_kvs_teardown(kvdb_handle, kvs_name, kvs_handle);

    return hse_err_to_errno(err);
}

MTF_DEFINE_UTEST(cursor_txn_test, max_kvs_cnt)
{
    hse_err_t err;
    char buf[8];

    for (unsigned int i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        snprintf(buf, sizeof(buf), "%u", i);

        err = hse_kvdb_kvs_create(kvdb_handle, buf, 0, NULL);
        ASSERT_EQ(0, err);
    }

    snprintf(buf, sizeof(buf), "%u", HSE_KVS_COUNT_MAX);

    err = hse_kvdb_kvs_create(kvdb_handle, buf, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));

    for (unsigned int i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        snprintf(buf, sizeof(buf), "%u", i);

        err = hse_kvdb_kvs_drop(kvdb_handle, buf);
        ASSERT_EQ(0, err);
    }
}

MTF_DEFINE_UTEST_PREPOST(cursor_txn_test, max_cursor_cnt, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    ulong mavail = 0;
    int i, max_curcnt;
    struct hse_kvs_cursor **cur;

    hse_meminfo(NULL, &mavail, 0);
    max_curcnt = (100 * mavail) >> 30; /* 100 cursors per GiB of memory */

    cur = malloc(sizeof(*cur) * max_curcnt);
    ASSERT_NE(NULL, cur);

    for (i = 0; i < max_curcnt; i++) {
        err = hse_kvs_cursor_create(kvs_handle, 0, NULL, NULL, 0, &cur[i]);
        ASSERT_EQ(0, err);
    }

    for (int i = 0; i < max_curcnt; i++) {
        err = hse_kvs_cursor_destroy(cur[i]);
        ASSERT_EQ(0, err);
    }

    free(cur);
}

void *
max_txn_helper(void *arg)
{
    pthread_barrier_t *barrier = arg;
    const int max_txn_per_cpu = 1000;
    struct hse_kvdb_txn *txn[max_txn_per_cpu];
    hse_err_t err;

    pthread_t my_id = pthread_self();

    for (int i = 0; i < max_txn_per_cpu; i++) {
        char kbuf[128];
        size_t klen;

        txn[i] = hse_kvdb_txn_alloc(kvdb_handle);
        VERIFY_NE_RET(NULL, txn[i], 0);

        err = hse_kvdb_txn_begin(kvdb_handle, txn[i]);
        VERIFY_EQ_RET(0, err, 0);

        klen = snprintf(kbuf, sizeof(kbuf), "key.%lu.%05d", my_id, i);
        err = hse_kvs_put(kvs_handle, 0, txn[i], kbuf, klen, kbuf, klen);
        VERIFY_EQ_RET(0, err, 0);
    }

    /* Wait here, so there are 1000 * nproc open transactions.
     */
    pthread_barrier_wait(barrier);

    for (int i = 0; i < max_txn_per_cpu; i++) {
        err = hse_kvdb_txn_commit(kvdb_handle, txn[i]);
        VERIFY_EQ_RET(0, err, 0);

        hse_kvdb_txn_free(kvdb_handle, txn[i]);
    }

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(cursor_txn_test, max_transaction_cnt, kvs_txn_setup, kvs_teardown)
{
    const int nproc = sysconf(_SC_NPROCESSORS_CONF);
    pthread_t tid[nproc];
    pthread_barrier_t barrier;
    int rc;

    pthread_barrier_init(&barrier, NULL, nproc);

    for (int i = 0; i < nproc; i++) {
        rc = pthread_create(tid + i, NULL, max_txn_helper, &barrier);
        ASSERT_EQ(0, rc);
    }

    for (int i = 0; i < nproc; i++) {
        rc = pthread_join(tid[i], NULL);
        ASSERT_EQ(0, rc);
    }

    pthread_barrier_destroy(&barrier);
}

MTF_DEFINE_UTEST_PREPOST(cursor_txn_test, max_key_size, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    char key[HSE_KVS_KEY_LEN_MAX + 1] = {};

    ASSERT_EQ(1344, HSE_KVS_KEY_LEN_MAX);

    err = hse_kvs_put(kvs_handle, 0, NULL, key, HSE_KVS_KEY_LEN_MAX, "", 0);
    ASSERT_EQ(0, err);

    err = hse_kvs_put(kvs_handle, 0, NULL, key, HSE_KVS_KEY_LEN_MAX + 1, "", 0);
    ASSERT_EQ(ENAMETOOLONG, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(cursor_txn_test, max_value_size, kvs_setup, kvs_teardown)
{
    hse_err_t err;
    char *key = "key01";
    char val[HSE_KVS_VALUE_LEN_MAX + 1] = {};

    ASSERT_EQ(1024 * 1024, HSE_KVS_VALUE_LEN_MAX);

    err = hse_kvs_put(kvs_handle, 0, NULL, key, strlen(key), val, HSE_KVS_VALUE_LEN_MAX);
    ASSERT_EQ(0, err);

    err = hse_kvs_put(kvs_handle, 0, NULL, key, strlen(key), val, HSE_KVS_VALUE_LEN_MAX + 1);
    ASSERT_EQ(EMSGSIZE, hse_err_to_errno(err));
}

MTF_END_UTEST_COLLECTION(cursor_txn_test)
