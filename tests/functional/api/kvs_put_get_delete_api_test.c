/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/hse.h>

#include <hse_ut/framework.h>
#include <hse_ut/fixtures.h>

struct hse_kvdb *kvdb;
struct hse_kvs * kvs;

#define KEY_LEN_MAX 32
#define VAL_LEN_MAX 32

struct tuple {
    char   key[KEY_LEN_MAX];
    char   putval[VAL_LEN_MAX];
    char   getval[VAL_LEN_MAX];
    size_t klen;
    size_t vlen;
};

int
make_tuple(struct mtf_test_info *lcl_ti, struct tuple *tup, const char *prefix, int id)
{
    tup->klen = snprintf(tup->key, sizeof(tup->key), "%s%d", prefix, id);
    ASSERT_LT_RET(tup->klen, sizeof(tup->key), -1);

    tup->vlen = snprintf(tup->putval, sizeof(tup->putval), "V%s%d", prefix, id);
    ASSERT_LT_RET(tup->vlen, sizeof(tup->putval), -1);

    ASSERT_EQ_RET(sizeof(tup->putval), sizeof(tup->getval), -1);
    memcpy(tup->getval, tup->putval, sizeof(tup->putval));

    return 0;
}

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    int       rc;

    rc = mtf_kvdb_setup(lcl_ti, &kvdb, 0);
    ASSERT_EQ_RET(rc, 0, -1);

    err = hse_kvdb_kvs_make(kvdb, "test", 0, NULL);
    ASSERT_EQ_RET(err, 0, -1);

    err = hse_kvdb_kvs_open(kvdb, "test", 0, NULL, &kvs);
    ASSERT_EQ_RET(err, 0, -1);

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *lcl_ti)
{
    hse_err_t err;
    int       rc;

    err = hse_kvdb_kvs_close(kvs);
    ASSERT_EQ_RET(err, 0, -1);

    rc = mtf_kvdb_teardown(lcl_ti);
    ASSERT_EQ_RET(rc, 0, -1);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(put_get_delete, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST(put_get_delete, put_get)
{
    int          rc;
    hse_err_t    err;
    const char * prefix = "AAA";
    struct tuple tup;

    for (int i = -10; i <= 10; i++) {
        rc = make_tuple(lcl_ti, &tup, prefix, i);
        ASSERT_EQ(rc, 0);

        err = hse_kvs_put(kvs, NULL, tup.key, tup.klen, tup.putval, tup.vlen);
        ASSERT_EQ(err, 0);
    }
}

MTF_DEFINE_UTEST(put_get_delete, kvs_put_get_delete)
{
    hse_err_t  err;
    char       vbuf[VAL_LEN_MAX];
    size_t     vlen;
    bool       found;
    const char test_key[] = "test_key";
    const char test_value[] = "test_value";
    size_t     klen = sizeof(test_key) - 1;
    size_t     vallen = sizeof(test_value) - 1;

    /* TC: A KVS cannot put a NULL key */
    err = hse_kvs_put(kvs, NULL, NULL, 0, test_value, vallen);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);

    /* TC: A KVS can put a valid key value pair */
    err = hse_kvs_put(kvs, NULL, test_key, klen, test_value, vallen);
    ASSERT_EQ(err, 0);

    /* TC: A KVS get with an existing key can be found and will return a correct value */
    found = false;
    err = hse_kvs_get(kvs, NULL, test_key, klen, &found, vbuf, sizeof(vbuf), &vlen);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(found, true);
    ASSERT_EQ(vlen, vallen);
    ASSERT_EQ(memcmp(vbuf, test_value, vlen), 0);

    /* TC: A KVS can delete an existing key value pair */
    found = false;
    err = hse_kvs_delete(kvs, NULL, test_key, klen);
    ASSERT_EQ(err, 0);
    err = hse_kvs_get(kvs, NULL, test_key, klen, &found, vbuf, sizeof(vbuf), &vlen);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(found, false);
}

MTF_END_UTEST_COLLECTION(put_get_delete)
