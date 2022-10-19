/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/lc.h>

#include <hse_util/seqno.h>

#include <kvdb/kvdb_kvs.h>

#include <mocks/mock_c0cn.h>

#include <bsd/string.h>

static struct ikvs *kvs;
static struct lc *lc;
static struct kvdb_health mock_health;

static int
test_pre(struct mtf_test_info *lcl_ti)
{
    merr_t             err;
    void *             dummy = (void *)-1;
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvdb_kvs    kvdb_kvs;

    strlcpy(kvdb_kvs.kk_name, "dummy", sizeof(kvdb_kvs.kk_name));

    mock_c0cn_set();

    err = lc_create(&lc, &mock_health);
    ASSERT_EQ_RET(0, err, -1);

    lc_ingest_seqno_set(lc, 1);

    mapi_inject_ptr(mapi_idx_ikvdb_alias, "0");
    err = kvs_open(dummy, &kvdb_kvs, dummy, dummy, lc, NULL, &rp, dummy, dummy, false, 0);
    ASSERT_EQ_RET(0, err, -1);
    mapi_inject_unset(mapi_idx_ikvdb_alias);

    kvs = kvdb_kvs.kk_ikvs;
    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    lc_destroy(lc);

    kvs_close(kvs);

    mock_c0cn_unset();
    mapi_inject_clear();
    return 0;
}

void
insert_key(struct mtf_test_info *lcl_ti, char *key)
{
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    merr_t            err;

    kvs_ktuple_init(&kt, key, strlen(key));
    kvs_vtuple_init(&vt, key, strlen(key));

    err = kvs_put(kvs, NULL, &kt, &vt, 1);
    ASSERT_EQ(0, err);
}

char *
construct_key(char *buf, uint buf_sz, const char *pfx, int idx)
{
    snprintf(buf, buf_sz, "%s-%02d", pfx, idx);
    return buf;
}

void
insert_key_multiple(struct mtf_test_info *lcl_ti, char *pfx, uint nkeys)
{
    int i;

    for (i = 0; i < nkeys; i++) {
        char buf[20];

        construct_key(buf, sizeof(buf), pfx, i);
        insert_key(lcl_ti, buf);
    }
}

void
expect_key(struct mtf_test_info *lcl_ti, const void *key, size_t klen, const char *expected)
{
    int rc;

    ASSERT_TRUE(strlen(expected) == klen);

    rc = strncmp(key, expected, klen);
    ASSERT_EQ(0, rc);
}

void
expect_pfx(struct mtf_test_info *lcl_ti, const void *key, size_t klen, const char *pfx)
{
    int rc;

    ASSERT_TRUE(strlen(pfx) <= klen);

    rc = strncmp(pfx, key, strlen(pfx));
    ASSERT_EQ(0, rc);
}

void verify_range(struct mtf_test_info *lcl_ti, const char *pfx, int start, int cnt)
{
    int i;
    int c = 0;
    char buf[20];
    merr_t err;

    struct hse_kvs_cursor *cur;
    struct kvs_ktuple kt;

    cur = kvs_cursor_alloc(kvs, pfx, strlen(pfx), false);
    ASSERT_NE(NULL, cur);

    err = kvs_cursor_init(cur, NULL);
    ASSERT_EQ(0, err);

    if (start) {
        construct_key(buf, sizeof(buf), pfx, start);
        err = kvs_cursor_seek(cur, buf, strlen(buf), NULL, 0, &kt);
        ASSERT_EQ(0, err);

        expect_pfx(lcl_ti, kt.kt_data, kt.kt_len, pfx);
        expect_key(lcl_ti, kt.kt_data, kt.kt_len, buf);
    }

    for (i = start;; i++) {
        const void  *key;
        char keybuf[32];
        size_t key_len;
        bool eof;

        err = kvs_cursor_read(cur, 0, &eof);
        ASSERT_EQ(0, err);
        if (eof)
            break;

        kvs_cursor_key_copy(cur, NULL, 0, &key, &key_len);

        expect_pfx(lcl_ti, key, key_len, pfx);

        construct_key(buf, sizeof(buf), pfx, i);
        expect_key(lcl_ti, key, key_len, buf);

        key_len = 0;
        kvs_cursor_key_copy(cur, keybuf, sizeof(keybuf), &key, &key_len);
        expect_key(lcl_ti, key, key_len, buf);

        ++c;
    }

    ASSERT_EQ(cnt, c);
    kvs_cursor_destroy(cur);
}

MTF_BEGIN_UTEST_COLLECTION(kvs_cursor_test);

MTF_DEFINE_UTEST_PREPOST(kvs_cursor_test, basic_test, test_pre, test_post)
{
    /* Insert phase */
    insert_key_multiple(lcl_ti, "ab", 10);
    insert_key_multiple(lcl_ti, "pq", 10);
    insert_key(lcl_ti, "this is a key");

    /* Verify phase */

    /* Verify 10 keys starting at key 0 */
    verify_range(lcl_ti, "pq", 0, 10);

    /* Verify 7 keys starting at key 3 */
    verify_range(lcl_ti, "pq", 3, 7);
}

MTF_DEFINE_UTEST(kvs_cursor_test, val_copy_null_cursor)
{
    merr_t err;

    err = kvs_cursor_val_copy(NULL, NULL, 0, (const void **)-1, (size_t *)-1);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(kvs_cursor_test, val_copy_null_val_out, test_pre, test_post)
{
    merr_t                 err;
    struct hse_kvs_cursor *cur;
    size_t                 value_len = 0;
    char *                 data = "test";
    bool                   eof = false;

    insert_key(lcl_ti, data);

    cur = kvs_cursor_alloc(kvs, NULL, 0, false);
    ASSERT_NE(NULL, cur);

    err = kvs_cursor_init(cur, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = kvs_cursor_read(cur, 0, &eof);
    ASSERT_EQ(0, err);
    ASSERT_FALSE(eof);

    err = kvs_cursor_val_copy(cur, NULL, 0, NULL, &value_len);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(strlen(data), value_len);

    kvs_cursor_destroy(cur);
}

MTF_END_UTEST_COLLECTION(kvs_cursor_test);
