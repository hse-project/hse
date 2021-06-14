/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/lc.h>

#include <hse_util/seqno.h>

#include <kvdb/kvdb_kvs.h>

#include <mocks/mock_c0cn.h>

static struct ikvs *kvs;
static struct lc *lc;

static int
test_pre(struct mtf_test_info *lcl_ti)
{
    merr_t             err;
    void *             dummy = (void *)-1;
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvdb_kvs    kvdb_kvs;

    mock_c0cn_set();

    err = lc_create(&lc);
    ASSERT_EQ_RET(0, err, -1);

    lc_ingest_seqno_set(lc, 1);

    err = kvs_open(dummy, &kvdb_kvs, "mp_test", dummy, dummy, lc, &rp, dummy, dummy, 0);
    ASSERT_EQ_RET(0, err, -1);

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
construct_key(char *buf, uint buf_sz, char *pfx, int idx)
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
create_cursor(
    struct mtf_test_info *  lcl_ti,
    char *                  pfx,
    uint                    nkeys,
    bool                    reverse,
    struct hse_kvs_cursor **cur_out)
{
    struct hse_kvs_cursor *cur;
    merr_t                 err;

    cur = kvs_cursor_alloc(kvs, pfx, strlen(pfx), reverse);
    ASSERT_NE(NULL, cur);

    err = kvs_cursor_init(cur, NULL);
    ASSERT_EQ(0, err);

    err = kvs_cursor_prepare(cur);
    ASSERT_EQ(0, err);

    *cur_out = cur;
}

void
expect_key(struct mtf_test_info *lcl_ti, struct kvs_ktuple *kt_found, char *expected)
{
    int rc;

    rc = strcmp(kt_found->kt_data, expected);
    ASSERT_EQ(0, rc);
}

void
expect_pfx(struct mtf_test_info *lcl_ti, struct kvs_ktuple *kt_found, char *pfx)
{
    int rc;

    rc = strncmp(pfx, kt_found->kt_data, strlen(pfx));
    ASSERT_EQ(0, rc);
}

MTF_BEGIN_UTEST_COLLECTION(kvs_cursor_test);

MTF_DEFINE_UTEST_PREPOST(kvs_cursor_test, basic_test, test_pre, test_post)
{
    merr_t err;

    /* Insert phase */
    insert_key_multiple(lcl_ti, "ab", 10);
    insert_key_multiple(lcl_ti, "pq", 10);
    insert_key(lcl_ti, "this is a key");

    /* Verify phase */
    struct hse_kvs_cursor *cur;

    create_cursor(lcl_ti, "pq", 2, false, &cur);

    void check_keys(int start, int cnt)
    {
        int i;
        int c = 0;

        for (i = start;; i++) {
            struct kvs_kvtuple kvt;
            char               buf[20];
            bool               eof;
            merr_t             err;

            err = kvs_cursor_read(cur, &kvt, &eof);
            ASSERT_EQ(0, err);
            if (eof)
                break;

            snprintf(buf, sizeof(buf), "%s-%02d", "pq", i);
            expect_pfx(lcl_ti, &kvt.kvt_key, "pq");
            expect_key(lcl_ti, &kvt.kvt_key, buf);

            ++c;
        }

        ASSERT_EQ(cnt, c);
    }

    check_keys(0, 10);

    char      buf[20];
    const int start = 3;
    construct_key(buf, sizeof(buf), "pq", start);
    struct kvs_ktuple kt;

    err = kvs_cursor_seek(cur, buf, strlen(buf), NULL, 0, &kt);
    ASSERT_EQ(0, err);

    expect_pfx(lcl_ti, &kt, "pq");
    expect_key(lcl_ti, &kt, buf);
    check_keys(start, 10 - start);

    kvs_cursor_destroy(cur);
}

MTF_END_UTEST_COLLECTION(kvs_cursor_test);
