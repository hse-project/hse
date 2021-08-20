/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/logging.h>
#include <hse_util/element_source.h>
#include <hse_util/seqno.h>
#include <hse_util/keycmp.h>

#include <hse_test_support/random_buffer.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>

int
test_collection_setup(struct mtf_test_info *info)
{
    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    return 0;
}

int
no_fail_pre(struct mtf_test_info *info)
{
    return 0;
}

int
no_fail_post(struct mtf_test_info *info)
{
    return 0;
}

static void
c0kvs_get_content_metrics(struct c0_kvset *c0kvs, u64 *num_entries, u64 *num_tombs, u64 *key_bytes, u64 *val_bytes)
{
    struct c0_usage u;

    c0kvs_usage(c0kvs, &u);

    *num_entries = u.u_keys;
    *num_tombs = u.u_tombs;
    *key_bytes = u.u_keyb;
    *val_bytes = u.u_valb;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(c0_kvset_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, basic, no_fail_pre, no_fail_post)
{
    struct c0_kvset *kvs;
    merr_t           err = 0;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    c0kvs_destroy(kvs);
    c0kvs_destroy(NULL);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, basic_put_get, no_fail_pre, no_fail_post)
{
    struct c0_kvset *kvs;
    merr_t           err = 0;
    char             kbuf[100], vbuf[1000];
    uintptr_t        iseqnoref, oseqnoref;
    u64              view_seqno;
    int              i;
    int              seq;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    for (i = 0; i < 10; ++i) {
        struct kvs_ktuple kt;
        struct kvs_vtuple vt;

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));

        for (seq = 0; seq < 8; seq++) {
            int j = 0;

            iseqnoref = HSE_ORDNL_TO_SQNREF(i + seq);

            memset(vbuf, 0, sizeof(vbuf));
            while (j < i) {
                vbuf[j] = seq;
                ++j;
            }

            kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

            err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
            ASSERT_EQ(0, err);
        }
    }

    for (i = 9; i >= 0; --i) {
        struct kvs_ktuple   kt;
        struct kvs_buf      vb;
        enum key_lookup_res res;

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
        kvs_buf_init(&vb, vbuf, sizeof(vbuf));

        for (seq = 0; seq < 8; seq++) {
            int sum = 0;
            int j;

            iseqnoref = HSE_ORDNL_TO_SQNREF(i + seq);
            view_seqno = i + seq;
            res = (enum key_lookup_res) - 1;
            err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
            ASSERT_EQ(err, 0);
            ASSERT_EQ(res, FOUND_VAL);
            ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

            for (j = 0; j < vb.b_len; ++j)
                sum += ((u8 *)vb.b_buf)[j];

            ASSERT_EQ(sum, i * seq);

            c0kvs_prefix_get_excl(kvs, 0, &kt, view_seqno, 0, kt.kt_len, &oseqnoref);
            ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

            if (seq == i % 8) {
                err = c0kvs_del(kvs, 0, &kt, iseqnoref);
                ASSERT_EQ(err, 0);
            }
        }
    }

    for (i = 9; i >= 0; --i) {
        struct kvs_ktuple   kt;
        struct kvs_buf      vb;
        enum key_lookup_res res;

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
        kvs_buf_init(&vb, vbuf, sizeof(vbuf));

        for (seq = 0; seq < 8; seq++) {
            int sum = 0;

            view_seqno = i + seq;
            res = (enum key_lookup_res) - 1;
            err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
            ASSERT_EQ(err, 0);
            ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

            if (seq != i % 8) {
                int j;

                ASSERT_EQ(res, FOUND_VAL);
                for (j = 0; j < vb.b_len; ++j)
                    sum += ((u8 *)vb.b_buf)[j];

                ASSERT_EQ(sum, i * seq);
            } else {
                ASSERT_EQ(res, FOUND_TMB);
            }

            c0kvs_prefix_get_excl(kvs, 0, &kt, view_seqno, 0, kt.kt_len, &oseqnoref);
            ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);
        }
    }

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, basic_put_get_fail, no_fail_pre, no_fail_post)
{
    struct c0_usage   usage;
    struct c0_kvset * kvs;
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    merr_t            err;
    size_t            avail;
    uintptr_t         seqnoref;
    char *            bigly;
    void             *mem;
    int               n;

    /* Allocate largest possible kvs.
     */
    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE(NULL, kvs);

    c0kvs_usage(kvs, &usage);
    avail = usage.u_alloc - usage.u_used + 1;
    ASSERT_GT(avail, HSE_C0_CHEAP_SZ_DFLT / 2);
    ASSERT_LT(avail, HSE_C0_CHEAP_SZ_DFLT);

    bigly = malloc(avail);
    ASSERT_NE(NULL, bigly);

    n = snprintf(bigly, avail, "%p", &bigly);
    ASSERT_LT(n, avail);
    ASSERT_GT(n, 0);

    /* Try to put an excessively large value
     */
    kvs_ktuple_init(&kt, "key", 3);
    kvs_vtuple_init(&vt, bigly, avail);
    seqnoref = HSE_ORDNL_TO_SQNREF(0);

    err = c0kvs_put(kvs, 0, &kt, &vt, seqnoref);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    /* Use up most of the available space from the cheap..
     */
    mem = c0kvs_alloc(kvs, 8, avail - HSE_KVS_KEY_LEN_MAX);
    ASSERT_NE(NULL, mem);

    /* Try to put an excessively large key
     */
    kvs_ktuple_init(&kt, bigly, strlen(bigly));
    kvs_vtuple_init(&vt, "val", 3);
    kt.kt_len = HSE_KVS_KEY_LEN_MAX;

    err = c0kvs_put(kvs, 0, &kt, &vt, seqnoref);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    /* Try to delete an excessively large key
     */
    kvs_ktuple_init(&kt, bigly, strlen(bigly));
    kt.kt_len = HSE_KVS_KEY_LEN_MAX;

    err = c0kvs_del(kvs, 0, &kt, seqnoref);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    /* Try to prefix delete an excessively large key
     */
    kvs_ktuple_init(&kt, bigly, strlen(bigly));
    kt.kt_len = HSE_KVS_KEY_LEN_MAX;

    err = c0kvs_prefix_del(kvs, 0, &kt, seqnoref);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    /* Fill up the kvs.
     */
    u64 key = get_cycles();

    while (1) {
        kvs_ktuple_init(&kt, &key, sizeof(key));
        kvs_vtuple_init(&vt, &key, sizeof(key));

        err = c0kvs_put(kvs, 0, &kt, &vt, seqnoref);

        if (ENOMEM == merr_errno(err))
            break;

        ASSERT_EQ(0, err);

        key++;
    }

    c0kvs_destroy(kvs);
    free(bigly);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, basic_repeated_put, no_fail_pre, no_fail_post)
{
    struct c0_kvset *   kvs;
    merr_t              err = 0;
    char                kbuf[1], vbuf[1];
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    struct kvs_buf      vb;
    enum key_lookup_res res;
    uintptr_t           iseqnoref, oseqnoref;
    u64                 view_seqno;
    int                 i;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    kvs_ktuple_init(&kt, kbuf, 1);
    kvs_vtuple_init(&vt, vbuf, 1);
    kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));

    iseqnoref = HSE_ORDNL_TO_SQNREF(0);

    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i;

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    kbuf[0] = 3;
    res = (enum key_lookup_res) - 1;
    view_seqno = 0;
    err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, FOUND_VAL);
    ASSERT_EQ(3, ((u8 *)vb.b_buf)[0]);
    ASSERT_TRUE(HSE_SQNREF_ORDNL_P(oseqnoref));
    ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

    kbuf[0] = 3;
    vbuf[0] = 4;
    kvs_vtuple_init(&vt, vbuf, 1);
    kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));
    err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
    ASSERT_EQ(0, err);
    vbuf[0] = 0;
    res = (enum key_lookup_res) - 1;
    err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, FOUND_VAL);
    ASSERT_EQ(4, ((u8 *)vb.b_buf)[0]);
    ASSERT_TRUE(HSE_SQNREF_ORDNL_P(oseqnoref));
    ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

    kbuf[0] = 3;
    iseqnoref = HSE_ORDNL_TO_SQNREF(2);
    vbuf[0] = 1;
    kvs_vtuple_init(&vt, vbuf, 1);
    kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));
    err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
    ASSERT_EQ(0, err);

    vbuf[0] = 0;
    res = (enum key_lookup_res) - 1;
    view_seqno = 3;
    err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, FOUND_VAL);
    ASSERT_EQ(1, ((u8 *)vb.b_buf)[0]);
    ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), 2);

    vbuf[0] = 0;
    res = (enum key_lookup_res) - 1;
    view_seqno = 1;
    err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, FOUND_VAL);
    ASSERT_EQ(4, ((u8 *)vb.b_buf)[0]);
    ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), 0);

    iseqnoref = HSE_ORDNL_TO_SQNREF(3);
    err = c0kvs_del(kvs, 0, &kt, iseqnoref);
    ASSERT_EQ(0, err);

    res = (enum key_lookup_res) - 1;
    view_seqno = 3;
    err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, FOUND_TMB);
    ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

    kbuf[0] = 3;
    iseqnoref = HSE_ORDNL_TO_SQNREF(3);
    kvs_vtuple_init(&vt, vbuf, 0);
    kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));
    err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
    ASSERT_EQ(0, err);

    res = (enum key_lookup_res) - 1;
    view_seqno = 3;
    err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, FOUND_VAL);
    ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

    iseqnoref = HSE_ORDNL_TO_SQNREF(3);
    err = c0kvs_del(kvs, 0, &kt, iseqnoref);
    ASSERT_EQ(0, err);

    res = (enum key_lookup_res) - 1;
    view_seqno = 3;
    err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, FOUND_TMB);
    ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, ctxn_put, no_fail_pre, no_fail_post)
{
    struct c0_kvset *   kvs;
    merr_t              err = 0;
    char                kbuf[1], vbuf[1];
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    struct kvs_buf      vb;
    uintptr_t           iseqnoref;
    u64                 ctxn_priv_1[10], ctxn_priv_2[10];
    int                 i;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    kvs_ktuple_init(&kt, kbuf, 1);
    kvs_vtuple_init(&vt, vbuf, 1);
    kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));

    for (i = 0; i < 10; i++)
        ctxn_priv_1[i] = HSE_SQNREF_UNDEFINED;

    /* Insert a key per transaction */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i;
        iseqnoref = HSE_REF_TO_SQNREF(&ctxn_priv_1[i]);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys with non-transactional puts */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 1;
        iseqnoref = HSE_ORDNL_TO_SQNREF(3);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys within the same transaction */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 2;
        iseqnoref = HSE_REF_TO_SQNREF(&ctxn_priv_1[i]);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys with same seqno */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 3;
        iseqnoref = HSE_ORDNL_TO_SQNREF(3);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys with new seqno */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 4;
        iseqnoref = HSE_ORDNL_TO_SQNREF(4);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Commit the transactions. */
    for (i = 0; i < 10; i++)
        ctxn_priv_1[i] = HSE_ORDNL_TO_SQNREF(5);

    /* Update the keys with non-transactional puts */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 5;
        iseqnoref = HSE_ORDNL_TO_SQNREF(6);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Repeat with second transaction which will be aborted. */
    for (i = 0; i < 10; i++)
        ctxn_priv_2[i] = HSE_SQNREF_UNDEFINED;

    /* Insert a key per transaction */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 6;
        iseqnoref = HSE_REF_TO_SQNREF(&ctxn_priv_2[i]);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys with non-transactional puts */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 7;
        iseqnoref = HSE_ORDNL_TO_SQNREF(7);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys within the same transaction */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 8;
        iseqnoref = HSE_REF_TO_SQNREF(&ctxn_priv_2[i]);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys with same seqno */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 9;
        iseqnoref = HSE_ORDNL_TO_SQNREF(7);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Update the keys with non-transactional puts */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 10;
        iseqnoref = HSE_ORDNL_TO_SQNREF(8);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    /* Abort the transactions. */
    for (i = 0; i < 10; i++)
        ctxn_priv_2[i] = HSE_SQNREF_ABORTED;

    /* Update the keys with non-transactional puts */
    for (i = 0; i < 10; ++i) {
        kbuf[0] = i;
        vbuf[0] = i + 11;
        iseqnoref = HSE_ORDNL_TO_SQNREF(9);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, advanced_repeated_put, no_fail_pre, no_fail_post)
{
    struct c0_kvset *        kvs;
    merr_t                   err = 0;
    struct call_rcu_data *   rcu_thrd;
    u32                      kbuf[1], vbuf[1];
    const u32                insert_count = 10000;
    const u32                reinsert_count = 1000;
    u32                      keys[insert_count];
    struct kvs_ktuple        kt;
    struct kvs_vtuple        vt;
    struct c0_kvset_iterator iter;
    struct kvs_buf           vb;
    struct element_source *  source;
    enum key_lookup_res      res;
    u32                      indexes[reinsert_count];
    int                      i, j;
    u64                      num_entries, num_tombs;
    u64                      key_bytes, val_bytes;
    u64                      tr_keys = 0, tr_tombs = 0;
    u64                      tr_key_bytes = 0, tr_val_bytes = 0;
    uintptr_t                iseqnoref, oseqnoref;
    u64                      view_seqno;
    struct bonsai_kv *       bkv;
    struct bonsai_val *      val;
    void *                   last_key, *key;
    size_t                   last_key_len, key_len;
    bool                     found;

    ASSERT_LE(reinsert_count, insert_count);

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    kvs_ktuple_init(&kt, kbuf, sizeof(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    /* Insert a bunch of pseudo-random stuff ... */
    srand(42);

    generate_unique_random_u32_sequence(0, 1000000000, keys, insert_count);
    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = keys[i];

        for (j = 0; j < 8; ++j) {
            vbuf[0] = rand();

            iseqnoref = HSE_ORDNL_TO_SQNREF(j);
            err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
            ASSERT_EQ(0, err);
        }
    }
    synchronize_rcu();

    /* Create a permuted array of the first reinsert_count keys used */
    permute_u32_sequence(keys, reinsert_count);

    /* Create a permuted array of indexes */
    for (i = 0; i < reinsert_count; ++i)
        indexes[i] = i;
    permute_u32_sequence(indexes, reinsert_count);

    /* Using the permuted indexes, perform the re-put's */
    for (i = 0; i < reinsert_count; ++i) {
        kbuf[0] = keys[indexes[i]];
        for (j = 0; j < 8; ++j) {
            vbuf[0] = indexes[i] + j;

            iseqnoref = HSE_ORDNL_TO_SQNREF(j);
            err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
            ASSERT_EQ(0, err);
        }
    }
    synchronize_rcu();

    /* Permute the array indices again ... */
    permute_u32_sequence(indexes, reinsert_count);

    /* Check that the updated values are all present */
    for (i = reinsert_count - 1; i >= 0; --i) {
        kbuf[0] = keys[indexes[i]];
        for (j = 0; j < 8; ++j) {
            kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));
            res = (enum key_lookup_res) - 1;
            view_seqno = j;
            err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
            ASSERT_EQ(err, 0);
            ASSERT_EQ(res, FOUND_VAL);
            ASSERT_EQ(indexes[i] + j, ((u32 *)vb.b_buf)[0]);
            ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), view_seqno);
        }
    }
    synchronize_rcu();

    c0kvs_finalize(kvs);

    c0kvs_get_content_metrics(kvs, &num_entries, &num_tombs, &key_bytes, &val_bytes);

    /* set up the iteration apparatus */
    c0kvs_iterator_init(kvs, &iter, 0, 0);
    source = c0_kvset_iterator_get_es(&iter);

    /* get the first element and initialize counts & last element */
    found = source->es_get_next(source, (void *)&bkv);
    ASSERT_EQ(true, found);

    tr_keys++;
    tr_key_bytes += key_imm_klen(&bkv->bkv_key_imm);

    val = bkv->bkv_values;
    ASSERT_NE(0, val);

    if (HSE_CORE_IS_TOMB(val->bv_value))
        tr_tombs++;
    else
        tr_val_bytes += bonsai_val_vlen(val);

    last_key = bkv->bkv_key;
    last_key_len = key_imm_klen(&bkv->bkv_key_imm);

    /* loop over the elements in order */
    while (source->es_get_next(source, (void *)&bkv)) {
        int rc;

        key = bkv->bkv_key;
        key_len = key_imm_klen(&bkv->bkv_key_imm);

        val = bkv->bkv_values;
        ASSERT_NE(0, val);

        ASSERT_EQ(val->bv_seqnoref, HSE_ORDNL_TO_SQNREF(7));

        /* Validate that the keys are traversed in order */
        rc = keycmp(last_key, last_key_len, key, key_len);
        ASSERT_EQ(rc < 0, true);

        tr_keys++;
        tr_key_bytes += key_len;

        if (HSE_CORE_IS_TOMB(val->bv_value))
            tr_tombs++;
        else
            tr_val_bytes += bonsai_val_vlen(val);

        last_key = key;
        last_key_len = key_len;
    }

    /* [HSE_REVISIT] reenable ASSERTs once we ingest all seqnos for a key.
    ASSERT_EQ(tr_tombs, num_tombs);
    ASSERT_EQ(tr_key_bytes, key_bytes);
    ASSERT_EQ(tr_val_bytes, val_bytes);
    */

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, basic_put_get_del, no_fail_pre, no_fail_post)
{
    struct c0_kvset *   kvs;
    merr_t              err = 0;
    char                kbuf[100], vbuf[1000];
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    struct kvs_buf      vb;
    enum key_lookup_res res;
    int                 i;
    uintptr_t           iseqnoref, oseqnoref;
    u64                 view_seqno;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    for (i = 0; i < 10; ++i) {
        int j = 0;

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
        iseqnoref = HSE_ORDNL_TO_SQNREF(i);

        memset(vbuf, 0, sizeof(vbuf));
        while (j < i) {
            vbuf[j] = 1;
            ++j;
        }

        kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqnoref);
        ASSERT_EQ(0, err);
    }

    for (i = 9; i >= 0; --i) {
        int sum = 0, j;

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);

        kt.kt_len = 1 + strlen(kbuf);
        view_seqno = i + 1;
        kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));

        res = (enum key_lookup_res) - 1;
        err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
        ASSERT_EQ(err, 0);
        ASSERT_EQ(res, FOUND_VAL);
        ASSERT_GT(view_seqno, HSE_SQNREF_TO_ORDNL(oseqnoref));

        for (j = 0; j < vb.b_len; ++j)
            sum += ((u8 *)vb.b_buf)[j];

        ASSERT_EQ(i, sum);
    }

    {
        i = 3;
        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 1 + strlen(kbuf);
        iseqnoref = HSE_ORDNL_TO_SQNREF(i);
        err = c0kvs_del(kvs, 0, &kt, iseqnoref);
        ASSERT_EQ(0, err);

        i = 7;
        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 1 + strlen(kbuf);
        iseqnoref = HSE_ORDNL_TO_SQNREF(i);
        err = c0kvs_del(kvs, 0, &kt, iseqnoref);
        ASSERT_EQ(0, err);

        i = 4;
        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 5;
        iseqnoref = HSE_ORDNL_TO_SQNREF(i + 1);
        err = c0kvs_prefix_del(kvs, 0, &kt, iseqnoref);
        ASSERT_EQ(0, err);

        c0kvs_prefix_get_excl(kvs, 0, &kt, iseqnoref, 0, kt.kt_len, &oseqnoref);
        ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), i + 1);

        c0kvs_prefix_get_excl(kvs, 0, &kt, HSE_ORDNL_TO_SQNREF(i + 2), 0, kt.kt_len, &oseqnoref);
        ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), i + 1);
    }

    for (i = 9; i >= 0; --i) {

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 1 + strlen(kbuf);
        view_seqno = i + 1;

        res = (enum key_lookup_res) - 1;
        err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
        ASSERT_EQ(err, 0);
        ASSERT_GT(view_seqno, HSE_SQNREF_TO_ORDNL(oseqnoref));
        if (res != FOUND_VAL) {
            ASSERT_TRUE(res == FOUND_TMB);
            ASSERT_TRUE((i == 3) || (i == 7));
        }

        view_seqno = i;
        c0kvs_prefix_get_excl(kvs, 0, &kt, view_seqno, 0, kt.kt_len, &oseqnoref);
        ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), i);

        view_seqno = i + 1;
        c0kvs_prefix_get_excl(kvs, 0, &kt, view_seqno, 0, kt.kt_len, &oseqnoref);
        ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), i);

        view_seqno = i;
        c0kvs_prefix_get_excl(kvs, 0, &kt, view_seqno, 0, 5, &oseqnoref);
        ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), 0);

        view_seqno = i + 1;
        c0kvs_prefix_get_excl(kvs, 0, &kt, view_seqno, 0, 5, &oseqnoref);
        if (i != 4)
            ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), 0);
        else
            ASSERT_GE(view_seqno, HSE_SQNREF_TO_ORDNL(oseqnoref));

        res = (enum key_lookup_res) - 1;
        view_seqno = i;
        kt.kt_len = 5;
        err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
        ASSERT_EQ(err, 0);
        ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), 0);
        ASSERT_EQ(res, NOT_FOUND);

        res = (enum key_lookup_res) - 1;
        view_seqno = i + 1;
        err = c0kvs_get_excl(kvs, 0, &kt, view_seqno, 0, &res, &vb, &oseqnoref);
        ASSERT_EQ(err, 0);
        if (i != 4) {
            ASSERT_EQ(HSE_SQNREF_TO_ORDNL(oseqnoref), 0);
            ASSERT_EQ(res, NOT_FOUND);
        } else {
            ASSERT_EQ(view_seqno, HSE_SQNREF_TO_ORDNL(oseqnoref));
            ASSERT_EQ(res, FOUND_TMB);
        }
    }

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, get_content_metrics, no_fail_pre, no_fail_post)
{
    struct c0_kvset * kvs;
    merr_t            err = 0;
    u64               num_entries;
    u64               num_tombstones;
    u64               total_key_bytes;
    u64               total_value_bytes;
    u32               kbuf[1];
    char              vbuf[3];
    int               i;
    const int         initial_insert_count = 273;
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    const int         delete_count = 7;
    const int         delete_step = 3;
    uintptr_t         seqno;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    c0kvs_get_content_metrics(
        kvs, &num_entries, &num_tombstones, &total_key_bytes, &total_value_bytes);
    ASSERT_EQ(0, num_entries);
    ASSERT_EQ(0, num_tombstones);
    ASSERT_EQ(0, total_key_bytes);
    ASSERT_EQ(0, total_value_bytes);

    kvs_ktuple_init(&kt, kbuf, sizeof(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));
    seqno = HSE_ORDNL_TO_SQNREF(0);

    for (i = 0; i < initial_insert_count; ++i) {
        kbuf[0] = i;
        vbuf[0] = i;

        err = c0kvs_put(kvs, 0, &kt, &vt, seqno);
        ASSERT_EQ(0, err);
    }

    c0kvs_get_content_metrics(
        kvs, &num_entries, &num_tombstones, &total_key_bytes, &total_value_bytes);
    ASSERT_EQ(initial_insert_count, num_entries);
    ASSERT_EQ(0, num_tombstones);
    ASSERT_EQ(sizeof(kbuf) * initial_insert_count, total_key_bytes);
    ASSERT_EQ(3 * initial_insert_count, total_value_bytes);

    ASSERT_LT(1 + (delete_count * delete_step), initial_insert_count);
    for (i = 0; i < delete_count; ++i) {
        struct kvs_ktuple key;

        kvs_ktuple_init(&key, kbuf, sizeof(kbuf));
        kbuf[0] = i * delete_step;

        err = c0kvs_del(kvs, 0, &key, seqno);
        ASSERT_EQ(0, err);
    }

    c0kvs_get_content_metrics(
        kvs, &num_entries, &num_tombstones, &total_key_bytes, &total_value_bytes);
    ASSERT_EQ(initial_insert_count - delete_count, num_entries);
    ASSERT_EQ(delete_count, num_tombstones);
    ASSERT_EQ(sizeof(kbuf) * initial_insert_count, total_key_bytes);
    ASSERT_EQ(3 * (initial_insert_count - delete_count), total_value_bytes);

    c0kvs_destroy(kvs);
}

#include <signal.h>
#include <setjmp.h>

static sig_atomic_t sigabrt_cnt;
sigjmp_buf          env;

void
sigabrt_isr(int sig)
{
    ++sigabrt_cnt;
    siglongjmp(env, 1);
}

int
signal_reliable(int signo, __sighandler_t func)
{
    struct sigaction nact;

    memset(&nact, 0, sizeof(nact));
    nact.sa_handler = func;
    sigemptyset(&nact.sa_mask);

    if (SIGALRM == signo || SIGINT == signo)
        nact.sa_flags |= SA_INTERRUPT;
    else
        nact.sa_flags |= SA_RESTART;

    return sigaction(signo, &nact, (struct sigaction *)0);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, finalize, no_fail_pre, no_fail_post)
{
    struct c0_kvset *   kvs;
    merr_t              err = 0;
    char                kbuf[100], vbuf[1000];
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    struct kvs_buf      vb;
    enum key_lookup_res res;
    int                 i;
    uintptr_t           iseqno, oseqno;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    kvs_ktuple_init(&kt, kbuf, 0);
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));
    iseqno = HSE_ORDNL_TO_SQNREF(0);

    for (i = 0; i < 10; ++i) {
        int j = 0;

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 1 + strlen(kbuf);

        memset(vbuf, 0, sizeof(vbuf));
        while (j < i) {
            vbuf[j] = 1;
            ++j;
        }

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqno);
        ASSERT_EQ(0, err);
    }

    c0kvs_finalize(kvs);

    for (i = 9; i >= 0; --i) {
        int sum = 0, j;

        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 1 + strlen(kbuf);
        iseqno = HSE_ORDNL_TO_SQNREF(1);
        kvs_buf_init(&vb, vt.vt_data, kvs_vtuple_vlen(&vt));

        res = (enum key_lookup_res) - 1;
        err = c0kvs_get_excl(kvs, 0, &kt, iseqno, 0, &res, &vb, &oseqno);
        ASSERT_EQ(err, 0);
        ASSERT_EQ(res, FOUND_VAL);
        ASSERT_EQ(oseqno, HSE_ORDNL_TO_SQNREF(0));

        for (j = 0; j < vb.b_len; ++j)
            sum += ((u8 *)vb.b_buf)[j];

        ASSERT_EQ(i, sum);
    }

    /* c0kvs_put() and c0kvs_del() assert if called when the c0kvs
     * is finalized.  So we catch the call to abort.
     */
    signal_reliable(SIGABRT, sigabrt_isr);

    err = merr(ENOTSUP);

    if (0 == sigsetjmp(env, 1)) {
        i = 3;
        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 1 + strlen(kbuf);
        iseqno = HSE_ORDNL_TO_SQNREF(0);
        err = c0kvs_del(kvs, 0, &kt, iseqno);
    }

    /* If assert() is disabled then c0kvs_del() will quietly succeed.
     * Otherwise, the assert will trigger and the we'll jump back to a
     * context in which err contains its initial value.
     */
#ifdef NDEBUG
    ASSERT_EQ(0, sigabrt_cnt);
    ASSERT_EQ(ENOMEM, merr_errno(err));
#else
    ASSERT_EQ(1, sigabrt_cnt);
    ASSERT_EQ(ENOTSUP, merr_errno(err));
#endif

    if (0 == sigsetjmp(env, 1)) {
        i = 203;
        sprintf(kbuf, "c0%03dsnapple%03d", i, i);
        kt.kt_len = 1 + strlen(kbuf);

        memset(vbuf, 0, sizeof(vbuf));
        kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqno);
    }

    /* If assert() is disabled then c0kvs_put() will quietly succeed.
     * Otherwise, the assert will trigger and the we'll jump back to a
     * context in which err contains its initial value.
     */
#ifdef NDEBUG
    ASSERT_EQ(0, sigabrt_cnt);
    ASSERT_EQ(ENOMEM, merr_errno(err));
#else
    ASSERT_EQ(2, sigabrt_cnt);
    ASSERT_EQ(ENOTSUP, merr_errno(err));
#endif

    signal(SIGABRT, SIG_DFL);

    c0kvs_destroy(kvs);
}

/* Test that finalizing the kvset produces a fixated linked list
 * of cb_kv nodes in the correct order.
 */
MTF_DEFINE_UTEST_PREPOST(c0_kvset_test, iterator, no_fail_pre, no_fail_post)
{
    struct c0_kvset * kvs;
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    struct bonsai_kv *bkv;
    merr_t            err;
    char              kbuf, vbuf;
    uintptr_t         iseqno;
    bool              found;
    int               i;
    char              c;

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE(NULL, kvs);

    iseqno = HSE_ORDNL_TO_SQNREF(0);

    /* Insert "b" through "y".
     */
    for (c = 'b'; c < 'z'; ++c) {
        kbuf = c;
        vbuf = c;

        kvs_ktuple_init(&kt, &kbuf, 1);
        kvs_vtuple_init(&vt, &vbuf, 1);

        err = c0kvs_put(kvs, 0, &kt, &vt, iseqno);
        ASSERT_EQ(0, err);
    }

    synchronize_rcu();

    c0kvs_finalize(kvs);

    /* Test forward iteration over the finalized cb_kv list.
     */
    for (i = 0; i < 3; ++i) {
        struct c0_kvset_iterator iter;
        struct element_source *  source;

        c0kvs_iterator_init(kvs, &iter, 0, 0);
        source = c0_kvset_iterator_get_es(&iter);

        for (c = 'b'; source->es_get_next(source, (void *)&bkv); ++c) {
            u16 klen = key_imm_klen(&bkv->bkv_key_imm);

            ASSERT_EQ(1, klen);
            ASSERT_EQ(c, bkv->bkv_key[0]);
        }
        ASSERT_EQ(c, 'z');

        found = source->es_get_next(source, (void *)&bkv);
        ASSERT_EQ(false, found);
    }

    /* Test reverse iteration over the finalized cb_kv list.
     */
    for (i = 0; i < 3; ++i) {
        struct c0_kvset_iterator iter;
        struct element_source *  source;

        c0kvs_iterator_init(kvs, &iter, C0_KVSET_ITER_FLAG_REVERSE, 0);
        source = c0_kvset_iterator_get_es(&iter);

        for (c = 'y'; source->es_get_next(source, (void *)&bkv); --c) {
            u16 klen = key_imm_klen(&bkv->bkv_key_imm);

            ASSERT_EQ(1, klen);
            ASSERT_EQ(c, bkv->bkv_key[0]);
        }
        ASSERT_EQ(c, 'a');

        found = source->es_get_next(source, (void *)&bkv);
        ASSERT_EQ(false, found);
    }

    c0kvs_destroy(kvs);
}

MTF_END_UTEST_COLLECTION(c0_kvset_test)
