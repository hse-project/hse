/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/platform.h>
#include <hse_util/seqno.h>
#include <hse_util/bonsai_tree.h>

#include <hse_test_support/random_buffer.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>

#include "../c0_kvset_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

MTF_BEGIN_UTEST_COLLECTION(c0_kvset_iterator_test);

MTF_DEFINE_UTEST(c0_kvset_iterator_test, basic_construction)
{
    struct c0_kvset *        kvs;
    merr_t                   err = 0;
    struct call_rcu_data *   rcu_thrd;
    u32                      kbuf[1], vbuf[1];
    const u32                insert_count = 10000;
    struct kvs_ktuple        kt;
    struct kvs_vtuple        vt;
    struct c0_kvset_iterator iter, riter;
    int                      i;

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    err = c0kvs_create(HSE_C0_CHEAP_SZ_DFLT, 0, 0, false, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    kt.kt_data = kbuf;
    kt.kt_len = sizeof(kbuf);
    vt.vt_data = vbuf;
    vt.vt_len = sizeof(vbuf);

    srand(42);
    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = generate_random_u32(0, 1000000000);
        vbuf[0] = rand();
        err = c0kvs_put(kvs, 0, &kt, &vt, HSE_ORDNL_TO_SQNREF(117));
        ASSERT_EQ(0, err);
    }

    c0kvs_iterator_init(kvs, &iter, 0, 0);
    c0kvs_iterator_init(kvs, &riter, C0_KVSET_ITER_FLAG_REVERSE, 0);

    rcu_barrier();
    set_thread_call_rcu_data(NULL);
    call_rcu_data_free(rcu_thrd);

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST(c0_kvset_iterator_test, element_source)
{
    merr_t                   err = 0;
    struct call_rcu_data *   rcu_thrd;
    struct c0_kvset *        kvs;
    struct c0_kvset_impl *   kvs_impl;
    struct c0_kvset_iterator iter, riter;
    const u32                insert_count = 10000;
    u32                      kbuf[1], vbuf[1];
    struct kvs_ktuple        kt;
    struct kvs_vtuple        vt;
    int                      i;
    struct element_source *  es;
    bool                     br;
    int                      source_count;
    struct bonsai_kv *       last_bkv, *bkv;

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    err = c0kvs_create(HSE_C0_CHEAP_SZ_DFLT, 0, 0, false, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);
    kvs_impl = c0_kvset_h2r(kvs);

    c0_kvset_iterator_init(&iter, kvs_impl->c0s_broot, 0, 0);
    es = c0_kvset_iterator_get_es(&iter);
    ASSERT_NE(0, es);
    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_FALSE(br);
    br = es->es_unget(es);
    ASSERT_FALSE(br);
    br = c0_kvset_iterator_eof(&iter);
    ASSERT_TRUE(br);

    c0_kvset_iterator_init(&riter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_REVERSE, 0);
    es = c0_kvset_iterator_get_es(&riter);
    ASSERT_NE(0, es);
    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_FALSE(br);
    br = es->es_unget(es);
    ASSERT_FALSE(br);
    br = c0_kvset_iterator_eof(&riter);
    ASSERT_TRUE(br);

    kt.kt_data = kbuf;
    kt.kt_len = sizeof(kbuf);
    vt.vt_data = vbuf;
    vt.vt_len = sizeof(vbuf);

    srand(42);
    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = generate_random_u32(0, 1000000000);
        vbuf[0] = rand();
        err = c0kvs_put(kvs, 0, &kt, &vt, HSE_ORDNL_TO_SQNREF(117));
        ASSERT_EQ(0, err);
    }

    synchronize_rcu();

    c0kvs_finalize(&kvs_impl->c0s_handle);

    c0_kvset_iterator_init(&iter, kvs_impl->c0s_broot, 0, 0);

    es = c0_kvset_iterator_get_es(&iter);
    ASSERT_NE(0, es);

    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_TRUE(br);

    br = es->es_unget(es);
    ASSERT_TRUE(br);

    br = c0_kvset_iterator_eof(&iter);
    ASSERT_FALSE(br);

    source_count = 0;
    last_bkv = bkv;

    while (es->es_get_next(es, (void *)&bkv)) {

        /* Validate that the keys are traversed in order */
        int rc = keycmp(
            last_bkv->bkv_key,
            last_bkv->bkv_key_imm.ki_klen,
            bkv->bkv_key,
            bkv->bkv_key_imm.ki_klen);

        if (source_count)
            ASSERT_EQ(rc < 0, true);
        else
            ASSERT_EQ(rc, 0);

        last_bkv = bkv;
        ++source_count;
    }

    ASSERT_EQ(insert_count, source_count);

    br = c0_kvset_iterator_eof(&iter);
    ASSERT_TRUE(br);

    c0_kvset_iterator_init(&riter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_REVERSE, 0);

    es = c0_kvset_iterator_get_es(&riter);
    ASSERT_NE(0, es);

    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_TRUE(br);

    br = es->es_unget(es);
    ASSERT_TRUE(br);

    br = c0_kvset_iterator_eof(&riter);
    ASSERT_FALSE(br);

    source_count = 0;
    last_bkv = bkv;

    while (es->es_get_next(es, (void *)&bkv)) {

        /* Validate that the keys are traversed in order */
        int rc = keycmp(
            bkv->bkv_key,
            bkv->bkv_key_imm.ki_klen,
            last_bkv->bkv_key,
            last_bkv->bkv_key_imm.ki_klen);

        if (source_count)
            ASSERT_EQ(rc < 0, true);
        else
            ASSERT_EQ(rc, 0);

        last_bkv = bkv;
        ++source_count;
    }

    ASSERT_EQ(insert_count, source_count);

    br = c0_kvset_iterator_eof(&riter);
    ASSERT_TRUE(br);

    rcu_barrier();
    set_thread_call_rcu_data(NULL);
    call_rcu_data_free(rcu_thrd);

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST(c0_kvset_iterator_test, seek)
{
    merr_t                   err = 0;
    struct call_rcu_data *   rcu_thrd;
    struct c0_kvset *        kvs;
    struct c0_kvset_impl *   kvs_impl;
    struct c0_kvset_iterator iter, riter;
    struct c0_kvset_iterator bkvs_iter, bkvs_riter;
    struct c0_kvset_iterator gkvs_iter, gkvs_riter;
    const u32                insert_count = 10000;
    u32                      kbuf[1], vbuf[1];
    struct kvs_ktuple        kt;
    struct kvs_vtuple        vt;
    int                      i;
    struct element_source *  es;
    bool                     br;
    int                      source_count;
    struct bonsai_kv *       last_bkv, *bkv;
    void *                   seek;
    int                      seeklen;

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    c0kvs_create(HSE_C0_CHEAP_SZ_DFLT, 0, 0, false, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);
    kvs_impl = c0_kvset_h2r(kvs);

    kt.kt_data = kbuf;
    kt.kt_len = sizeof(kbuf);
    vt.vt_data = vbuf;
    vt.vt_len = sizeof(vbuf);

    srand(42);
    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = generate_random_u32(0, 1000000000);
        vbuf[0] = rand();
        err = c0kvs_put(kvs, 1, &kt, &vt, HSE_ORDNL_TO_SQNREF(117));
        ASSERT_EQ(0, err);
    }

    /* NB: finalize NOT necessary!

     * Create iterators that do not filter on KVS index */
    c0_kvset_iterator_init(&iter, kvs_impl->c0s_broot, 0, 0);
    c0_kvset_iterator_init(&riter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_REVERSE, 0);

    /* Create iterators that filter on KVS index */
    c0_kvset_iterator_init(&gkvs_iter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_INDEX, 1);
    c0_kvset_iterator_init(
        &gkvs_riter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_REVERSE | C0_KVSET_ITER_FLAG_INDEX, 1);
    c0_kvset_iterator_init(&bkvs_iter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_INDEX, 0);
    c0_kvset_iterator_init(
        &bkvs_riter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_REVERSE | C0_KVSET_ITER_FLAG_INDEX, 2);

    es = c0_kvset_iterator_get_es(&iter);
    ASSERT_NE(0, es);

    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_TRUE(br);

    source_count = 1;
    while (es->es_get_next(es, (void *)&bkv)) {
        if (++source_count == insert_count / 2)
            last_bkv = bkv;
    }
    ASSERT_EQ(insert_count, source_count);

    seek = last_bkv->bkv_key;
    seeklen = last_bkv->bkv_key_imm.ki_klen;

    /* This iterator's index doesn't match. */
    es = c0_kvset_iterator_get_es(&bkvs_iter);
    ASSERT_NE(0, es);

    c0_kvset_iterator_seek(&bkvs_iter, seek, seeklen, &kt);
    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_FALSE(br);

    /* Use an iterator that filters on and matches KVS index. */
    c0_kvset_iterator_seek(&gkvs_iter, seek, seeklen, &kt);

    /* and we should find an exact match */
    i = keycmp(seek, seeklen, kt.kt_data, kt.kt_len);
    ASSERT_EQ(i, 0);

    es = c0_kvset_iterator_get_es(&gkvs_iter);
    ASSERT_NE(0, es);

    /* ... next should return the key sought */
    br = es->es_get_next(es, (void **)&bkv);
    i = keycmp(seek, seeklen, bkv->bkv_key, bkv->bkv_key_imm.ki_klen);
    ASSERT_EQ(i, 0);

    /* ... and the keys should be in order */
    br = es->es_get_next(es, (void **)&bkv);
    i = keycmp(seek, seeklen, bkv->bkv_key, bkv->bkv_key_imm.ki_klen);
    ASSERT_LT(i, 0);

    /* A reverse iterator that doesn't filter on index */
    es = c0_kvset_iterator_get_es(&riter);
    ASSERT_NE(0, es);

    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_TRUE(br);

    source_count = 1;
    while (es->es_get_next(es, (void *)&bkv)) {
        if (++source_count == insert_count / 2)
            last_bkv = bkv;
    }
    ASSERT_EQ(insert_count, source_count);

    seek = last_bkv->bkv_key;
    seeklen = last_bkv->bkv_key_imm.ki_klen;

    es = c0_kvset_iterator_get_es(&bkvs_riter);
    ASSERT_NE(0, es);

    /* Use an iterator that filters but doesn't match index */
    c0_kvset_iterator_seek(&bkvs_riter, seek, seeklen, &kt);
    br = es->es_get_next(es, (void **)&bkv);
    ASSERT_FALSE(br);

    /* Use an iterator that filters and does match index */
    c0_kvset_iterator_seek(&gkvs_riter, seek, seeklen, &kt);

    /* and we should find an exact match */
    i = keycmp(seek, seeklen, kt.kt_data, kt.kt_len);
    ASSERT_EQ(i, 0);

    es = c0_kvset_iterator_get_es(&gkvs_riter);
    ASSERT_NE(0, es);

    /* ... next should return the key sought */
    br = es->es_get_next(es, (void **)&bkv);
    i = keycmp(seek, seeklen, bkv->bkv_key, bkv->bkv_key_imm.ki_klen);
    ASSERT_EQ(i, 0);

    /* ... and the keys should be in order */
    br = es->es_get_next(es, (void **)&bkv);
    i = keycmp(bkv->bkv_key, bkv->bkv_key_imm.ki_klen, seek, seeklen);
    ASSERT_LT(i, 0);

    rcu_barrier();
    set_thread_call_rcu_data(NULL);
    call_rcu_data_free(rcu_thrd);

    c0kvs_destroy(kvs);
}

MTF_DEFINE_UTEST(c0_kvset_iterator_test, skip)
{
    merr_t                   err = 0;
    struct call_rcu_data *   rcu_thrd;
    struct c0_kvset *        kvs;
    struct c0_kvset_impl *   kvs_impl;
    struct c0_kvset_iterator iter;
    const u32                insert_count = 10000;
    u32                      kbuf[2], vbuf[1];
    u32                      exp1[2], exp2[2];
    struct kvs_ktuple        kt;
    struct kvs_vtuple        vt;
    int                      i;
    struct element_source *  es;
    void *                   pfx;
    int                      pfx_len;

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    c0kvs_create(HSE_C0_CHEAP_SZ_DFLT, 0, 0, false, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);
    kvs_impl = c0_kvset_h2r(kvs);

    kt.kt_data = kbuf;
    kt.kt_len = sizeof(kbuf);
    vt.vt_data = vbuf;
    vt.vt_len = sizeof(vbuf);

    exp1[0] = 1;
    exp2[0] = 2;

    exp1[1] = exp2[1] = -1;

    srand(42);
    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = i & 0x01 ? 1 : 2; /* prefix */
        kbuf[1] = generate_random_u32(0, 1000000000);
        vbuf[0] = rand();
        err = c0kvs_put(kvs, 1, &kt, &vt, HSE_ORDNL_TO_SQNREF(117));
        ASSERT_EQ(0, err);

        /* set exp1 and exp2 to the minimum of prefix1 and prefix2 */
        if (kbuf[0] == 2) {
            if (keycmp(exp2, sizeof(exp2), kbuf, sizeof(kbuf)) > 0)
                exp2[1] = kbuf[1];
        } else {
            if (keycmp(exp1, sizeof(exp1), kbuf, sizeof(kbuf)) > 0)
                exp1[1] = kbuf[1];
        }
    }

    c0_kvset_iterator_init(&iter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_INDEX, 1);

    es = c0_kvset_iterator_get_es(&iter);
    ASSERT_NE(0, es);

    /* Skip past pfx '3' - expect eof */
    kbuf[0] = 3;
    pfx = kbuf;
    pfx_len = sizeof(kbuf[0]);

    iter.c0it_root = 0;
    c0_kvset_iterator_skip_pfx(&iter, pfx, pfx_len, 0);

    c0_kvset_iterator_init(&iter, kvs_impl->c0s_broot, C0_KVSET_ITER_FLAG_INDEX, 1);

    c0_kvset_iterator_skip_pfx(&iter, pfx, pfx_len, 0);
    ASSERT_EQ(true, c0_kvset_iterator_eof(&iter));

    c0_kvset_iterator_seek(&iter, 0, 0, 0);

    /* Skip past pfx '2' - should land at eof */
    kbuf[0] = 2;
    pfx = kbuf;
    pfx_len = sizeof(kbuf[0]);

    c0_kvset_iterator_skip_pfx(&iter, pfx, pfx_len, 0);
    ASSERT_EQ(true, c0_kvset_iterator_eof(&iter));

    c0_kvset_iterator_seek(&iter, 0, 0, 0);

    /* Skip past pfx '1' */
    kbuf[0] = 1;
    pfx = kbuf;
    pfx_len = sizeof(kbuf[0]);

    c0_kvset_iterator_skip_pfx(&iter, pfx, pfx_len, &kt);

    /* and we should find an exact match */
    i = keycmp(exp2, sizeof(exp2), kt.kt_data, kt.kt_len);
    ASSERT_EQ(i, 0);

    /* Skip past pfx '0' */
    kbuf[0] = 0;
    pfx = kbuf;
    pfx_len = sizeof(kbuf[0]);

    c0_kvset_iterator_skip_pfx(&iter, pfx, pfx_len, &kt);

    /* and we should find an exact match */
    i = keycmp(exp1, sizeof(exp1), kt.kt_data, kt.kt_len);
    ASSERT_EQ(i, 0);

    rcu_barrier();
    set_thread_call_rcu_data(NULL);
    call_rcu_data_free(rcu_thrd);
}

MTF_END_UTEST_COLLECTION(c0_kvset_iterator_test);
