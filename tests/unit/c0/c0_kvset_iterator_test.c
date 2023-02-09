/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <c0/c0_kvset_internal.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/c0_kvset.h>
#include <hse/ikvdb/c0_kvset_iterator.h>
#include <hse/ikvdb/limits.h>
#include <hse/util/keycmp.h>
#include <hse/util/seqno.h>

#include <hse/test/mtf/framework.h>
#include <hse/test/support/random_buffer.h>

MTF_BEGIN_UTEST_COLLECTION(c0_kvset_iterator_test);

MTF_DEFINE_UTEST(c0_kvset_iterator_test, basic_construction)
{
    struct c0_kvset *kvs;
    merr_t err = 0;
    struct call_rcu_data *rcu_thrd;
    uint32_t kbuf[1], vbuf[1];
    const uint32_t insert_count = 10000;
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    struct c0_kvset_iterator iter, riter;
    int i;
    uint keys[insert_count];

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    err = c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);

    kvs_ktuple_init(&kt, kbuf, sizeof(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    srand(42);
    generate_random_u32_sequence_unique(0, 1000000000, keys, NELEM(keys));
    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = keys[i];
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
    merr_t err = 0;
    struct call_rcu_data *rcu_thrd;
    struct c0_kvset *kvs;
    struct c0_kvset_impl *kvs_impl;
    struct c0_kvset_iterator iter, riter;
    const uint32_t insert_count = 10000;
    uint32_t kbuf[1], vbuf[1];
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    int i;
    struct element_source *es;
    bool br;
    int source_count;
    struct bonsai_kv *last_bkv, *bkv;
    uint keys[insert_count];

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    err = c0kvs_create(NULL, NULL, &kvs);
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

    kvs_ktuple_init(&kt, kbuf, sizeof(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    srand(42);
    generate_random_u32_sequence_unique(0, 1000000000, keys, NELEM(keys));

    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = keys[i];
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
            last_bkv->bkv_key, key_imm_klen(&last_bkv->bkv_key_imm), bkv->bkv_key,
            key_imm_klen(&bkv->bkv_key_imm));

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
            bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm), last_bkv->bkv_key,
            key_imm_klen(&last_bkv->bkv_key_imm));

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
    merr_t err = 0;
    struct call_rcu_data *rcu_thrd;
    struct c0_kvset *kvs;
    struct c0_kvset_impl *kvs_impl;
    struct c0_kvset_iterator iter, riter;
    struct c0_kvset_iterator bkvs_iter, bkvs_riter;
    struct c0_kvset_iterator gkvs_iter, gkvs_riter;
    const uint32_t insert_count = 10000;
    uint32_t kbuf[1], vbuf[1];
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    int i;
    struct element_source *es;
    bool br;
    int source_count;
    struct bonsai_kv *last_bkv = NULL, *bkv;
    void *seek;
    int seeklen;
    uint keys[insert_count];

    rcu_thrd = create_call_rcu_data(0, -1);
    ASSERT_TRUE(rcu_thrd);
    set_thread_call_rcu_data(rcu_thrd);

    c0kvs_create(NULL, NULL, &kvs);
    ASSERT_NE((struct c0_kvset *)0, kvs);
    kvs_impl = c0_kvset_h2r(kvs);

    kvs_ktuple_init(&kt, kbuf, sizeof(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    srand(42);
    generate_random_u32_sequence_unique(0, 1000000000, keys, NELEM(keys));

    for (i = 0; i < insert_count; ++i) {
        kbuf[0] = keys[i];
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
    seeklen = key_imm_klen(&last_bkv->bkv_key_imm);

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
    i = keycmp(seek, seeklen, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));
    ASSERT_EQ(i, 0);

    /* ... and the keys should be in order */
    br = es->es_get_next(es, (void **)&bkv);
    i = keycmp(seek, seeklen, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));
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
    seeklen = key_imm_klen(&last_bkv->bkv_key_imm);

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
    i = keycmp(seek, seeklen, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));
    ASSERT_EQ(i, 0);

    /* ... and the keys should be in order */
    br = es->es_get_next(es, (void **)&bkv);
    i = keycmp(bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm), seek, seeklen);
    ASSERT_LT(i, 0);

    rcu_barrier();
    set_thread_call_rcu_data(NULL);
    call_rcu_data_free(rcu_thrd);

    c0kvs_destroy(kvs);
}

MTF_END_UTEST_COLLECTION(c0_kvset_iterator_test);
