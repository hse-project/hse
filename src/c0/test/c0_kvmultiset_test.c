/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/bin_heap.h>
#include <hse_util/keycmp.h>
#include <hse_util/seqno.h>
#include <hse_util/rcu.h>
#include <hse_util/bonsai_tree.h>

#include <hse_test_support/random_buffer.h>
#include <hse_ikvdb/limits.h>

#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/kvb_builder.h>

#include "../c0_ingest_work.h"
#include "../c0skm_internal.h"
#include "../c0_kvmsm.h"
#include "../c0_kvmsm_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

int
test_collection_setup(struct mtf_test_info *info)
{
    fail_nth_alloc_test_pre(info);

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
    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = -1;

    return 0;
}

int
no_fail_post(struct mtf_test_info *info)
{
    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = -1;

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    c0_kvmultiset_test,
    test_collection_setup,
    test_collection_teardown);

MTF_DEFINE_UTEST_PREPOST(c0_kvmultiset_test, basic, no_fail_pre, no_fail_post)
{
    struct c0_kvmultiset *kvms;
    struct c0_kvset *     p;
    merr_t                err;
    u32                   rc;

    err = c0kvms_create(1, HSE_C0_CHEAP_SZ_DFLT, 0, 0, true, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0_kvmultiset *)0, kvms);

    p = c0kvms_get_hashed_c0kvset(kvms, 0);
    ASSERT_NE((struct c0_kvset *)0, p);

    p = c0kvms_get_c0kvset(kvms, 0);
    ASSERT_NE((struct c0_kvset *)0, p);

    rc = c0kvms_width(kvms);
    ASSERT_EQ(rc, 2);

    c0kvms_putref(kvms);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvmultiset_test, basic_create, no_fail_pre, no_fail_post)
{
    struct c0_kvmultiset *kvms = 0;
    struct c0_kvset *     p = 0;
    merr_t                err;
    int                   i;

    const int WIDTH = 8;

    err = c0kvms_create(WIDTH, HSE_C0_CHEAP_SZ_DFLT, 0, 0, true, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0_kvmultiset *)0, kvms);

    for (i = 0; i < WIDTH; ++i) {
        p = c0kvms_get_hashed_c0kvset(kvms, i);
        ASSERT_NE((struct c0_kvset *)0, p);

        p = c0kvms_get_c0kvset(kvms, i);
        ASSERT_NE((struct c0_kvset *)0, p);
    }

    c0kvms_putref(kvms);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvmultiset_test, limit_create, no_fail_pre, no_fail_post)
{
    struct c0_kvmultiset *kvms = 0;
    merr_t                err;

    const int WIDTH = -1;

    err = c0kvms_create(WIDTH, HSE_C0_CHEAP_SZ_DFLT, 0, 0, true, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0_kvmultiset *)0, kvms);

    c0kvms_putref(kvms);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvmultiset_test, create_insert_check, no_fail_pre, no_fail_post)
{
    struct c0_kvmultiset *kvms = 0;
    struct c0_kvset *     p = 0;
    merr_t                err;
    uintptr_t             iseqno, oseqno;
    int                   i;

    const int WIDTH = 31;

    ASSERT_LT(WIDTH, 256);

    err = c0kvms_create(WIDTH, HSE_C0_CHEAP_SZ_DFLT, 0, 0, true, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0_kvmultiset *)0, kvms);

    for (i = 0; i < WIDTH; ++i) {
        char              kbuf[1], vbuf[1];
        struct kvs_ktuple kt;
        struct kvs_vtuple vt;

        p = c0kvms_get_hashed_c0kvset(kvms, i);
        ASSERT_NE((struct c0_kvset *)0, p);

        kbuf[0] = i;
        vbuf[0] = i % 17;

        kvs_ktuple_init(&kt, kbuf, 1);
        kvs_vtuple_init(&vt, vbuf, 1);
        iseqno = HSE_ORDNL_TO_SQNREF(0);

        err = c0kvs_put(p, 0, &kt, &vt, iseqno);
        ASSERT_EQ(0, err);
    }

    for (i = 0; i < WIDTH; ++i) {
        char                kbuf[1], vbuf[1];
        struct kvs_ktuple   kt;
        struct kvs_buf      vb;
        enum key_lookup_res res;

        p = c0kvms_get_hashed_c0kvset(kvms, i);
        ASSERT_NE((struct c0_kvset *)0, p);

        kbuf[0] = i;

        kvs_ktuple_init(&kt, kbuf, 1);
        kvs_buf_init(&vb, vbuf, sizeof(vbuf));
        iseqno = HSE_ORDNL_TO_SQNREF(1);

        c0kvs_get_excl(p, 0, &kt, iseqno, 0, &res, &vb, &oseqno);
        ASSERT_EQ(FOUND_VAL, res);
        ASSERT_EQ(oseqno, HSE_ORDNL_TO_SQNREF(0));

        ASSERT_EQ(1, vb.b_len);
        ASSERT_EQ((i % 17), ((char *)vb.b_buf)[0]);
    }

    for (i = WIDTH - 1; i >= 0; --i) {
        char                kbuf[1], vbuf[1];
        struct kvs_ktuple   kt;
        struct kvs_buf      vb;
        enum key_lookup_res res;

        p = c0kvms_get_hashed_c0kvset(kvms, i);
        ASSERT_NE((struct c0_kvset *)0, p);

        kbuf[0] = i;

        kvs_ktuple_init(&kt, kbuf, 1);
        kvs_buf_init(&vb, vbuf, sizeof(vbuf));
        iseqno = HSE_ORDNL_TO_SQNREF(1);

        c0kvs_get_excl(p, 0, &kt, iseqno, 0, &res, &vb, &oseqno);
        ASSERT_EQ(FOUND_VAL, res);
        ASSERT_EQ(oseqno, HSE_ORDNL_TO_SQNREF(0));

        ASSERT_EQ(1, vb.b_len);
        ASSERT_EQ((i % 17), ((char *)vb.b_buf)[0]);
    }

    c0kvms_putref(kvms);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvmultiset_test, ingest_sk, no_fail_pre, no_fail_post)
{
    struct c0_kvmultiset *kvms = 0;
    struct c0_kvset *     p = 0;
    merr_t                err;

    u64             keys_out = 0, tombs_out = 0, keyb_out = 0, valb_out = 0;
    uintptr_t       seqno;
    struct c0_usage usage;
    u64             db_put_cnt = 0, db_del_cnt = 0;
    const int       WIDTH = 3;
    int             i, j;

    ASSERT_LT(WIDTH, 200);

    err = c0kvms_create(WIDTH, HSE_C0_CHEAP_SZ_DFLT, 0, 0, true, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0_kvmultiset *)NULL, kvms);

    srand(32);
    for (i = 0; i <= WIDTH; ++i) {
        u32               kbuf[1];
        char              vbuf[1];
        struct kvs_ktuple kt;
        struct kvs_vtuple vt;

        p = c0kvms_get_hashed_c0kvset(kvms, i);
        ASSERT_NE((struct c0_kvset *)NULL, p);

        for (j = i + 3; j >= 0; --j) {
            u16 skidx;

            kbuf[0] = generate_random_u32(0, 1000000000);
            vbuf[0] = i + j + 3;

            skidx = kbuf[0] % 256;
            kvs_ktuple_init(&kt, kbuf, sizeof(kbuf));
            kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

            seqno = HSE_ORDNL_TO_SQNREF(kbuf[0]);
            err = c0kvs_put(p, skidx, &kt, &vt, seqno);
            ASSERT_EQ(0, err);
            ++db_put_cnt;

            if (kbuf[0] % 7 == 0) {
                err = c0kvs_del(p, skidx, &kt, seqno);
                ASSERT_EQ(0, err);
                ++db_del_cnt;
            }
        }
    }

    c0kvms_finalize(kvms, NULL);

    struct c0_ingest_work *c0skwork;
    struct bin_heap2 *     bh;
    struct bonsai_kv *     bkv;
    bool                   first_time = true;
    struct kvs_ktuple      last_kt = { 0, 0, 0 };
    u16                    last_skidx;

    c0skwork = c0kvms_ingest_work_prepare(kvms, NULL);

    bin_heap2_create(c0skwork->c0iw_iterc, bn_kv_cmp, &bh);
    bin_heap2_prepare(
        bh,
        c0skwork->c0iw_iterc,
        c0skwork->c0iw_sourcev + HSE_C0_KVSET_ITER_MAX - c0skwork->c0iw_iterc);

    while (bin_heap2_pop(bh, (void *)&bkv)) {
        struct kvs_ktuple  kt;
        struct kvs_vtuple  vt;
        struct bonsai_val *val;
        u32                key0;
        u16                skidx;

        val = bkv->bkv_values;
        while (val) {
            if (val->bv_valuep != HSE_CORE_TOMB_PFX)
                break;
            val = val->bv_next;
        }

        if (!val)
            continue;

        ++keys_out;

        kt.kt_data = bkv->bkv_key;
        kt.kt_len = key_imm_klen(&bkv->bkv_key_imm);
        skidx = key_immediate_index(&bkv->bkv_key_imm);

        kvs_vtuple_init(&vt, bonsai_val_vlen(val) ? val->bv_value : val->bv_valuep, val->bv_xlen);

        keyb_out += kt.kt_len;
        valb_out += kvs_vtuple_vlen(&vt);

        if (vt.vt_data == HSE_CORE_TOMB_REG)
            ++tombs_out;

        key0 = *(u32 *)kt.kt_data;
        ASSERT_EQ(skidx, key0 % 256);

        if (!first_time) {
            /* Validate that items are pulled off in order */
            int rc = (int)(last_skidx - skidx);

            if (rc == 0)
                rc = keycmp(last_kt.kt_data, last_kt.kt_len, kt.kt_data, kt.kt_len);
            ASSERT_LT(rc, 0);
        }
        first_time = false;

        last_kt.kt_data = kt.kt_data;
        last_kt.kt_len = kt.kt_len;
        last_skidx = skidx;
    }

    bin_heap2_destroy(bh);

    c0kvms_usage(kvms, &usage);
    assert(usage.u_keys == (keys_out - tombs_out));
    assert(usage.u_tombs == tombs_out);
    assert(usage.u_keyb == keyb_out);
    assert(usage.u_valb == valb_out);

    c0kvms_putref(kvms);
}

MTF_DEFINE_UTEST_PREPOST(c0_kvmultiset_test, ingest_mutation_test, no_fail_pre, no_fail_post)
{
    struct c0_kvmultiset *    kvms = 0;
    struct kvb_builder_iter **iterv;

    merr_t    err;
    const int WIDTH = 3;
    int       i;

    err = c0kvms_create(WIDTH, HSE_C0_CHEAP_SZ_DFLT, 0, 0, true, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0_kvmultiset *)NULL, kvms);

    err = c0kvmsm_iterv_alloc(kvms, 1, 0, 2, 10, &iterv);
    ASSERT_EQ(0, err);

    for (i = 0; i < 2; i++)
        kvb_builder_iter_destroy(iterv[i]);

    mapi_inject(mapi_idx_malloc, 0);
    err = c0kvmsm_iterv_alloc(kvms, 1, 0, 2, 10, &iterv);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 2, 0);
    err = c0kvmsm_iterv_alloc(kvms, 1, 0, 2, 10, &iterv);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 3, 0);
    err = c0kvmsm_iterv_alloc(kvms, 1, 0, 2, 10, &iterv);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    free(iterv);

    c0kvms_unset_mutating(kvms);
    ASSERT_EQ(false, c0kvms_is_mutating(kvms));
    c0kvms_putref(kvms);
}

MTF_END_UTEST_COLLECTION(c0_kvmultiset_test)

MTF_DEFINE_UTEST_PREPOST(c0_kvmultiset_test, ingest_work_create_fail, no_fail_pre, no_fail_post)
{
    struct c0_ingest_work ingest;
    merr_t                err;

    /* c0_ingest_work_init() calls bin_heap2_create(), so make
     * that allocation fail...
     */
    mapi_inject_once_ptr(mapi_idx_malloc, 1, 0);
    err = c0_ingest_work_init(&ingest);
    mapi_inject_unset(mapi_idx_malloc);
    ASSERT_NE(0, err);
}
