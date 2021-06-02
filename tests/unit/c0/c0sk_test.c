/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/logging.h>
#include <hse_util/seqno.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0snr_set.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "cn_mock.h"
#include <tools/key_generation.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/csched.h>
#include <hse_test_support/random_buffer.h>

#include <c0/c0sk_internal.h>
#include <c0/c0_cursor.h>

static struct kvdb_health    mock_health;
static struct cursor_summary summary;
struct csched *              csched;

#define MAX_TXNS (32)

atomic_t ctxn_locks[MAX_TXNS];
uintptr_t c0snr[MAX_TXNS];

struct kvdb_rparams kvdb_rp;
u8 c0sk_test_kdata[32];
uint c0sk_test_klen;

#define KOBJ2KEY(_kobjptr) key_obj_copy(c0sk_test_kdata, sizeof(c0sk_test_kdata), &c0sk_test_klen, (_kobjptr))

int
test_collection_setup(struct mtf_test_info *info)
{
    hse_log_set_verbose(true);
    kvdb_rp = kvdb_rparams_defaults();
    csched_create(csched_policy_noop, NULL, &kvdb_rp, "mp_name", &mock_health, &csched);
    return 0;
}

merr_t
_kvset_builder_create(
    struct kvset_builder **builder_out,
    struct cn *            cn,
    struct perfc_set *     pc,
    u64                    vgroup,
    uint                   flags)
{
    *builder_out = (struct kvset_builder *)1111;
    return 0;
}

struct mock_kvdb {
    struct c0sk *ikdb_c0sk;
};

void
_ikvdb_get_c0sk(struct ikvdb *kvdb, struct c0sk **out)
{
    struct mock_kvdb *mkvdb = (struct mock_kvdb *)kvdb;

    *out = mkvdb->ikdb_c0sk;
}

/* Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
static struct mapi_injection inject_list[] = {
    { mapi_idx_kvset_builder_set_agegroup, MAPI_RC_SCALAR, 0},
    { mapi_idx_kvset_builder_get_mblocks, MAPI_RC_SCALAR, 0},
    { mapi_idx_kvset_builder_add_key, MAPI_RC_SCALAR, 0},
    { mapi_idx_kvset_builder_add_val, MAPI_RC_SCALAR, 0},
    { mapi_idx_kvset_builder_add_nonval, MAPI_RC_SCALAR, 0},
    { mapi_idx_kvset_builder_add_vref, MAPI_RC_SCALAR, 0},
    { mapi_idx_kvset_builder_destroy, MAPI_RC_SCALAR, 0},
    { mapi_idx_kvset_mblocks_destroy, MAPI_RC_SCALAR, 0},
    { -1 }
};

void
mocks_set(struct mtf_test_info *info)
{
    MOCK_SET(ikvdb, _ikvdb_get_c0sk);

    MOCK_SET(kvset_builder, _kvset_builder_create);

    mapi_inject_list_set(inject_list);
}

void
mocks_unset()
{
    MOCK_UNSET(ikvdb, _ikvdb_get_c0sk);

    MOCK_UNSET(kvset_builder, _kvset_builder_create);

    mapi_inject_list_unset(inject_list);
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    /*
     * WARNING: If mocks_unset is called with data in c0 on a workqueue,
     * the code will segv since the real kvset_builder_add_val is called.
     *
     * mocks_unset();
     */
    return 0;
}

int
no_fail_pre(struct mtf_test_info *info)
{
    mocks_set(info);

    kvdb_health_clear(&mock_health, KVDB_HEALTH_FLAG_NOMEM);

    return 0;
}

int
no_fail_post(struct mtf_test_info *info)
{
    MOCK_UNSET(c0sk_internal, _c0sk_release_multiset);

    return 0;
}

int
no_fail_ctxn_pre(struct mtf_test_info *info)
{
    int i;

    mocks_set(info);

    for (i = 0; i < MAX_TXNS; i++) {
        atomic_set(&ctxn_locks[i], 0);
        c0snr[i] = 0;
    }

    kvdb_health_clear(&mock_health, KVDB_HEALTH_FLAG_NOMEM);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(c0sk_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST_PREPOST(c0sk_test, basic, no_fail_pre, no_fail_post)
{
    merr_t              err;
    struct kvdb_rparams kvdb_rp;
    struct mock_kvdb    mkvdb;
    atomic64_t          seqno;

    kvdb_rp = kvdb_rparams_defaults();

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    err = c0sk_close(NULL);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, ingest, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct kvs_ktuple     kt = { 0 };
    merr_t                err;
    struct c0sk_impl *    self;
    struct c0_kvmultiset *kvms;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    atomic64_t            seqno;
    u16                   skidx = 0;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "foo", 3);

    err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, ingest_debug, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct c0sk_impl *    self;
    struct c0_kvmultiset *kvms;
    struct kvs_ktuple     kt, pfx_kt;
    struct kvs_vtuple     vt;
    merr_t                err;
    int                   i;
    enum key_lookup_res   res;
    struct kvs_buf        vbuf;
    char                  keybuf[] = "abcdefghijklmnopqrstuvwxyz";
    int                   kw = sizeof(keybuf);
    u8                    val_buf[kw + 1];
    char *                key;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    const int             pfx_len = 20;
    atomic64_t            seqno;
    u16                   skidx;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 3;
    kvdb_rp.c0_debug = -1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, pfx_len);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    kvs_buf_init(&vbuf, val_buf, sizeof(val_buf));

    for (i = 0; i < 1000; ++i) {
        key = keybuf + (i % (sizeof(keybuf) - 1));

        kvs_ktuple_init(&kt, key, strlen(key));
        kvs_vtuple_init(&vt, key, strlen(key));

        if ((i % 5) == 0) {
            err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
            ASSERT_EQ(0, err);
        }

        err = c0sk_put(mkvdb.ikdb_c0sk, skidx, &kt, &vt, HSE_SQNREF_SINGLE);
        ASSERT_EQ(0, err);

        err = c0sk_get(mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
        ASSERT_EQ(0, err);
        ASSERT_EQ(res, FOUND_VAL);

        if (i % 5 == 0 && kt.kt_len >= pfx_len) {
            err = c0sk_get(
                mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
            ASSERT_EQ(0, err);

            if (res != FOUND_TMB) {
                ASSERT_EQ(res, FOUND_VAL);

                kvs_ktuple_init(&pfx_kt, key, pfx_len);
                err = c0sk_prefix_del(mkvdb.ikdb_c0sk, skidx, &pfx_kt, HSE_SQNREF_SINGLE);
                ASSERT_EQ(0, err);

                err = c0sk_get(
                    mkvdb.ikdb_c0sk,
                    skidx,
                    pfx_len,
                    &pfx_kt,
                    atomic64_read(&seqno),
                    0,
                    &res,
                    &vbuf);
                ASSERT_EQ(0, err);
                ASSERT_EQ(res, FOUND_PTMB);

                err = c0sk_get(
                    mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
                ASSERT_EQ(0, err);
                ASSERT_EQ(res, FOUND_PTMB);

                err = c0sk_put(mkvdb.ikdb_c0sk, skidx, &kt, &vt, HSE_SQNREF_SINGLE);
                ASSERT_EQ(0, err);
            }

            atomic64_inc(&seqno);
            err = c0sk_get(
                mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
            ASSERT_EQ(0, err);
            ASSERT_EQ(res, FOUND_VAL);

        } else if ((i % 15) == 0) {
            err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
            ASSERT_EQ(0, err);

            err = c0sk_get(
                mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
            ASSERT_EQ(0, err);
            ASSERT_EQ(res, FOUND_TMB);
        }
    }

    err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    err = c0sk_get(mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(res, FOUND_TMB);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, t_sync, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct c0_kvmultiset *kvms;
    struct kvs_ktuple     kt = { 0 };
    merr_t                err;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    struct c0sk_impl *    self;
    atomic64_t            seqno;
    u16                   skidx = 0;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "foo", 3);

    err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    err = c0sk_sync(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    /* [HSE_REVISIT] Replace with cndb_ingest.
     ASSERT_EQ(1, mapi_calls(mapi_idx_cn_ingestv));
    */

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, various, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0sk_impl *  self;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    u16                 skidx = 0;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    err = c0sk_install_c0kvms(self, NULL, NULL);
    ASSERT_EQ(0, err);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

#if 0
/* Disabled during c1 removing, consider reenabling after 2.0...
 */
MTF_DEFINE_UTEST_PREPOST(c0sk_test, throttling, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0sk_impl *  self;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    size_t              lwm;
    size_t              hwm;
    size_t              hwm_max;
    int                 c0sk_kvmultisets_cnt_saved;
    size_t              c0sk_kvmultisets_sz_saved;
    atomic64_t          seqno;
    int                 i;
    u16                 skidx = 0;
    /* static because kvdb_fini uses this to log dt */
    static struct throttle throttle;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    throttle_init(&throttle, &kvdb_rp);
    c0sk_throttle_sensor(mkvdb.ikdb_c0sk, throttle_sensor(&throttle, 0));

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    /* [HSE_REVISIT] This test fails if throttle_c0_hi_th isn't 4096, why?
     */
    kvdb_rp.throttle_c0_hi_th = 1024 * 4;

    /* lwm and hwm must match constants in c0sk_adjust_throttling() */
    hwm = kvdb_rp.throttle_c0_hi_th * 1024 * 1024;
    lwm = 2ul << 30;
    hwm_max = hwm + (10ul << 30);

    c0sk_kvmultisets_cnt_saved = self->c0sk_kvmultisets_cnt;
    c0sk_kvmultisets_sz_saved = self->c0sk_kvmultisets_sz;

    self->c0sk_kvmultisets_cnt = 0;
    self->c0sk_kvmultisets_sz = 0;

/* verify result is in range expect-1 to expect+1 */
#define check(msg, ilo, ihi, pct, expect)                \
    do {                                                 \
        int    result;                                   \
        size_t input = ilo + pct * (ihi - ilo) / 100;    \
                                                         \
        self->c0sk_kvmultisets_sz = input;               \
        result = c0sk_adjust_throttling(self);           \
        hse_log(                                         \
            HSE_NOTICE "%s: input: %zu <= %12zu <= %zu," \
                       " expect: %d .. %d, actual: %d",  \
            msg,                                         \
            (size_t)ilo,                                 \
            input,                                       \
            (size_t)ihi,                                 \
            expect - 1,                                  \
            expect + 1,                                  \
            result);                                     \
        ASSERT_GE(result, expect - 1);                   \
        ASSERT_LE(result, expect + 1);                   \
    } while (0)

    for (i = 0; i < 100; i += 10)
        check("between 0 and lwm", 0, lwm, i, 0);

    for (i = 0; i < 100; i += 10)
        check("between lwm and hwm", lwm, hwm, i, i * THROTTLE_SENSOR_SCALE / 100 - 1);

    for (i = 0; i < 100; i += 10)
        check(
            "between hwm and max",
            hwm,
            hwm_max,
            i,
            (THROTTLE_SENSOR_SCALE + i * THROTTLE_SENSOR_SCALE / 100 - 1));

    self->c0sk_kvmultisets_cnt = c0sk_kvmultisets_cnt_saved;
    self->c0sk_kvmultisets_sz = c0sk_kvmultisets_sz_saved;

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}
#endif

MTF_DEFINE_UTEST_PREPOST(c0sk_test, ingest_fail, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct c0_kvmultiset *kvms;
    struct kvs_ktuple     kt = { 0 };
    merr_t                err;
    struct c0sk_impl *    self;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    atomic64_t            seqno;
    u16                   skidx = 0;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_kvset_builder_create, ENOMEM);

    kt.kt_len = 3;
    kt.kt_data = "foo";

    err = c0sk_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    ASSERT_EQ(1, mapi_calls(mapi_idx_kvset_builder_create));
    mapi_inject_unset(mapi_idx_kvset_builder_create);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, open_test, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct c0_kvmultiset *kvms[8];
    int                   i;
    const int             num_kvs = 8;
    struct c0sk_impl *    self;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    merr_t                err;
    atomic64_t            seqno;
    u16                   skidx = 0;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);

        c0kvms_putref(kvms[i]);
    }

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    mkvdb.ikdb_c0sk = NULL;

    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    ASSERT_EQ(NULL, mkvdb.ikdb_c0sk);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, serial_put1, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    const int             num_kvs = 8;
    struct c0_kvmultiset *kvms[num_kvs];
    merr_t                err;
    struct c0sk_impl *    self;

    const int             kw = 6;
    const int             num_keys = 30000;
    struct key_generator *kg;
    u8                    key_buf[kw + 1];
    int                   key_len = kw;
    u8                    val_buf[100];
    int                   val_len = 100;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    int                   i, j;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    atomic64_t            seqno;
    u16                   skidx[num_kvs];

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    memset(key_buf, 0, sizeof(key_buf));
    memset(val_buf, 0, sizeof(val_buf));

    kvs_ktuple_init(&kt, key_buf, key_len);
    kvs_vtuple_init(&vt, val_buf, val_len);

    srand(456);
    for (i = 0; i < num_keys; ++i) {
        u32 key_num = generate_random_u32(0, 4000000000);

        get_key(kg, key_buf, key_num);

        memcpy(val_buf, key_buf, kw);

        for (j = 0; j < num_kvs; j++) {
            err = c0sk_put(mkvdb.ikdb_c0sk, skidx[j], &kt, &vt, HSE_SQNREF_SINGLE);
            ASSERT_EQ(0, err);
        }
    }

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);
    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, serial_put2, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    const int             num_kvs = 8;
    struct c0_kvmultiset *kvms[num_kvs];
    merr_t                err;

    const int             kw = 6;
    const int             num_keys = 30000;
    struct key_generator *kg;
    u8                    key_buf[kw + 1];
    int                   key_len = kw;
    u8                    val_buf[100];
    int                   val_len = 100;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    int                   i, j;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    struct c0sk_impl *    self;
    atomic64_t            seqno;
    u16                   skidx[num_kvs];

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    memset(key_buf, 0, sizeof(key_buf));
    memset(val_buf, 0, sizeof(val_buf));

    kvs_ktuple_init(&kt, key_buf, key_len);
    kvs_vtuple_init(&vt, val_buf, val_len);

    srand(456);
    for (i = 0; i < num_keys; ++i) {
        u32 key_num = generate_random_u32(0, 4000000000);

        get_key(kg, key_buf, key_num);

        memcpy(val_buf, key_buf, kw);

        for (j = 0; j < num_kvs; j++) {
            err = c0sk_put(mkvdb.ikdb_c0sk, skidx[j], &kt, &vt, HSE_SQNREF_SINGLE);
            ASSERT_EQ(0, err);
        }
    }

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

static __always_inline bool
ctxn_trylock(int num)
{
    assert(num < MAX_TXNS);
    return atomic_cmpxchg(&ctxn_locks[num], 0, 1) == 0;
}

static __always_inline void
ctxn_unlock(int num)
{
    int old HSE_MAYBE_UNUSED;

    assert(num < MAX_TXNS);

    old = atomic_cmpxchg(&ctxn_locks[num], 1, 0);
    assert(old == 1);
}

static void
c0sk_test_finish_txn(int index, u64 commit_sn)
{
    uintptr_t *priv;
    uintptr_t ref;
    u64 osn HSE_MAYBE_UNUSED;

    assert(index >= 0 && index < MAX_TXNS);

    if (ctxn_trylock(index)) {
        ref = c0snr[index];
        priv = (uintptr_t *)ref;
        if (priv) {
            assert(seqnoref_to_seqno(ref, &osn) == HSE_SQNREF_STATE_UNDEFINED);
            if (commit_sn == 0)
                *priv = HSE_SQNREF_ABORTED;
            else
                *priv = HSE_ORDNL_TO_SQNREF(commit_sn);

            c0snr_clear_txn(priv);
            c0snr[index] = 0;
        }
        ctxn_unlock(index);
    }
}

static void
c0snr_set_abort_test_handler(struct kvdb_ctxn *ctxn)
{
    long index = (long)ctxn;

    if (index) {
        index--;
        assert(index < MAX_TXNS);

        c0sk_test_finish_txn((int)index, 0);
    }
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, ctxn_put, no_fail_ctxn_pre, no_fail_post)
{
    struct kvdb_rparams     kvdb_rp;
    struct kvs_rparams      kvs_rp;
    const int               num_kvs = 8;
    struct c0snr_set       *css;
    struct c0_kvmultiset   *kvms[num_kvs];
    merr_t                  err;

    const int               num_txns = 32;
    const int               kw = 6;
    const int               num_keys = 30000;
    struct key_generator   *kg;
    u8                      key_buf[kw + 1];
    int                     key_len = kw;
    u8                      val_buf[100];
    int                     val_len = 100;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    int                     i, j;
    struct mock_kvdb        mkvdb;
    struct cn              *mock_cn;
    struct c0sk_impl       *self;
    atomic64_t              seqno;
    u16                     skidx = 0;
    uintptr_t               priv, iseqnoref;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    err = c0snr_set_create(c0snr_set_abort_test_handler, &css);
    ASSERT_TRUE(err == 0);

    for (i = 0; i < num_txns; ++i) {
        uintptr_t *tmp;

        tmp = c0snr_set_get_c0snr(css, (struct kvdb_ctxn *)(int64_t)(i + 1));
        ASSERT_NE(0, tmp);

        *tmp = HSE_SQNREF_UNDEFINED;

        assert(c0snr[i] == 0);
        c0snr[i] = (uintptr_t)tmp;
    }

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    memset(key_buf, 0, sizeof(key_buf));
    memset(val_buf, 0, sizeof(val_buf));

    kvs_ktuple_init(&kt, key_buf, key_len);
    kvs_vtuple_init(&vt, val_buf, val_len);

    srand(456);
    for (i = 0; i < num_keys; ++i) {
        u32 key_num = generate_random_u32(0, 4000000000);

        get_key(kg, key_buf, key_num);

        memcpy(val_buf, key_buf, kw);

        for (j = 0; j < num_kvs; j++) {
            int idx = i % num_txns;
            u64 oseqno HSE_MAYBE_UNUSED;

retry:
            if (ctxn_trylock(idx)) {
                priv = c0snr[idx];
                if (priv) {
                    assert(seqnoref_to_seqno(priv, &oseqno) == HSE_SQNREF_STATE_UNDEFINED);
                } else {
                    ctxn_unlock(idx);
                    j = num_kvs - 1;
                    continue;
                }
            } else {
                goto retry;
            }

            iseqnoref = HSE_REF_TO_SQNREF(priv);

            err = c0sk_put(mkvdb.ikdb_c0sk, skidx, &kt, &vt, iseqnoref);
            ASSERT_EQ(0, err);

            ctxn_unlock(idx);
        }
    }

    for (i = 0; i < num_txns; ++i)
        c0sk_test_finish_txn(i, 0);

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    c0snr_set_destroy(css);

    destroy_mock_cn(mock_cn);
}

struct parallel_thrd_arg {
    struct c0sk *         ikdb_c0sk;
    struct key_generator *kg;
    uintptr_t             c0snr;
    int                   kw;
    int                   cnt;
    int                   pfx_len;
    int                   index;
    u16                   skidx;
};

void *
parallel_put_helper(void *arg)
{
    struct parallel_thrd_arg *p = (struct parallel_thrd_arg *)arg;

    struct c0sk *         ikdb = p->ikdb_c0sk;
    struct key_generator *kg = p->kg;
    const int             kw = p->kw;
    const int             cnt = p->cnt;
    const u16             skidx = p->skidx;
    int                   idx = p->index;
    uintptr_t             priv;
    merr_t                err;
    u8                    key_buf[kw + 1];
    int                   key_len = kw;
    u8                    val_buf[100];
    int                   val_len = 100;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    int                   i;

    memset(key_buf, 0, sizeof(key_buf));
    memset(val_buf, 0, sizeof(val_buf));

    priv = (idx == -1) ? HSE_SQNREF_SINGLE : 0;

    for (i = 0; i < cnt; ++i) {
        u32 key_num = generate_random_u32(0, 4000000000);

        get_key(kg, key_buf, key_num);

        memcpy(val_buf, key_buf, kw);

        kvs_ktuple_init(&kt, key_buf, key_len);
        kvs_vtuple_init(&vt, val_buf, val_len);

        if (idx != -1) {
retry:
            if (ctxn_trylock(idx)) {
                u64 oseqno HSE_MAYBE_UNUSED;

                priv = c0snr[idx];
                if (priv) {
                    assert(seqnoref_to_seqno(priv, &oseqno) == HSE_SQNREF_STATE_UNDEFINED);
                } else {
                    ctxn_unlock(idx);
                    break;
                }
            } else {
                goto retry;
            }
        }
        if (cnt % 59)
            err = c0sk_del(ikdb, skidx, &kt, priv);
        else if (cnt % 199)
            err = c0sk_prefix_del(ikdb, skidx, &kt, priv);
        else
            err = c0sk_put(ikdb, skidx, &kt, &vt, priv);

        if (idx != -1)
            ctxn_unlock(idx);

        if (err)
            hse_elog(HSE_ERR "c0sk_put() failed: @@e", err);
        VERIFY_EQ_RET(0, err, 0);
    }

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, parallel_put1, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    const int             num_kvs = 4;
    struct c0_kvmultiset *kvms[num_kvs];
    merr_t                err;

    const int                kw = 6;
    const int                num_threads = 4;
    pthread_t                thread_idv[num_threads * num_kvs];
    int                      rc;
    struct parallel_thrd_arg argstruct;
    struct key_generator *   kg;
    int                      i, j;
    struct mock_kvdb         mkvdb;
    struct cn *              mock_cn;
    struct c0sk_impl *       self;
    atomic64_t               seqno;
    u16                      skidx[num_kvs];

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    srand(456);

    for (i = 0; i < num_kvs; i++) {
        argstruct.ikdb_c0sk = mkvdb.ikdb_c0sk;
        argstruct.kg = kg;
        argstruct.kw = kw;
        argstruct.cnt = 25;
        argstruct.skidx = skidx[i];
        argstruct.index = -1;

        for (j = 0; j < num_threads; ++j) {
            rc = pthread_create(
                thread_idv + i * num_threads + j, 0, parallel_put_helper, &argstruct);
            ASSERT_EQ(0, rc);
        }
    }

    for (i = 0; i < num_threads * num_kvs; ++i) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    synchronize_rcu();

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, parallel_put2, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    const int             num_kvs = 4;
    struct c0_kvmultiset *kvms[num_kvs];
    merr_t                err;

    const int                kw = 6;
    const int                num_threads = 40;
    pthread_t                thread_idv[num_threads * num_kvs];
    int                      rc;
    struct parallel_thrd_arg argstruct;
    struct key_generator *   kg;
    int                      i, j;
    struct mock_kvdb         mkvdb;
    struct cn *              mock_cn;
    struct c0sk_impl *       self;
    atomic64_t               seqno;
    u16                      skidx[num_kvs];

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 2;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    srand(456);

    for (i = 0; i < num_kvs; i++) {
        argstruct.ikdb_c0sk = mkvdb.ikdb_c0sk;
        argstruct.kg = kg;
        argstruct.kw = kw;
        argstruct.cnt = 2500;
        argstruct.skidx = skidx[i];
        argstruct.index = -1;

        for (j = 0; j < num_threads; ++j) {
            rc = pthread_create(
                thread_idv + i * num_threads + j, 0, parallel_put_helper, &argstruct);
            ASSERT_EQ(0, rc);
        }
    }

    for (i = 0; i < num_threads * num_kvs; ++i) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    synchronize_rcu();

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, parallel_put3, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    const int             num_kvs = 4;
    struct c0_kvmultiset *kvms[num_kvs];
    merr_t                err;

    const int                kw = 11;
    const int                num_threads = 29;
    pthread_t                thread_idv[num_threads * num_kvs];
    int                      rc;
    struct parallel_thrd_arg argstruct;
    struct key_generator *   kg;
    int                      i, j;
    struct mock_kvdb         mkvdb;
    struct cn *              mock_cn;
    struct c0sk_impl *       self;
    atomic64_t               seqno;
    u16                      skidx[num_kvs];

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = num_threads;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    srand(456);

    for (i = 0; i < num_kvs; i++) {
        argstruct.ikdb_c0sk = mkvdb.ikdb_c0sk;
        argstruct.kg = kg;
        argstruct.kw = kw;
        argstruct.cnt = 10000;
        argstruct.skidx = skidx[i];
        argstruct.index = -1;

        for (j = 0; j < num_threads; ++j) {
            rc = pthread_create(
                thread_idv + i * num_threads + j, 0, parallel_put_helper, &argstruct);
            ASSERT_EQ(0, rc);
        }
    }

    for (i = 0; i < num_threads * num_kvs; ++i) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    synchronize_rcu();

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, parallel_ctxn_put, no_fail_ctxn_pre, no_fail_post)
{
    struct kvdb_rparams     kvdb_rp;
    struct kvs_rparams      kvs_rp;
    const int               num_kvs = 4;
    struct c0snr_set       *css;
    struct c0_kvmultiset   *kvms[num_kvs];
    merr_t                  err;

    const int                kw = 11;
    const int                num_threads = 29;
    pthread_t                thread_idv[num_threads * num_kvs];
    int                      rc;
    struct parallel_thrd_arg argstruct;
    struct key_generator *   kg;
    int                      i, j;
    struct mock_kvdb         mkvdb;
    struct cn *              mock_cn;
    struct c0sk_impl *       self;
    atomic64_t               seqno;
    u16                      skidx[num_kvs];

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = num_threads;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0snr_set_create(c0snr_set_abort_test_handler, &css);
    ASSERT_TRUE(err == 0);

    for (i = 0; i < num_threads; ++i) {
        uintptr_t *tmp;

        tmp = c0snr_set_get_c0snr(css, (struct kvdb_ctxn *)(int64_t)(i + 1));
        ASSERT_NE(0, tmp);

        *tmp = HSE_SQNREF_UNDEFINED;

        assert(i < MAX_TXNS && c0snr[i] == 0);
        c0snr[i] = (uintptr_t)tmp;
    }

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    srand(456);

    for (i = 0; i < num_kvs; i++) {
        argstruct.ikdb_c0sk = mkvdb.ikdb_c0sk;
        argstruct.kg = kg;
        argstruct.kw = kw;
        argstruct.skidx = skidx[i];
        argstruct.cnt = 10000;

        for (j = 0; j < num_threads; ++j) {
            argstruct.index = j;

            rc = pthread_create(
                thread_idv + i * num_threads + j, 0, parallel_put_helper, &argstruct);
            ASSERT_EQ(0, rc);
        }
    }

    for (i = 0; i < num_threads * num_kvs; ++i) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; ++i) {
        if (i % 2 == 0) {
            c0sk_test_finish_txn(i, 0);
        }
    }

    for (i = 0; i < num_threads; ++i) {
        if (i % 2) {
            c0sk_test_finish_txn(i, 6 + i);
        }
    }

    synchronize_rcu();

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    c0snr_set_destroy(css);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, parallel_put_cheap, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    const int             num_kvs = 4;
    struct c0_kvmultiset *kvms[num_kvs];
    merr_t                err;

    const int                kw = 11;
    const int                num_threads = 8;
    pthread_t                thread_idv[num_threads * num_kvs];
    int                      rc;
    struct parallel_thrd_arg argstruct;
    struct key_generator *   kg;
    int                      i, j;
    struct mock_kvdb         mkvdb;
    struct cn *              mock_cn;
    struct c0sk_impl *       self;
    atomic64_t               seqno;
    u16                      skidx[num_kvs];

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 8;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2176782000, kw);
    ASSERT_NE(kg, (void *)0);

    srand(456);

    for (i = 0; i < num_kvs; i++) {
        argstruct.ikdb_c0sk = mkvdb.ikdb_c0sk;
        argstruct.kg = kg;
        argstruct.kw = kw;
        argstruct.skidx = skidx[i];
        argstruct.cnt = 2500;
        argstruct.index = -1;

        for (j = 0; j < num_threads; ++j) {
            rc = pthread_create(
                thread_idv + i * num_threads + j, 0, parallel_put_helper, &argstruct);
            ASSERT_EQ(0, rc);
        }
    }

    for (i = 0; i < num_threads * num_kvs; ++i) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    synchronize_rcu();

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

void *
parallel_get_helper(void *arg)
{
    struct parallel_thrd_arg *p = (struct parallel_thrd_arg *)arg;

    struct c0sk *         ikvdb = p->ikdb_c0sk;
    struct key_generator *kg = p->kg;
    const int             kw = p->kw;
    const int             cnt = p->cnt;
    const u16             skidx = p->skidx;
    const u32             pfx_len = p->pfx_len;
    enum key_lookup_res   res;
    u8                    val_buf[kw + 1];
    u8                    key_buf[kw + 1];
    int                   key_len = kw;
    struct kvs_ktuple     kt;
    struct kvs_buf        vbuf;
    int                   i;
    u64                   seq;

    seq = 0;

    memset(key_buf, 0, sizeof(key_buf));
    memset(val_buf, 0, sizeof(val_buf));

    kvs_buf_init(&vbuf, val_buf, sizeof(val_buf));

    for (i = 0; i < cnt; ++i) {
        u32  key_num = generate_random_u32(0, 4000000000);
        bool found = false;

        get_key(kg, key_buf, key_num);

        kvs_ktuple_init(&kt, key_buf, key_len);

        c0sk_get(ikvdb, skidx, pfx_len, &kt, seq, 0, &res, &vbuf);
        if (found) {
            int rc = memcmp(key_buf, val_buf, key_len);

            VERIFY_EQ_RET(0, rc, 0);
        }
    }

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, parallel_get_put, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    const int             num_kvs = 4;
    struct c0_kvmultiset *kvms[num_kvs];
    merr_t                err;

    const int                kw = 11;
    const int                num_put_threads = 7;
    const int                num_get_threads = 9;
    pthread_t                pthread_idv[num_put_threads * num_kvs];
    pthread_t                gthread_idv[num_get_threads * num_kvs];
    int                      rc;
    struct parallel_thrd_arg argstruct;
    struct key_generator *   kg;
    int                      i, j;
    struct mock_kvdb         mkvdb;
    struct cn *              mock_cn;
    struct c0sk_impl *       self;
    atomic64_t               seqno;
    u16                      skidx[num_kvs];
    const u32                pfx_len = 0;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 16;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, pfx_len);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    for (i = 0; i < num_kvs; i++) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx[i]);
        ASSERT_EQ(0, err);

        err = c0kvms_create(1, 0, &seqno, &kvms[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvms[i]);

        err = c0sk_install_c0kvms(self, NULL, kvms[i]);
        ASSERT_EQ(0, err);
    }

    kg = create_key_generator(2000000, kw);
    ASSERT_NE(kg, (void *)0);

    srand(456);

    for (i = 0; i < num_kvs; i++) {
        argstruct.ikdb_c0sk = mkvdb.ikdb_c0sk;
        argstruct.kg = kg;
        argstruct.kw = kw;
        argstruct.cnt = 25000;
        argstruct.skidx = skidx[i];
        argstruct.pfx_len = pfx_len;

        for (j = 0; j < num_get_threads; ++j) {
            rc = pthread_create(
                gthread_idv + i * num_get_threads + j, 0, parallel_get_helper, &argstruct);
            ASSERT_EQ(0, rc);
        }

        for (j = 0; j < num_put_threads; ++j) {
            argstruct.index = -1;

            rc = pthread_create(
                pthread_idv + i * num_put_threads + j, 0, parallel_put_helper, &argstruct);
            ASSERT_EQ(0, rc);
        }
    }

    for (i = 0; i < num_get_threads * num_kvs; ++i) {
        rc = pthread_join(gthread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_put_threads * num_kvs; ++i) {
        rc = pthread_join(pthread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    synchronize_rcu();

    for (i = 0; i < num_kvs; i++) {
        c0kvms_putref(kvms[i]);
    }

    destroy_key_generator(kg);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, c0sk_get_test, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct c0_kvmultiset *kvms = 0;
    merr_t                err;
    struct kvs_ktuple     kt = { 0 };
    struct kvs_vtuple     vt = { 0 };
    char                  buf[100];
    struct kvs_buf        vbuf;
    enum key_lookup_res   res;
    struct mock_kvdb      mkvdb;
    struct cn *           mock_cn;
    struct c0sk_impl *    self;
    atomic64_t            seqno;
    u16                   skidx = 0;
    const u32             pfx_len = 0;
    char *                str;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 16;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, pfx_len);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    str = "alpha";
    kvs_ktuple_init(&kt, str, strlen(str));
    str = "this_is_a_large_val";
    kvs_vtuple_init(&vt, str, strlen(str));

    err = c0sk_put(mkvdb.ikdb_c0sk, skidx, &kt, &vt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    /* small buffer */
    kvs_buf_init(&vbuf, buf, 4); /* insufficiently sized buffer */
    err = c0sk_get(mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(res, FOUND_VAL);
    ASSERT_EQ(vbuf.b_len, kvs_vtuple_vlen(&vt));
    ASSERT_EQ(0, strncmp(buf, "this", vbuf.b_buf_sz));

    kvs_buf_init(&vbuf, buf, vbuf.b_len);
    err = c0sk_get(mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(res, FOUND_VAL);
    ASSERT_EQ(vbuf.b_len, kvs_vtuple_vlen(&vt));
    ASSERT_EQ(0, strncmp(buf, vt.vt_data, vbuf.b_len));

    /* nonexistent key */
    str = "shouldnt_exist";
    kvs_ktuple_init(&kt, str, strlen(str));
    kvs_buf_init(&vbuf, buf, sizeof(buf));
    err = c0sk_get(mkvdb.ikdb_c0sk, skidx, pfx_len, &kt, atomic64_read(&seqno), 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(res, NOT_FOUND);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

static struct c0_kvmultiset *deferred_release[HSE_C0_KVSET_CURSOR_MAX + 2];

static void
_c0sk_release_multiset(struct c0sk_impl *self, struct c0_kvmultiset *c0kvms)
{
    struct c0_kvmultiset **dr = deferred_release;

    while (*dr)
        ++dr;

    assert(dr - deferred_release < NELEM(deferred_release));
    *dr++ = c0kvms;
    *dr = 0;
}

static void
release_deferred(struct c0sk *self)
{
    struct c0_kvmultiset **dr = deferred_release;

    while (*dr) {
        c0sk_release_multiset(c0sk_h2r(self), *dr);
        *dr++ = 0;
    }
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, c0_cursor_robust, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct mock_kvdb      mkvdb;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    struct c0sk *         c0sk;
    struct c0_kvmultiset *kvms;
    struct cn *           cn;
    struct c0sk_impl *    self;
    struct c0_cursor *    cur[5];
    u16                   skidx;
    char                  kbuf[10], vbuf[10], seek[10];
    int                   seeklen;
    merr_t                err;
    bool                  eof;
    atomic64_t            seqno;

#define nkeys (100 * 1000)

    static int keys[nkeys];
    int        i, j;

    /*
     * create 100,000 int keys in order
     * knuth shuffle them
     * loop:
     * create a cursor
     * put 20,000 keys, flush
     * goto loop
     * verify: first cursor: eof, 1-20k, 1-40k, 1-60k, 1-80k,
     * update first
     * verify 1-100k, 1-20k
     * seek 0, verify 1-100k
     * seek 200,000, verify eof
     * for 100 times:
     * seek random < 100,000, verify get key sought
     *
     * This tests:
     *  - multiple simultaneous cursors with different views
     *  - merging multiple kvms
     *  - cbkv linking list
     *  - update improves view
     *  - seek various locations, before, mid, eof
     */

    /* knuth shuffle, inside-out */
    for (i = 0; i < nkeys; ++i) {
        j = random() % (i + 1);
        if (j != i)
            keys[i] = keys[j];
        keys[j] = i;
    }

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 16;
    kvdb_rp.c0_diag_mode = 1; /* prevent ingest worker from working */

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    _ikvdb_get_c0sk((struct ikvdb *)&mkvdb, &c0sk);
    ASSERT_EQ(c0sk, mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    MOCK_SET(c0sk_internal, _c0sk_release_multiset);

    mapi_inject_unset(mapi_idx_cn_ingestv);
    mapi_inject(mapi_idx_cn_ingestv, 0);
    mapi_calls_clear(mapi_idx_c0_put);

    kt.kt_data = kbuf;
    vt.vt_data = vbuf;
    j = 0;
    for (i = 0; i < 5; ++i) {
        int n = (i + 1) * 20000;

        err = c0sk_cursor_create(c0sk, atomic64_read(&seqno), skidx, 0, 0, 0, 0, &summary, &cur[i]);
        ASSERT_EQ(0, err);
        atomic64_inc(&seqno);

        /* this cursor will NOT see these keys */

        for (; j < n; ++j) {
            int vlen;

            kvs_ktuple_init(&kt, kbuf, sprintf(kbuf, "%05d", keys[j]) + 1);

            vlen = sprintf(vbuf, "%lu", (ulong)atomic64_read(&seqno));
            kvs_vtuple_init(&vt, vbuf, vlen);

            err = c0sk_put(mkvdb.ikdb_c0sk, skidx, &kt, &vt, HSE_SQNREF_SINGLE);
            ASSERT_EQ(0, err);
            if (random() % 100 < 5)
                atomic64_inc(&seqno);
            if (j > 0 && j % 17977 == 0)
                c0sk_flush(c0sk);
        }
    }

    /*
     * we have 5 cursors with 5 different views,
     * with 5 kvms, all views span kvms
     *
     * the 5 cursors should each have 20,000 keys in order,
     * but not sequential -- only when the cursor is updated
     * will it see the unbroken sequence -- strings are used
     * to improve debugging
     */

    for (i = 0; i < 5; ++i) {
        int cnt = 0;
        int want = i * 20000;
        int last = -1;

        for (eof = false; !eof;) {
            struct kvs_cursor_element elem;

            err = c0sk_cursor_read(cur[i], &elem, &eof);
            ASSERT_EQ(0, err);

            if (cnt < want)
                ASSERT_FALSE(eof);
            else
                ASSERT_TRUE(eof);

            if (!eof) {
                int n;

                n = atoi(KOBJ2KEY(&elem.kce_kobj));
                ASSERT_LT(last, n);
                last = n;
                ++cnt;
            }
        }
        ASSERT_EQ(cnt, want);
    }

    /* now update the first cursor, which should see all keys in order */
    err = c0sk_cursor_update(cur[0], atomic64_read(&seqno), 0);
    ASSERT_EQ(0, err);

    seek[0] = 0;
    err = c0sk_cursor_seek(cur[0], seek, 0, 0);
    ASSERT_EQ(0, err);

    for (i = 0; i < nkeys; ++i) {
        struct kvs_cursor_element elem;

        err = c0sk_cursor_read(cur[0], &elem, &eof);
        ASSERT_EQ(0, err);
        ASSERT_FALSE(eof);

        ASSERT_EQ(i, atoi(KOBJ2KEY(&elem.kce_kobj)));
    }

    struct kvs_cursor_element elem;

    err = c0sk_cursor_read(cur[0], &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    /* seek before first key */
    seek[0] = 0;
    err = c0sk_cursor_seek(cur[0], seek, 0, 0);
    ASSERT_EQ(0, err);

    err = c0sk_cursor_read(cur[0], &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_FALSE(eof);
    ASSERT_EQ(0, atoi(KOBJ2KEY(&elem.kce_kobj)));

    /* seek after last key */
    seeklen = sprintf(seek, "%05d", 999999);
    err = c0sk_cursor_seek(cur[0], seek, seeklen + 1, 0);
    ASSERT_EQ(0, err);

    /* now test seek on all cursors */
    for (i = 0; i < 100; ++i) {
        char seek[10];
        int  len, k;

        /* always a valid key, never eof */
        j = random() % (nkeys - 1);
        len = sprintf(seek, "%05d", j);
        for (k = 0; k < 5; ++k) {
            const char kdata[32];
            uint klen;
            int x;

            err = c0sk_cursor_seek(cur[k], seek, len + 1, 0);
            ASSERT_EQ(0, err);

            err = c0sk_cursor_read(cur[k], &elem, &eof);
            ASSERT_EQ(0, err);

            key_obj_copy((void *)kdata, sizeof(kdata), &klen, &elem.kce_kobj);
            x = atoi(kdata);
            ASSERT_GE(x, j);
        }
    }

    MOCK_UNSET(c0sk_internal, _c0sk_release_multiset);
    release_deferred(c0sk);

    for (i = 0; i < NELEM(cur); ++i)
        c0sk_cursor_destroy(cur[i]);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, c0_cursor_eagain, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct mock_kvdb      mkvdb;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    struct c0sk *         c0sk;
    struct c0_kvmultiset *kvms;
    struct cn *           cn;
    struct c0_cursor *    cur;
    struct c0sk_impl *    self;
    u16                   skidx;
    char                  kbuf[10], vbuf[10];
    merr_t                err;
    int                   i;
    atomic64_t            seqno;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 16;
    kvdb_rp.c0_diag_mode = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    _ikvdb_get_c0sk((struct ikvdb *)&mkvdb, &c0sk);
    ASSERT_EQ(c0sk, mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    MOCK_SET(c0sk_internal, _c0sk_release_multiset);

    mapi_inject_unset(mapi_idx_cn_ingestv);
    mapi_inject(mapi_idx_cn_ingestv, 0);
    mapi_calls_clear(mapi_idx_c0_put);

    kt.kt_data = kbuf;
    vt.vt_data = vbuf;

    err = c0sk_cursor_create(c0sk, atomic64_read(&seqno), skidx, 0, 0, 0, 0, &summary, &cur);
    ASSERT_EQ(0, err);

    /* at least one too many */
    for (i = 0; i <= HSE_C0_KVSET_CURSOR_MAX; ++i) {
        int vlen;

        kvs_ktuple_init(&kt, kbuf, sprintf(kbuf, "%05d", i));

        vlen = sprintf(vbuf, "%lu", (ulong)atomic64_read(&seqno));
        kvs_vtuple_init(&vt, vbuf, vlen);

        err = c0sk_put(c0sk, skidx, &kt, &vt, HSE_SQNREF_SINGLE);
        ASSERT_EQ(0, err);

        c0sk_flush(c0sk);
        err = c0sk_cursor_update(cur, atomic64_fetch_add(1, &seqno), 0);
        if (err)
            ASSERT_EQ(EAGAIN, merr_errno(err));
        else
            ASSERT_EQ(0, err);
    }

    MOCK_UNSET(c0sk_internal, _c0sk_release_multiset);
    release_deferred(c0sk);

    c0sk_cursor_destroy(cur);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, c0_rcursor_robust, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct mock_kvdb      mkvdb;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    struct c0sk *         c0sk;
    struct c0_kvmultiset *kvms;
    struct cn *           cn;
    struct c0sk_impl *    self;
    struct c0_cursor *    cur[5];
    u16                   skidx;
    char                  kbuf[10], vbuf[10], seek[10];
    int                   seeklen;
    merr_t                err;
    bool                  eof;
    atomic64_t            seqno;
    u8                    pfx[HSE_KVS_KLEN_MAX];

    struct kvs_cursor_element elem;

    memset(pfx, 0xFF, HSE_KVS_KLEN_MAX);

#define nkeys (100 * 1000)

    static int keys[nkeys];
    int        i, j;

    /*
     * create 100,000 int keys in order
     * knuth shuffle them
     * loop:
     * create a cursor
     * put 20,000 keys, flush
     * goto loop
     * verify: first cursor: eof, 1-20k, 1-40k, 1-60k, 1-80k,
     * update first
     * verify 1-100k, 1-20k
     * seek 0, verify 1-100k
     * seek 200,000, verify eof
     * for 100 times:
     * seek random < 100,000, verify get key sought
     *
     * This tests:
     *  - multiple simultaneous cursors with different views
     *  - merging multiple kvms
     *  - cbkv linking list
     *  - update improves view
     *  - seek various locations, before, mid, eof
     */

    /* knuth shuffle, inside-out */
    for (i = 0; i < nkeys; ++i) {
        j = random() % (i + 1);
        if (j != i)
            keys[i] = keys[j];
        keys[j] = i;
    }

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 16;
    kvdb_rp.c0_diag_mode = 1; /* prevent ingest worker from working */

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    _ikvdb_get_c0sk((struct ikvdb *)&mkvdb, &c0sk);
    ASSERT_EQ(c0sk, mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    MOCK_SET(c0sk_internal, _c0sk_release_multiset);

    mapi_inject_unset(mapi_idx_cn_ingestv);
    mapi_inject(mapi_idx_cn_ingestv, 0);
    mapi_calls_clear(mapi_idx_c0_put);

    kt.kt_data = kbuf;
    vt.vt_data = vbuf;
    j = 0;
    for (i = 0; i < 5; ++i) {
        int n = (i + 1) * 20000;

        err = c0sk_cursor_create(
            c0sk, atomic64_read(&seqno), skidx, true, 0, pfx, 0, &summary, &cur[i]);
        ASSERT_EQ(0, err);
        atomic64_inc(&seqno);

        /* this cursor will NOT see these keys */

        for (; j < n; ++j) {
            int vlen;

            kvs_ktuple_init(&kt, kbuf, sprintf(kbuf, "%05d", keys[j]) + 1);

            vlen = sprintf(vbuf, "%lu", (ulong)atomic64_read(&seqno));
            kvs_vtuple_init(&vt, vbuf, vlen);

            err = c0sk_put(mkvdb.ikdb_c0sk, skidx, &kt, &vt, HSE_SQNREF_SINGLE);
            ASSERT_EQ(0, err);
            if (random() % 100 < 5)
                atomic64_inc(&seqno);
            if (j > 0 && j % 17977 == 0)
                c0sk_flush(c0sk);
        }
    }

    /*
     * we have 5 cursors with 5 different views,
     * with 5 kvms, all views span kvms
     *
     * the 5 cursors should each have 20,000 keys in order,
     * but not sequential -- only when the cursor is updated
     * will it see the unbroken sequence -- strings are used
     * to improve debugging
     */

    for (i = 0; i < 5; ++i) {
        int cnt = 0;
        int want = i * 20000;
        int last = 200000;

        for (eof = false; !eof;) {
            struct kvs_cursor_element elem;

            err = c0sk_cursor_read(cur[i], &elem, &eof);
            ASSERT_EQ(0, err);
            if (cnt < want)
                ASSERT_FALSE(eof);
            else
                ASSERT_TRUE(eof);

            if (!eof) {
                int n;

                n = atoi(KOBJ2KEY(&elem.kce_kobj));
                ASSERT_GT(last, n);
                last = n;
                ++cnt;
            }
        }
        ASSERT_EQ(cnt, want);
    }

    /* now update the first cursor, which should see all keys in order */
    err = c0sk_cursor_update(cur[0], atomic64_read(&seqno), 0);
    ASSERT_EQ(0, err);

    /* seek to the first key */
    seeklen = sprintf(seek, "%05d", 99999);
    err = c0sk_cursor_seek(cur[0], seek, seeklen + 1, 0);
    ASSERT_EQ(0, err);

    for (i = 0; i < nkeys; ++i) {
        err = c0sk_cursor_read(cur[0], &elem, &eof);
        ASSERT_EQ(0, err);
        ASSERT_FALSE(eof);

        ASSERT_EQ(nkeys - 1 - i, atoi(KOBJ2KEY(&elem.kce_kobj)));
    }

    err = c0sk_cursor_read(cur[0], &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    /* seek to first element <= 999999 */
    seeklen = sprintf(seek, "%05d", 999999);
    err = c0sk_cursor_seek(cur[0], seek, seeklen + 1, 0);
    ASSERT_EQ(0, err);

    err = c0sk_cursor_read(cur[0], &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_FALSE(eof);
    ASSERT_EQ(99999, atoi(KOBJ2KEY(&elem.kce_kobj)));

    /* seek to first element <= smallest key */
    seek[0] = 0;
    err = c0sk_cursor_seek(cur[0], seek, 0, 0);
    ASSERT_EQ(0, err);

    err = c0sk_cursor_read(cur[0], &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    /* now test seek on all cursors */
    for (i = 0; i < 100; ++i) {
        char seek[10];
        int  len, k;

        /* always a valid key, never eof */
        j = random() % (nkeys - 1);
        len = sprintf(seek, "%05d", j);
        for (k = 0; k < 5; ++k) {
            const char kdata[32];
            uint klen;
            int x;

            err = c0sk_cursor_seek(cur[k], seek, len + 1, 0);
            ASSERT_EQ(0, err);

            err = c0sk_cursor_read(cur[k], &elem, &eof);
            ASSERT_EQ(0, err);

            key_obj_copy((void *)kdata, sizeof(kdata), &klen, &elem.kce_kobj);
            x = atoi(kdata);
            ASSERT_LE(x, j);
        }
    }

    MOCK_UNSET(c0sk_internal, _c0sk_release_multiset);
    release_deferred(c0sk);

    for (i = 0; i < NELEM(cur); ++i)
        c0sk_cursor_destroy(cur[i]);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, c0_register, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    int                 i;
    u16                 skidx;
    u16                 skidxv[HSE_KVS_COUNT_MAX];
    merr_t              err;
    atomic64_t          seqno;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);
    err = c0sk_c0_deregister(mkvdb.ikdb_c0sk, skidx);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(0, mock_cn, &skidx);
    ASSERT_EQ(EINVAL, merr_errno(err));
    err = c0sk_c0_register(mkvdb.ikdb_c0sk, 0, &skidx);
    ASSERT_EQ(EINVAL, merr_errno(err));
    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, 0);
    ASSERT_EQ(EINVAL, merr_errno(err));

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidxv[i]);
        ASSERT_EQ(0, err);
    }

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(ENOSPC, merr_errno(err));

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        err = c0sk_c0_deregister(mkvdb.ikdb_c0sk, skidxv[i]);
        ASSERT_EQ(0, err);
    }

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, c0_cursor_ptombs, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams   kvdb_rp;
    struct kvs_rparams    kvs_rp;
    struct mock_kvdb      mkvdb;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    struct c0sk *         c0sk;
    struct c0_kvmultiset *kvms;
    struct cn *           cn;
    struct c0sk_impl *    self;
    struct c0_cursor *    cur;
    u16                   skidx;
    int                   tot_keys = 20000;
    u64                   pt_seq = -1;
    uint                  kbuf[2], vbuf;
    merr_t                err;
    bool                  eof;
    uint                  cnt, expcnt;
    int                   i;
    atomic64_t            seqno;

    struct kvs_cursor_element elem;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    kvdb_rp.c0_ingest_width = 16;
    kvdb_rp.c0_diag_mode = 1; /* prevent ingest worker from working */

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&cn, false, false, &kvs_rp, 4);
    ASSERT_EQ(0, err);

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, cn, &skidx);
    ASSERT_EQ(0, err);

    self = c0sk_h2r(mkvdb.ikdb_c0sk);

    _ikvdb_get_c0sk((struct ikvdb *)&mkvdb, &c0sk);
    ASSERT_EQ(c0sk, mkvdb.ikdb_c0sk);

    err = c0kvms_create(1, 0, &seqno, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    err = c0sk_install_c0kvms(self, NULL, kvms);
    ASSERT_EQ(0, err);

    MOCK_SET(c0sk_internal, _c0sk_release_multiset);

    mapi_inject_unset(mapi_idx_cn_ingestv);
    mapi_inject(mapi_idx_cn_ingestv, 0);
    mapi_calls_clear(mapi_idx_c0_put);

    kt.kt_data = kbuf;

    kvs_vtuple_init(&vt, &vbuf, sizeof(vbuf));

    kt.kt_data = kbuf;
    kt.kt_len = sizeof(kbuf);

    srand(42);
    for (i = 0; i < tot_keys; ++i) {
        kbuf[0] = 1;
        kbuf[1] = generate_random_u32(0, 1000000000);
        kbuf[1] = i;
        kvs_ktuple_init(&kt, kbuf, sizeof(kbuf));

        vbuf = atomic64_read(&seqno);
        err = c0sk_put(mkvdb.ikdb_c0sk, skidx, &kt, &vt, HSE_SQNREF_SINGLE);
        ASSERT_EQ(0, err);
        if (i > 0 && i % 4000 == 0)
            c0sk_flush(c0sk);

        if (i > 0 && i == 8765) {
            kvs_ktuple_init(&kt, kbuf, sizeof(kbuf[0]));
            c0sk_prefix_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
            pt_seq = atomic64_read(&seqno);

            /* use a tree prefix length of sizeof(kbuf[0]) */
            err = c0sk_cursor_create(
                c0sk, atomic64_read(&seqno), skidx, 0, sizeof(kbuf[0]), 0, 0, &summary, &cur);
            ASSERT_EQ(0, err);

            atomic64_inc(&seqno);
        } else if (random() % 100 < 5) {
            atomic64_inc(&seqno);
        }
    }

    /* expect ptomb (meant for cn )*/
    err = c0sk_cursor_read(cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(false, eof);
    ASSERT_TRUE(HSE_CORE_IS_PTOMB(elem.kce_vt.vt_data));

    /* expect eof */
    err = c0sk_cursor_read(cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(true, eof);

    err = c0sk_cursor_seek(cur, NULL, 0, NULL);
    ASSERT_EQ(0, err);

    /* use a tree prefix length of sizeof(kbuf[0]) */
    u32 flags = 0;

    err = c0sk_cursor_update(cur, atomic64_read(&seqno), &flags);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(flags & CURSOR_FLAG_SEQNO_CHANGE);

    cnt = 0;
    expcnt = tot_keys - 8765;
    do {
        err = c0sk_cursor_read(cur, &elem, &eof);
        ASSERT_EQ(0, err);
        if (cnt < expcnt)
            ASSERT_FALSE(eof);
        else
            ASSERT_TRUE(eof);

        if (!eof) {
            uint *res = elem.kce_vt.vt_data;

            if (cnt == 0)
                ASSERT_EQ(true, HSE_CORE_IS_PTOMB(res));
            else
                ASSERT_LE(pt_seq, *res);

            ++cnt;
        }
    } while (!eof);

    ASSERT_EQ(expcnt, cnt);

    /* cleanup */
    kbuf[0] = 1;
    kvs_ktuple_init(&kt, kbuf, sizeof(kbuf[0]));
    err = c0sk_prefix_del(mkvdb.ikdb_c0sk, skidx, &kt, HSE_SQNREF_SINGLE);
    ASSERT_EQ(0, err);

    err = c0sk_cursor_seek(cur, NULL, 0, NULL);
    ASSERT_EQ(0, err);

    flags = 0;

    err = c0sk_cursor_update(cur, HSE_SQNREF_SINGLE, &flags);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(flags & CURSOR_FLAG_SEQNO_CHANGE);

    err = c0sk_cursor_seek(cur, NULL, 0, NULL);
    ASSERT_EQ(0, err);

    /* expect ptomb (meant for cn )*/
    err = c0sk_cursor_read(cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(false, eof);
    ASSERT_TRUE(HSE_CORE_IS_PTOMB(elem.kce_vt.vt_data));

    /* expect eof */
    err = c0sk_cursor_read(cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(true, eof);

    MOCK_UNSET(c0sk_internal, _c0sk_release_multiset);
    release_deferred(c0sk);

    c0sk_cursor_destroy(cur);

    c0kvms_putref(kvms);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(cn);
}

MTF_DEFINE_UTEST_PREPOST(c0sk_test, c0_deregister, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    u16                 skidx;
    merr_t              err;
    atomic64_t          seqno;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0sk_c0_deregister(0, skidx);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = c0sk_c0_register(mkvdb.ikdb_c0sk, mock_cn, &skidx);
    ASSERT_EQ(0, err);

    err = c0sk_c0_deregister(mkvdb.ikdb_c0sk, skidx);
    ASSERT_EQ(0, err);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_END_UTEST_COLLECTION(c0sk_test)
