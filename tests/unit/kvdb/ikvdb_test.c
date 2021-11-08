/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include "mapi_idx.h"
#include <ftw.h>
#include <dirent.h>

#include <hse/flags.h>

#include <mtf/framework.h>
#include <mock/api.h>
#include <support/random_buffer.h>

#include <hse_util/hse_err.h>
#include <hse_util/delay.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/rparam_debug_flags.h>
#include <hse_ikvdb/argv.h>

#include <c0/c0_cursor.h>
#include <c0/c0sk_internal.h>

#include <mocks/mock_c0cn.h>

void
_hse_meminfo(ulong *freep, ulong *availp, uint shift)
{
    if (freep)
        *freep = 32;

    if (availp)
        *availp = 32;
}

/*
 * Pre and Post Functions
 */
struct kvs_cparams g_kvs_cp;

static int
test_pre(struct mtf_test_info *ti)
{
    srand(time(NULL));

    mock_kvdb_meta_set();
    mock_cndb_set();
    mock_wal_set();
    mock_c0cn_set();

    g_kvs_cp = kvs_cparams_defaults();
    mapi_inject_ptr(mapi_idx_cndb_cn_cparams, &g_kvs_cp);

    mapi_inject(mapi_idx_cn_get_rp, 0);
    mapi_inject(mapi_idx_cn_get_cnid, 0);
    mapi_inject(mapi_idx_cn_get_ingest_perfc, 0);
    mapi_inject(mapi_idx_cn_get_sfx_len, 0);

    mapi_inject(mapi_idx_cndb_cn_drop, 0);
    mapi_inject(mapi_idx_c0_get_pfx_len, 0);
    mapi_inject(mapi_idx_mpool_mclass_props_get, ENOENT);
    mapi_inject(mapi_idx_mpool_open, 0);
    mapi_inject(mapi_idx_mpool_close, 0);

    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    mock_kvdb_meta_unset();
    mock_c0cn_unset();
    mock_wal_unset();

    mapi_inject_unset(mapi_idx_cn_get_rp);
    mapi_inject_unset(mapi_idx_cn_get_cnid);
    mapi_inject_unset(mapi_idx_cn_get_ingest_perfc);
    mapi_inject_unset(mapi_idx_cn_get_sfx_len);

    mapi_inject(mapi_idx_cndb_cn_drop, 0);
    mapi_inject_unset(mapi_idx_c0_get_pfx_len);
    mapi_inject(mapi_idx_mpool_mclass_props_get, ENOENT);
    mapi_inject_unset(mapi_idx_mpool_open);
    mapi_inject_unset(mapi_idx_mpool_close);

    return 0;
}

static int
test_pre_c0(struct mtf_test_info *ti)
{
    srand(time(NULL));

    mock_kvdb_meta_set();
    mock_cndb_set();
    mock_wal_set();
    mock_cn_set();

    g_kvs_cp = kvs_cparams_defaults();
    mapi_inject_ptr(mapi_idx_cndb_cn_cparams, &g_kvs_cp);

    mapi_inject(mapi_idx_cn_get_ingest_perfc, 0);
    mapi_inject(mapi_idx_cndb_cn_drop, 0);
    mapi_inject(mapi_idx_mpool_open, 0);
    mapi_inject(mapi_idx_mpool_close, 0);

    return 0;
}

static int
test_post_c0(struct mtf_test_info *ti)
{
    mock_kvdb_meta_set();
    mock_cn_unset();
    mock_wal_unset();

    mapi_inject_unset(mapi_idx_cn_get_ingest_perfc);
    mapi_inject(mapi_idx_cndb_cn_drop, 0);
    mapi_inject(mapi_idx_mpool_open, 0);
    mapi_inject(mapi_idx_mpool_close, 0);

    return 0;
}

/* [HSE_REVISIT] Fixme:  gdb --args ikvdb_test -1 cursor_tombspan
 * Needed for cursor_tombspan test...
 */
#if 0
static struct c0_kvmultiset *deferred_release[HSE_C0_KVSET_CURSOR_MAX + 2];

static void
_c0sk_release_multiset(struct c0sk_impl *self, struct c0_kvmultiset *c0kvms)
{
    /* Defer the release of c0kvms to exercise c0 cursors/tombspan code.
     * Update c0sk_release_gen (used by tombspan code).
     */
    struct c0_kvmultiset **dr = deferred_release;
    u64                    gen;

    while (*dr)
        ++dr;

    assert(dr - deferred_release < NELEM(deferred_release));
    *dr++ = c0kvms;
    *dr = 0;

    gen = c0kvms_gen_read(c0kvms);

    mutex_lock(&self->c0sk_kvms_mutex);
    assert(self->c0sk_release_gen < gen);
    self->c0sk_release_gen = gen;
    mutex_unlock(&self->c0sk_kvms_mutex);
}

static void
release_deferred(struct c0sk *c0sk)
{
    struct c0_kvmultiset **dr = deferred_release;
    struct c0sk_impl *     self = c0sk_h2r(c0sk);

    mutex_lock(&self->c0sk_kvms_mutex);
    self->c0sk_release_gen = 0;
    mutex_unlock(&self->c0sk_kvms_mutex);

    while (*dr) {
        c0sk_release_multiset(self, *dr);
        *dr++ = 0;
    }
}
#endif

static int
collection_pre(struct mtf_test_info *t1)
{
    MOCK_SET(platform, _hse_meminfo);
    return 0;
}

static int
collection_post(struct mtf_test_info *t1)
{
    MOCK_UNSET(platform, _hse_meminfo);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(ikvdb_test, collection_pre, collection_post);

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, init, test_pre, test_post)
{
    const char *        mpool = __func__;
    struct ikvdb *      store = NULL;
    merr_t              err;
    const char *const   paramv[] = { "c0_diag_mode=true" };
    struct kvdb_rparams params = kvdb_rparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &store);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, store);

    err = ikvdb_close(store);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, init_fail, test_pre, test_post)
{
    const char *        mpool = __func__;
    struct ikvdb *      store;
    merr_t              err;
    const char *const   paramv[] = { "c0_diag_mode=true" };
    struct kvdb_rparams params = kvdb_rparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    mapi_inject_ptr(mapi_idx_malloc, 0);
    err = ikvdb_open(mpool, &params, &store);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, basic_txn_alloc, test_pre, test_post)
{
    const char *         mpool = __func__;
    struct ikvdb *       store;
    struct hse_kvdb_txn *txn1, *txn2;
    merr_t               err;
    const char *const    paramv[] = { "c0_diag_mode=true" };
    struct kvdb_rparams  params = kvdb_rparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &store);
    ASSERT_EQ(0, err);

    txn1 = ikvdb_txn_alloc(store);
    ASSERT_NE(NULL, txn1);

    mapi_inject_ptr(mapi_idx_malloc, 0);
    txn2 = ikvdb_txn_alloc(store);
    ASSERT_EQ(NULL, txn2);

    mapi_inject_unset(mapi_idx_malloc);

    ikvdb_txn_free(store, txn1);

    err = ikvdb_close(store);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, basic_lifecycle, test_pre, test_post)
{
    const char *         mpool = __func__;
    struct ikvdb *       store;
    struct hse_kvdb_txn *txn1, *txn2;
    const char *const    paramv[] = { "c0_diag_mode=true" };
    merr_t               err;
    struct kvdb_rparams  params = kvdb_rparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &store);
    ASSERT_EQ(0, err);

    txn1 = ikvdb_txn_alloc(store);
    txn2 = ikvdb_txn_alloc(store);
    ASSERT_NE(NULL, txn1);
    ASSERT_NE(NULL, txn2);

    err = ikvdb_txn_begin(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_begin(store, txn2);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_ACTIVE, ikvdb_txn_state(store, txn1));
    ASSERT_EQ(KVDB_CTXN_ACTIVE, ikvdb_txn_state(store, txn2));

    err = ikvdb_txn_commit(store, txn2);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_commit(store, txn1);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_COMMITTED, ikvdb_txn_state(store, txn1));
    ASSERT_EQ(KVDB_CTXN_COMMITTED, ikvdb_txn_state(store, txn2));

    err = ikvdb_txn_begin(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_begin(store, txn2);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_commit(store, txn2);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_commit(store, txn1);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_COMMITTED, ikvdb_txn_state(store, txn1));
    ASSERT_EQ(KVDB_CTXN_COMMITTED, ikvdb_txn_state(store, txn2));

    err = ikvdb_txn_begin(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_begin(store, txn2);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_commit(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_abort(store, txn2);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_COMMITTED, ikvdb_txn_state(store, txn1));
    ASSERT_EQ(KVDB_CTXN_ABORTED, ikvdb_txn_state(store, txn2));

    err = ikvdb_txn_begin(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_begin(store, txn2);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_abort(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_commit(store, txn2);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_ABORTED, ikvdb_txn_state(store, txn1));
    ASSERT_EQ(KVDB_CTXN_COMMITTED, ikvdb_txn_state(store, txn2));

    err = ikvdb_txn_begin(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_begin(store, txn2);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_abort(store, txn1);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_abort(store, txn2);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_ABORTED, ikvdb_txn_state(store, txn1));
    ASSERT_EQ(KVDB_CTXN_ABORTED, ikvdb_txn_state(store, txn2));

    ikvdb_txn_free(store, txn1);
    ikvdb_txn_free(store, txn2);

    // At this point one of the previous txns will be recycled for txn3
    struct hse_kvdb_txn *txn3 = ikvdb_txn_alloc(store);
    ASSERT_EQ(KVDB_CTXN_INVALID, ikvdb_txn_state(store, txn3));
    ikvdb_txn_free(store, txn3);

    err = ikvdb_close(store);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, ikvdb_kvs_open_test, test_pre, test_post)
{
    struct ikvdb *      hdl = NULL;
    struct hse_kvs *    h = NULL;
    const char *        mpool = __func__;
    const char *        kvs = "kvs_gamma";
    const char *const   paramv[] = { "c0_diag_mode=true" };
    merr_t              err;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvs_rparams  kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &hdl);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, hdl);

    err = ikvdb_kvs_create(hdl, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    mapi_inject_ptr(mapi_idx_malloc, 0);
    err = ikvdb_kvs_open(hdl, kvs, &kvs_rp, 0, &h);
    ASSERT_EQ(NULL, h);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject(mapi_idx_c0_open, merr(EBUG));
    err = ikvdb_kvs_open(hdl, kvs, &kvs_rp, 0, &h);
    ASSERT_EQ(NULL, h);
    ASSERT_EQ(EBUG, merr_errno(err));
    mapi_inject_unset(mapi_idx_c0_open);
    mock_c0cn_set(); /* revert to original c0cn mocks */

    err = ikvdb_kvs_open(hdl, kvs, &kvs_rp, 0, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_close(h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, ikvdb_kvs_create_test, test_pre, test_post)
{
    struct ikvdb *      hdl = NULL;
    const char *        mpool = __func__;
    const char *        kvs = "kvs_gamma";
    merr_t              err;
    const char *const   paramv[] = { "c0_diag_mode=true" };
    unsigned int        cnt;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &hdl);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, hdl);

    mapi_inject_ptr(mapi_idx_malloc, 0);

    err = ikvdb_kvs_create(hdl, kvs, &kvs_cp);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    mapi_inject_unset(mapi_idx_malloc);

    err = ikvdb_kvs_create(hdl, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    /* Duplicate kvs */
    err = ikvdb_kvs_create(hdl, kvs, &kvs_cp);
    ASSERT_EQ(EEXIST, merr_errno(err));

    ikvdb_kvs_count(hdl, &cnt);
    ASSERT_EQ(1, cnt);

    /* Add a kvs with create-time params */
    err = ikvdb_kvs_create(hdl, "kvs_delta", &kvs_cp);
    ASSERT_EQ(0, err);

    ikvdb_kvs_count(hdl, &cnt);
    ASSERT_EQ(2, cnt);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, ikvdb_kvs_destroy_test, test_pre, test_post)
{
    struct ikvdb *      hdl = NULL;
    const char *        mpool = __func__;
    const char *        kvs = "kvs_gamma";
    merr_t              err;
    unsigned int        cnt;
    const char *const   paramv[] = { "c0_diag_mode=true" };
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &hdl);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, hdl);

    err = ikvdb_kvs_create(hdl, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    ikvdb_kvs_count(hdl, &cnt);
    ASSERT_EQ(1, cnt);

    mapi_inject(mapi_idx_cndb_cn_drop, 0);
    err = ikvdb_kvs_drop(hdl, kvs);
    ASSERT_EQ(0, merr_errno(err));
    mapi_inject_unset(mapi_idx_cndb_cn_drop);

    ikvdb_kvs_count(hdl, &cnt);
    ASSERT_EQ(0, cnt);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, txn_del_test, test_pre, test_post)
{
    struct ikvdb *       h = NULL;
    struct hse_kvs *     kvs_h = NULL;
    const char *         mpool = __func__;
    const char *         kvs = "kvs";
    const char *const    kvdb_open_paramv[] = { "c0_diag_mode=true" };
    const char *const    kvs_open_paramv[] = { "transactions.enabled=true" };
    merr_t               err;
    struct hse_kvdb_txn *txn;
    struct kvs_ktuple    kt;
    struct kvs_vtuple    vt;
    struct kvs_buf       vbuf;
    char                 buf[100];
    enum key_lookup_res  found;
    char *               str;
    struct kvdb_rparams  kvdb_rp = kvdb_rparams_defaults();
    struct kvs_rparams   kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams   kvs_cp = kvs_cparams_defaults();

    /* we want a valid c0/c0sk here */
    mock_c0_unset();

    err = argv_deserialize_to_kvdb_rparams(NELEM(kvdb_open_paramv), kvdb_open_paramv, &kvdb_rp);
    ASSERT_EQ(0, err);

    err = argv_deserialize_to_kvs_rparams(NELEM(kvs_open_paramv), kvs_open_paramv, &kvs_rp);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &kvdb_rp, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_create(h, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(h, kvs, &kvs_rp, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    kvs_ktuple_init(&kt, "key", 3);
    str = "data";
    kvs_vtuple_init(&vt, str, strlen(str));

    txn = ikvdb_txn_alloc(h);
    ASSERT_NE(0, txn);

    err = ikvdb_txn_begin(h, txn);
    ASSERT_EQ(0, err);
    err = ikvdb_kvs_put(kvs_h, 0, txn, &kt, &vt);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_commit(h, txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_begin(h, txn);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_del(kvs_h, 0, txn, &kt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(h, txn);
    ASSERT_EQ(0, err);

    ikvdb_txn_free(h, txn);
    txn = 0;

    vbuf.b_buf = buf;
    vbuf.b_buf_sz = sizeof(buf);
    vbuf.b_len = 0;
    err = ikvdb_kvs_get(kvs_h, 0, txn, &kt, &found, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(found, FOUND_TMB);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);
}

struct tx_info {
    struct ikvdb *  kvdb;
    struct hse_kvs *kvs;
    int             idx;
};

void *
parallel_transactions(void *info)
{
    struct tx_info *     ti = info;
    char                 kbuf[16];
    struct kvs_ktuple    kt;
    struct kvs_vtuple    vt;
    struct hse_kvdb_txn *txn;
    struct kvs_buf       val;
    enum key_lookup_res  found;
    char                 vbuf[100];
    merr_t               err;
    char *               str;

    txn = ikvdb_txn_alloc(ti->kvdb);
    VERIFY_NE_RET(0, txn, 0);

    err = ikvdb_txn_begin(ti->kvdb, txn);
    VERIFY_EQ_RET(0, err, 0);

    snprintf(kbuf, sizeof(kbuf), "key-%d", ti->idx);
    kvs_ktuple_init(&kt, kbuf, strlen(kbuf));
    str = "data";
    kvs_vtuple_init(&vt, str, strlen(str));

    err = ikvdb_kvs_put(ti->kvs, 0, txn, &kt, &vt);
    VERIFY_EQ_RET(0, err, 0);

    err = ikvdb_txn_commit(ti->kvdb, txn);
    VERIFY_EQ_RET(0, err, 0);

    ikvdb_txn_free(ti->kvdb, txn);

    val.b_buf = vbuf;
    val.b_buf_sz = sizeof(vbuf);
    val.b_len = 0;
    txn = 0;
    err = ikvdb_kvs_get(ti->kvs, 0, txn, &kt, &found, &val);
    VERIFY_EQ_RET(0, err, 0);
    VERIFY_EQ_RET(found, FOUND_VAL, 0);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, txn_put_test, test_pre, test_post)
{
    struct ikvdb *      h = NULL;
    struct hse_kvs *    kvs_h = NULL;
    const char *        mpool = __func__;
    const char *        kvs = "kvs";
    const char *const   kvdb_open_paramv[] = { "c0_debug=16" };
    const char *const   kvs_open_paramv[] = { "transactions.enabled=true" };
    merr_t              err;
    const int           num_txn = 256;
    struct tx_info      info[num_txn];
    pthread_t           th[num_txn];
    int                 rc, i;
    struct kvdb_rparams kvdb_rp = kvdb_rparams_defaults();
    struct kvs_rparams  kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    /* we want a valid c0/c0sk here */
    mock_c0_unset();

    err = argv_deserialize_to_kvdb_rparams(NELEM(kvdb_open_paramv), kvdb_open_paramv, &kvdb_rp);
    ASSERT_EQ(0, err);

    err = argv_deserialize_to_kvs_rparams(NELEM(kvs_open_paramv), kvs_open_paramv, &kvs_rp);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &kvdb_rp, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_create(h, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(h, kvs, &kvs_rp, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject(mapi_idx_c0sk_sync, 0);

    for (i = 0; i < num_txn; i++) {
        info[i].kvdb = h;
        info[i].kvs = kvs_h;
        info[i].idx = i;
        rc = pthread_create(th + i, 0, parallel_transactions, &info[i]);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_txn; i++) {
        rc = pthread_join(th[i], 0);
        ASSERT_EQ(0, rc);
    }

    mapi_inject_unset(mapi_idx_c0sk_sync);

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, aborted_txn_bind, test_pre, test_post)
{
    struct ikvdb *         kvdb_h = NULL;
    struct hse_kvs *       kvs_h = NULL;
    const char *           mpool = __func__;
    const char *           kvs = "kvs";
    const char *const      kvdb_open_paramv[] = { "c0_debug=16", "c0_diag_mode=true" };
    const char *const      kvs_open_paramv[] = { "transactions.enabled=true" };
    merr_t                 err;
    struct hse_kvdb_txn *  txn;
    struct hse_kvs_cursor *cur;
    struct kvdb_rparams    kvdb_rp = kvdb_rparams_defaults();
    struct kvs_rparams     kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams     kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(kvdb_open_paramv), kvdb_open_paramv, &kvdb_rp);
    ASSERT_EQ(0, err);

    err = argv_deserialize_to_kvs_rparams(NELEM(kvs_open_paramv), kvs_open_paramv, &kvs_rp);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &kvdb_rp, &kvdb_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvdb_h);

    err = ikvdb_kvs_create(kvdb_h, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(kvdb_h, kvs, &kvs_rp, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    /* Create a txn and abort it */
    txn = ikvdb_txn_alloc(kvdb_h);
    ASSERT_NE(NULL, txn);

    err = ikvdb_txn_begin(kvdb_h, txn);
    ASSERT_EQ(err, 0);

    err = ikvdb_txn_abort(kvdb_h, txn);
    ASSERT_EQ(err, 0);

    cur = NULL;
    err = ikvdb_kvs_cursor_create(kvs_h, 0, txn, "foo", 3, &cur);
    ASSERT_EQ(EPROTO, merr_errno(err));
    ASSERT_EQ(NULL, cur);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(kvdb_h);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, cursor_0, test_pre, test_post)
{
    struct ikvdb *         h = NULL;
    struct hse_kvs *       kvs_h = NULL;
    const char *           mpool = __func__;
    const char *           kvs = "kvs";
    const char *const      paramv[] = { "c0_debug=16", "c0_diag_mode=true" };
    merr_t                 err;
    struct hse_kvdb_txn *  txn = NULL;
    struct hse_kvs_cursor *cur;
    const void *           key, *val;
    size_t                 klen, vlen;
    bool                   eof;
    struct kvdb_rparams    params = kvdb_rparams_defaults();
    struct kvs_rparams     kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams     kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_create(h, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(h, kvs, &kvs_rp, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject(mapi_idx_c0_cursor_create, merr(EBUG));
    err = ikvdb_kvs_cursor_create(kvs_h, 0, txn, "foo", 3, &cur);
    ASSERT_EQ(EBUG, merr_errno(err));
    mapi_inject_unset(mapi_idx_c0_cursor_create);
    mock_c0cn_set(); /* revert to original c0cn mocks */

    err = ikvdb_kvs_cursor_create(kvs_h, 0, txn, "foo", 3, &cur);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, cur);

    err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    err = ikvdb_kvs_cursor_destroy(cur);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, cursor_1, test_pre_c0, test_post_c0)
{
    struct ikvdb *         h = NULL;
    struct hse_kvs *       kvs_h = NULL;
    const char *           mpool = __func__;
    const char *           kvs = "kvs";
    const char *const      paramv[] = { "c0_diag_mode=true" };
    struct hse_kvdb_txn *  txn = NULL;
    struct hse_kvs_cursor *cur;
    struct kvs_ktuple      kt = { 0 };
    struct kvs_vtuple      vt = { 0 };
    const void *           key, *val;
    size_t                 klen, vlen;
    merr_t                 err;
    bool                   eof;
    int                    i;
    struct kvdb_rparams    params = kvdb_rparams_defaults();
    struct kvs_rparams     kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams     kvs_cp = kvs_cparams_defaults();

    struct kvdata {
        char *key;
        char *val;
    } kvdata[] = {
        { "AABC", "AABC_1" }, { "AC", "AC_1" }, { "AA", "AA_1" },   { "AABB", "AABB_1" },
        { "ABAA", "ABAA_1" }, { "AB", "AB_1" }, { "ABC", "ABC_1" }, { "AAA", "AAA_1" },
    };

    struct kvdata sorted[] = {
        { "AA", "AA_1" }, { "AAA", "AAA_1" },   { "AABB", "AABB_1" }, { "AABC", "AABC_1" },
        { "AB", "AB_1" }, { "ABAA", "ABAA_1" }, { "ABC", "ABC_1" },   { "AC", "AC_1" },
    };

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_create(h, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(h, kvs, &kvs_rp, 0, &kvs_h);
    ASSERT_EQ(0, err);

    /* insert data into "c0" */
    for (i = 0; i < NELEM(kvdata); ++i) {
        kvs_ktuple_init(&kt, kvdata[i].key, strlen(kvdata[i].key));
        kvs_vtuple_init(&vt, kvdata[i].val, strlen(kvdata[i].val));

        err = ikvdb_kvs_put(kvs_h, 0, txn, &kt, &vt);
        ASSERT_EQ(0, err);
    }

    /* Test full scans */

    mapi_calls_clear(mapi_idx_c0_cursor_create);

    err = ikvdb_kvs_cursor_create(kvs_h, 0, txn, 0, 0, &cur);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, cur);

    ASSERT_EQ(1, mapi_calls(mapi_idx_c0_cursor_create));

    /* Note: this does NOT need to test full functionality
     * of the cursors, as the cn unit tests check for many
     * more variations.  This needs to be simply a functional
     * test of the API.
     */
    eof = 0;
    for (i = 0;; ++i) {
        err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
        ASSERT_EQ(err, 0);
        if (eof)
            break;

        ASSERT_LE(i, NELEM(sorted));

        ASSERT_EQ(klen, strlen(sorted[i].key));
        ASSERT_EQ(vlen, strlen(sorted[i].val));
        ASSERT_EQ(0, memcmp(key, sorted[i].key, klen));
        ASSERT_EQ(0, memcmp(val, sorted[i].val, vlen));
    }
    ASSERT_TRUE(eof);
    ASSERT_EQ(i, NELEM(kvdata));

    err = ikvdb_kvs_cursor_destroy(cur);
    ASSERT_EQ(0, err);

    /* Test seek */
    err = ikvdb_kvs_cursor_create(kvs_h, 0, txn, 0, 0, &cur);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, cur);

    key = sorted[3].key;
    klen = strlen(key);
    err = ikvdb_kvs_cursor_seek(cur, 0, key, klen, 0, 0, &kt);
    ASSERT_EQ(0, err);
    ASSERT_EQ(kt.kt_len, klen);
    ASSERT_EQ(0, memcmp(kt.kt_data, key, klen));

    err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
    ASSERT_EQ(0, err);
    ASSERT_FALSE(eof);
    ASSERT_EQ(0, memcmp(key, sorted[3].key, klen));
    ASSERT_EQ(0, memcmp(val, sorted[3].val, vlen));

    err = ikvdb_kvs_cursor_seek(cur, 0, "ZZZ", 3, 0, 0, &kt);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, kt.kt_len); /* eof */

    err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    err = ikvdb_kvs_cursor_destroy(cur);
    ASSERT_EQ(0, err);

    /* Test prefix scans */

    err = ikvdb_kvs_cursor_create(kvs_h, 0, txn, "AB", 2, &cur);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, cur);

    /* This code knows prefix AB is at offset 4..7 */
    for (i = 4;; ++i) {
        err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
        ASSERT_EQ(0, err);
        if (eof)
            break;

        ASSERT_LE(i, NELEM(sorted));

        ASSERT_EQ(klen, strlen(sorted[i].key));
        ASSERT_EQ(vlen, strlen(sorted[i].val));
        ASSERT_EQ(0, memcmp(key, sorted[i].key, klen));
        ASSERT_EQ(0, memcmp(val, sorted[i].val, vlen));
    }
    ASSERT_EQ(7, i);

    err = ikvdb_kvs_cursor_update_view(cur, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_cursor_destroy(cur);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);
}

#if 0
MTF_DEFINE_UTEST_PREPOST(ikvdb_test, cursor_tx, test_pre_c0, test_post_c0)
{
    struct ikvdb *         h = NULL;
    struct hse_kvs *       kvs_h = NULL;
    const char *           mpool = __func__;
    const char *           kvs = "kvs";
    struct mpool *         ds = (struct mpool *)-1;
    const char *const      kvdb_open_paramv[] = { "c0_diag_mode=true" };
    const char *const      kvs_open_paramv[] = { "transactions.enabled=true" };
    struct hse_kvdb_txn *  txn1;
    unsigned int           flags1 = 0;
    struct hse_kvdb_txn *  txn2;
    unsigned int           flags2 = 0;
    struct hse_kvs_cursor *cur, *spam, *bound;
    struct kvs_ktuple      kt = { 0 };
    struct kvs_vtuple      vt = { 0 };
    const void *           key, *val;
    size_t                 klen, vlen;
    merr_t                 err;
    u64                    hor1, hor2;
    bool                   eof;
    struct kvdb_rparams    kvdb_rp = kvdb_rparams_defaults();
    struct kvs_rparams     kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams     kvs_cp = kvs_cparams_defaults();

    struct kvdata {
        char *key;
        char *val;
    } kvdata[] = {
        { "AABC", "AABC_1" }, { "AC", "AC_1" }, { "AA", "AA_1" },   { "AABB", "AABB_1" },
        { "ABAA", "ABAA_1" }, { "AB", "AB_1" }, { "ABC", "ABC_1" }, { "AAA", "AAA_1" },
    };

    /* keep this as documentation
    struct kvdata sorted[] = {
        { "AA",   "AA_1"   },
        { "AAA",  "AAA_1"  },
        { "AABB", "AABB_1" },
        { "AABC", "AABC_1" },
        { "AB",   "AB_1"   },
        { "ABAA", "ABAA_1" },
        { "ABC",  "ABC_1"  },
        { "AC",   "AC_1"   },
    };
    */

    err = argv_deserialize_to_kvdb_rparams(NELEM(kvdb_open_paramv), kvdb_open_paramv, &kvdb_rp);
    ASSERT_EQ(0, err);

    err = argv_deserialize_to_kvs_rparams(NELEM(kvs_open_paramv), kvs_open_paramv, &kvs_rp);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &kvdb_rp, NULL, ds, NULL, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_create(h, kvs, &kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(h, kvs, &kvs_rp, 0, &kvs_h);
    ASSERT_EQ(0, err);

#define PUT(txn, kvdata)                                      \
    do {                                                      \
        kvs_ktuple_init(&kt, kvdata.key, strlen(kvdata.key)); \
        kvs_vtuple_init(&vt, kvdata.val, strlen(kvdata.val)); \
        err = ikvdb_kvs_put(kvs_h, 0, txn, &kt, &vt);         \
        ASSERT_EQ(0, err);                                    \
    } while (0)

    txn2 = ikvdb_txn_alloc(h);
    ASSERT_NE(NULL, txn2);

    txn1 = ikvdb_txn_alloc(h);
    ASSERT_NE(NULL, txn1);

    /* cursor should see these two keys; seqno 0 */
    err = ikvdb_txn_begin(h, txn2);
    ASSERT_EQ(err, 0);
    PUT(txn2, kvdata[0]);
    PUT(txn2, kvdata[1]);
    err = ikvdb_txn_commit(h, txn2);
    ASSERT_EQ(err, 0);

    hor1 = ikvdb_horizon(h);

    err = ikvdb_txn_begin(h, txn2);
    ASSERT_EQ(err, 0);
    err = ikvdb_kvs_cursor_create(kvs_h, flags2, txn2, 0, 0, &spam);
    ASSERT_EQ(err, 0);

    /* tx bumps the seqno; view 1, seqno 2 */
    err = ikvdb_txn_begin(h, txn1);
    ASSERT_EQ(err, 0);

#if 0
    do {
        hor2 = ikvdb_horizon(h);
        usleep(1000 * 100);
        printf("hor1 %lu hor2 %lu\n", hor1, hor2);
    } while (hor2 < hor1 + 2);
    ASSERT_EQ(hor2, hor1 + 2);
#endif

    /* txn cursor */
    flags1 = 0;
    err = ikvdb_kvs_cursor_create(kvs_h, flags1, txn1, 0, 0, &bound);
    ASSERT_EQ(err, 0);
    ASSERT_NE(0, bound);

    /* the bound cursor should work here, and see kvdata[0] */
    err = ikvdb_kvs_cursor_seek(bound, 0, 0, 0, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0, memcmp(kt.kt_data, kvdata[0].key, kt.kt_len));

    /* reg cursor should NOT see this key: inside txn; bound should see */
    PUT(txn1, kvdata[2]);

    /* the put above should NOT have invalidated bound cursor */
    key = kvdata[2].key;
    klen = strlen(key);
    err = ikvdb_kvs_cursor_seek(bound, 0, key, klen, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(kt.kt_len, klen);
    ASSERT_EQ(0, memcmp(key, kt.kt_data, klen));

    /* can unbind a bound cursor -- an lose view -- then regain it */
    err = ikvdb_kvs_cursor_update_view(bound, 0);
    ASSERT_EQ(err, 0);

    /* ... cannot find what we just did */
    err = ikvdb_kvs_cursor_seek(bound, 0, key, klen, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0, memcmp(key, kt.kt_data, klen));

    /* ... and we should find it again */
    err = ikvdb_kvs_cursor_update_view(bound, flags1);
    ASSERT_EQ(err, 0);
    err = ikvdb_kvs_cursor_seek(bound, 0, key, klen, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(kt.kt_len, klen);
    ASSERT_EQ(0, memcmp(key, kt.kt_data, klen));

    /* cursor should NOT see this key; seqno 2 */
    PUT(txn2, kvdata[3]);

    /* validate horizon -- tx cursor should not change horizon */
    hor1 = ikvdb_horizon(h);

    /* does not bump seqno, reuses tx view seqno 1, horz still 1 */
    flags1 = 0;
    err = ikvdb_kvs_cursor_create(kvs_h, flags1, txn1, 0, 0, &cur);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, cur);

    hor2 = ikvdb_horizon(h);
    ASSERT_EQ(hor1, hor2);

    /* view seqno of txn should be 1, horz should be 0 */
    err = kvdb_ctxn_get_view_seqno(kvdb_ctxn_h2h(txn1), &hor1);
    ASSERT_EQ(err, 0);
    //ASSERT_EQ(hor1, hor2);

    /* but a tx-view-cursor should NOT be able to see inside tx */
    err = ikvdb_kvs_cursor_seek(cur, 0, 0, 0, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    if (kt.kt_len == 2)
        ASSERT_NE(0, memcmp(kt.kt_data, "AA", kt.kt_len));

    /* cursor should not see these, due to normal cursor create semantics */
    PUT(txn2, kvdata[4]);
    PUT(txn2, kvdata[5]);
    PUT(txn2, kvdata[6]);
    PUT(txn2, kvdata[7]);
    err = ikvdb_txn_commit(h, txn2);
    ASSERT_EQ(err, 0);

    /* the visible set is presently {AABC,AC} */
    eof = true;
    err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
    ASSERT_EQ(err, 0);
    ASSERT_FALSE(eof);
    ASSERT_EQ(0, memcmp(key, "AABC", klen));
    ASSERT_EQ(0, memcmp(val, "AABC_1", vlen));

    /* verify passing a tx to update succeeds */
    err = ikvdb_kvs_cursor_update_view(cur, 0);
    ASSERT_EQ(err, 0);

    /* this key is not visible to txn view */
    key = kvdata[4].key;
    klen = strlen(key);
    err = ikvdb_kvs_cursor_seek(cur, 0, key, klen, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_NE(0, memcmp(kt.kt_data, key, kt.kt_len));

    /* update cursor - no longer has view seq of tx */
    err = ikvdb_kvs_cursor_update_view(cur, 0);
    ASSERT_EQ(err, 0);

    /* start over, visible set now all but tx {AA} */
    err = ikvdb_kvs_cursor_seek(cur, 0, 0, 0, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0, memcmp(kt.kt_data, "AAA", kt.kt_len));

    /* commit tx, but do not update cursor */
    err = ikvdb_txn_commit(h, txn1);
    ASSERT_EQ(err, 0);

    /* bound cursor is now canceled */
    err = ikvdb_kvs_cursor_read(bound, 0, &key, &klen, &val, &vlen, &eof);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0, memcmp(kt.kt_data, "AAA", kt.kt_len));

    err = ikvdb_kvs_cursor_destroy(bound);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_cursor_seek(cur, 0, 0, 0, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(kt.kt_len, 3);
    ASSERT_EQ(0, memcmp(kt.kt_data, "AAAXXX", kt.kt_len));

    /* update cursor, should now see all keys */
    err = ikvdb_kvs_cursor_update_view(cur, 0);
    ASSERT_EQ(err, 0);

    err = ikvdb_kvs_cursor_seek(cur, 0, 0, 0, 0, 0, &kt);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(kt.kt_len, 2);
    ASSERT_EQ(0, memcmp(kt.kt_data, "AAAXXX", kt.kt_len));

    err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
    ASSERT_EQ(err, 0);
    ASSERT_FALSE(eof);
    ASSERT_EQ(0, memcmp(key, "AAAXXX", klen));
    ASSERT_EQ(0, memcmp(val, "AA_1XXX", vlen));

    err = ikvdb_kvs_cursor_destroy(cur);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_cursor_destroy(spam);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);
}
#endif

/* [HSE_REVISIT] Fixme:  gdb --args ikvdb_test -1 cursor_tombspan
 */
#if 0
MTF_DEFINE_UTEST_PREPOST(ikvdb_test, cursor_tombspan, test_pre_c0, test_post_c0)
{
    struct c0sk *          c0sk;
    struct ikvdb *         h = NULL;
    struct hse_kvs *       kvs_h = NULL;
    const char *           mpool = __func__;
    const char *           kvs = "kvs";
    struct mpool *         ds = (struct mpool *)-1;
    struct hse_params *    params;
    struct hse_kvdb_opspec txspec;
    struct hse_kvdb_opspec opspec;
    struct hse_kvs_cursor *cur;
    struct kvs_ktuple      kt = { 0 };
    struct kvs_vtuple      vt = { 0 };
    char                   kbuf[12];
    const void *           key, *val;
    size_t                 klen, vlen, kmin_len;
    merr_t                 err;
    bool                   eof;
    int                    i, j;
    const int              LEN = 100000;
    u64                    gen;

    HSE_KVDB_OPSPEC_INIT(&txspec);
    HSE_KVDB_OPSPEC_INIT(&opspec);

    hse_params_create(&params);

    err = hse_params_set(params, "kvdb.c0_diag_mode", "1");
    ASSERT_EQ(err, 0);

    err = hse_params_set(params, "kvdb.c0_ingest_width", "16");
    ASSERT_EQ(err, 0);

    err = ikvdb_open(mpool, NULL, ds, params, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_create(h, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(h, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);

    ikvdb_get_c0sk(h, &c0sk);

    MOCK_SET(c0sk_internal, _c0sk_release_multiset);

    mapi_inject_unset(mapi_idx_cn_ingestv);
    mapi_inject(mapi_idx_cn_ingestv, 0);

    for (i = 0; i < LEN; i++) {
        kvs_ktuple_init(&kt, kbuf, sprintf(kbuf, "%06d", i) + 1);
        kvs_vtuple_init(&vt, kbuf, kt.kt_len);
        err = ikvdb_kvs_put(kvs_h, &opspec, &kt, &vt);
        ASSERT_EQ(0, err);
    }

    txspec.kop_txn = ikvdb_txn_alloc(h);
    ASSERT_NE(NULL, txspec.kop_txn);
    opspec.kop_txn = txspec.kop_txn;

    kmin_len = sprintf(kbuf, "%06d", 0) + 1;
    kvs_ktuple_init(&kt, kbuf, kmin_len);

    err = c0sk_flush_current_multiset(c0sk_h2r(c0sk), &gen, false);
    ASSERT_EQ(0, err);

    for (i = 0; i < LEN / 100; i++) {
        kmin_len = sprintf(kbuf, "%06d", i * LEN / 100 + i) + 1;

        for (j = 0; j < LEN / 200; j++) {
            int value = i * LEN / 100 + i + j;

            kvs_ktuple_init(&kt, kbuf, kmin_len);

            err = ikvdb_txn_begin(h, txspec.kop_txn);
            ASSERT_EQ(err, 0);

            txspec.kop_flags = HSE_KVDB_KOP_FLAG_BIND_TXN;
            err = ikvdb_kvs_cursor_create(kvs_h, &txspec, 0, 0, &cur);
            if (err) {
                log_errx("cursor create failed: @@e", err);
                abort();
            }
            ASSERT_EQ(err, 0);

            err = ikvdb_kvs_cursor_seek(cur, 0, kbuf, kmin_len, 0, 0, &kt);
            ASSERT_EQ(err, 0);
            if (value < LEN)
                ASSERT_EQ(value, atoi(kt.kt_data));
            else
                ASSERT_EQ(kt.kt_len, 0);

            err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
            ASSERT_EQ(value >= LEN, eof);
            if (!eof) {
                ASSERT_EQ(value, atoi(val));

                err = ikvdb_kvs_del(kvs_h, &opspec, &kt);
                ASSERT_EQ(0, err);
            }

            err = ikvdb_txn_commit(h, txspec.kop_txn);
            ASSERT_EQ(err, 0);

            err = ikvdb_kvs_cursor_destroy(cur);
            ASSERT_EQ(0, err);
        }
    }

    for (i = 0; i < LEN / 100; i++) {
        int value = i * LEN / 100 + i + LEN / 200;

        klen = sprintf(kbuf, "%06d", value) + 1;
        kvs_ktuple_init(&kt, kbuf, klen);
        kvs_vtuple_init(&vt, kbuf, klen);

        if (value < LEN) {
            err = ikvdb_txn_begin(h, txspec.kop_txn);
            ASSERT_EQ(err, 0);

            err = ikvdb_kvs_put(kvs_h, &opspec, &kt, &vt);
            ASSERT_EQ(0, err);

            err = ikvdb_txn_commit(h, txspec.kop_txn);
            ASSERT_EQ(err, 0);
        }
    }

    err = c0sk_flush_current_multiset(c0sk_h2r(c0sk), &gen, false);
    ASSERT_EQ(0, err);

    for (i = 0; i < LEN / 100; i++) {
        int value = i * LEN / 100 + i + LEN / 200;

        kmin_len = sprintf(kbuf, "%06d", i * LEN / 100 + i) + 1;

        kvs_ktuple_init(&kt, kbuf, kmin_len);

        err = ikvdb_txn_begin(h, txspec.kop_txn);
        ASSERT_EQ(err, 0);

        txspec.kop_flags = HSE_KVDB_KOP_FLAG_BIND_TXN;
        err = ikvdb_kvs_cursor_create(kvs_h, &txspec, 0, 0, &cur);
        ASSERT_EQ(err, 0);

        err = ikvdb_kvs_cursor_seek(cur, 0, kbuf, kmin_len, 0, 0, &kt);
        ASSERT_EQ(err, 0);
        if (value < LEN)
            ASSERT_EQ(value, atoi(kt.kt_data));
        else
            ASSERT_EQ(kt.kt_len, 0);

        err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
        ASSERT_EQ(value >= LEN, eof);
        if (!eof)
            ASSERT_EQ(value, atoi(val));

        err = ikvdb_txn_abort(h, txspec.kop_txn);
        ASSERT_EQ(err, 0);

        err = ikvdb_kvs_cursor_destroy(cur);
        ASSERT_EQ(0, err);
    }

    MOCK_UNSET(c0sk_internal, _c0sk_release_multiset);
    release_deferred(c0sk);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);

    hse_params_destroy(params);
}
#endif

struct cursor_info {
    const char *    keyfmt;
    uint            pfxmod;
    struct hse_kvs *kvs;
    uint64_t        ttl;
    uint            tid;
    pthread_t       td;
};

void *
parallel_cursors(void *info)
{
    struct cursor_info *   ci = info;
    struct hse_kvs_cursor *c;
    struct kvs_ktuple      kt;
    char                   buf[32];
    const void *           k, *v;
    size_t                 klen, vlen;
    int                    i;
    merr_t                 err;

    for (i = 0; i < 100000; ++i) {
        u32  r = generate_random_u32(0, 10000 - 1); /* max is inclusive */
        bool eof = true;

        /* create different prefixes each time */
        sprintf(buf, ci->keyfmt, r % ci->pfxmod, r);

        err = ikvdb_kvs_cursor_create(ci->kvs, 0, NULL, buf, 3, &c);
        if (err && merr_errno(err) == ENOMEM) {
            usleep(333);
            --i;
            continue;
        }

        VERIFY_EQ_RET(err, 0, 0);

        klen = strlen(buf);
        err = ikvdb_kvs_cursor_seek(c, 0, buf, klen, 0, 0, &kt);
        VERIFY_EQ_RET(0, err, 0);
        VERIFY_EQ_RET(kt.kt_len, klen, 0);
        VERIFY_EQ_RET(0, memcmp(kt.kt_data, buf, klen), 0);

        err = ikvdb_kvs_cursor_read(c, 0, &k, &klen, &v, &vlen, &eof);
        VERIFY_EQ_RET(0, err, 0);
        VERIFY_FALSE_RET(eof, 0);
        VERIFY_EQ_RET(0, memcmp(k, buf, klen), 0);
        VERIFY_EQ_RET(0, memcmp(v, buf, vlen), 0);

        if (i < 50)
            msleep(20);

        err = ikvdb_kvs_cursor_destroy(c);
        VERIFY_EQ_RET(0, err, 0);

        /* Let half the threads exit, thereby leaving the cursor
         * cache with lots of cursors that should soon expire...
         */
        if (jclock_ns > ci->ttl)
            break;
    }

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, cursor_cache, test_pre_c0, test_post_c0)
{
    struct ikvdb *      h = NULL;
    struct hse_kvs *    kvs_h[3];
    const char *        mpool = __func__;
    const char *const   paramv[] = { "c0_diag_mode=true" };
    const int           num_threads = get_nprocs() * 3;
    struct cursor_info  info[num_threads];
    merr_t              err;
    int                 rc, i, j;
    char                namebuf[NELEM(kvs_h)][32];
    const char *        keyfmt = "%03d%d";
    const uint          pfxmod = 256;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvs_rparams  kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    for (i = 0; i < NELEM(kvs_h); ++i) {
        snprintf(namebuf[i], sizeof(namebuf[i]), "kvs%d", i);

        err = ikvdb_kvs_create(h, namebuf[i], &kvs_cp);
        ASSERT_EQ(0, err);
    }

    kvs_rp.perfc_level = PERFC_LEVEL_MIN;

again:
    for (i = 0; i < NELEM(kvs_h); ++i) {
        err = ikvdb_kvs_open(h, namebuf[i], &kvs_rp, 0, &kvs_h[i]);
        ASSERT_EQ(0, err);
        ASSERT_NE(NULL, kvs_h[i]);
    }

    /*
     * Seed the c0kvms with 10,000 keys such that there are 512
     * unique prefixes each with 10 unique keys.
     * each key has at least 3 bytes, so prefixes work
     * and get enough variation that some will age more than others
     * and the rb-tree in the cache sees sufficient churn
     */
    for (i = 0; i < 10000; ++i) {
        struct kvs_ktuple kt;
        struct kvs_vtuple vt;
        char              buf[64];
        int               n;

        n = snprintf(buf, sizeof(buf), keyfmt, i % pfxmod, i);
        ASSERT_GT(n, 0);

        kvs_ktuple_init(&kt, buf, n);
        kvs_vtuple_init(&vt, buf, n);

        for (j = 0; j < NELEM(kvs_h); ++j) {
            err = ikvdb_kvs_put(kvs_h[j], 0, NULL, &kt, &vt);
            ASSERT_EQ(err, 0);
        }
    }

    for (i = 0; i < num_threads; ++i) {
        info[i].keyfmt = keyfmt;
        info[i].pfxmod = pfxmod;
        info[i].kvs = kvs_h[i % NELEM(kvs_h)];
        info[i].ttl = jclock_ns + NSEC_PER_SEC;
        if (i >= num_threads / 2)
            info[i].ttl += NSEC_PER_SEC * (23 + (i % 8));

        rc = pthread_create(&info[i].td, 0, parallel_cursors, &info[i]);
        if (rc) {
            if (rc == EAGAIN || rc == ENOMEM) {
                usleep(333);
                --i;
                continue;
            }
        }

        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; ++i) {
        rc = pthread_join(info[i].td, 0);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < NELEM(kvs_h); ++i) {
        err = ikvdb_kvs_close(kvs_h[i]);
        ASSERT_EQ(err, 0);
    }

    if (kvs_rp.perfc_level == PERFC_LEVEL_MIN) {
        kvs_rp.perfc_level = PERFC_LEVEL_MAX;
        goto again;
    }

    kvs_rp.perfc_level = PERFC_LEVEL_DEFAULT;

    err = ikvdb_close(h);
    ASSERT_EQ(err, 0);
}

#if 0
MTF_DEFINE_UTEST_PREPOST(ikvdb_test, cursor_2, test_pre_c0, test_post_c0)
{
    struct ikvdb          *h = NULL;
    struct hse_kvs        *kvs[4] = { };
    char *                 names[4] = { "k1", "k2", "k3", "k4" };
    const char *           mpool = __func__;
    struct mpool *         ds  = (struct mpool *)-1;
    struct hse_params *    params;
    struct hse_kvdb_opspec opspec;
    struct hse_kvs_cursor *cur;
    struct kvs_ktuple      kt = { 0 };
    struct kvs_vtuple      vt = { 0 };
    const void *           key;
    const void *           val;
    size_t                 klen, vlen;
    merr_t                 err;
    bool                   eof;
    int                    i;

    HSE_KVDB_OPSPEC_INIT(&opspec);

    hse_params_create(&params);

    err = hse_params_set(params, "kvdb.c0_diag_mode", "1");
    ASSERT_EQ(err, 0);

    err = ikvdb_open(mpool, NULL, ds, params, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    for (i = 0; i < 4; ++i) {
        err = ikvdb_kvs_create(h, names[i], NULL);
        ASSERT_EQ(0, err);
    }

    for (i = 0; i < 4; ++i) {
        err = ikvdb_kvs_open(h, names[i], 0, 0, &kvs[i]);
        ASSERT_EQ(0, err);
    }

    /*
     * put 1M keys into multiple kvs, and multiple kvms
     * prevent kvms deletion by back-door reference
     * prevent ingest by creating a cursor
     * test update by refreshing this cursor periodically
     */
    for (i = 0; i < 1000000; ++i) {
        ASSERT_EQ(i, i);
        ASSERT_NE(i, 0);
    }

    err = ikvdb_close(h);
    ASSERT_EQ(err, 0);

    hse_params_destroy(params);
}
#endif

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, kvdb_sync_test, test_pre, test_post)
{
    struct ikvdb *      h = NULL;
    const char *        mpool = __func__;
    const char *        kvs_base = "kvs";
    const char *const   paramv[] = { "c0_diag_mode=true" };
    u8                  kvs_cnt = 5;
    merr_t              err;
    u32                 i;
    struct hse_kvs *    kvs_h[kvs_cnt];
    char **             list;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvs_rparams  kvs_rp = kvs_rparams_defaults();
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    for (i = 0; i < kvs_cnt; i++) {
        char kvs[HSE_KVS_NAME_LEN_MAX];

        snprintf(kvs, sizeof(kvs), "%s%d", kvs_base, i);

        err = ikvdb_kvs_create(h, kvs, &kvs_cp);
        ASSERT_EQ(0, err);

        err = ikvdb_kvs_open(h, kvs, &kvs_rp, 0, &kvs_h[i]);
        ASSERT_EQ(0, err);
    }

    err = ikvdb_kvs_names_get(h, 0, &list);
    ASSERT_EQ(0, err);

    for (i = 0; i < kvs_cnt; i++) {
        char kvs[HSE_KVS_NAME_LEN_MAX];

        snprintf(kvs, sizeof(kvs), "%s%d", kvs_base, i);

        ASSERT_STREQ(list[i], kvs);
    }

    ikvdb_kvs_names_free(h, list);

    err = ikvdb_sync(h, 0);
    ASSERT_EQ(0, err);

    for (i = 0; i < kvs_cnt; ++i) {
        err = ikvdb_kvs_close(kvs_h[i]);
        ASSERT_EQ(0, err);
    }

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);
}

struct thread_info {
    struct ikvdb *  h;
    atomic_t *      num_opens;
    struct hse_kvs *kvs_h;
    pthread_t       tid;
};

void *
parallel_kvs_open(void *arg)
{
    struct thread_info *info = arg;
    merr_t              err;
    struct kvs_rparams  kvs_rp = kvs_rparams_defaults();

    err = ikvdb_kvs_open(info->h, "same_kvs", &kvs_rp, 0, &info->kvs_h);

    if (!err)
        atomic_inc(info->num_opens);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, kvdb_parallel_kvs_opens, test_pre, test_post)
{
    const int           num_threads = get_nprocs() * 2;
    atomic_t            num_opens;
    int                 i;
    merr_t              err;
    struct ikvdb *      h;
    struct thread_info  infov[num_threads];
    const char *        mpool = __func__;
    const char *const   paramv[] = { "c0_diag_mode=true" };
    int                 rc;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, h);

    err = ikvdb_kvs_create(h, "same_kvs", &kvs_cp);
    ASSERT_EQ(0, err);

    atomic_set(&num_opens, 0);

    for (i = 0; i < num_threads; ++i) {
        infov[i].h = h;
        infov[i].kvs_h = NULL;
        infov[i].num_opens = &num_opens;

        rc = pthread_create(&infov[i].tid, 0, parallel_kvs_open, infov + i);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; ++i) {
        rc = pthread_join(infov[i].tid, 0);
        ASSERT_EQ(0, rc);
    }

    ASSERT_EQ(1, atomic_read(&num_opens));

    for (i = 0; i < num_threads; ++i) {
        if (infov[i].kvs_h) {
            err = ikvdb_kvs_close(infov[i].kvs_h);
            ASSERT_EQ(0, err);
        }
    }

    err = ikvdb_close(h);
    ASSERT_EQ(0, err);
}

void *
parallel_kvs_make(void *info)
{
    struct thread_info *arg = (struct thread_info *)info;
    struct kvs_cparams  kvs_cp = kvs_cparams_defaults();

    ikvdb_kvs_create(arg->h, "same_kvs", &kvs_cp);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, kvdb_parallel_kvs_makes, test_pre, test_post)
{
    const int           num_threads = get_nprocs() * 2;
    int                 i;
    merr_t              err;
    pthread_t           t[num_threads];
    struct thread_info  info = { 0 };
    const char         *mpool = __func__;
    const char *const   paramv[] = { "c0_diag_mode=true" };
    int                 rc;
    unsigned int        kvs_cnt;
    struct kvdb_rparams params = kvdb_rparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, &params, &info.h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, info.h);

    for (i = 0; i < num_threads; ++i) {
        rc = pthread_create(t + i, 0, parallel_kvs_make, &info);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; ++i) {
        rc = pthread_join(t[i], 0);
        ASSERT_EQ(0, rc);
    }

    ikvdb_kvs_count(info.h, &kvs_cnt);
    ASSERT_EQ(1, kvs_cnt);

    err = ikvdb_close(info.h);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, prefix_delete_test, test_pre, test_post)
{
    merr_t              err;
    const char *const   kvdb_open_paramv[] = { "c0_diag_mode=true" };
    const char *const   kvs_make_paramv[] = { "prefix.length=4" };
    struct kvs_ktuple   kt;
    struct ikvdb *      kvdb = NULL;
    struct hse_kvs *    kvs = NULL;
    struct kvdb_rparams kvdb_rp = kvdb_rparams_defaults();
    struct kvs_rparams  kvs_rp = kvs_rparams_defaults();

    err = argv_deserialize_to_kvdb_rparams(NELEM(kvdb_open_paramv), kvdb_open_paramv, &kvdb_rp);
    ASSERT_EQ(0, err);

    err = argv_deserialize_to_kvs_cparams(NELEM(kvs_make_paramv), kvs_make_paramv, &g_kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_open(__func__, &kvdb_rp, &kvdb);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvdb);

    err = ikvdb_kvs_create(kvdb, "kvs", &g_kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(kvdb, "kvs", &kvs_rp, 0, &kvs);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs);

    /* ikvdb_kvs_prefix_delete w/ incorrect prefix length */
    kt.kt_len = 2;
    kt.kt_data = "ba";
    err = ikvdb_kvs_prefix_delete(kvs, 0, NULL, &kt);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = ikvdb_kvs_close(kvs);
    ASSERT_EQ(err, 0);

    err = ikvdb_close(kvdb);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, ikvdb_test_various, test_pre, test_post)
{
    char   invalid[HSE_KVS_NAME_LEN_MAX * 2];
    merr_t err;
    int    i;

    err = validate_kvs_name("foo");
    ASSERT_EQ(err, 0);

    snprintf(invalid, sizeof(invalid), "frog%%");
    err = validate_kvs_name(invalid);
    ASSERT_NE(err, 0);

    snprintf(invalid, sizeof(invalid), "!toad");
    err = validate_kvs_name(invalid);
    ASSERT_NE(err, 0);

    snprintf(invalid, sizeof(invalid), "%*c", (int)sizeof(invalid) - 1, 'x');
    err = validate_kvs_name(invalid);
    ASSERT_NE(err, 0);

    for (i = 0; i < 1000; ++i)
        kvs_init();

    for (i = 0; i < 1000; ++i)
        kvs_fini();
}

MTF_DEFINE_UTEST(ikvdb_test, ikvdb_hash_test)
{
    const char *data = "slartibartfast";
    u64         hash, ref;

    ref = hse_hash64(data, 4);

    hash = pfx_hash64(data, strlen(data), 4);
    ASSERT_EQ(ref, hash);

    hash = pfx_hash64(data, 4, strlen(data));
    ASSERT_EQ(ref, hash);
}

MTF_DEFINE_UTEST_PREPOST(ikvdb_test, ikvdb_mclass_policies_test, test_pre, test_post)
{
    const char *          mpool = __func__;
    struct ikvdb *        store = NULL;
    merr_t                err;
    struct mclass_policy *policy = NULL;
    const char **         default_policies;
    int                   count;
    int                   i;
    struct kvdb_rparams   params = kvdb_rparams_defaults();

    count = mclass_policy_get_num_default_policies();
    default_policies = mclass_policy_get_default_policy_names();

    err = ikvdb_open(mpool, &params, &store);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, store);

    for (i = 0; i < count; i++) {
        policy = ikvdb_get_mclass_policy(store, default_policies[i]);
        ASSERT_NE(policy, NULL);
    }

    policy = ikvdb_get_mclass_policy(store, "whoami_policy");
    ASSERT_EQ(policy, NULL);

    err = ikvdb_close(store);
    ASSERT_EQ(0, err);
}

MTF_END_UTEST_COLLECTION(ikvdb_test);
