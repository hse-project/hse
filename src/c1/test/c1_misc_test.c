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
#include <hse_util/seqno.h>

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "../../c0/test/cn_mock.h"
#include <hse_test_support/key_generation.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_test_support/random_buffer.h>

#include "../../c0/c0sk_internal.h"
#include "../../c0/c0_cursor.h"
#include "../../kvdb/test/mock_c1.h"
#include "../../c1/c1_private.h"
#include "mock_mpool.h"

#include "../../kvdb/kvdb_params.h"
#include "../../kvdb/kvdb_log.h"
#include "../../kvdb/test/mock_c0cn.h"
#include "../../kvdb/test/mock_c1.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

struct mock_kvdb {
    struct c0sk *ikdb_c0sk;
};

static merr_t
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

static void
_kvset_builder_set_agegroup(struct kvset_builder *bldr, enum hse_mclass_policy_age age)
{
}

static merr_t
_cn_open(
    struct cn_kvdb *    cn_kvdb,
    struct mpool *      mp_dataset,
    struct kvdb_kvs *   kvs,
    struct cndb *       cndb,
    u64                 cnid,
    struct kvs_rparams *rp,
    const char *        mp_name,
    const char *        kvs_name,
    struct kvdb_health *health,
    uint                flags,
    struct cn **        cn_out)
{
    *cn_out = (struct cn *)-1;
    return 0;
}

static merr_t
_kvdb_log_replay(struct kvdb_log *log, u64 *oid1, u64 *oid2, u64 *c1_oid1, u64 *c1_oid2)
{
    *oid1 = 0;
    *oid2 = 0;
    *c1_oid1 = 1;
    *c1_oid2 = 1;

    return 0;
}

static void
mocks_unset(void)
{
    mapi_inject_clear();
}

struct kvs_cparams cp;

static void
mocks_set(struct mtf_test_info *info)
{
    mocks_unset();
    mock_c0skm_unset();
    mock_c1_unset();

    MOCK_SET(kvset_builder, _kvset_builder_create);
    MOCK_SET(kvset_builder, _kvset_builder_set_agegroup);

    mapi_inject(mapi_idx_cndb_cn_drop, 0);

    mapi_inject(mapi_idx_kvset_builder_get_mblocks, 0);
    mapi_inject(mapi_idx_kvset_builder_add_key, 0);
    mapi_inject(mapi_idx_kvset_builder_add_val, 0);
    mapi_inject(mapi_idx_kvset_builder_add_nonval, 0);
    mapi_inject(mapi_idx_kvset_builder_add_vref, 0);
    mapi_inject(mapi_idx_kvset_builder_destroy, 0);
    mapi_inject(mapi_idx_kvset_mblocks_destroy, 0);

    mapi_inject_ptr(mapi_idx_cndb_cn_cparams, &cp);
    mapi_inject_ptr(mapi_idx_cn_get_cparams, &cp);

    mapi_inject(mapi_idx_cn_get_sfx_len, 0);
}

static int
test_pre(struct mtf_test_info *ti)
{
    mocks_set(ti);

    c1_mock_mpool();

    MOCK_SET(kvdb_log, _kvdb_log_replay);
    MOCK_SET(cn, _cn_open);
    mapi_inject(mapi_idx_cndb_cn_info_idx, 0);
    mapi_inject(mapi_idx_cndb_cn_count, 0);
    mapi_inject(mapi_idx_cndb_open, 0);
    mapi_inject(mapi_idx_cndb_close, 0);
    mapi_inject(mapi_idx_c0_prefix_del, 0);
    mapi_inject(mapi_idx_cndb_make, 0);
    mapi_inject(mapi_idx_cndb_alloc, 0);
    mapi_inject(mapi_idx_kvdb_log_open, 0);
    mapi_inject(mapi_idx_kvdb_log_make, 0);
    mapi_inject(mapi_idx_kvdb_log_mdc_create, 0);
    mapi_inject(mapi_idx_cndb_replay, 0);
    mapi_inject(mapi_idx_kvdb_log_done, 0);
    mapi_inject(mapi_idx_cn_make, 0);
    mapi_inject(mapi_idx_cn_close, 0);
    mapi_inject(mapi_idx_cn_get_ingest_perfc, 0);
    mapi_inject(mapi_idx_cn_ref_get, 0);
    mapi_inject(mapi_idx_cn_ref_put, 0);
    mapi_inject(mapi_idx_cn_hash_get, 0);
    mapi_inject(mapi_idx_cn_periodic, 0);
    mapi_inject(mapi_idx_cndb_cn_make, 0);

    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    mock_kvdb_log_unset();
    mock_c0cn_unset();

    MOCK_UNSET(kvdb_log, _kvdb_log_replay);
    mapi_inject_unset(mapi_idx_cndb_cn_info_idx);
    mapi_inject_unset(mapi_idx_cndb_cn_count);
    mapi_inject_unset(mapi_idx_cndb_open);
    mapi_inject_unset(mapi_idx_cndb_close);
    mapi_inject_unset(mapi_idx_c0_prefix_del);
    mapi_inject_unset(mapi_idx_cndb_make);
    mapi_inject_unset(mapi_idx_cndb_alloc);
    mapi_inject_unset(mapi_idx_cn_periodic);
    mapi_inject_unset(mapi_idx_cndb_cn_make);
    mocks_unset();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(c1_misc_test)
MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc1, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct cn *         mock_cn;
    struct hse_params * params;

    hse_params_create(&params);

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, params, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    err = ikvdb_sync(hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_flush(hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    err = hse_params_set(params, "kvdb.rdonly", "1");
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, params, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    /* Test c1_get_capacity interface */
    ASSERT_EQ(HSE_C1_DEFAULT_CAP, c1_get_capacity(0));
    ASSERT_EQ(HSE_C1_MIN_CAP + 1, c1_get_capacity(HSE_C1_MIN_CAP + 1));
    ASSERT_EQ(HSE_C1_MIN_CAP, c1_get_capacity(HSE_C1_MIN_CAP));
    ASSERT_EQ(HSE_C1_MIN_CAP, c1_get_capacity(HSE_C1_MIN_CAP - 1));
    ASSERT_EQ(HSE_C1_MAX_CAP - 1, c1_get_capacity(HSE_C1_MAX_CAP - 1));
    ASSERT_EQ(HSE_C1_MAX_CAP, c1_get_capacity(HSE_C1_MAX_CAP));
    ASSERT_EQ(HSE_C1_MAX_CAP, c1_get_capacity(HSE_C1_MAX_CAP + 1));

    ASSERT_EQ(HSE_C1_MIN_CAP + 100, c1_get_capacity(HSE_C1_MIN_CAP + 100));

    destroy_mock_cn(mock_cn);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc2, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct cn *         mock_cn;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);
    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mlog_open, merr(ev(ENOENT)));
    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_mpool_mlog_open);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc3, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    merr_t              err;
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct cn *         mock_cn;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    mapi_inject_once(mapi_idx_mpool_mlog_close, 3, merr(ev(ENOMEM)));

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);
    mapi_inject_unset(mapi_idx_mpool_mlog_close);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    mapi_inject_once(mapi_idx_mpool_mlog_close, 4, merr(ev(ENOMEM)));
    err = ikvdb_open(mpool, ds, NULL, &hdl);
    mapi_inject_unset(mapi_idx_mpool_mlog_close);

    err = ikvdb_close(hdl);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc4, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct mpool *      ds = NULL;
    merr_t              err;
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct cn *         mock_cn;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_kvdb_log_abort, 0);
    mapi_inject_once(mapi_idx_mpool_mlog_alloc, 3, merr(ev(ENOMEM)));

    err = ikvdb_make(ds, 0, 0, &cp, 0);

    mapi_inject_unset(mapi_idx_mpool_mlog_alloc);
    mapi_inject_unset(mapi_idx_kvdb_log_abort);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc5, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    int                 vt_len = 1024;
    char *              buffer;
    struct cn *         mock_cn;
    int                 i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    buffer = malloc(vt_len);
    ASSERT_NE(0, buffer);

    for (i = 0; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i + 1, 0);

        kvs_ktuple_init(&kt, "key", 3);
        kvs_vtuple_init(&vt, buffer, vt_len);

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
        if (err)
            ASSERT_EQ(ENOMEM, merr_errno(err));
        mapi_inject_unset(mapi_idx_malloc);
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_sync(hdl);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    free(buffer);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc6, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    int                 vt_len = 1024;
    char *              buffer;
    struct cn *         mock_cn;
    int                 i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    buffer = malloc(vt_len);
    ASSERT_NE(0, buffer);

    for (i = 0; i < 20; i++) {
        mapi_inject_once(mapi_idx_malloc, i + 1, 0);
        kvs_ktuple_init(&kt, "key", 3);
        kvs_vtuple_init(&vt, buffer, vt_len);

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
        if (err)
            ASSERT_EQ(ENOMEM, merr_errno(err));
        mapi_inject_unset(mapi_idx_malloc);
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_sync(hdl);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    free(buffer);

    destroy_mock_cn(mock_cn);
}
static size_t c1_test_mdc_size = 8 * 1024 * 1024;

u64
_c1_get_capacity(u64 capacity)
{
    return c1_test_mdc_size;
}

u64
_c1_get_size(u64 size)
{
    return 0;
}

bool
_c1_jrnl_reaching_capacity(struct c1 *c1)
{
    static int count;

    count++;
    if ((count % 2))
        return false;

    return true;
}

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc7, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    int                 vt_len = 1024;
    char *              buffer;
    struct cn *         mock_cn;
    int                 i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    MOCK_SET(c1_ops, _c1_get_capacity);
    MOCK_SET(c1_ops, _c1_get_size);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    buffer = malloc(vt_len);
    ASSERT_NE(0, buffer);

    mapi_inject(mapi_idx_malloc, 0);

    for (i = 0; i < 1024; i++) {
        kvs_ktuple_init(&kt, "key", 3);
        kvs_vtuple_init(&vt, buffer, vt_len);

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
        if (err)
            ASSERT_EQ(ENOMEM, merr_errno(err));
    }

    mapi_inject_unset(mapi_idx_malloc);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_sync(hdl);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    free(buffer);

    MOCK_UNSET(c1_ops, _c1_get_capacity);
    MOCK_UNSET(c1_ops, _c1_get_size);
    mapi_inject_unset(mapi_idx_malloc);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc8, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    int                 vt_len = 1024 * 1024;
    char *              buffer;
    struct cn *         mock_cn;
    int                 i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    MOCK_SET(c1_ops, _c1_get_capacity);
    MOCK_SET(c1_ops, _c1_get_size);
    MOCK_SET(c1_ops, _c1_jrnl_reaching_capacity);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    buffer = malloc(vt_len);
    ASSERT_NE(0, buffer);

    for (i = 0; i < 1024; i++) {
        kvs_ktuple_init(&kt, "key", 3);
        kvs_vtuple_init(&vt, buffer, vt_len);

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
    }

    err = ikvdb_sync(hdl);
    mapi_inject(mapi_idx_mpool_mdc_append, merr(ev(EIO)));
    for (i = 0; i < 1024; i++) {
        kvs_ktuple_init(&kt, "key", 3);
        kvs_vtuple_init(&vt, buffer, vt_len);

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
    }
    mapi_inject_unset(mapi_idx_mpool_mdc_append);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    free(buffer);

    MOCK_UNSET(c1_ops, _c1_jrnl_reaching_capacity);
    MOCK_UNSET(c1_ops, _c1_get_capacity);
    MOCK_UNSET(c1_ops, _c1_get_size);

    destroy_mock_cn(mock_cn);
}

#if 0
MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc9,
             test_pre, test_post)
{
    struct kvdb_cparams   cp = kvdb_cparams_defaults();
    struct mpool         *ds  = NULL;
    struct ikvdb         *hdl = NULL;
    const char           *mpool = "mpool_alpha";
    const char           *kvs = "kvs-0";
    struct hse_kvs       *kvs_h = NULL;
    merr_t                err;
    struct kvs_ktuple     kt;
    struct kvs_vtuple     vt;
    int                   vt_len = 1024 * 1024;
    char                 *buffer;
    struct cn            *mock_cn;
    int                   i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    MOCK_SET(c1_ops, _c1_get_capacity);
    MOCK_SET(c1_ops, _c1_get_size);
    MOCK_SET(c1_ops, _c1_jrnl_reaching_capacity);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    buffer = malloc(vt_len);
    ASSERT_NE(0, buffer);

    for (i = 0; i < 512; i++) {
        mapi_inject_once(mapi_idx_mpool_mdc_append,
                 i + 1, merr(ev(EIO)));
        kvs_ktuple_init(&kt, "key", 3);
        vt.vt_data = buffer;
        vt.vt_len  = vt_len;

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
        mapi_inject_unset(mapi_idx_mpool_mdc_append);
        /*
        if (!(i % 10))
            err = ikvdb_flush(kvs_h);
        */
    }

    for (i = 0; i < 512; i++) {
        mapi_inject_once(mapi_idx_mpool_mlog_append,
                 i + 1, merr(ev(EIO)));
        kvs_ktuple_init(&kt, "key", 3);
        vt.vt_data = buffer;
        vt.vt_len  = vt_len;

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
        mapi_inject_unset(mapi_idx_mpool_mlog_append);
        /*
        if (!(i % 10))
            err = ikvdb_flush(kvs_h);
        */
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err  = ikvdb_sync(hdl);

    err  = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    free(buffer);

    MOCK_UNSET(c1_ops, _c1_jrnl_reaching_capacity);
    MOCK_UNSET(c1_ops, _c1_get_capacity);
    MOCK_UNSET(c1_ops, _c1_get_size);
}
#endif

MTF_DEFINE_UTEST_PREPOST(c1_misc_test, misc10, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    int                 vt_len = 1024 * 1024;
    char *              buffer;
    struct cn *         mock_cn;
    int                 i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    MOCK_SET(c1_ops, _c1_get_capacity);
    MOCK_SET(c1_ops, _c1_get_size);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    buffer = malloc(vt_len);
    ASSERT_NE(0, buffer);

    for (i = 0; i < 1024; i++) {
        kvs_ktuple_init(&kt, "key", 3);
        kvs_vtuple_init(&vt, buffer, vt_len);

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    if (!err)
        err = ikvdb_close(hdl);

    free(buffer);

    MOCK_UNSET(c1_ops, _c1_get_capacity);
    MOCK_UNSET(c1_ops, _c1_get_size);

    destroy_mock_cn(mock_cn);
}

MTF_END_UTEST_COLLECTION(c1_misc_test);
