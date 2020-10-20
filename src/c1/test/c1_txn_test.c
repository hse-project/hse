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
#include <hse_ikvdb/kvb_builder.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/hse_params_internal.h>

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
#include "mock_mpool.h"

#include "../../kvdb/kvdb_params.h"
#include "../../kvdb/kvdb_log.h"
#include "../../kvdb/test/mock_c0cn.h"
#include "../../kvdb/test/mock_c1.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

struct kvdb_kvs;

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

/* After effectively eliminating many mallocs from c1 this test
 * starting crashing in kvb_builder_iter_put() due to an unexpected
 * null ptr in the iterator.  I suspect this is because the test is
 * now getting much farther along than expected by whomever wrote
 * the mapi malloc tests in this file.  Mocking kvb_builder_iter_put()
 * avoids the crash, but probably the mapi malloc tests need to be
 * revisited and perhaps expunged.
 */
static void
_kvb_builder_iter_put(struct kvb_builder_iter *iter)
{
    free(iter);
}

static void
mocks_unset(void)
{
    mapi_inject_clear();
}

struct kvs_cparams kvs_cp;

static void
mocks_set(struct mtf_test_info *info)
{
    mocks_unset();
    mock_c0skm_unset();
    mock_c1_unset();

    MOCK_SET(kvset_builder, _kvset_builder_create);
    MOCK_SET(kvset_builder, _kvset_builder_set_agegroup);
    MOCK_SET(kvb_builder, _kvb_builder_iter_put);

    mapi_inject(mapi_idx_cndb_cn_drop, 0);

    mapi_inject(mapi_idx_kvset_builder_get_mblocks, 0);
    mapi_inject(mapi_idx_kvset_builder_add_key, 0);
    mapi_inject(mapi_idx_kvset_builder_add_val, 0);
    mapi_inject(mapi_idx_kvset_builder_add_nonval, 0);
    mapi_inject(mapi_idx_kvset_builder_add_vref, 0);
    mapi_inject(mapi_idx_kvset_builder_destroy, 0);
    mapi_inject(mapi_idx_kvset_mblocks_destroy, 0);

    kvs_cp = kvs_cparams_defaults();

    mapi_inject_ptr(mapi_idx_cndb_cn_cparams, &kvs_cp);
    mapi_inject_ptr(mapi_idx_cn_get_cparams, &kvs_cp);
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

MTF_BEGIN_UTEST_COLLECTION(c1_txn_test)

MTF_DEFINE_UTEST_PREPOST(c1_txn_test, commit, test_pre, test_post)
{
    struct kvdb_cparams    cp = kvdb_cparams_defaults();
    struct kvs_rparams     rp = kvs_rparams_defaults();
    struct mpool *         ds = NULL;
    struct ikvdb *         hdl = NULL;
    const char *           mpool = "mpool_alpha";
    const char *           kvs = "kvs-0";
    struct hse_kvs *       kvs_h = NULL;
    merr_t                 err;
    struct kvs_ktuple      kt;
    struct kvs_vtuple      vt;
    int                    vt_len = 32 * 1024;
    char *                 buffer;
    struct hse_kvdb_opspec os;
    struct cn *            mock_cn;

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

    os.kop_txn = ikvdb_txn_alloc(hdl);
    ASSERT_NE(0, os.kop_txn);

    /*
     * Dummy transaction
     */
    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "key", 3);
    kvs_vtuple_init(&vt, buffer, vt_len);

    err = ikvdb_kvs_put(kvs_h, &os, &kt, &vt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "key", 3);
    err = ikvdb_kvs_del(kvs_h, &os, &kt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "Key", 3);
    kvs_vtuple_init(&vt, "data", 4);
    err = ikvdb_kvs_put(kvs_h, &os, &kt, &vt);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "Key", 3);
    err = ikvdb_kvs_del(kvs_h, &os, &kt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_abort(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    ikvdb_txn_free(hdl, os.kop_txn);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_sync(hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    free(buffer);
    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_txn_test, commit_replay, test_pre, test_post)
{
    struct kvdb_cparams    cp = kvdb_cparams_defaults();
    struct kvs_rparams     rp = kvs_rparams_defaults();
    struct mpool *         ds = NULL;
    struct ikvdb *         hdl = NULL;
    const char *           mpool = "mpool_alpha";
    const char *           kvs = "kvs-0";
    struct hse_kvs *       kvs_h = NULL;
    merr_t                 err;
    struct kvs_ktuple      kt;
    struct kvs_vtuple      vt;
    int                    vt_len = 32 * 1024;
    char *                 buffer;
    struct hse_kvdb_opspec os;
    struct cn *            mock_cn;

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

    os.kop_txn = ikvdb_txn_alloc(hdl);
    ASSERT_NE(0, os.kop_txn);

    /*
     * Dummy transaction
     */
    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "key", 3);
    kvs_vtuple_init(&vt, buffer, vt_len);

    err = ikvdb_kvs_put(kvs_h, &os, &kt, &vt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_sync(hdl);
    ASSERT_EQ(0, err);
    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "key", 3);
    err = ikvdb_kvs_del(kvs_h, &os, &kt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "key1", 3);
    kvs_vtuple_init(&vt, "data", 4);
    err = ikvdb_kvs_put(kvs_h, &os, &kt, &vt);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "Key", 3);
    err = ikvdb_kvs_del(kvs_h, &os, &kt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_abort(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    ikvdb_txn_free(hdl, os.kop_txn);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_sync(hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_c1_is_clean, 0);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_c1_is_clean);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    free(buffer);
    destroy_mock_cn(mock_cn);
}

static merr_t
c1_txn_test_perform_ingest(struct ikvdb *hdl, struct hse_kvs *kvs_h, bool pdel)
{
    struct kvs_ktuple      kt;
    struct kvs_vtuple      vt;
    int                    vt_len = 128;
    char *                 buffer;
    struct hse_kvdb_opspec os;
    int                    i;
    merr_t                 err;
    size_t                 pfx_len;

    buffer = malloc(vt_len);
    if (!buffer)
        return merr(ev(ENOMEM));

    os.kop_txn = NULL;
    err = 0;

    for (i = 0; i < 3; i++) {
        os.kop_txn = ikvdb_txn_alloc(hdl);
        if (!os.kop_txn)
            goto err_exit;

        err = ikvdb_txn_begin(hdl, os.kop_txn);
        if (err)
            goto err_exit;

        kvs_ktuple_init(&kt, "key", 3);
        kvs_vtuple_init(&vt, buffer, vt_len);

        err = ikvdb_kvs_put(kvs_h, &os, &kt, &vt);
        if (err)
            goto err_exit;

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
        if (err)
            goto err_exit;

        if (pdel) {
            err = ikvdb_kvs_prefix_delete(kvs_h, &os, &kt, &pfx_len);
            if (err)
                goto err_exit;
        }

        err = ikvdb_txn_commit(hdl, os.kop_txn);
        if (err)
            goto err_exit;

        err = ikvdb_kvs_put(kvs_h, NULL, &kt, &vt);
        if (err)
            goto err_exit;

        err = ikvdb_sync(hdl);
        if (err)
            goto err_exit;

        ikvdb_txn_free(hdl, os.kop_txn);
        os.kop_txn = NULL;
    }

err_exit:
    free(buffer);
    ikvdb_txn_free(hdl, os.kop_txn);

    return err;
}

MTF_DEFINE_UTEST_PREPOST(c1_txn_test, commit_replay2, test_pre, test_post)
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

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    err = c1_txn_test_perform_ingest(hdl, kvs_h, false);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_c1_is_clean, 0);
    mapi_inject(mapi_idx_c1_ingest_kvbundle, true);
    mapi_inject(mapi_idx_c1_ingest_seqno, false);
    mapi_inject(mapi_idx_c1_kvmsgen, 0);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_c1_is_clean);
    mapi_inject_unset(mapi_idx_c1_ingest_kvbundle);
    mapi_inject_unset(mapi_idx_c1_ingest_seqno);
    mapi_inject_unset(mapi_idx_c1_kvmsgen);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_txn_test, commit_replay3, test_pre, test_post)
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
    int                 i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    for (i = 1; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_txn_test_perform_ingest(hdl, kvs_h, false);
        mapi_inject_unset(mapi_idx_malloc);
    }

    for (i = 1; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_txn_test_perform_ingest(hdl, kvs_h, false);
        mapi_inject_unset(mapi_idx_malloc);
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_c1_is_clean, 0);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_c1_is_clean);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_txn_test, commit_replay4, test_pre, test_post)
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
    int                 i;

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    err = ikvdb_kvs_open(hdl, kvs, 0, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    for (i = 1; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_txn_test_perform_ingest(hdl, kvs_h, false);
        mapi_inject_unset(mapi_idx_malloc);
    }

    for (i = 1; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_txn_test_perform_ingest(hdl, kvs_h, false);
        mapi_inject_unset(mapi_idx_malloc);
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_c1_ikvdb, 0);
    mapi_inject(mapi_idx_c1_replay_on_ikvdb, merr(ev(EIO)));

    err = ikvdb_open(mpool, ds, NULL, &hdl);

    mapi_inject_unset(mapi_idx_c1_ikvdb);
    mapi_inject_unset(mapi_idx_c1_replay_on_ikvdb);
    mapi_inject_unset(mapi_idx_c1_is_clean);

    err = ikvdb_close(hdl);

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_txn_test, commit_replay5, test_pre, test_post)
{
    struct hse_params * params;
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct kvs_rparams  rp = kvs_rparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    const char *        kvs = "kvs-0";
    const char *        kvs1 = "kvs-1";
    struct hse_kvs *    kvs_h = NULL;
    merr_t              err;
    struct cn *         mock_cn;
    int                 i;

    hse_params_create(&params);

    err = hse_params_set(params, "kvdb.perfc_enable", "1");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &rp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, params, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs, NULL);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_ikvdb_kvs_put);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_del);
    mapi_inject_unset(mapi_idx_ikvdb_kvs_prefix_delete);

    err = ikvdb_kvs_open(hdl, kvs, params, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    for (i = 1; i < 10; i++) {
        err = c1_txn_test_perform_ingest(hdl, kvs_h, false);
        ASSERT_EQ(0, err);
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = hse_params_set(params, "kvs.pfx_len", "3");
    ASSERT_EQ(0, err);

    err = hse_params_to_kvs_cparams(params, kvs1, NULL, &kvs_cp);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_make(hdl, kvs1, params);
    ASSERT_EQ(0, err);

    err = ikvdb_kvs_open(hdl, kvs1, params, 0, &kvs_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvs_h);

    for (i = 1; i < 10; i++) {
        err = c1_txn_test_perform_ingest(hdl, kvs_h, true);
        ASSERT_EQ(0, err);
    }

    for (i = 1; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_txn_test_perform_ingest(hdl, kvs_h, true);
        mapi_inject_unset(mapi_idx_malloc);
    }

    for (i = 1; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_txn_test_perform_ingest(hdl, kvs_h, true);
        mapi_inject_unset(mapi_idx_malloc);
    }

    err = ikvdb_kvs_close(kvs_h);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_c1_ikvdb, 0);
    mapi_inject(mapi_idx_c1_replay_on_ikvdb, merr(ev(EIO)));

    err = ikvdb_open(mpool, ds, params, &hdl);

    mapi_inject_unset(mapi_idx_c1_ikvdb);
    mapi_inject_unset(mapi_idx_c1_replay_on_ikvdb);
    mapi_inject_unset(mapi_idx_c1_is_clean);

    err = ikvdb_close(hdl);

    destroy_mock_cn(mock_cn);

    hse_params_destroy(params);
}

#if 0
MTF_DEFINE_UTEST_PREPOST(c1_txn_test, fail,
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
    int                   vt_len = 32 * 1024;
    char                 *buffer;
    struct hse_kvdb_opspec    os;
    struct cn            *mock_cn;

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

    os.kop_txn = ikvdb_txn_alloc(hdl);
    ASSERT_NE(0, os.kop_txn);

    kvs_ktuple_init(&kt, "key", 3);
    vt.vt_data = buffer;
    vt.vt_len  = vt_len;

    mapi_inject(mapi_idx_mpool_mlog_append, merr(ev(EIO)));
    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "Key", 3);
    vt.vt_data = "data";
    vt.vt_len = strlen(vt.vt_data);
    err = ikvdb_kvs_put(kvs_h, &os, &kt, &vt);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "Key", 3);
    err = ikvdb_kvs_del(kvs_h, &os, &kt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    ikvdb_txn_free(hdl, os.kop_txn);

    err = ikvdb_kvs_close(kvs_h);
    /*
    ASSERT_NE(0, err);
    */

    err  = ikvdb_sync(hdl);
    /*
    ASSERT_NE(0, err);
    */
    mapi_inject_unset(mapi_idx_mpool_mlog_append);

    err  = ikvdb_close(hdl);
    /*
    ASSERT_NE(0, err);
    */

    destroy_mock_cn(mock_cn);
}

MTF_DEFINE_UTEST_PREPOST(c1_txn_test, fail2,
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
    int                   vt_len = 32 * 1024;
    char                 *buffer;
    struct hse_kvdb_opspec    os;
    struct cn            *mock_cn;

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

    os.kop_txn = ikvdb_txn_alloc(hdl);
    ASSERT_NE(0, os.kop_txn);

    kvs_ktuple_init(&kt, "key", 3);
    vt.vt_data = buffer;
    vt.vt_len  = vt_len;

    mapi_inject(mapi_idx_mpool_mlog_append, merr(ev(EIO)));
    err = ikvdb_txn_begin(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "Key", 3);
    vt.vt_data = "data";
    vt.vt_len = strlen(vt.vt_data);
    err = ikvdb_kvs_put(kvs_h, &os, &kt, &vt);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "Key", 3);
    err = ikvdb_kvs_del(kvs_h, &os, &kt);
    ASSERT_EQ(0, err);

    err = ikvdb_txn_commit(hdl, os.kop_txn);
    ASSERT_EQ(0, err);

    ikvdb_txn_free(hdl, os.kop_txn);

    err = ikvdb_kvs_close(kvs_h);
    /*
    ASSERT_NE(0, err);
    */

    err  = ikvdb_sync(hdl);
    /*
    ASSERT_NE(0, err);
    */
    mapi_inject_unset(mapi_idx_mpool_mlog_append);

    err  = ikvdb_close(hdl);
    /*
    ASSERT_NE(0, err);
    */

    destroy_mock_cn(mock_cn);
}
#endif

MTF_END_UTEST_COLLECTION(c1_txn_test);
