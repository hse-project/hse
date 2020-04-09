/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>
#include <hse_test_support/random_buffer.h>

#include <hse_util/hse_err.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "../../kvdb/kvdb_params.h"
#include "../../kvdb/kvdb_log.h"

#include "../../kvdb/test/mock_c0cn.h"
#include "../../kvdb/test/mock_c1.h"
#include "mock_mpool.h"

static u64 c1_mdc_oid = 1;
static u64 c1_test_error;

static merr_t
_kvdb_log_replay(struct kvdb_log *log, u64 *oid1, u64 *oid2, u64 *c1_oid1, u64 *c1_oid2)
{
    *oid1 = 0;
    *oid2 = 0;
    *c1_oid1 = c1_mdc_oid;
    *c1_oid2 = c1_mdc_oid;

    return 0;
}

/*
 * Pre and Post Functions
 */
static int
test_pre(struct mtf_test_info *ti)
{
    mock_kvdb_log_set();
    mock_c0cn_set();

    return 0;
}

int
test_pre_c1(struct mtf_test_info *ti)
{
    mock_kvdb_log_set();

    c1_mock_mpool();

    MOCK_SET(kvdb_log, _kvdb_log_replay);
    mapi_inject(mapi_idx_cndb_cnv_get, 0);
    mapi_inject(mapi_idx_cndb_cn_info_idx, 0);
    mapi_inject(mapi_idx_cndb_cn_count, 0);
    mapi_inject(mapi_idx_cndb_open, 0);
    mapi_inject(mapi_idx_cndb_close, 0);
    mapi_inject(mapi_idx_c0_prefix_del, 0);
    mapi_inject(mapi_idx_cndb_make, 0);
    mapi_inject(mapi_idx_cndb_alloc, 0);

    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    mock_kvdb_log_unset();
    mock_c0cn_unset();

    MOCK_UNSET(kvdb_log, _kvdb_log_replay);
    mapi_inject_unset(mapi_idx_cndb_cnv_get);
    mapi_inject_unset(mapi_idx_cndb_cn_info_idx);
    mapi_inject_unset(mapi_idx_cndb_cn_count);
    mapi_inject_unset(mapi_idx_cndb_open);
    mapi_inject_unset(mapi_idx_cndb_close);
    mapi_inject_unset(mapi_idx_c0_prefix_del);
    mapi_inject_unset(mapi_idx_cndb_make);
    mapi_inject_unset(mapi_idx_cndb_alloc);

    return 0;
}

static int
test_post_c1(struct mtf_test_info *ti)
{
    mock_kvdb_log_unset();

    c1_unmock_mpool();

    MOCK_UNSET(kvdb_log, _kvdb_log_replay);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(c1_make_test)

MTF_DEFINE_UTEST_PREPOST(c1_make_test, make_mock_test, test_pre, test_post)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    merr_t              err;
    struct mpool *      ds = NULL;

    mapi_inject(mapi_idx_c1_alloc, merr(EIO));
    mapi_inject(mapi_idx_cndb_alloc, 0);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_NE(0, err);

    /* [HSE_REVISIT] these ASSERT_EQs were inverted and should be restored */
    mapi_inject(mapi_idx_c1_alloc, 0);
    mapi_inject(mapi_idx_c1_make, merr(EIO));
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_NE(0, err);

    mapi_inject(mapi_idx_c1_alloc, 0);
    mapi_inject(mapi_idx_c1_make, 0);
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_c1_alloc);
    mapi_inject_unset(mapi_idx_c1_make);
    mapi_inject_unset(mapi_idx_cndb_make);

    mock_c1_unset();
}

MTF_DEFINE_UTEST_PREPOST(c1_make_test, make_test, test_pre_c1, test_post_c1)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    merr_t              err;
    struct mpool *      ds = NULL;

    mapi_inject(mapi_idx_cndb_alloc, 0);

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(c1_make_test, make_test2, test_pre_c1, test_post_c1)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    merr_t              err;
    struct mpool *      ds = NULL;

    mapi_inject(mapi_idx_mpool_mdc_alloc, merr(ev(EIO)));
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    mapi_inject_unset(mapi_idx_mpool_mdc_alloc);

    mapi_inject(mapi_idx_mpool_mdc_commit, merr(ev(EIO)));
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    mapi_inject_unset(mapi_idx_mpool_mdc_commit);

    mapi_inject(mapi_idx_mpool_mlog_commit, merr(ev(EIO)));
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    mapi_inject_unset(mapi_idx_mpool_mlog_commit);

    mapi_inject(mapi_idx_mpool_mlog_put, merr(ev(EIO)));
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    mapi_inject_unset(mapi_idx_mpool_mlog_put);

    mapi_inject(mapi_idx_mpool_mlog_find_get, merr(ev(EIO)));
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    mapi_inject_unset(mapi_idx_mpool_mlog_find_get);

    mapi_inject(mapi_idx_mpool_mlog_open, merr(ev(EIO)));
    err = ikvdb_make(ds, 0, 0, &cp, 0);
    mapi_inject_unset(mapi_idx_mpool_mlog_open);

    if (err)
        c1_test_error++;
}

MTF_DEFINE_UTEST_PREPOST(c1_make_test, open_test, test_pre_c1, test_post_c1)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    merr_t              err;

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(c1_make_test, open_test2, test_pre_c1, test_post_c1)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    merr_t              err;

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mdc_open, merr(ev(EIO)));
    err = ikvdb_open(mpool, ds, NULL, &hdl);
    mapi_inject_unset(mapi_idx_mpool_mdc_open);

    mapi_inject(mapi_idx_mpool_mlog_find_get, merr(ev(EIO)));
    err = ikvdb_open(mpool, ds, NULL, &hdl);
    mapi_inject_unset(mapi_idx_mpool_mlog_find_get);

    mapi_inject(mapi_idx_mpool_mlog_open, merr(ev(EIO)));
    err = ikvdb_open(mpool, ds, NULL, &hdl);
    mapi_inject_unset(mapi_idx_mpool_mlog_open);
}

MTF_DEFINE_UTEST_PREPOST(c1_make_test, make_at_open, test_pre_c1, test_post_c1)
{
    struct kvdb_cparams cp = kvdb_cparams_defaults();
    struct mpool *      ds = NULL;
    struct ikvdb *      hdl = NULL;
    const char *        mpool = "mpool_alpha";
    merr_t              err;

    err = ikvdb_make(ds, 0, 0, &cp, 0);
    ASSERT_EQ(0, err);

    c1_mdc_oid = 0;
    err = ikvdb_open(mpool, ds, NULL, &hdl);
    ASSERT_EQ(0, err);

    err = ikvdb_close(hdl);
    ASSERT_EQ(0, err);
}

MTF_END_UTEST_COLLECTION(c1_make_test);
