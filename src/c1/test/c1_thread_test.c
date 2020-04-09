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
#include <hse_ikvdb/kvdb_rparams.h>

#include "../../kvdb/kvdb_params.h"
#include "../../kvdb/kvdb_log.h"

#include "../../kvdb/test/mock_c0cn.h"
#include "../../kvdb/test/mock_c1.h"
#include "mock_mpool.h"
#include "../c1_private.h"

static int
test_pre(struct mtf_test_info *ti)
{
    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    return 0;
}

static void
thr_func(void *arg)
{
}

MTF_BEGIN_UTEST_COLLECTION(c1_thread_test)

MTF_DEFINE_UTEST_PREPOST(c1_thread_test, basic, test_pre, test_post)
{
    struct c1_thread *thr;
    merr_t            err;

    err = c1_thread_create("mythread", thr_func, NULL, &thr);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, thr);

    err = c1_thread_destroy(thr);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_thread_create("mythread", thr_func, NULL, &thr);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);
}

MTF_END_UTEST_COLLECTION(c1_thread_test);
