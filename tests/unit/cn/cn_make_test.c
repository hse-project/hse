/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse/error/merr.h>
#include <hse_util/inttypes.h>
#include <hse_util/log2.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvdb_health.h>

#include <cn/cn_internal.h>

static struct kvdb_health health;

static int
init(struct mtf_test_info *lcl_ti)
{
    return 0;
}

static int
fini(struct mtf_test_info *lcl_ti)
{
    return 0;
}

static int
pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

static int
post(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(cn_make_test, init, fini);

MTF_DEFINE_UTEST_PREPOST(cn_make_test, cn_make1, pre, post)
{
    struct mpool *     ds = (void *)-1;
    merr_t             err;
    struct kvs_cparams cp;

    cp = kvs_cparams_defaults();

    err = cn_make(ds, &cp, &health);
    ASSERT_EQ(0, err);
}

MTF_END_UTEST_COLLECTION(cn_make_test)
