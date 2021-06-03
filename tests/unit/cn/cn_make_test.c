/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvdb_health.h>
#include <mpool/mpool_ioctl.h>

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
    u32                i;
    struct kvs_cparams cp;

    cp = kvs_cparams_defaults();
    for (i = 0; i < 100; i++) {
        cp.cp_fanout = i;
        switch (i) {
            case 2:
            case 4:
            case 8:
            case 16:
                err = cn_make(ds, &cp, &health);
                ASSERT_EQ(err, 0);
                break;
            default:
                err = cn_make(ds, &cp, &health);
                ASSERT_EQ(merr_errno(err), EINVAL);
                break;
        }
    }
}

MTF_END_UTEST_COLLECTION(cn_make_test)
