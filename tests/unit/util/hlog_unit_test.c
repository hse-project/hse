/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <mtf/framework.h>
#include <hse/util/hash.h>
#include <hse/util/hlog.h>

MTF_BEGIN_UTEST_COLLECTION(hlog);

MTF_DEFINE_UTEST(hlog, t_hlog_create)
{
    merr_t       err;
    struct hlog *hlog;
    uint         p, i;

    for (p = 0; p < HLOG_PRECISION_MAX + 4; p++) {
        err = hlog_create(&hlog, p);
        if (p < HLOG_PRECISION_MIN || p > HLOG_PRECISION_MAX)
            ASSERT_EQ(merr_errno(err), EINVAL);
        else {
            ASSERT_EQ(err, 0);
            hlog_destroy(hlog);
        }
    }

    p = HLOG_PRECISION_MIN;
    for (i = 1; i <= 3; i++) {
        mapi_inject_once_ptr(mapi_idx_malloc, i, 0);
        err = hlog_create(&hlog, p);
        if (i < 3)
            ASSERT_EQ(merr_errno(err), ENOMEM);
        else {
            ASSERT_EQ(err, 0);
            hlog_destroy(hlog);
        }
    }
    mapi_inject_unset(mapi_idx_malloc);
}

static void
add(struct hlog *hlog, uint64_t start, uint64_t count)
{
    uint64_t i, h;

    for (i = 0; i < count; i++) {
        h = hse_hash64_seed(&start, 8, 0xabcd123400112233ull);
        hlog_add(hlog, h);
        start++;
    }
}

static int
check(struct mtf_test_info *lcl_ti, uint precision, uint64_t count)
{
    merr_t       err;
    struct hlog *hlog;
    uint64_t     i, est, est2;
    double       pct;

    err = hlog_create(&hlog, precision);
    ASSERT_EQ_RET(err, 0, -1);

    i = hlog_precision(hlog);
    ASSERT_EQ_RET(i, precision, -1);

    add(hlog, 0, count);
    est = hlog_card(hlog);

    /* add some duplicates */
    add(hlog, 0, count / 10);
    est2 = hlog_card(hlog);

    ASSERT_EQ_RET(est, est2, -1);

    if (count) {
        pct = (double)est - (double)count;
        pct = 100 * pct / count;
    } else {
        pct = 0.0;
    }

    printf("hlog: %2u  %10lu  %10lu  %6.2f%%\n", precision, count, est, pct);

    hlog_destroy(hlog);

    return 0;
}

MTF_DEFINE_UTEST(hlog, t_hlog)
{
    int  err;
    uint p, base;

    printf("hlog: %2s  %10s  %10s  %6s\n", "p", "actual", "estimate", "error");

    for (p = HLOG_PRECISION_MIN; p <= HLOG_PRECISION_MAX; p++) {

        for (base = 1; base <= 1 * 1000 * 1000; base = base * 10) {

            err = check(lcl_ti, p, base);
            ASSERT_EQ(err, 0);

            err = check(lcl_ti, p, base * 2);
            ASSERT_EQ(err, 0);

            err = check(lcl_ti, p, base * 5);
            ASSERT_EQ(err, 0);
        }
    }
}

MTF_END_UTEST_COLLECTION(hlog)
