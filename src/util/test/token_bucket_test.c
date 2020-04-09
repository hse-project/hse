/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>
#include <hse_test_support/mapi_alloc_tester.h>

#include <hse_util/timer.h>
#include <hse_util/minmax.h>
#include <hse_util/token_bucket.h>

#define K (1024L)
#define M (1024L * 1024)
#define G (1024L * 1024 * 1024)

static int
pre_collection(struct mtf_test_info *info)
{
    hse_log_set_squelch_ns(0);
    hse_log_set_verbose(true);
    hse_log_set_pri(HSE_DEBUG_VAL);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

static int
tbkt_check_delay(struct mtf_test_info *lcl_ti, u64 delay, uint tolerance_pct, int debug)
{
    u64  lo, hi;
    bool result;

    lo = delay * (100 - tolerance_pct) / 100;
    hi = delay * (100 + tolerance_pct) / 100;
    result = (lo <= delay) && (delay <= hi);

    if (debug || !result) {
        hse_log(
            HSE_DEBUG "check %lu <= %lu <= %lu: %s",
            (ulong)lo,
            (ulong)delay,
            (ulong)hi,
            result ? "pass" : "FAILED");
    }

    ASSERT_LE_RET(lo, delay, -1);
    ASSERT_GE_RET(hi, delay, -1);
    ASSERT_TRUE_RET(result, -1);

    return 0;
}

static int
tbkt_test(struct mtf_test_info *lcl_ti, u64 burst, u64 rate)
{
    struct tbkt tb;
    u64         grow, req, req_tot;
    u64         delay;
    int         debug = 1;
    int         i;
    uint        tolerance = 10;

    ASSERT_GE_RET((u64)burst, (u64)0, -1);
    ASSERT_GT_RET((u64)rate, (u64)0, -1);

    tbkt_init(&tb, burst, rate);
    hse_log(HSE_DEBUG "burst %ld, rate %ld", burst, rate);

    /* Request up to 'burst' tokens without delay, start with small request,
     * make it bigger each time. */
    req_tot = 0;
    grow = 1;
    while (req_tot < burst) {

        req = min(grow, burst - req_tot);
        req_tot += req;

        delay = tbkt_request(&tb, req);
        ASSERT_EQ_RET(delay, 0, -1);

        if (grow < S64_MAX / 2)
            grow += grow;
    }

    /* Ensure bucket is depleted.  When delay first hits, it should
     * be less than 1 second since we're requesting one second worth of
     * tokens each time.
     */
    delay = 0;
    while ((delay = tbkt_request(&tb, rate)) == 0)
        ;
    ASSERT_LE_RET(delay, NSEC_PER_SEC, -1);

    /* Request (2 * rate) tokens, expect delay of 2 seconds.  But since
     * we're not actually delaying, expect the i-th iteration to get a
     * delay of (i * 2 * rate).
     */
    for (i = 0; i < 5; i++) {
        delay = tbkt_request(&tb, 2 * rate);
        if (tbkt_check_delay(lcl_ti, i * 2 * NSEC_PER_SEC, tolerance, debug))
            return -1;
    }

    return 0;
}

MTF_DEFINE_UTEST(test, t_token_bucket)
{
    u64 bursts[] = {
        0, 1 * K, 12 * K, 123 * K, 1 * M, 12 * M, 123 * M, 1 * G, 2 * G, 3 * G, 100 * G
    };

    u64 rates[] = { 1 * M, 10 * M, 50 * M, 1 * G, 5 * G };

    uint bx, rx;
    int  rc;

    for (bx = 0; bx < NELEM(bursts); bx++) {
        for (rx = 0; rx < NELEM(rates); rx++) {
            rc = tbkt_test(lcl_ti, bursts[bx], rates[rx]);
            ASSERT_EQ(rc, 0);
        }
    }
}

MTF_END_UTEST_COLLECTION(test);
