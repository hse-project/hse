/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/test/mtf/framework.h>
#include <hse/test/mock/api.h>
#include <hse/test/mock/alloc_tester.h>

#include <hse/logging/logging.h>
#include <hse/util/timer.h>
#include <hse/util/minmax.h>
#include <hse/util/token_bucket.h>

#define K (1024L)
#define M (1024L * 1024)
#define G (1024L * 1024 * 1024)

static int
pre_collection(struct mtf_test_info *info)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

static int
tbkt_check_delay(struct mtf_test_info *lcl_ti, uint64_t delay, uint tolerance_pct, int debug)
{
    uint64_t lo, hi;
    bool result;

    lo = delay * (100 - tolerance_pct) / 100;
    hi = delay * (100 + tolerance_pct) / 100;
    result = (lo <= delay) && (delay <= hi);

    if (debug || !result) {
        log_debug("check %lu <= %lu <= %lu: %s",
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
tbkt_test(struct mtf_test_info *lcl_ti, uint64_t burst, uint64_t rate)
{
    struct tbkt tb;
    uint64_t    grow, req, req_tot;
    uint64_t    delay, now;
    int         debug = 1;
    int         i;
    uint        tolerance = 10;

    ASSERT_GE_RET((uint64_t)burst, (uint64_t)0, -1);
    ASSERT_GT_RET((uint64_t)rate, (uint64_t)0, -1);

    tbkt_init(&tb, burst, rate);
    log_debug("burst %ld, rate %ld", burst, rate);

    /* Request up to 'burst' tokens without delay, start with small request,
     * make it bigger each time. */
    req_tot = 0;
    grow = 1;
    while (req_tot < burst) {

        req = min(grow, burst - req_tot);
        req_tot += req;

        delay = tbkt_request(&tb, req, &now);
        ASSERT_EQ_RET(delay, 0, -1);

        if (grow < INT64_MAX / 2)
            grow += grow;
    }

    /* Ensure bucket is depleted.  When delay first hits, it should
     * be less than 1 second since we're requesting one second worth of
     * tokens each time.
     */
    delay = 0;
    while ((delay = tbkt_request(&tb, rate, &now)) == 0)
        ;
    ASSERT_LE_RET(delay, NSEC_PER_SEC, -1);

    /* Request (2 * rate) tokens, expect delay of 2 seconds.  But since
     * we're not actually delaying, expect the i-th iteration to get a
     * delay of (i * 2 * rate).
     */
    for (i = 0; i < 5; i++) {
        delay = tbkt_request(&tb, 2 * rate, &now);
        if (tbkt_check_delay(lcl_ti, i * 2 * NSEC_PER_SEC, tolerance, debug))
            return -1;
    }

    return 0;
}

MTF_DEFINE_UTEST(test, t_token_bucket)
{
    uint64_t bursts[] = {
        0, 1 * K, 12 * K, 123 * K, 1 * M, 12 * M, 123 * M, 1 * G, 2 * G, 3 * G, 100 * G
    };

    uint64_t rates[] = { 1 * M, 10 * M, 50 * M, 1 * G, 5 * G };

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
