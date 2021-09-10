/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/slab.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/timer.h>
#include <hse_util/timing.h>
#include <hse_util/logging.h>

int
timer_test_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
timer_test_post(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(timer_test, timer_test_pre, timer_test_post);

struct cb {
    struct timer_list timer;
    ulong             tinit;
    volatile ulong    tdispatch;
    volatile ulong    value;
};

void
cb_init(struct cb *cb, void (*func)(ulong), ulong data, int delay)
{
    ulong now = jiffies;

    setup_timer(&cb->timer, func, data);
    cb->timer.expires = now + msecs_to_jiffies(delay);

    cb->tinit = get_time_ns() / 1000;
    cb->tinit = cb->tinit - (cb->tinit % NSEC_PER_JIFFY);
    cb->tdispatch = 0;
    cb->value = 0;
}

void
timer_test_basic_cb(unsigned long data)
{
    struct cb *cb = (void *)data;

    cb->tdispatch = get_time_ns() / 1000;
    cb->value = data;
}

MTF_DEFINE_UTEST(timer_test, timer_test_jiffies)
{
    u64 j;

    /* millseconds...
     */
    j = msecs_to_jiffies(0);
    ASSERT_EQ(j, 0);

    j = msecs_to_jiffies(MSEC_PER_SEC);
    ASSERT_EQ(j, HSE_HZ);

    j = msecs_to_jiffies(MSEC_PER_SEC - 1);
    ASSERT_EQ(j, HSE_HZ - 1);

    j = msecs_to_jiffies(MSEC_PER_SEC * 2 - 1);
    ASSERT_EQ(j, HSE_HZ * 2 - 1);

    j = msecs_to_jiffies(-1);
    ASSERT_EQ(j, MAX_JIFFY_OFFSET);

    /* microseconds...
     */
    j = usecs_to_jiffies(0);
    ASSERT_EQ(j, 0);

    j = usecs_to_jiffies(USEC_PER_SEC);
    ASSERT_EQ(j, HSE_HZ);

    j = usecs_to_jiffies(USEC_PER_SEC - 1);
    ASSERT_EQ(j, HSE_HZ);

    j = usecs_to_jiffies(USEC_PER_SEC * 2 - 1);
    ASSERT_EQ(j, HSE_HZ * 2);

    j = usecs_to_jiffies(-1);
    ASSERT_EQ(j, MAX_JIFFY_OFFSET);

    /* nanoseconds...
     */
    j = nsecs_to_jiffies(0);
    ASSERT_EQ(j, 0);

    j = nsecs_to_jiffies(NSEC_PER_SEC);
    ASSERT_EQ(j, HSE_HZ);
}

/* Create timers of varying delays and measure the time
 * it takes for their callback to run.
 */
MTF_DEFINE_UTEST(timer_test, timer_test_basic)
{
    struct cb cb;
    ulong     tdiff;
    int       retries;
    int       rc;
    int       i;

    for (i = 1; i < 9; ++i) {
        while (1) {
            ulong jlast = jiffies;

            while (jlast == jiffies)
                usleep(1);

            cb_init(&cb, timer_test_basic_cb, (ulong)&cb, i * 10);
            add_timer(&cb.timer);

            if (jlast + 1 == jiffies)
                break;

            del_timer(&cb.timer);
            hse_log(HSE_ERR "%s: %lu %lu", __func__, jlast, jiffies);
        }

        retries = 3000;
        while (retries-- > 0 && cb.value != cb.timer.data)
            usleep(1000);
        usleep(10000);
        ASSERT_EQ(cb.value, cb.timer.data);

        rc = del_timer(&cb.timer);
        ASSERT_EQ(0, rc);

        ASSERT_GT(cb.tdispatch, cb.tinit);
        tdiff = cb.tdispatch - cb.tinit;

        if (tdiff < i * 10000 || tdiff > (i + 1) * 10000)
            hse_log(HSE_ERR "%s: %lu %lu %lu %d", __func__, cb.tinit, cb.tdispatch, tdiff, i);
        ASSERT_GE(tdiff, i * 10000);
    }
}

/* Create and delete a timer before it expires.
 */
MTF_DEFINE_UTEST(timer_test, timer_test_delete)
{
    struct cb cb;
    int       rc;

    cb_init(&cb, timer_test_basic_cb, (ulong)&cb, 1000);
    add_timer(&cb.timer);

    usleep(20 * 1000);

    rc = del_timer(&cb.timer);
    ASSERT_EQ(1, rc);

    usleep(20 * 1000);

    ASSERT_EQ(cb.tdispatch, 0);
    ASSERT_EQ(cb.value, 0);
}

void
timer_test_resched_cb(unsigned long data)
{
    struct cb *cb = (void *)data;

    if (++cb->value >= 5)
        return;

    cb->timer.expires = jiffies + msecs_to_jiffies(30);

    add_timer(&cb->timer);
}

/* Test iterative rescheulde from timer callback.
 */
MTF_DEFINE_UTEST(timer_test, timer_resched)
{
    struct cb cb;
    int       retries;
    int       rc;

    cb_init(&cb, timer_test_resched_cb, (ulong)&cb, 30);
    add_timer(&cb.timer);

    retries = 1000;
    while (retries-- > 0 && cb.value < 5)
        usleep(10000);
    usleep(60 * 1000);
    ASSERT_EQ(cb.value, 5);

    rc = del_timer(&cb.timer);
    ASSERT_EQ(0, rc);
}

MTF_END_UTEST_COLLECTION(timer_test)
