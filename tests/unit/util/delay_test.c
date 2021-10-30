/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/atomic.h>
#include <hse_util/delay.h>
#include <hse_util/event_counter.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(delay);

/*
 * 1. Test delaying for small duration (<250ms)
 */
MTF_DEFINE_UTEST(delay, delay_small_duration)
{
    atomic64_t before, after;
    u64        b, a;

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);
    msleep(200);
    ev_get_timestamp(&after);

    b = atomic64_read(&before);
    a = atomic64_read(&after);

    ASSERT_LE(b + (200 * 1000), a);
}

/*
 * 2. Test delaying for larger duration (>250ms)
 */
MTF_DEFINE_UTEST(delay, delay_larger_duration)
{
    atomic64_t before, after;
    u64        b, a;

    /* Take a "before" time reading. */
    ev_get_timestamp(&before);
    msleep(500);
    ev_get_timestamp(&after);

    b = atomic64_read(&before);
    a = atomic64_read(&after);

    ASSERT_LE(b + (500 * 1000), a);
}

MTF_END_UTEST_COLLECTION(delay)
