/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <sys/poll.h>

#define USE_EVENT_TIMER
#include <hse_util/event_timer.h>
#include <hse_util/platform.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(event_timer);

MTF_DEFINE_UTEST(event_timer, once)
{
    char *cp;

    EVENT_TIMER(t);
    EVENT_INIT(t);
    EVENT_START(t);
    poll(0, 0, 10);
    EVENT_SAMPLE(t);
    EVENT_REPORT(t, "basic");

    cp = strstr(t.buf, "cnt");
    ASSERT_FALSE(cp == 0);

    cp = strstr(t.buf, "mode");
    ASSERT_TRUE(cp == 0);
}

MTF_DEFINE_UTEST(event_timer, many)
{
    char *cp;
    int   i;

    EVENT_TIMER(t);
    EVENT_INIT(t);

    for (i = 0; i < 100; ++i) {
        EVENT_START(t);
        poll(0, 0, 1);
        EVENT_SAMPLE(t);
    }

    EVENT_REPORT(t, "several");
    EVENT_PRINT(t, "several");

    cp = strstr(t.buf, "cnt");
    ASSERT_FALSE(cp == 0);

    cp = strstr(t.buf, "mode");
    ASSERT_FALSE(cp == 0);

    ASSERT_EQ(t.n, 100);
    ASSERT_NE(t.min, t.max);
}

static void *
event_helper(void *arg)
{
    struct event_timer *t = arg;
    int                 i;

    for (i = 0; i < 1000; ++i) {
        EVENT_WRAP_PTR(t, poll(0, 0, 1););
    }
    return 0;
}

MTF_DEFINE_UTEST(event_timer, deadlock)
{
    pthread_t tidv[16];
    int       i, rc;

    EVENT_TIMER(t);
    EVENT_INIT(t);

    for (i = 0; i < NELEM(tidv); ++i) {
        rc = pthread_create(&tidv[i], 0, event_helper, &t);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < NELEM(tidv); ++i) {
        rc = pthread_join(tidv[i], 0);
        ASSERT_EQ(0, rc);
    }

    EVENT_PRINT(t, "deadlock test");

    printf("# of busys: %ld\n", t.t1);

    /* collisions may not happen, especially if instrumented */
    ASSERT_GE(t.t1, 0);

    ASSERT_GT(t.min, 0);
    ASSERT_LT(t.max, 1000 * 1000 * 1000);
    ASSERT_GT(t.mode, 900);
    ASSERT_GT(t.m, 900);
    ASSERT_EQ(t.n, NELEM(tidv) * 1000);
}

MTF_END_UTEST_COLLECTION(event_timer);
