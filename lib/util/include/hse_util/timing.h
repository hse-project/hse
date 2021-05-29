/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TIMING_H
#define HSE_PLATFORM_TIMING_H

#include "_config.h"

#include <hse_util/base.h>
#include <hse_util/inttypes.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>

#include <time.h>
#include <unistd.h>

static HSE_ALWAYS_INLINE u64
get_time_ns(void)
{
    struct timespec ts = { 0, 0 };

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static HSE_ALWAYS_INLINE int
get_realtime(struct timespec *ts)
{
    return clock_gettime(CLOCK_REALTIME, ts);
}
#endif
