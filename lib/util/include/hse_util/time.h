/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TIME_H
#define HSE_PLATFORM_TIME_H

#include <hse_util/base.h>

#define MSEC_PER_SEC (1000L)
#define USEC_PER_SEC (1000000L)
#define NSEC_PER_SEC (1000000000L)

static inline u64
ktime_get_real(void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (tv.tv_sec * USEC_PER_SEC) + tv.tv_usec;
}

void
time_to_tm(time_t totalsecs, int offset, struct tm *result);

#endif
