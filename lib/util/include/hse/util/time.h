/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TIME_H
#define HSE_PLATFORM_TIME_H

/* clang-format off */

#ifndef HSE_HZ
#define HSE_HZ              (1000)
#endif

#define MSEC_PER_SEC        (1000L)
#define USEC_PER_SEC        (1000000L)
#define NSEC_PER_SEC        (1000000000L)

#define MAX_JIFFY_OFFSET    ((LONG_MAX >> 1) - 1)
#define USEC_PER_JIFFY      (USEC_PER_SEC / HSE_HZ)
#define NSEC_PER_JIFFY      (NSEC_PER_SEC / HSE_HZ)

/* clang-format on */

#endif
