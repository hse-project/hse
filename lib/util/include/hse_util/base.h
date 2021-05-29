/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_BASE_H
#define HSE_PLATFORM_BASE_H

/*
 * Other hse_util header files should include this file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <linux/fs.h>

#define container_of(ptr, type, member)                \
    ({                                                 \
        __typeof(((type *)0)->member) *_p = (ptr);     \
        (type *)((char *)_p - offsetof(type, member)); \
    })

#ifndef offsetof
#define offsetof(type, member) ((size_t) & ((type *)0)->member)
#endif

#define HSE_UTIL_DESC "Heterogeneous-memory Storage Engine Utilities"

#define NELEM(_x) (sizeof(_x) / sizeof((_x)[0]))

#define STR_SAFE(_s) ((_s) ?: "")

#endif
