/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
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
#include <stdalign.h>
#include <stddef.h>
#include <stdarg.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <sched.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/file.h>

#if __linux__
#include <sys/sysinfo.h>
#include <linux/fs.h>
#endif

#define container_of(ptr, type, member)                \
    ({                                                 \
        __typeof(((type *)0)->member) *_p = (ptr);     \
        (type *)((char *)_p - offsetof(type, member)); \
    })

/* clang-format off */

#define HSE_UTIL_DESC   "Heterogeneous-memory Storage Engine Utilities"
#define STR_SAFE(_str)  ((_str) ?: "")
#define NELEM(_arr)     (sizeof(_arr) / sizeof((_arr)[0]))

/* clang-format on */

#endif
