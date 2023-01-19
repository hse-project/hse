/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_BASE_H
#define HSE_PLATFORM_BASE_H

/*
 * Other hse_util header files should include this file.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#if __linux__
#include <linux/fs.h>
#include <sys/sysinfo.h>
#endif

/** @brief Cast a member of a structure out to the containing structure.
 *
 * @param _ptr Pointer to the member.
 * @param _type Type of the container struct this is embedded in.
 * @param _member Name of the member within the struct.
 */
#define container_of(_ptr, _type, _member)            \
    ({                                                \
        void *mptr = (void *)(_ptr);                  \
        ((_type *)(mptr - offsetof(_type, _member))); \
    })

#define NELEM(_arr) (sizeof(_arr) / sizeof((_arr)[0]))

#endif
