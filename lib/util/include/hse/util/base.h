/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
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
