/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_SAMPLES_HELPER_H
#define HSE_SAMPLES_HELPER_H

#include <stdarg.h>
#include <stdio.h>

#include <hse/hse.h>

void
error(const hse_err_t err, const char *fmt, ...)
{
    va_list args;
    char buf[256];

    va_start(args, fmt);
    hse_strerror(err, buf, sizeof(buf));
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, ": %s\n", buf);
}

#endif
