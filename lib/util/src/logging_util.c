/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <syslog.h>

#include <hse_util/logging.h>

#include "logging_util.h"

extern FILE *hse_log_file;

void
hse_log_backstop(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    if (hse_log_file) {
        vfprintf(hse_log_file, fmt, ap);
    } else {
        vsyslog(LOG_ERR, fmt, ap);
    }
    va_end(ap);
}
