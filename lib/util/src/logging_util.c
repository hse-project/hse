/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_logging_util
#include "logging_util.h"
#include <stdio.h>
#include <syslog.h>

#include <hse_util/logging.h>
#include <hse_ikvdb/hse_gparams.h>

void
backstop_log(const char *fmt)
{
    if (hse_gparams.logging.destination == LD_SYSLOG) {
        syslog(3, "%s: %s", __func__, fmt);
    } else {
        fprintf(logging_file, "%s: %s", __func__, fmt);
    }
}

#if HSE_MOCKING
#include "logging_util_ut_impl.i"
#endif /* HSE_MOCKING */
