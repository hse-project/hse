/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>

#define MTF_MOCK_IMPL_logging_util
#include "logging_util.h"
#include <syslog.h>

#include <hse/hse_version.h>

#define MAX_MSG_SIZE 500

void
backstop_log(const char *fmt)
{
    syslog(3, "%s: %s", __func__, fmt);
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "logging_util_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
