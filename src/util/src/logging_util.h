/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LOGGING_UTIL_HEADER
#define HSE_LOGGING_UTIL_HEADER

#include <hse_util/logging.h>
#include <hse_util/inttypes.h>

/* MTF_MOCK_DECL(logging_util) */

/* MTF_MOCK */
void
backstop_log(const char *msg);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "logging_util_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_LOGGING_UTIL_HEADER */
