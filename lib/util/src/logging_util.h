/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LOGGING_UTIL_HEADER
#define HSE_LOGGING_UTIL_HEADER

#include <hse_util/compiler.h>

void HSE_NONNULL(1)
hse_log_backstop(const char *fmt, ...);

#endif /* HSE_LOGGING_UTIL_HEADER */
