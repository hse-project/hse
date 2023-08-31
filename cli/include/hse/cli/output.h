/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2023 Micron Technology, Inc.
 */

#include <hse/types.h>

#include <hse/util/compiler.h>

HSE_PRINTF(2, 3) void
error(hse_err_t err, const char *fmt, ...);

#define errorx(_fmt, ...) error(0, (_fmt), ##__VA_ARGS__)

HSE_PRINTF(2, 3) HSE_NORETURN void
fatal(hse_err_t err, const char *fmt, ...);

#define fatalx(_fmt, ...) fatal(0, (_fmt), ##__VA_ARGS__)

HSE_PRINTF(1, 2) HSE_NORETURN void
syntax(const char *fmt, ...);
