/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_UTIL_ERR_CTX_H
#define HSE_UTIL_ERR_CTX_H

#include <hse/util/compiler.h>

const char *
err_ctx_strerror(unsigned int ctx) HSE_RETURNS_NONNULL;

#endif
