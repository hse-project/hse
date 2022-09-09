/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022-2023 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_UTIL_ERR_CTX_H
#define HSE_UTIL_ERR_CTX_H

#include <hse/util/compiler.h>

const char *
err_ctx_strerror(unsigned int ctx) HSE_RETURNS_NONNULL;

#endif
