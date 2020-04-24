/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_STRINGS_H
#define HSE_STRINGS_H

#include <stddef.h>

size_t strlcat(char *dst, const char *src, size_t dsize);

size_t strlcpy(char *dst, const char *src, size_t dsize);

#endif
