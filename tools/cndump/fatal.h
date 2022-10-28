/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CNDUMP_FATAL_H
#define CNDUMP_FATAL_H

#include <hse/error/merr.h>
#include <hse/util/compiler.h>

HSE_NORETURN
void
fatal(const char *who, merr_t err);

HSE_NORETURN
void HSE_PRINTF(1, 2)
syntax(const char *fmt, ...);

#endif
