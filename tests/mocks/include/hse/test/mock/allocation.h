/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2016 Micron Technology, Inc.
 */

#ifndef MOCK_ALLOCATION_H
#define MOCK_ALLOCATION_H

#include <stddef.h>

#include <hse/util/compiler.h>

#include <hse/test/mtf/framework.h>

void *malloc(size_t) HSE_MOCK;

void
free(void *) HSE_MOCK;

void *calloc(size_t, size_t) HSE_MOCK;

void *aligned_alloc(size_t, size_t) HSE_MOCK;

int
memcmp(const void *, const void *, size_t) HSE_MOCK;

#if HSE_MOCKING
#include "allocation_ut.h"
#endif

#endif
