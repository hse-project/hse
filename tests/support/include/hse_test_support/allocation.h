/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016 Micron Technology, Inc. All rights reserved.
 */

#ifndef HSE_UTEST_UTIL_ALLOCATION_H
#define HSE_UTEST_UTIL_ALLOCATION_H

#include <hse_util/inttypes.h>

#include <hse_ut/common.h>

/* MTF_MOCK_DECL(allocation) */

/* MTF_MOCK */
void *malloc(size_t);

/* MTF_MOCK */
void free(void *);

/* MTF_MOCK */
void *calloc(size_t, size_t);

/* MTF_MOCK */
void *aligned_alloc(size_t, size_t);

/* MTF_MOCK */
int memcmp(const void *ptr1, const void *ptr2, size_t num);

#if HSE_MOCKING
#include "allocation_ut.h"
#endif

#endif
