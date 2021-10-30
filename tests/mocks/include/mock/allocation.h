/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016 Micron Technology, Inc. All rights reserved.
 */

#ifndef MOCK_ALLOCATION_H
#define MOCK_ALLOCATION_H

#include <stddef.h>

/* MTF_MOCK_DECL(allocation) */

/* MTF_MOCK */
void *malloc(size_t);

/* MTF_MOCK */
void
free(void *);

/* MTF_MOCK */
void *calloc(size_t, size_t);

/* MTF_MOCK */
void *aligned_alloc(size_t, size_t);

/* MTF_MOCK */
int
memcmp(const void *ptr1, const void *ptr2, size_t num);

#if HSE_MOCKING
#include "allocation_ut.h"
#endif

#endif
