/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PAGE_H
#define HSE_PLATFORM_PAGE_H

#include <hse_util/base.h>
#include <hse_util/mman.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))

/* Align @x upward to @mask. Value of @mask should be one less
 * than a power of two (e.g., 0x0001ffff).
 */
#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

/* Align @x upward to boundary @a (@a expected to be a power of 2).
 */
#define ALIGN(x, a) ALIGN_MASK(x, (typeof(x))(a)-1)

/* Align pointer @p upward to boundary @a (@a expected to be a power of 2).
 */
#define PTR_ALIGN(p, a) ((typeof(p))ALIGN((unsigned long)(p), (a)))

/* Align 'addr' to the next page boundary.
 */
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

/* Test if 'addr', cast to an unsigned long, is aligned to
 * a page boundary.
 */
#define PAGE_ALIGNED(addr) IS_ALIGNED((unsigned long)addr, PAGE_SIZE)

/* Test if 'x' is aligned to 'a' boundary ('a' must be a power 2).
 */
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a)-1)) == 0)

/* Return number of elements in array 'arr'.
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif /* HSE_PLATFORM_PAGE_H */
