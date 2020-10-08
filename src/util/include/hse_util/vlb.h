/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_VLB_H
#define HSE_PLATFORM_VLB_H

#include <hse_util/hse_err.h>

#include <hse/hse_limits.h>

/* The read buf cache maintains a small pool of preallocated large
 * (mostly sparse) buffers primarily for cn maintenance reads.  The cache
 * helps to minimize the number of trips into the kernel to allocate large
 * buffers that would perform expensive address map modifications.
 */
#define VLB_ALLOCSZ_MAX     (roundup(HSE_KVS_VLEN_MAX, PAGE_SIZE) * 2)
#define VLB_CACHESZ_MAX     (2ul << 30)
#define VLB_KEEPSZ_MAX      (1ul << 20)

merr_t vlb_init(void) __cold;
void vlb_fini(void) __cold;

/**
 * vlb_alloc() - allocate a read buffer
 * @sz: requested buffer size
 *
 * Caller may request any size, but only requests of size %sz
 * or smaller will come from the cache.
 */
void *vlb_alloc(size_t sz);

/**
 * vlb_free() - free a read buffer
 * @mem:  buffer address from vlb_alloc()
 * @used: see below
 *
 * %used must be the size of the allocation from vlb_alloc()
 * if it was larger than VLB_ALLOCSZ_MAX.  Otherwise, it
 * should indicate the amount of the buffer that was modified.
 */
void vlb_free(void *mem, size_t used);

#endif
