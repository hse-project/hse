/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_alloc

#include <stdalign.h>

#include <hse_util/mutex.h>
#include <hse_util/spinlock.h>
#include <hse_util/timing.h>
#include <hse_util/minmax.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>
#include <hse_util/page.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/assert.h>
#include <hse_util/rest_api.h>
#include <hse_util/log2.h>

#ifndef ARCH_KMALLOC_MINALIGN
#define ARCH_KMALLOC_MINALIGN alignof(unsigned long long)
#endif

void *
alloc_aligned(size_t size, size_t align)
{
    void * mem;
    size_t sz;

    assert(!(align & (align - 1))); /* must be a power-of-2 */

    if (align < ARCH_KMALLOC_MINALIGN)
        align = ARCH_KMALLOC_MINALIGN;

    sz = size < align ? align : size;
    sz = ALIGN(sz, align);

    mem = malloc(sz + align);
    if (mem) {
        void **ptr = (void *)(((uintptr_t)mem + align) & ~(align - 1));

        *(ptr - 1) = mem;
        mem = ptr;
    }

    return mem;
}

void
free_aligned(const void *ptr)
{
    if (ptr) {
        ptr = *((const void **)ptr - 1);
        free((void *)ptr);
    }
}

#if HSE_MOCKING
#include "alloc_ut_impl.i"
#endif /* HSE_MOCKING */
