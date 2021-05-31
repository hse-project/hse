/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_alloc

#include <hse_util/platform.h>
#include <hse_util/alloc.h>

void *
alloc_aligned(size_t size, size_t align)
{
    void *mem;

    if ((align & (align - 1)) || align > UINT32_MAX || size > UINT32_MAX)
        return NULL;

    if (align < _Alignof(max_align_t))
        align = _Alignof(max_align_t);

    mem = malloc(size + align);
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
