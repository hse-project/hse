/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_SLAB_H
#define HSE_PLATFORM_SLAB_H

/* MTF_MOCK_DECL(slab) */

#include <hse_util/hse_err.h>

#define __GFP_ZERO 0x00000001
#define GFP_KERNEL 0x00000004

typedef unsigned int gfp_t;

#define SLAB_HWCACHE_ALIGN 0x00002000ul

static __always_inline void *
malloc_array(size_t n, size_t size)
{
    if (size != 0 && n > SIZE_MAX / size)
        return NULL;

    return malloc(n * size);
}

struct kmem_cache;
struct kmc_zone;

#pragma GCC visibility push(hidden)

/* MTF_MOCK */
merr_t
kmem_cache_init(void);

/* MTF_MOCK */
void
kmem_cache_fini(void);

struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align, ulong flags, void (*ctor)(void *));

/* MTF_MOCK */
void
kmem_cache_destroy(struct kmem_cache *cache);

unsigned int
kmem_cache_size(struct kmem_cache *cache);

/* MTF_MOCK */
void *
kmem_cache_alloc(struct kmem_cache *cache);

/* MTF_MOCK */
void
kmem_cache_free(struct kmem_cache *cache, void *mem);

/* MTF_MOCK */
void *
kmem_cache_zalloc(struct kmem_cache *cache);

#pragma GCC visibility pop

unsigned long __get_free_page(gfp_t flags);
unsigned long get_zeroed_page(gfp_t flags);
void free_page(unsigned long addr);

#if HSE_UNIT_TEST_MODE
#include "slab_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_PLATFORM_SLAB_H */
