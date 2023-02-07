/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_SLAB_H
#define HSE_PLATFORM_SLAB_H

/* MTF_MOCK_DECL(slab) */

#include <stdlib.h>

#include <hse/error/merr.h>

/* clang-format off */

/*
 * kmem_cache_create flags
 *
 * SLAB_HWCACHE_ALIGN   Use L1D cache line item alignment
 * SLAB_PACKED          Allocate items from minimally sized working set
 * SLAB_HUGE            Try to use huge pages regardless of item size
 * SLAB_DESC            Enable conversions to/from 32-bit descriptors
 *
 * SLAB_PACKED always allocates items from the same per-cpu cache (one
 * cache per NUMA node), which improves the chances that subsequently
 * allocated items all come from the same page (or minmimal set of pages).
 * It comes at the cost of increased contention on the cache lock, so
 * should be avoided if alloc/free frequency is expected to be high.
 *
 * SLAB_DESC enables use of kmem_cache_addr2desc() and kmem_cache_desc2addr()
 * to convert kmem_cache_alloc() addresses to/from a compact 32-bit descriptor.
 * Requires an additional 8M.
 *
 * By default, caches with aligned item sizes greater than (PAGE_SIZE / 4)
 * use huge pages if possible.  Use SLAB_HUGE to force use of huge pages
 * regardless of item size.
 */
#define SLAB_HWCACHE_ALIGN      (0x00002000ul)
#define SLAB_PACKED             (0x00010000ul)
#define SLAB_HUGE               (0x00020000ul)
#define SLAB_DESC               (0x00040000ul)

/* clang-format on */

static HSE_ALWAYS_INLINE void *
malloc_array(size_t n, size_t size)
{
    if (size != 0 && n > SIZE_MAX / size)
        return NULL;

    return malloc(n * size);
}

struct kmem_cache;
struct kmc_zone;

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

void *
hse_page_alloc(void);

void *
hse_page_zalloc(void);

void
hse_page_free(void *mem);

void *
kmem_cache_desc2addr(struct kmem_cache *zone, uint32_t desc);

uint32_t
kmem_cache_addr2desc(struct kmem_cache *zone, void *mem);

#if HSE_MOCKING
#include "slab_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_PLATFORM_SLAB_H */
