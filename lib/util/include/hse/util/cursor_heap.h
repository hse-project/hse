/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_CURSOR_HEAP_H
#define HSE_PLATFORM_CURSOR_HEAP_H

/*
 * This is an allocator for use by the components of the HSE storage stack
 * stack.
 *
 * A Cursor Heap (cheap) is a memory range from which items can be allocated
 * via a cursor.  The cursor starts at offset 0, and moves forward as items
 * are allocated.
 */

#include <stdint.h>

#include <hse/util/base.h>
#include <hse/error/merr.h>

#ifdef HSE_BUILD_RELEASE
#define CHEAP_POISON_SZ 0
#else
#define CHEAP_POISON_SZ (HSE_ACP_LINESIZE)
#endif

/* Everything in this structure is opaque to callers (but not really,
 * because the cheap unit tests need access to the implementation).
 */
struct cheap {
    size_t    alignment;
    uint64_t  cursorp;
    size_t    size;
    uint64_t  lastp;
    uint64_t  base;
    uint64_t  brk;
    void *    mem;
    uintptr_t magic;
};

/**
 * cheap_create() - Create a cursor heap from which to cheaply allocate memory
 * @alignment:  Alignment for cheap_alloc() (must be a power of 2 from 0 to 64)
 * @size:       Maximum size of the heap (in bytes)
 *
 * Return: Returns a ptr to a struct cheap if successful, otherwise NULL.
 */
struct cheap *
cheap_create(size_t alignment, size_t size);

/**
 * cheap_destroy() - destroy a cheap
 * @h:  the cheap to destroy
 *
 * Free and destroy a cheap entirely.
 * It's a bad bug to touch anything from a cheap after calling this.
 */
void
cheap_destroy(struct cheap *h);

/**
 * cheap_reset() - reset a cheap
 * @h:           the cheap to reset
 * @base_offset: offset from base of cheap region to reset to
 *
 * Return a cheap to an empty state, ready for use
 */
void
cheap_reset(struct cheap *h, size_t base_offset);

/**
 * cheap_trim() - trim to a maximum resident set size
 * @h:          the cheap to trim
 * @rss:        maximum resident set size (in bytes)
 *
 * Reduce the RSS of the cheap to at most %rss bytes.
 */
void
cheap_trim(struct cheap *h, size_t rss);

/**
 * cheap_malloc() - allocate space from a cheap
 * @h:      the cheap from which to allocate
 * @size:   size in bytes of the desired allocation
 *
 * This function has the same general calling convention and semantics
 * as malloc().
 *
 * Return: Returns a pointer to the allocated memory if succussful,
 * otherwise returns NULL.
 */
void *
cheap_malloc(struct cheap *h, size_t size);

/**
 * cheap_calloc() - allocate zeroed space from a cheap
 * @h:      the cheap from which to allocate
 * @size:   size in bytes of the desired allocation
 *
 * This function has the same general calling convention and semantics
 * as calloc().
 *
 * Return: Returns a pointer to the allocated memory if succussful,
 * otherwise returns NULL.
 */
static inline void *
cheap_calloc(struct cheap *h, size_t size)
{
    void *mem;

    mem = cheap_malloc(h, size);
    if (mem)
        memset(mem, 0, size);

    return mem;
}

void
cheap_free(struct cheap *h, void *addr);

/**
 * cheap_memalign() - allocate aligned storage from a cheap
 * @h:          the cheap from which to allocate
 * @alignment:  the desired alignement
 * @size:       size in bytes of the desired allocation
 *
 * This function has the same general calling convention and semantics
 * as aligned_alloc() and memalign().
 *
 * Return: Returns 0 if successful, otherwise returns an errno.
 */
void *
cheap_memalign(struct cheap *h, size_t alignment, size_t size);

/**
 * cheap_used() - return number of bytes used
 * @h:  ptr to a cheap
 *
 * Return number of bytes used, including all padding incurred
 * by aligned allocations.
 */
size_t
cheap_used(struct cheap *h);

/**
 * cheap_avail() - return remaining free space
 * @h:  ptr to a cheap
 *
 * Calculate remaining free space in a cursor_heap (cheap).
 */
size_t
cheap_avail(struct cheap *h);

#endif /* HSE_PLATFORM_CURSOR_HEAP_H */
