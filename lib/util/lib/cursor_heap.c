/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <sys/mman.h>

#include <hse/util/alloc.h>
#include <hse/util/arch.h>
#include <hse/util/assert.h>
#include <hse/util/cursor_heap.h>
#include <hse/util/event_counter.h>
#include <hse/util/minmax.h>
#include <hse/util/page.h>
#include <hse/util/slab.h>
#include <hse/util/xrand.h>

struct cheap *
cheap_create(size_t alignment, size_t size)
{
    struct cheap *h = NULL;
    void *mem;

    if (alignment < 2)
        alignment = 1;
    else if (alignment > size / 2)
        return NULL; /* This is item alignment, not heap alignment */
    else if (alignment & (alignment - 1))
        return NULL; /* Alignment must be a power of 2 */

    /* Align the size of all cheaps to an integral multiple
     * of 2MB in hopes of making life easier on the VMM.
     */
    size = ALIGN(size, 2u << 20);

    /* Use MAP_PRIVATE so that cheap_trim() can release pages.
     */
    mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

    if (mem != MAP_FAILED) {
        size_t halign = ALIGN(sizeof(*h), HSE_L1D_LINESIZE);
        size_t color = xrand64_tls() % (PAGE_SIZE / HSE_ACP_LINESIZE - 1);
        size_t offset = HSE_ACP_LINESIZE * color;

        /* Offset the base of the cheap by a random number of cache lines
         * in effort to ameliorate cache conflict misses.  However, do not
         * use more than half a page (including the header).
         */
        h = mem + offset;
        h->mem = mem;
        h->magic = (uintptr_t)h;
        h->alignment = alignment;
        h->size = size - offset - halign - CHEAP_POISON_SZ;
        h->base = (uint64_t)h + halign;
        h->cursorp = h->base;
        h->brk = PAGE_ALIGN(h->cursorp);
        h->lastp = 0;

        ev_info(1);
    }

    return h;
}

void
cheap_destroy(struct cheap *h)
{
    if (!h)
        return;

    assert(h->magic == (uintptr_t)h);
    h->magic = ~h->magic;

    munmap(h->mem, ALIGN(h->size, PAGE_SIZE));

    ev_info(1);
}

void
cheap_reset(struct cheap *h, size_t size)
{
    assert(h->magic == (uintptr_t)h);
    assert(size < h->size);
    assert(size <= h->cursorp - h->base);

    if (h->brk < h->cursorp)
        h->brk = PAGE_ALIGN(h->cursorp);

    h->cursorp = h->base + size;
    h->lastp = 0;

#if CHEAP_POISON_SZ > 0
    memset((void *)h->cursorp, 0xa5, CHEAP_POISON_SZ);
#endif
}

void
cheap_trim(struct cheap *h, size_t rss)
{
    size_t len;
    int rc;

    assert(h->magic == (uintptr_t)h);

    if (h->brk < h->cursorp)
        h->brk = PAGE_ALIGN(h->cursorp);

    rss = max(PAGE_ALIGN(rss), PAGE_SIZE);

    if (rss < h->cursorp - h->base)
        rss = PAGE_ALIGN(h->cursorp - h->base);

    if (rss > h->brk - (uint64_t)h->mem)
        return;

    len = h->brk - (uint64_t)h->mem - rss;
    if (len < PAGE_SIZE)
        return;

    h->brk = (uint64_t)h->mem + rss;

    rc = madvise(h->mem + rss, len, MADV_FREE);

    ev(rc);
}

static inline void *
cheap_memalign_impl(struct cheap *h, size_t alignment, size_t size)
{
    uint64_t allocp;

    assert(h->magic == (uintptr_t)h);

    allocp = ALIGN(h->cursorp, alignment);

    if (ev(size > h->size))
        return NULL;

    if ((allocp - h->base + size) > h->size)
        return NULL;

    h->cursorp = allocp + size;
    h->lastp = allocp;

    return (void *)allocp;
}

void *
cheap_memalign(struct cheap *h, size_t alignment, size_t size)
{
    if (alignment & (alignment - 1))
        return NULL;

    return cheap_memalign_impl(h, alignment, size);
}

void *
cheap_malloc(struct cheap *h, size_t size)
{
    return cheap_memalign_impl(h, h->alignment, size);
}

/* Freeing within a cheap can only occur if the user of the cheap only
 * ever frees a chunk that was just allocated. Once another chunk has
 * been allocated we can't free the previously allocated chunk. The
 * use case for cheap_free() is to handle the case where the owner of the
 * cheap needs to allocate space to ensure that it can make progress
 * after it does something that may fail. If the failure occurs, we want
 * to free the just-allocated space.
 */
void
cheap_free(struct cheap *h, void *addr)
{
    if (h->lastp && (uint64_t)addr == h->lastp) {
        if (h->brk < h->cursorp)
            h->brk = PAGE_ALIGN(h->cursorp);
        h->cursorp = h->lastp;
        h->lastp = 0;
    }
}

size_t
cheap_used(struct cheap *h)
{
    assert(h->magic == (uintptr_t)h);

    return min_t(size_t, h->size, (h->cursorp - h->base));
}

size_t
cheap_avail(struct cheap *h)
{
    assert(h->magic == (uintptr_t)h);

    return h->size - cheap_used(h);
}
