/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>
#include <sys/mman.h>

#include <hse/util/arch.h>
#include <hse/util/cursor_heap.h>
#include <hse/util/page.h>

#include "cheap_testlib.h"

#include <hse/test/mtf/framework.h>

MTF_BEGIN_UTEST_COLLECTION(cheap_test);

/* Create a pool with invalid alignment (not power of 2) */
MTF_DEFINE_UTEST(cheap_test, invalid_create1)
{
    size_t        total = 1048576;
    struct cheap *h;

    h = cheap_create(3, total);
    ASSERT_EQ(0UL, h);
    cheap_destroy(h);
}

/* Valid create with alignment=1 */
MTF_DEFINE_UTEST(cheap_test, valid_create0)
{
    size_t        total = 1048576;
    struct cheap *h;

    h = cheap_create(1, total);
    ASSERT_NE(0UL, h);
    cheap_destroy(h);
}

/* Valid create with alignment=2 */
MTF_DEFINE_UTEST(cheap_test, valid_create1)
{
    size_t        total = 1048576;
    struct cheap *h;

    h = cheap_create(2, total);
    ASSERT_NE(0UL, h);
    cheap_destroy(h);
}

/* Valid create with alignment=8 */
MTF_DEFINE_UTEST(cheap_test, valid_fill0)
{
    int           rc;
    size_t        size = 4096;
    size_t        total = 1048576;
    struct cheap *h = 0;

    h = cheap_create(8, total);
    ASSERT_NE(0UL, h);

    total = cheap_avail(h);

    rc = cheap_fill_test(h, size); /* Allocate all, but don't use */
    ASSERT_EQ((total / size), rc);
    cheap_destroy(h);
}

/* Valid create with alignment=8 */
MTF_DEFINE_UTEST(cheap_test, verify_test1)
{
    int           rc;
    size_t        total = 1048576;
    struct cheap *h = 0;

    h = cheap_create(8, total);
    ASSERT_NE(0UL, h);

    rc = cheap_verify_test1(h, 4, 4096);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Valid create with alignment=8 */
MTF_DEFINE_UTEST(cheap_test, verify_test2)
{
    int           rc;
    size_t        total = 104857600;
    struct cheap *h = 0;

    h = cheap_create(8, total);
    ASSERT_NE(0UL, h);

    rc = cheap_verify_test1(h, 4, 8192);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Fill and verify, alignment 0 */
MTF_DEFINE_UTEST(cheap_test, verify_test3)
{
    int           rc;
    size_t        total = 104857600;
    struct cheap *h = 0;

    h = cheap_create(0, total);
    ASSERT_NE(0UL, h);

    rc = cheap_verify_test1(h, 8, 64);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Fill and verify, alignment 0 */
MTF_DEFINE_UTEST(cheap_test, verify_test4)
{
    int           rc;
    size_t        total = 104857600;
    struct cheap *h = 0;

    h = cheap_create(0, total);
    ASSERT_NE(0UL, h);

    /* Very small allocations */
    rc = cheap_verify_test1(h, 1, 64);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Valid create with alignment=4 */
MTF_DEFINE_UTEST(cheap_test, zero_test1)
{
    int           rc;
    size_t        total = 1048576;
    struct cheap *h = 0;

    h = cheap_create(8, total);
    ASSERT_NE(0UL, h);

    rc = cheap_zero_test1(h, 4, 4096);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Valid create with alignment=4 */
MTF_DEFINE_UTEST(cheap_test, zero_test2)
{
    int           rc;
    size_t        total = 104857600;
    struct cheap *h = 0;

    h = cheap_create(8, total);
    ASSERT_NE(0UL, h);

    rc = cheap_zero_test1(h, 4, 8192);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Fill and zero, alignment 0 */
MTF_DEFINE_UTEST(cheap_test, zero_test3)
{
    int           rc;
    size_t        total = 104857600;
    struct cheap *h = 0;

    h = cheap_create(0, total);
    ASSERT_NE(0UL, h);

    rc = cheap_zero_test1(h, 8, 64);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Fill and verify, alignment 0 */
MTF_DEFINE_UTEST(cheap_test, zero_test4)
{
    int           rc;
    size_t        total = 104857600;
    struct cheap *h = 0;

    h = cheap_create(0, total);
    ASSERT_NE(0UL, h);

    /* Very small allocations */
    rc = cheap_zero_test1(h, 1, 64);
    ASSERT_EQ(0, rc);
    cheap_destroy(h);
}

/* Test that cheap_used() and cheap_avail() work as expected.
 */
MTF_DEFINE_UTEST(cheap_test, cheap_test_used)
{
    struct cheap *h;
    size_t        used, avail;
    uint8_t *     p;
    int           i;

    h = cheap_create(0, 4096);
    ASSERT_NE(NULL, h);

    avail = cheap_avail(h);
    ASSERT_GT(avail, 1024);

    used = cheap_used(h);
    ASSERT_EQ(used, 0);

    for (i = 0; i < 7; ++i) {
        p = cheap_malloc(h, 100);
        ASSERT_NE(NULL, p);

        used = cheap_used(h);
        ASSERT_EQ(used, (i + 1) * 100);
    }

    ASSERT_EQ(avail - used, cheap_avail(h));

    cheap_destroy(h);
}

#ifndef HSE_BUILD_RELEASE
/* Test that cheap_reset() poisons the memory that would
 * be given out by the next call to cheap_malloc().
 *
 * Note: cheap_reset() poisoning is disabled in release builds.
 */
MTF_DEFINE_UTEST(cheap_test, cheap_test_poison)
{
    struct cheap *h;
    uint8_t *     p;
    int           i;

    ASSERT_GT(CHEAP_POISON_SZ, 0);

    h = cheap_create(0, CHEAP_POISON_SZ * 4);
    ASSERT_NE(NULL, h);

    p = cheap_malloc(h, CHEAP_POISON_SZ * 2);
    ASSERT_NE(NULL, p);

    for (i = 0; i < CHEAP_POISON_SZ; ++i)
        p[i] = i;

    cheap_reset(h, CHEAP_POISON_SZ);

    for (i = 0; i < CHEAP_POISON_SZ; ++i) {
        ASSERT_EQ(i, p[i]);
        ASSERT_EQ(0xa5, p[i + CHEAP_POISON_SZ]);
    }

    cheap_destroy(h);
}
#endif

/* Verify cheap_memalign() works as expected. */
MTF_DEFINE_UTEST(cheap_test, cheap_test_memalign)
{
    size_t        total = 1024 * 1024 * 1024;
    struct cheap *h;
    size_t        align, sz;
    void *        p;

    h = cheap_create(0, total);
    ASSERT_NE(0UL, h);

    p = cheap_memalign(h, 16, total + 1);
    ASSERT_EQ(NULL, p);

    p = cheap_memalign(h, 3, 8);
    ASSERT_EQ(NULL, p);

    sz = cheap_avail(h);
    ASSERT_GT(sz, total / 2);
    total = sz;

    for (align = 1; align < total; align *= 2) {
        p = cheap_memalign(h, align, sizeof(*p));

        /* cheap allocation alignment is highly non-deterministic
         * and may not always be able to fulfill an alignment
         * request that would otherwise succeed if the base of
         * the cheap were suitably aligned.
         */
        if (!p) {
            ASSERT_GE(align * 2, total);
            break;
        }

        ASSERT_TRUE(IS_ALIGNED((uintptr_t)p, align));
    }

    cheap_destroy(h);
}

/* Verify cheap_free() works as expected. */
MTF_DEFINE_UTEST(cheap_test, cheap_test_free)
{
    struct cheap *h;
    size_t        align;

    for (align = 1; align < 128; align *= 2) {
        size_t   free, avail, alloc;
        size_t   cheapsz, allocmax;
        uint     i, itermax;
        void *   p0, *p1;
        uint8_t *prev[256];

        itermax = ((get_cycles() >> 1) % 128) + 3;
        allocmax = ((get_cycles() >> 1) % 32768) + 1;
        cheapsz = itermax * ALIGN(allocmax, align) + PAGE_SIZE;

        h = cheap_create(align, cheapsz);
        ASSERT_NE(NULL, h);

        free = cheap_avail(h);
        ASSERT_GT(free, 0);

        alloc = 0;

        for (i = 0; i < itermax; ++i) {
            size_t sz = ((get_cycles() >> 1) % allocmax) + 1;

            p0 = cheap_malloc(h, sz);
            ASSERT_NE(NULL, p0);

            memset(p0, 0xff, sz);
            cheap_free(h, p0);
            cheap_free(h, p0);

            sz = ALIGN(sz, align);
            p1 = cheap_malloc(h, sz);
            ASSERT_NE(NULL, p1);
            ASSERT_EQ(p0, p1);

            /* Mark the last byte in the allocation.
             */
            prev[i] = p1 + sz - 1;
            *(prev[i]) = ~i;

            alloc += sz;
        }

        /* Check that the last byte of each allocation is intact.
         */
        for (i = 0; i < itermax; ++i)
            ASSERT_EQ(*(prev[i]), (uint8_t)~i);

        /* Allocate an aligned chunk so that the result
         * from cheap_avail() is aligned.
         */
        p1 = cheap_malloc(h, align);
        ASSERT_NE(NULL, p1);
        alloc += align;

        avail = cheap_avail(h);
        ASSERT_EQ(free - alloc, avail);
        free = avail;

        p0 = cheap_malloc(h, align);
        ASSERT_NE(NULL, p0);
        p1 = cheap_malloc(h, 1);
        ASSERT_NE(NULL, p0);
        cheap_free(h, p0);
        cheap_free(h, p1);

        avail = cheap_avail(h);
        ASSERT_EQ(free - align, avail);

        cheap_free(h, NULL);
        cheap_free(h, NULL);

        cheap_destroy(h);
    }
}

static size_t
rss(void *mem, size_t maxpg, unsigned char *vec)
{
    size_t sz = 0;
    int    rc;
    int    i;

    memset(vec, 0, maxpg);

    mem = (void *)((uintptr_t)mem & PAGE_MASK);

    rc = mincore(mem, maxpg * PAGE_SIZE, vec);
    if (rc)
        return -1;

    for (i = 0; i < maxpg; ++i)
        sz += (vec[i] & 0x01) ? PAGE_SIZE : 0;

    return sz;
}

/* Verify cheap_trim() works as expected. */
MTF_DEFINE_UTEST(cheap_test, cheap_test_trim)
{
    size_t        maxpg = 256;
    unsigned char vec[maxpg];
    size_t        sz;
    struct cheap *h;
    void *        p;
    int           i;

    h = cheap_create(0, maxpg * PAGE_SIZE);
    ASSERT_NE(NULL, h);

    /* After create at least one page should be resident.
     */
    sz = rss(h, maxpg, vec);
    ASSERT_GE(sz, PAGE_SIZE);

    for (i = 0; i < maxpg - 1; ++i) {
        p = cheap_memalign(h, PAGE_SIZE, sizeof(*p));
        ASSERT_NE(NULL, p);
        ASSERT_TRUE(IS_ALIGNED((uintptr_t)p, PAGE_SIZE));

        *(int *)p = i;
    }

    /* After allocating and touching all pages they all
     * should be resident.
     */
    sz = rss(h, maxpg, vec);
    ASSERT_EQ(sz, maxpg * PAGE_SIZE);

    cheap_reset(h, 0);

    /* After reset all pages should still be resident.
     */
    sz = rss(h, maxpg, vec);
    ASSERT_EQ(sz, maxpg * PAGE_SIZE);

    cheap_destroy(h);
}

MTF_END_UTEST_COLLECTION(cheap_test)
