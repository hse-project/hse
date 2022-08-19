/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/allocation.h>

#include <hse_util/arch.h>
#include <hse_util/inttypes.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>
#include <hse_util/page.h>
#include <logging/logging.h>

int
allocation_test_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
allocation_test_post(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(allocation, allocation_test_pre, allocation_test_post);

MTF_DEFINE_UTEST(allocation, methods)
{
    void *ptr;

    ptr = malloc_array(4, SIZE_MAX - 1);
    ASSERT_EQ(NULL, ptr);

    ptr = malloc_array(4, 32);
    ASSERT_NE(NULL, ptr);
    free(ptr);

    ptr = malloc_array(0, 32);
    ASSERT_NE(NULL, ptr);
    free(ptr);

    ptr = malloc_array(4, 0);
    ASSERT_NE(NULL, ptr);
    free(ptr);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    ptr = calloc(1, 32);
    ASSERT_EQ(NULL, ptr);

    ptr = calloc(1, 32);
    ASSERT_NE(NULL, ptr);
    free(ptr);
}

MTF_DEFINE_UTEST(allocation, page_basic)
{
    void *zeropage, *addr;

    zeropage = calloc(1, PAGE_SIZE);
    ASSERT_NE(NULL, zeropage);

    addr = hse_page_alloc();
    ASSERT_NE(0, addr);
    memset(addr, 0xaa, PAGE_SIZE);
    hse_page_free(addr);

    addr = hse_page_zalloc();
    ASSERT_NE(0, addr);
    ASSERT_EQ(0, memcmp(addr, zeropage, PAGE_SIZE));
    memset(addr, 0xaa, PAGE_SIZE);
    hse_page_free(addr);

    free(zeropage);
}

MTF_DEFINE_UTEST(allocation, kmem_cache_basic)
{
    struct kmem_cache *zonev[100];
    void *             memv[100];
    int                i;

    struct kmem_cache *zone;
    void *             mem;

    zone = kmem_cache_create(NULL, 0, 0, 0, NULL);
    ASSERT_EQ(NULL, zone);

    zone = kmem_cache_create(NULL, 16 * 1024 + 1, 8, 0, NULL);
    ASSERT_EQ(NULL, zone);

    zone = kmem_cache_create(NULL, 8, 128 * 1024 + 1, 0, NULL);
    ASSERT_EQ(NULL, zone);

    zone = kmem_cache_create(NULL, 0, 13, 0, NULL);
    ASSERT_EQ(NULL, zone);

    zone = kmem_cache_create(__func__, 0, 0, 0, NULL);
    ASSERT_NE(NULL, zone);
    ASSERT_GE(kmem_cache_size(zone), 0);
    kmem_cache_destroy(zone);

    zone = kmem_cache_create(__func__, 4096, 0, 0, NULL);
    ASSERT_NE(NULL, zone);
    ASSERT_EQ(4096, kmem_cache_size(zone));
    kmem_cache_destroy(zone);

    zone = kmem_cache_create(__func__, 4096, 4096, 0, NULL);
    ASSERT_NE(NULL, zone);
    ASSERT_EQ(4096, kmem_cache_size(zone));

    mem = kmem_cache_alloc(zone);
    ASSERT_NE(NULL, mem);
    kmem_cache_free(zone, mem);
    kmem_cache_free(zone, NULL);
    kmem_cache_destroy(zone);

    zone = kmem_cache_create(__func__, 8, 0, SLAB_HWCACHE_ALIGN, NULL);
    ASSERT_NE(NULL, zone);
    ASSERT_EQ(8, kmem_cache_size(zone));

    mem = kmem_cache_alloc(zone);
    ASSERT_NE(NULL, mem);
    kmem_cache_free(zone, mem);
    kmem_cache_destroy(zone);

    kmem_cache_size(NULL);

    for (i = 0; i < ARRAY_SIZE(zonev); ++i) {
        zonev[i] = kmem_cache_create(__func__, i, 0, 0, NULL);
        ASSERT_NE(NULL, zonev[i]);
        ASSERT_EQ(i, kmem_cache_size(zonev[i]));

        memv[i] = kmem_cache_alloc(zonev[i]);
        ASSERT_NE(NULL, memv[i]);
    }

    for (i = 0; i < ARRAY_SIZE(zonev); ++i) {
        kmem_cache_free(zonev[i], memv[i]);
        kmem_cache_destroy(zonev[i]);
    }
}

u64
uma_test_alloc(
    struct mtf_test_info *lcl_ti,
    size_t                size,
    size_t                align,
    int                   itermax,
    int                   samplemax,
    void *                zone)
{
    u64    tstart, tstop;
    u64    avg = 0;
    void **memv;
    int    memc;
    int    i, j;

    memc = itermax / 15;
    ASSERT_NE_RET(0, memc, 0);

    memv = calloc(memc, sizeof(*memv));
    ASSERT_NE_RET(NULL, memv, 0);

    for (i = 0; i < samplemax; ++i) {
        tstart = get_time_ns();
        for (j = 0; j < itermax; ++j) {
            int   idx = j % memc;
            void *mem;

            kmem_cache_free(zone, memv[idx]);

            mem = kmem_cache_alloc(zone);
            ASSERT_NE_RET(NULL, mem, 0);
            ASSERT_TRUE_RET(IS_ALIGNED((uintptr_t)mem, align), 0);

            memv[idx] = mem;
            *(long *)mem = j;
        }

        for (i = 0; i < memc; ++i) {
            kmem_cache_free(zone, memv[i]);
            memv[i] = NULL;
        }

        tstop = get_time_ns();

        avg += (tstop - tstart);
    }

    free(memv);

    return (avg / (samplemax * itermax));
}

MTF_DEFINE_UTEST(allocation, kmem_cache_test)
{
    int    itermax, samplemax;
    size_t size;
    void * zone;
    u64    avg;

    log_info("%16s: %8s %8s %8s", "FUNC", "SIZE", "ITERMAX", "NS/ALLOC");

    for (size = 1; size < 32 * 1024; size *= 2) {
        size_t align;

        itermax = 1024 * 1024;
        samplemax = 3;

        if (size >= 1024)
            itermax /= (size * 2 / 1024);

        align = min_t(size_t, size, 32768);

        zone = kmem_cache_create("test", size, align, 0, NULL);
        if (zone) {
            avg = uma_test_alloc(lcl_ti, size, align, itermax, samplemax, zone);

            log_info("%16s: %8zu %8d %8lu", __func__, size, itermax, avg);

            kmem_cache_destroy(zone);
        }
    }
}

MTF_DEFINE_UTEST(allocation, kmem_cache_desc)
{
    void *zone, *mem, *memv[1024];
    uint32_t desc;
    size_t size;
    int i;

    zone = kmem_cache_create("test", 64, 64, 0, NULL);
    ASSERT_NE(NULL, zone);

    mem = kmem_cache_alloc(zone);
    ASSERT_NE(NULL, mem);

    desc = kmem_cache_addr2desc(zone, mem);
    ASSERT_EQ(UINT32_MAX, desc);

    kmem_cache_free(zone, mem);
    kmem_cache_destroy(zone);

    for (size = 1; size < 32 * 1024; size *= 2) {
        zone = kmem_cache_create("test", size, 0, SLAB_DESC, NULL);
        ASSERT_NE(NULL, zone);

        for (i = 0; i < NELEM(memv); ++i) {
            memv[i] = kmem_cache_alloc(zone);
            ASSERT_NE(NULL, memv[i]);
        }

        for (i = 0; i < NELEM(memv); ++i) {
            desc = kmem_cache_addr2desc(zone, memv[i]);
            mem = kmem_cache_desc2addr(zone, desc);
            ASSERT_EQ(memv[i], mem);

            kmem_cache_free(zone, memv[i]);
        }

        kmem_cache_destroy(zone);
    }
}

MTF_END_UTEST_COLLECTION(allocation)
