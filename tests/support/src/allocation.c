/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015 Micron Technology, Inc. All rights reserved.
 */

#include <hse_ut/common.h>

#include <hse_test_support/allocation.h>

/*
 * Fail On Flag Mock Allocator
 * ----------------------------------------------------------------------------
 */

int g_fail_flag = 0;

int g_fail_alloc_cnt = 0;

int g_fail_free_cnt = 0;

void *
fail_flag_malloc(size_t sz)
{
    void *p;

    ++g_fail_alloc_cnt;

    if (g_fail_flag)
        return 0;

    p = (mtfm_allocation_malloc_getreal())(sz);
    if (p)
        memset(p, 0xff, sz); /* poison test malloc memory */
    return p;
}

void *
fail_flag_calloc(size_t n, size_t sz)
{
    ++g_fail_alloc_cnt;

    if (g_fail_flag)
        return 0;
    else
        return (mtfm_allocation_calloc_getreal())(n, sz);
}

void
fail_flag_free(void *p)
{
    ++g_fail_free_cnt;

    if (!g_fail_flag)
        mtfm_allocation_free_getreal()(p);
}

int
fail_flag_alloc_test_pre(struct mtf_test_info *ti)
{
    g_fail_flag = 0;
    g_fail_alloc_cnt = 0;
    g_fail_free_cnt = 0;

    mtfm_allocation_malloc_set(fail_flag_malloc);
    mtfm_allocation_calloc_set(fail_flag_calloc);
    mtfm_allocation_free_set(fail_flag_free);

    return 0;
}

int
fail_flag_alloc_test_post(struct mtf_test_info *ti)
{
    mtfm_allocation_malloc_set(0);
    mtfm_allocation_calloc_set(0);
    mtfm_allocation_free_set(0);

    g_fail_flag = 0;
    g_fail_alloc_cnt = 0;
    g_fail_free_cnt = 0;

    return 0;
}

/*
 * Fail On Nth Allocation Mock Allocator
 * ----------------------------------------------------------------------------
 */

int g_fail_nth_alloc_cnt = 0;
int g_fail_nth_free_cnt = 0;

int g_fail_nth_alloc_limit = -1;

void *
fail_nth_malloc(size_t sz)
{
    void *p;

    if ((g_fail_nth_alloc_limit != -1) && (++g_fail_nth_alloc_cnt > g_fail_nth_alloc_limit))
        return 0;
    p = (mtfm_allocation_malloc_getreal())(sz);
    if (p)
        memset(p, 0xff, sz);

    return p;
}

void *
fail_nth_calloc(size_t n, size_t sz)
{
    if ((g_fail_nth_alloc_limit != -1) && (++g_fail_nth_alloc_cnt > g_fail_nth_alloc_limit))
        return 0;
    else
        return (mtfm_allocation_calloc_getreal())(n, sz);
}

void
fail_nth_free(void *p)
{
    if (g_fail_nth_alloc_limit != -1)
        ++g_fail_nth_free_cnt;

    mtfm_allocation_free_getreal()(p);
}

int
fail_nth_alloc_test_pre(struct mtf_test_info *ti)
{
    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_free_cnt = 0;
    g_fail_nth_alloc_limit = 0;

    mtfm_allocation_malloc_set(fail_nth_malloc);
    mtfm_allocation_calloc_set(fail_nth_calloc);
    mtfm_allocation_free_set(fail_nth_free);

    return 0;
}

int
fail_nth_alloc_test_post(struct mtf_test_info *ti)
{
    mtfm_allocation_malloc_set(0);
    mtfm_allocation_calloc_set(0);
    mtfm_allocation_free_set(0);

    g_fail_nth_alloc_limit = -1;

    return 0;
}

#if HSE_MOCKING
#include "allocation_ut_impl.i"
#endif /* HSE_MOCKING */
