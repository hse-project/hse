/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016 Micron Technology, Inc. All rights reserved.
 */

#ifndef HSE_UTEST_UTIL_ALLOCATION_H
#define HSE_UTEST_UTIL_ALLOCATION_H

#include <hse_util/inttypes.h>

#include <hse_ut/common.h>

/* MTF_MOCK_DECL(allocation) */

/* MTF_MOCK_KU */

#ifndef kmalloc
/* MTF_MOCK_K */
void *
kmalloc(size_t, unsigned int);
#endif

/* MTF_MOCK_U */
void *malloc(size_t);

/* MTF_MOCK_KU */

#ifndef kfree
/* MTF_MOCK_K */
void
kfree(const void *);
#endif

/* MTF_MOCK_U */
void
free(void *);

/* MTF_MOCK_KU */

#ifndef kcalloc
/* MTF_MOCK_K */
void *
kcalloc(size_t, size_t, unsigned int);
#endif

/* MTF_MOCK_U */
void *calloc(size_t, size_t);

/* MTF_MOCK */
int
memcmp(const void *ptr1, const void *ptr2, size_t num);

/**
 * DOC: Mock Allocation Routines
 *
 * Many unit tests wish to inject allocation errors into the units under
 * test. While some such injection patterns may necessarily be unique to a
 * given test, there are common patterns useful across many tests. Several
 * pre-defined mock allocation routines are declared in this file:
 *
 *   Fail On Flag - fail the next allocation if a global flag is set
 *
 *   Fail Nth Allocation - fail the nth allocation based on global settings
 *
 */

/*
 * ----------------------------------------------------------------------------
 *
 * Fail On Flag Mock Allocator:
 *
 * This a mock allocator that wraps the native allocator (kmalloc or malloc)
 * but checks a global flag ('g_fail_flag') to see if it should fail the
 * current allocation request. If the flag is zero it simply returns the
 * result of calling the mocked allocator. Otherwise it returns 0.
 *
 * The most straightforward method of using this mock allocator is to use
 * fail_flag_alloc_test_pre() and fail_flag_alloc_test_post() as pre- and
 * post-hooks for the individual sub-test. These inject/remove the mock and
 * set the flag value to 0.
 *
 * In addition, the counts for both alloc's and free's are exposed. The pre-
 * and post- initialize these counts to 0.
 */

extern int g_fail_flag;
extern int g_fail_alloc_cnt;
extern int g_fail_free_cnt;

/**
 * fail_flag_malloc - Mock allocation function for use in the userspace that
 *                    fails every allocation when the value of the global
 *                    variable 'g_fail_flag' != %0.
 *
 * @sz:    number of bytes to allocate (passed through)
 *
 * Return:
 *   result of malloc() on success, %0 on error
 */
void *
fail_flag_malloc(size_t sz);

/**
 * fail_flag_calloc - Mock allocation function for use in the userspace that
 *                    fails every allocation when the value of the global
 *                    variable 'g_fail_flag' != %0.
 *
 * @n:     number of elements of sz bytes to allocate (passed through)
 * @sz:    number of bytes to allocate per element (passed through)
 *
 * Return:
 *   result of calloc() on success, %0 on error
 */
void *
fail_flag_calloc(size_t n, size_t sz);

/**
 * fail_flag_alloc_test_pre - Unit test pre-hook that sets the variable
 *                            'g_fail_flag' to 0 and mocks the correct
 *                            kernel/user allocation function.
 *
 * @ti:    framework test info pointer
 *
 * Return:
 *   %0 always
 */
int
fail_flag_alloc_test_pre(struct mtf_test_info *ti);

/**
 * fail_flag_alloc_test_post - Unit test post-hook that sets the variable
 *                             'g_fail_flag' to 0 and un-mocks the correct
 *                             kernel/user allocation function.
 *
 * @ti:    framework test info pointer
 *
 * Return:
 *   %0 always
 */
int
fail_flag_alloc_test_post(struct mtf_test_info *ti);

/*
 * ----------------------------------------------------------------------------
 *
 * Fail Nth Allocation Mock Allocator
 *
 * The is a mock allocator that wraps the native allocator (kmalloc or malloc)
 * but checks global state to see if it should fail the current allocation
 * request. If not it simply returns the result of calling the wrapped
 * allocator. Otherwise it returns 0.
 *
 * The global state is the pair of variables 'g_fail_nth_alloc_limit' and
 * 'g_fail_nth_alloc_cnt'. If 'g_fail_nth_alloc_limit' == -1, then the wrapped
 * allocator is called immediately and the result returned.
 *
 * If 'g_fail_nth_alloc_limit' != -1, then if 'g_fail_nth_alloc_cnt' >=
 * 'g_fail_nth_alloc_limit' then the mock allocator increments
 * 'g_fail_nth_alloc_cnt' and returns 0. Otherwise the mock allocator
 * increments 'g_fail_nth_alloc_cnt' and calls the wrapped allocator.
 *
 * If 'g_fail_nth_alloc_limit' != -1, calls to free()/kfree() are tracked
 * by incrementing 'g_fail_nth_free_cnt'. By setting the limit value to a
 * sufficiently large value, a test can observe whether the unit under test
 * is freeing everything it is supposed to.
 *
 * The most straightforward method of using this mock allocator is to use
 * fail_nth_alloc_test_pre() and fail_nth_alloc_test_post() as pre- and
 * post-hooks for the individual sub-test. These inject/remove the mock, set
 * 'g_fail_nth_alloc_limit' to -1, and set 'g_fail_nth_alloc_cnt' to 0.
 */

extern int g_fail_nth_alloc_cnt;
extern int g_fail_nth_free_cnt;
extern int g_fail_nth_alloc_limit;

/**
 * fail_nth_malloc - Mock allocation function for use in the kernel that
 *                    is controlled through the global variables
 *                    'g_fail_nth_alloc_limit' and 'g_fail_nth_alloc_cnt'.
 *
 * @n:     number of elements of size sz bytes to allocate (passed through)
 * @sz:    number of bytes per element to allocate (passed through)
 *
 * Description:
 *
 * If 'g_fail_nth_alloc_limit' == -1, then the wrapped allocator is called
 * immediately and the result returned. If 'g_fail_nth_alloc_limit' != -1,
 * then if 'g_fail_nth_alloc_cnt' >= 'g_fail_nth_alloc_limit' then the mock
 * allocator increments 'g_fail_nth_alloc_cnt' and returns 0. Otherwise the
 * mock allocator increments 'g_fail_nth_alloc_cnt' and calls the wrapped
 * allocator.
 *
 * Return:
 *   result of malloc() on success, %0 on error
 */
void *
fail_nth_malloc(size_t sz);

/**
 * fail_nth_calloc - Mock allocation function for use in userspace that
 *                   is controlled through the global variables
 *                   'g_fail_nth_alloc_limit' and 'g_fail_nth_alloc_cnt'.
 *
 * @n:     number of elements of sz bytes to allocate (passed through)
 * @sz:    number of bytes to allocate (passed through)
 *
 * Description:
 *
 * See description of fail_nth_kcalloc for more detail.
 *
 * Return:
 *   result of calloc() on success, %0 on error
 */
void *
fail_nth_calloc(size_t n, size_t sz);

/**
 * fail_nth_alloc_test_pre - Unit test pre-hook that sets the variable
 *                           'g_fail_nth_alloc_limit' to -1, the variable
 *                           'g_fail_nth_alloc_cnt'to 0 and mocks the
 *                           correct kernel/user allocation function.
 *
 * @ti:    framework test info pointer
 *
 * Return:
 *   %0 always
 */
int
fail_nth_alloc_test_pre(struct mtf_test_info *ti);

/**
 * fail_nth_alloc_test_post - Unit test post-hook that sets the variable
 *                            'g_fail_nth_alloc_limit' to -1, the variable
 *                            'g_fail_nth_alloc_cnt'to 0 and unmocks the
 *                            correct kernel/user allocation function.
 *
 * @ti:    framework test info pointer
 *
 * Return:
 *   %0 always
 */
int
fail_nth_alloc_test_post(struct mtf_test_info *ti);

#if HSE_MOCKING
#include "allocation_ut.h"
#endif /* HSE_MOCKING */

#endif
