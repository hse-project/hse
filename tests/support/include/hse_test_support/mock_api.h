/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
 */

#ifndef HSE_CORE_HSE_TEST_MOCK_H
#define HSE_CORE_HSE_TEST_MOCK_H

#include <hse_util/inttypes.h>

#include "mapi_idx.h"

#define MOCK_SET(group, func) mtfm_##group##func##_set(func)
#define MOCK_UNSET(group, func) mtfm_##group##func##_set(0)

#define MOCK_SET_FN(group, orig_func, new_func) mtfm_##group##_##orig_func##_set(new_func)

#define MOCK_UNSET_FN(group, orig_func) mtfm_##group##_##orig_func##_set(0)

/**
 * mapi_init() - Initialize Mocking API (aka, mapi)
 *
 * Must be called before mapi can be used.  Sets the global %mapi_enabled
 * flag to true if successful.
 */
void
mapi_init(void);

/*
 * Access memory without getting caught up in the mocked memory allocator,
 * which is often configured to inject out of memory conditions.
 */
void *
mapi_safe_calloc(size_t nmemb, size_t size);
void *
mapi_safe_malloc(size_t size);
void
mapi_safe_free(void *mem);

/**
 * mapi_inject_set - inject failures into a mocked function
 * @api: mocked function
 * @start1: start of first range
 * @stop2:  end of first range
 * @rc1:    return value for first range
 * @ptr1:   ptr return value for first range
 * @start2: start of second range
 * @stop2:  end of second range
 * @rc2:    return value for second range
 * @ptr2:   ptr return value for second range
 *
 * Let @n be a value that counts the number of times @api is called.
 * Initially, of course, @n==0.  The following logic is applied in
 * the mocked function:
 *
 *        @n += 1;
 *        if (@start1 && @start1 <= @n && (@stop1 == 0 || @n <= @stop1))
 *            return (cast)@rc;
 *        if (@start2 && @start2 <= @n && (@stop2 == 0 || @n <= @stop2))
 *            return (cast)@r2;
 *
 * Notes:
 *
 *   - If @start is 0 the range is disabled.
 *
 *    - A @stop value of 0 means don't terminate the range (similar to
 *      using @stop==UINT_MAX.
 *
 *    - The return value, @rc, is cast to the proper type in the mocked
 *      function.
 *
 * Examples:
 *
 * Operate normally for the first 4 calls, return EBUSY for the next 2 calls,
 * and return EINVAL after that:
 *
 *     mapi_inject_set(api_foobar, 5, 6, EBUSY, 7, 0, EINVAL);
 *
 * Operate normally for the first 4 calls, return EBUSY for the next 2 calls,
 * and then resume normal operation:
 *
 *     mapi_inject_set(api_foobar, 5, 6, EBUSY, 0, 0, 0);
 *
 * Fail with ENOMEM on all calls:
 *
 *     mapi_inject_set(api_foobar, 1, 0, ENOMEM, 0, 0, 0);
 *
 * Disable injection:
 *
 *     mapi_inject_set(api_foobar, 0, 0, 0, 0, 0, 0);
 */
void
mapi_inject_set(u32 api, u32 start1, u32 stop1, u64 rc1, u32 start2, u32 stop2, u64 rc2);

void
mapi_inject_set_ptr(u32 api, u32 start1, u32 stop1, void *rc1, u32 start2, u32 stop2, void *rc2);

/**
 * mapi_inject_unset - configure @api to operate normally
 *                  and reset the call count
 */
void
mapi_inject_unset(u32 api);

void
mapi_inject_unset_range(u32 low, u32 hi);

/**
 * mapi_inject_clear - remove all injected errors
 */

void
mapi_inject_clear(void);

/**
 * mapi_calls - return the number of times @api was called
 */
u64
mapi_calls(u32 api);

/**
 * mapi_calls_clear - return the number of times @api was called
 *     and then reset counter
 */
u64
mapi_calls_clear(u32 api);

/**
 * mapi_inject - configure @api to always return @value.
 */
#define mapi_inject(api, value) mapi_inject_set((api), 1, 0, (value), 0, 0, 0)

#define mapi_inject_ptr(api, ptr) mapi_inject_set_ptr((api), 1, 0, (ptr), 0, 0, NULL)

/**
 * mapi_inject_once - Configure @api to return @value on @nth call
 */
#define mapi_inject_once(api, nth, value) mapi_inject_set((api), (nth), (nth), (value), 0, 0, 0)

#define mapi_inject_once_ptr(api, nth, value) \
    mapi_inject_set_ptr((api), (nth), (nth), (value), 0, 0, NULL)

/**
 * mapi_inject_check - Test if should inject error now
 *
 * These are normally called by the generated mocking framework.
 */
bool
mapi_inject_check(u32 api, u64 *rc);

bool
mapi_inject_check_ptr(u32 api, void **ptr);

extern bool mapi_enabled;

struct mapi_injection {
    int   api;
    int   rc_cookie;
    u64   rc_scalar;
    void *rc_ptr;
};
/* A hack to make the initialization of struct mapi_injection arrays
 * both readable and safe (ie, can detect misuse).  Users do this:
 *
 *    struct mapi_injection list[] = {
 *        { mapi_idx_foo,  MAPI_RC_SCALAR, 100 },
 *        { mapi_idx_bar,  MAPI_RC_PTR,    NULL },
 *        { -1 },
 *    };
 *
 * The above will result in rc_cookie indicating scalar or ptr.  If
 * rc_cookie is invalid, the array was incorrectly initialized.
 */
#define MAPI_RC_COOKIE_SCALAR  0x835ab001
#define MAPI_RC_COOKIE_PTR     0x835ab002
#define MAPI_RC_SCALAR  MAPI_RC_COOKIE_SCALAR
#define MAPI_RC_PTR     MAPI_RC_COOKIE_PTR, 0

void
mapi_inject_list(
    struct mapi_injection  *injectv,
    bool                    set);

static inline void
mapi_inject_list_set(
    struct mapi_injection  *injectv)
{
    mapi_inject_list(injectv, true);
}

static inline void
mapi_inject_list_unset(
    struct mapi_injection  *injectv)
{
    mapi_inject_list(injectv, false);
}

#endif /* HSE_CORE_HSE_TEST_MOCK_H */
