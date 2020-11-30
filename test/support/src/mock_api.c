/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
 */

#include <hse_ut/conditions.h>
#include <hse_test_support/mock_api.h>
#include <hse_test_support/allocation.h>

#include <hse_util/inttypes.h>
#include <hse_util/assert.h>
#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/arch.h>

union rc {
    u64   i;
    void *ptr;
};

struct mocked_api {
    u64      start1;
    u64      stop1;
    union rc rc1;

    u64      start2;
    u64      stop2;
    union rc rc2;

    __aligned(SMP_CACHE_BYTES) atomic64_t calls;
};

/*
 * max_mapi_idx is auto-generated during the build.
 * See debug/stage/include/mapi_idx.h after a build completes.
 *
 * NB: This implementation uses a table of pointers to mocked_api counters.
 * This allows similar APIs to be shared; e.g. malloc, calloc, etc. .
 */

static struct mocked_api  mock_tab[max_mapi_idx];
static struct mocked_api *mock_ptrs[max_mapi_idx];

bool mapi_enabled;

void
mapi_init(void)
{
    u32 i;

    if (mapi_enabled)
        return;

    for (i = 0; i < max_mapi_idx; ++i)
        mock_ptrs[i] = &mock_tab[i];

    /*
     * By sharing the various allocators, it is possible to
     * fail the nth allocation, no matter what API was called.
     * This is the generally desired action.
     *
     * [HSE_REVISIT]
     * If you really need to distinguish calloc from malloc,
     * this approach must change to a registration mechanism.
     * But be wary: such an approach requires deep understanding
     * and coupling of the tested code with the testing code.
     */
    mock_ptrs[mapi_idx_calloc] = mock_ptrs[mapi_idx_malloc];
    mock_ptrs[mapi_idx_kmem_cache_alloc] = mock_ptrs[mapi_idx_malloc];
    mock_ptrs[mapi_idx_kmem_cache_zalloc] = mock_ptrs[mapi_idx_malloc];

    /* [HSE_REVISIT] These were never mocked, but probably should be. */
    /* mock_ptrs[mapi_idx_realloc] = mock_ptrs[mapi_idx_malloc]; */

    mock_ptrs[mapi_idx_kmem_cache_free] = mock_ptrs[mapi_idx_free];

    mapi_enabled = true;
}

static bool
valid_api(u32 api)
{
    if (!mapi_enabled || api >= max_mapi_idx) {
        assert(mapi_enabled);
        assert(api < max_mapi_idx);
        return false;
    }

    return api < max_mapi_idx;
}

void *
mapi_safe_calloc(size_t nmemb, size_t size)
{
    return (mtfm_allocation_calloc_getreal())(nmemb, size);
}

void *
mapi_safe_malloc(size_t size)
{
    return (mtfm_allocation_malloc_getreal())(size);
}

void
mapi_safe_free(void *mem)
{
    return (mtfm_allocation_free_getreal())(mem);
}

u64
mapi_calls(u32 api)
{
    return valid_api(api) ? atomic64_read(&mock_ptrs[api]->calls) : 0;
}

u64
mapi_calls_clear(u32 api)
{
    u64 count;

    if (!valid_api(api))
        return 0;

    count = atomic64_read(&mock_ptrs[api]->calls);
    atomic64_set(&mock_ptrs[api]->calls, 0);

    return count;
}

void
mapi_inject_set(u32 api, u32 start1, u32 stop1, u64 rc1, u32 start2, u32 stop2, u64 rc2)
{
    struct mocked_api *m;

    if (!valid_api(api))
        return;

    m = mock_ptrs[api];
    m->start1 = start1;
    m->stop1 = stop1;
    m->rc1.i = rc1;
    m->start2 = start2;
    m->stop2 = stop2;
    m->rc2.i = rc2;
    atomic64_set(&m->calls, 0);
}

void
mapi_inject_set_ptr(u32 api, u32 start1, u32 stop1, void *rc1, u32 start2, u32 stop2, void *rc2)
{
    struct mocked_api *m;

    if (!valid_api(api))
        return;

    m = mock_ptrs[api];
    m->start1 = start1;
    m->stop1 = stop1;
    m->rc1.ptr = rc1;
    m->start2 = start2;
    m->stop2 = stop2;
    m->rc2.ptr = rc2;
    atomic64_set(&m->calls, 0);
}

void
mapi_inject_unset(u32 api)
{
    struct mocked_api *m;

    if (valid_api(api)) {
        m = mock_ptrs[api];
        m->start1 = m->start2 = 0;
        atomic64_set(&m->calls, 0);
    }
}

void
mapi_inject_unset_range(u32 lo, u32 hi)
{
    u32 api;

    for (api = lo; api <= hi; api++)
        mapi_inject_unset(api);
}

void
mapi_inject_clear()
{
    mapi_inject_unset_range(0, max_mapi_idx - 1);
}

/*
 * inject_check - implement injectable errors based on number of calls
 */
static bool
inject_check(u32 api, union rc *urc)
{
    struct mocked_api *m;
    u64                calls;

    if (!valid_api(api))
        return false;

    m = mock_ptrs[api];
    calls = atomic64_inc_return(&m->calls);

    if (m->start1 && m->start1 <= calls && (calls <= m->stop1 || m->stop1 == 0)) {
        *urc = m->rc1;
        return true;
    }

    if (m->start2 && m->start2 <= calls && (calls <= m->stop2 || m->stop2 == 0)) {
        *urc = m->rc2;
        return true;
    }

    return false;
}

/*
 * handles ptr return values
 */
bool
mapi_inject_check_ptr(u32 api, void **pp)
{
    union rc urc;
    bool     rc;

    rc = inject_check(api, &urc);
    if (rc && pp)
        *pp = urc.ptr;
    return rc;
}

/*
 * handles integer return values
 */
bool
mapi_inject_check(u32 api, u64 *i)
{
    union rc urc;
    bool     rc;

    rc = inject_check(api, &urc);
    if (rc && i)
        *i = urc.i;
    return rc;
}
