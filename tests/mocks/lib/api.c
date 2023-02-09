/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/util/arch.h>
#include <hse/util/assert.h>
#include <hse/util/atomic.h>
#include <hse/util/compiler.h>

#include <hse/test/mock/api.h>
#include <hse/test/mtf/conditions.h>

union rc {
    uint64_t i;
    void *ptr;
};

struct mocked_api {
    uint64_t start1 HSE_ACP_ALIGNED;
    uint64_t stop1;
    union rc rc1;

    uint64_t start2;
    uint64_t stop2;
    union rc rc2;

    atomic_ulong calls HSE_L1D_ALIGNED;
};

/*
 * max_mapi_idx is auto-generated during the build.
 * See debug/stage/include/mapi_idx.h after a build completes.
 *
 * NB: This implementation uses a table of pointers to mocked_api counters.
 * This allows similar APIs to be shared; e.g. malloc, calloc, etc. .
 */

static struct mocked_api mock_tab[max_mapi_idx];
static struct mocked_api *mock_ptrs[max_mapi_idx];

bool mapi_enabled;

void
mapi_init(void)
{
    if (mapi_enabled)
        return;

    for (uint32_t i = 0; i < max_mapi_idx; ++i)
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
    mock_ptrs[mapi_idx_aligned_alloc] = mock_ptrs[mapi_idx_malloc];
    mock_ptrs[mapi_idx_kmem_cache_alloc] = mock_ptrs[mapi_idx_malloc];
    mock_ptrs[mapi_idx_kmem_cache_zalloc] = mock_ptrs[mapi_idx_malloc];

    /* [HSE_REVISIT] These were never mocked, but probably should be. */
    /* mock_ptrs[mapi_idx_realloc] = mock_ptrs[mapi_idx_malloc]; */

    mock_ptrs[mapi_idx_kmem_cache_free] = mock_ptrs[mapi_idx_free];

    mapi_enabled = true;
}

static bool
valid_api(uint32_t api)
{
    if (!mapi_enabled || api >= max_mapi_idx) {
        assert(mapi_enabled);
        assert(api < max_mapi_idx);
        return false;
    }

    return api < max_mapi_idx;
}

/* [HSE_REVISIT] The mapi_safe_* functions are no longer required.  In
 * the past, test programs would include allocation.h in order to access
 * the malloc/free mocking control variables, but that had the unfortunate
 * effect of mocking all malloc/free calls within the test program itself.
 * Those variables and their usage have been replaced by mapi_inject()
 * and hence test programs no longer need to include allocation.h and
 * can now call malloc/free directly.
 */
#ifdef TESTS_MOCKS_ALLOCATION_UT_H
#error "Do not include hse_util/alloc.h nor mock/allocation.h"
#endif

void *
mapi_safe_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void *
mapi_safe_malloc(size_t size)
{
    return malloc(size);
}

void
mapi_safe_free(void *mem)
{
    free(mem);
}

uint64_t
mapi_calls(uint32_t api)
{
    return valid_api(api) ? atomic_read(&mock_ptrs[api]->calls) : 0;
}

uint64_t
mapi_calls_clear(uint32_t api)
{
    uint64_t count;

    if (!valid_api(api))
        return 0;

    count = atomic_read(&mock_ptrs[api]->calls);
    atomic_set(&mock_ptrs[api]->calls, 0);

    return count;
}

void
mapi_inject_set(
    uint32_t api,
    uint32_t start1,
    uint32_t stop1,
    uint64_t rc1,
    uint32_t start2,
    uint32_t stop2,
    uint64_t rc2)
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
    atomic_set_rel(&m->calls, 0);
}

void
mapi_inject_set_ptr(
    uint32_t api,
    uint32_t start1,
    uint32_t stop1,
    void *rc1,
    uint32_t start2,
    uint32_t stop2,
    void *rc2)
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
    atomic_set_rel(&m->calls, 0);
}

void
mapi_inject_unset(uint32_t api)
{
    struct mocked_api *m;

    if (valid_api(api)) {
        m = mock_ptrs[api];
        m->start1 = m->start2 = 0;
        atomic_set_rel(&m->calls, 0);
    }
}

void
mapi_inject_unset_range(uint32_t lo, uint32_t hi)
{
    uint32_t api;

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
inject_check(uint32_t api, union rc *urc)
{
    struct mocked_api *m;
    uint64_t calls;

    if (!valid_api(api))
        return false;

    m = mock_ptrs[api];
    calls = atomic_inc_return(&m->calls);

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
mapi_inject_check_ptr(uint32_t api, void **pp)
{
    union rc urc;
    bool rc;

    rc = inject_check(api, &urc);
    if (rc && pp)
        *pp = urc.ptr;
    return rc;
}

/*
 * handles integer return values
 */
bool
mapi_inject_check(uint32_t api, uint64_t *i)
{
    union rc urc;
    bool rc;

    rc = inject_check(api, &urc);
    if (rc && i)
        *i = urc.i;
    return rc;
}

void
mapi_inject_list(struct mapi_injection *inject, bool set)
{
    while (inject->api != -1) {

        int api = inject->api;

        assert(0 <= api && api < max_mapi_idx);

        if (set) {
            switch (inject->rc_cookie) {
            case MAPI_RC_COOKIE_SCALAR:
                mapi_inject(api, inject->rc_scalar);
                break;
            case MAPI_RC_COOKIE_PTR:
                mapi_inject_ptr(api, inject->rc_ptr);
                break;
            default:
                assert(0); /* incorrectly initialized array */
            }
        } else {
            mapi_inject_unset(api);
        }

        ++inject;
    }
}
