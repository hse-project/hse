/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/darray.h>

int
darray_init(struct darray *da, int cap)
{
    da->cur = 0;
    da->cap = cap;
    da->arr = calloc(cap, sizeof(void *));
    return da->arr ? 0 : -ENOMEM;
}

void
darray_reset(struct darray *da)
{
    da->cur = 0;

    memset(da->arr, 0, da->cap * sizeof(void *));
}

void
darray_fini(struct darray *da)
{
    free(da->arr);
    memset(da, 0, sizeof(*da));
}

int
darray_reserve(struct darray *da, int n)
{
    void **   na;
    const int quantum = 16;

    /*
     * In the interest of constraining growth on an increasing
     * size, allocate enough to accomodate the requested amount
     * rounded up to the quantum of allocation.
     *
     * Two simple rules:
     * 1. Only alloc when necessary.
     * 2. Alloc in quantum chunks.
     */
    if (da->cur + n >= da->cap) {
        /* do not realloc so works in kernel, too */
        n = 1 + (da->cur + n) / quantum;
        n *= quantum;
        na = calloc(n, sizeof(void *));
        if (ev(!na))
            return -ENOMEM;
        if (da->arr) {
            memcpy(na, da->arr, da->cur * sizeof(void *));
            free(da->arr);
        }
        da->arr = na;
        da->cap = n;
    }
    return 0;
}

int
darray_append(struct darray *da, void *p)
{
    int rc;

    rc = darray_reserve(da, 1);
    if (!rc)
        da->arr[da->cur++] = p;
    return rc;
}

int
darray_append_uniq(struct darray *da, void *p)
{
    int i;

    for (i = 0; i < da->cur; ++i)
        if (da->arr[i] == p)
            return 0;

    return darray_append(da, p);
}

void **
darray_append_loc(struct darray *da)
{
    void **p = 0;
    int    rc;

    rc = darray_reserve(da, 1);
    if (!rc)
        p = &da->arr[da->cur++];
    return p;
}

int
darray_len(struct darray *da)
{
    return da->cur;
}

void *
darray_arr(struct darray *da)
{
    return da->arr;
}

void
darray_apply(struct darray *da, void (*func)(void *))
{
    int i;

    for (i = 0; i < da->cur; ++i)
        func(da->arr[i]);
}

void
darray_apply_rev(struct darray *da, void (*func)(void *))
{
    int i;

    for (i = da->cur; i > 0; --i)
        func(da->arr[i - 1]);
}
