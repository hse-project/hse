/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/page.h>
#include <hse_util/cursor_heap.h>
#include <hse_util/xrand.h>

#include <hse_ut/conditions.h>

#include "cheap_testlib.h"

#include <hse_test_support/random_buffer.h>

/*
 * cheap_fill_test
 *
 * Return the number of items that fit
 */
int
cheap_fill_test(struct cheap *h, size_t size)
{
    void *ptr = 0;
    int   i;

    i = 0;
    while (1) {
        void *prev = ptr;

        ptr = cheap_malloc(h, size);
        if (!ptr)
            break;

        VERIFY_FALSE_RET(prev && (ptr != (prev + size)), -1);
        if (!ptr)
            break;

        ++i;
    }

    return i;
}

static int
my_memcmp(char *s1, char *s2, size_t len)
{
    int i;

    for (i = 0; i < len; i++)
        VERIFY_TRUE_RET(s1[i] == s2[i], -1);

    return 0;
}

/* cheap_verify_test
 *
 * This test does the following:
 *
 * 1. Allocate random sized bufs until cheap *h runs out of space
 *    a. verify that each allocated buf has been zeroed if appropriate
 *    b. verify that each buf complies with alignment reqs of the cheap
 *    c. verify that the alignment pad has been zeroed, if applicable
 * 2. Fill each with repeatable randome data
 * 3. Verify that all contain the correct data (would catch overlaps)
 */
int
cheap_verify_test1(struct cheap *h, u32 min_size, u32 max_size)
{
    int             rc = -1;
    int             i = 0;
    int             num_bufs;
    char **         bufs = 0;
    u32 *           buf_sizes = 0;
    char *          zero_buffer = 0;
    struct xrand xr;
    s64             max_bufs;
    ssize_t         buf_ptr_array_size;

    /* Malloc enough space to store an array of sizes if all allocations
     * are the min_size */
    max_bufs = h->size / min_size;
    buf_sizes = malloc(max_bufs * sizeof(size_t));
    VERIFY_NE_RET(0, buf_sizes, -1);

    buf_ptr_array_size = max_bufs * sizeof(char *);
    bufs = malloc(buf_ptr_array_size);
    VERIFY_NE_RET(0, bufs, -1);

    zero_buffer = calloc(1, max_size); /* calloc is zeroed */
    VERIFY_NE_RET(0, zero_buffer, -1);

    xrand_init(&xr, 42);

    while (1) {
        int lrc, cond;

        buf_sizes[i] = xrand_range64(&xr, min_size, max_size);

        cond = (buf_sizes[i] > max_size) || (buf_sizes[i] < min_size);
        VERIFY_FALSE_RET(cond, -1);

        /* Allocate a buffer */
        if (i & 1)
            bufs[i] = cheap_calloc(h, (size_t)buf_sizes[i]);
        else
            bufs[i] = cheap_malloc(h, (size_t)buf_sizes[i]);

        /* Not a failure of it failed because it didn't fit */
        if (!bufs[i] && (buf_sizes[i] > cheap_avail(h)))
            break;

        VERIFY_NE_RET(NULL, bufs[i], -1);

        if (i & 1) {
            /* Has the buffer been zeroed? */
            lrc = my_memcmp(bufs[i], zero_buffer, buf_sizes[i]);
            VERIFY_EQ_RET(0, lrc, -1);
        }

        /* Verify alignment while we're at it */
        if (h->alignment)
            VERIFY_TRUE_RET(IS_ALIGNED((u64)bufs[i], h->alignment), -1;);

        i++;
    }
    num_bufs = i;

    /* Fill the buffers with repeatable pseudo-random data */
    for (i = 0; i < num_bufs; i++) {
        /* random seed is buf size */
        randomize_buffer(bufs[i], buf_sizes[i], buf_sizes[i]);
    }

    /* Validate the data in the buffers */
    for (i = 0; i < num_bufs; i++) {
        rc = validate_random_buffer(bufs[i], buf_sizes[i], buf_sizes[i]);
        /* Success is -1, because the error offset is returned
         * on error (which ranges from 0 to size-1 */
        VERIFY_EQ_RET(-1, rc, -1);
    }

    if (zero_buffer)
        free(zero_buffer);
    if (bufs)
        free(bufs);
    if (buf_sizes)
        free(buf_sizes);

    return 0;
}

int
cheap_zero_test1(struct cheap *h, u32 min_size, u32 max_size)
{
    int             i = 0;
    char **         bufs = 0;
    u32 *           buf_sizes = 0;
    char *          zero_buffer = 0;
    struct xrand xr;
    int             max_bufs;

    /* Malloc enough space to store an array of sizes if all allocations
     * are the min_size */
    max_bufs = (int)(h->size) / min_size;
    buf_sizes = malloc(max_bufs * sizeof(size_t));
    VERIFY_NE_RET(0, buf_sizes, -1);

    bufs = malloc(max_bufs * sizeof(char *));
    VERIFY_NE_RET(0, bufs, -1);

    zero_buffer = calloc(1, max_size); /* calloc is zeroed */
    VERIFY_NE_RET(0, zero_buffer, -1);

    xrand_init(&xr, 42);

    while (1) {
        int lrc, cond;

        buf_sizes[i] = xrand_range64(&xr, min_size, max_size);

        cond = (buf_sizes[i] > max_size) || (buf_sizes[i] < min_size);
        VERIFY_FALSE_RET(cond, -1);

        /* Allocate a buffer */
        if (i & 1)
            bufs[i] = cheap_calloc(h, (size_t)buf_sizes[i]);
        else
            bufs[i] = cheap_malloc(h, (size_t)buf_sizes[i]);

        /* Not a failure if it failed because it didn't fit */
        if (!bufs[i] && (buf_sizes[i] > cheap_avail(h)))
            break;
        VERIFY_NE_RET(NULL, bufs[i], -1);

        if (i & 1) {
            /* Has the buffer been zeroed? */
            lrc = my_memcmp(bufs[i], zero_buffer, buf_sizes[i]);
            VERIFY_EQ_RET(0, lrc, -1);
        }
        i++;
    }

    if (bufs)
        free(bufs);
    if (buf_sizes)
        free(buf_sizes);
    if (zero_buffer)
        free(zero_buffer);

    return 0;
}

int
cheap_strict_test1(struct cheap *h, u32 min_size, u32 max_size, enum which_strict_test which)
{
    int             i = 0;
    char **         bufs = 0;
    u32 *           buf_sizes = 0;
    struct xrand xr;
    int             max_bufs;

    /* Malloc enough space to store an array of sizes if all allocations
     * are the min_size.
     */
    max_bufs = (int)h->size / min_size;
    buf_sizes = malloc(max_bufs * sizeof(*buf_sizes));
    VERIFY_NE_RET(0, buf_sizes, -1);

    bufs = malloc(max_bufs * sizeof(*bufs));
    VERIFY_NE_RET(0, bufs, -1);

    xrand_init(&xr, 42);

    while (1) {
        int cond;

        buf_sizes[i] = xrand_range64(&xr, min_size, max_size);
        cond = (buf_sizes[i] > max_size) || (buf_sizes[i] < min_size);
        VERIFY_FALSE_RET(cond, -1);

        /* Allocate a buffer */
        bufs[i] = cheap_malloc(h, buf_sizes[i]);

        /* Not a failure of it failed because it didn't fit? */
        if (bufs[i] && (buf_sizes[i] > cheap_avail(h)))
            break;
        VERIFY_NE_RET(NULL, bufs[i], -1);

        i++;
    }

    if (bufs)
        free(bufs);
    if (buf_sizes)
        free(buf_sizes);

    return 0;
}
