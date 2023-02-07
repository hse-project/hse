/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef MULTITHREADED_TESTER_H
#define MULTITHREADED_TESTER_H
/*
 * MTEST DRIVER == Multi-Threaded Test Driver
 *
 * The mtest driver is used by unit tests to facilitate writing
 * multi-threaded tests.  It doesn't currently work in kernel b/c it
 * uses pthreads.  But it could be ported to use workqueues and made to
 * work in the kernel.
 */

#include <hse/util/base.h>

#include <hse/test/mtf/common.h>

#define MTEST_ALIGN 128

#define mtest_alloc(SIZE)                                                           \
    ({                                                                              \
        void * mem = NULL;                                                          \
        size_t bytes = (size_t)(SIZE);                                              \
        int rc = posix_memalign(&mem, MTEST_ALIGN, bytes);                          \
        if (!mem || rc) {                                                           \
            printf("%s:%d: posix_memalign failed\n", REL_FILE(__FILE__), __LINE__); \
            exit(-1);                                                               \
        }                                                                           \
        memset(mem, 0, bytes);                                                      \
        mem;                                                                        \
    })

struct mtest;

typedef void
mtest_worker_fn(void *test_context, int worker_number);

typedef void
mtest_report_fn(void *test_context, double elapsed_time);

struct mtest *
mtest_create(
    int              num_workers,
    mtest_worker_fn *worker_func,
    mtest_report_fn *report_func,
    void *           test_context);

void
mtest_destroy(struct mtest *mt);

void
mtest_barrier(struct mtest *mt);

void
mtest_run(struct mtest *mt);

#endif
