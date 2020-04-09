/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef THREAD_TESTER_H
#define THREAD_TESTER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_THREADS 32

struct worker_info;

struct thread_test {
    struct worker_info *    thtst_workers;
    pthread_barrier_t       thtst_worker_barrier;
    pthread_barrier_t       thtst_global_barrier;
    struct thread_test_ops *thtst_ops;
};

struct thread_test_ops {
    /*
     * ctor/dtor
     */
    void (*thread_test_ctor)(struct thread_test *);
    void (*thread_test_dtor)(struct thread_test *);

    /*
     * Public method, invoked within thread.
     */
    void *(*thread_test_main)(struct worker_info *);

    /*
     * These were protected in the C++ version.
     */
    void (*thread_test_barrier)(struct thread_test *);
    void (*thread_test_run)(struct thread_test *, void *, int);

    /*
     * Protected, abstract--must be implemented by subclass.
     */
    void (*thread_test_init)(struct thread_test *, void *, int);
    void (*thread_test_fini)(struct thread_test *, void *);
    void (*thread_test_thread)(struct thread_test *, void *, int);
    void (*thread_test_report)(struct thread_test *, void *, double);

    /*
     * These were private in the C++ version.
     */
    void (*thread_test_wait_barrier)(struct thread_test *, pthread_barrier_t *);

    void (*thread_test_starting_gate)(struct thread_test *);
    void (*thread_test_finish_line)(struct thread_test *);
};

extern struct thread_test_ops thtest_ops;

#endif /* THREAD_TESTER_H */
