/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <hse/logging/logging.h>

#include <hse/test/mtf/conditions.h>

#include "multithreaded_tester.h"
#include "thread_tester.h"

static void *
launch_worker(void *rock);

struct worker_info {
    struct thread_test *thtester;
    void *test_data;
    pthread_t threadid;
    int wnum; /* worker number */
};

void
thread_test_ctor(struct thread_test *thtester)
{
    thtester->thtst_workers = mtest_alloc(MAX_THREADS * sizeof(struct worker_info));
}

void
thread_test_dtor(struct thread_test *thtester)
{
    free(thtester->thtst_workers);
}

static void
thread_test_wait_barrier(struct thread_test *thtester, pthread_barrier_t *bar)
{
    int rc = pthread_barrier_wait(bar);

    if (rc)
        VERIFY_EQ(rc, PTHREAD_BARRIER_SERIAL_THREAD);
}

void
thread_test_barrier(struct thread_test *thtester)
{
    thtester->thtst_ops->thread_test_wait_barrier(thtester, &thtester->thtst_worker_barrier);
}

void
thread_test_starting_gate(struct thread_test *thtester)
{
    thtester->thtst_ops->thread_test_wait_barrier(thtester, &thtester->thtst_global_barrier);
}

void
thread_test_finish_line(struct thread_test *thtester)
{
    thtester->thtst_ops->thread_test_wait_barrier(thtester, &thtester->thtst_global_barrier);
}

void
thread_test_run(struct thread_test *thtester, void *test_data, int num_threads)
{
    struct timespec tstart;
    struct timespec tend;
    double elapsed_time;
    int rc;
    int i;

    VERIFY_GT(num_threads, 0);

    rc = pthread_barrier_init(&thtester->thtst_worker_barrier, NULL, (unsigned)num_threads);

    VERIFY_EQ(rc, 0);

    rc = pthread_barrier_init(&thtester->thtst_global_barrier, NULL, (unsigned)num_threads + 1);

    VERIFY_EQ(rc, 0);

    thtester->thtst_ops->thread_test_init(thtester, test_data, num_threads);

    /* Instantiate threads */
    for (i = 0; i < num_threads; i++) {
        struct worker_info *w = &thtester->thtst_workers[i];

        w->thtester = thtester;
        w->test_data = test_data;
        w->wnum = i;

        rc = pthread_create(&w->threadid, NULL, launch_worker, w);
        VERIFY_EQ(rc, 0);
    }

    /* Get starting time */
    rc = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tstart);
    VERIFY_EQ(rc, 0);

    /* Let threads run, then wait for completion */
    thtester->thtst_ops->thread_test_starting_gate(thtester);
    thtester->thtst_ops->thread_test_finish_line(thtester);

    /* Get ending time */
    rc = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tend);
    VERIFY_EQ(rc, 0);

    elapsed_time = (tend.tv_sec + tend.tv_nsec * 1e-9) - (tstart.tv_sec + tstart.tv_nsec * 1e-9);

    /* Join threads */
    for (i = 0; i < num_threads; i++) {
        struct worker_info *w = &thtester->thtst_workers[i];
        void *result;

        rc = pthread_join(w->threadid, &result);
        VERIFY_EQ(rc, 0);
    }

    thtester->thtst_ops->thread_test_report(thtester, test_data, elapsed_time);

    thtester->thtst_ops->thread_test_fini(thtester, test_data);
}

void *
thread_test_main(struct worker_info *w)
{
    w->thtester->thtst_ops->thread_test_starting_gate(w->thtester);

    w->thtester->thtst_ops->thread_test_thread(w->thtester, w->test_data, w->wnum);

    w->thtester->thtst_ops->thread_test_finish_line(w->thtester);

    return NULL;
};

void *
launch_worker(void *rock)
{
    struct worker_info *w = rock;

    w->thtester->thtst_ops->thread_test_main(w);
    return NULL;
}

struct thread_test_ops thtest_ops = { .thread_test_ctor = thread_test_ctor,
                                      .thread_test_dtor = thread_test_dtor,
                                      .thread_test_main = thread_test_main,
                                      .thread_test_barrier = thread_test_barrier,
                                      .thread_test_run = thread_test_run,

#if 0
    /*
     * Protected, abstract--must be implemented by subclass.
     */
    .thread_test_init
    .thread_test_fini
    .thread_test_thread
    .thread_test_report
#endif

                                      .thread_test_wait_barrier = thread_test_wait_barrier,
                                      .thread_test_starting_gate = thread_test_starting_gate,
                                      .thread_test_finish_line = thread_test_finish_line };
