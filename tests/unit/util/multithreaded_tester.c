/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include "multithreaded_tester.h"

struct mtest_worker {
    struct mtest *mtest;
    pthread_t     threadid;
    int           wnum;
};

struct mtest {
    int                  num_workers;
    struct mtest_worker *workers;
    pthread_barrier_t    worker_barrier;
    pthread_barrier_t    global_barrier;
    mtest_worker_fn *    worker_func;
    mtest_report_fn *    report_func;
    void *               user_context;
};

struct mtest *
mtest_create(
    int              num_workers,
    mtest_worker_fn *worker_func,
    mtest_report_fn *report_func,
    void *           user_context)
{
    int           err;
    struct mtest *mtest = NULL;

    if (num_workers <= 0 || num_workers > 100)
        goto error;

    mtest = (struct mtest *)calloc(1, sizeof(struct mtest));
    if (!mtest)
        goto error;

    mtest->workers = (struct mtest_worker *)calloc(num_workers, sizeof(struct mtest_worker));
    if (!mtest->workers)
        goto error;

    err = pthread_barrier_init(&mtest->worker_barrier, NULL, (unsigned)num_workers);
    if (err)
        goto error;

    err = pthread_barrier_init(&mtest->global_barrier, NULL, (unsigned)num_workers + 1);
    if (err)
        goto error;

    mtest->num_workers = num_workers;
    mtest->worker_func = worker_func;
    mtest->report_func = report_func;
    mtest->user_context = user_context;
    return mtest;

error:
    if (mtest) {
        if (mtest->workers)
            free(mtest->workers);
        free(mtest);
    }
    return NULL;
}

void
mtest_destroy(struct mtest *mtest)
{
    free(mtest->workers);
    free(mtest);
}

void
mtest_barrier(struct mtest *mtest)
{
    int rc = pthread_barrier_wait(&mtest->worker_barrier);

    if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
        perror("pthread_barrier_wait");
        exit(-1);
    }
}

static void
starting_gate(struct mtest *mtest)
{
    int rc = pthread_barrier_wait(&mtest->global_barrier);

    if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
        perror("pthread_barrier_wait");
        exit(-1);
    }
}

static void
finish_line(struct mtest *mtest)
{
    int rc = pthread_barrier_wait(&mtest->global_barrier);

    if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
        perror("pthread_barrier_wait");
        exit(-1);
    }
}

static void *
launch_thread(void *rock)
{
    struct mtest_worker *w = (struct mtest_worker *)rock;
    struct mtest *       mtest = w->mtest;

    starting_gate(mtest);
    if (mtest->worker_func)
        mtest->worker_func(mtest->user_context, w->wnum);
    finish_line(mtest);
    return NULL;
}

void
mtest_run(struct mtest *mtest)
{
    int             rc;
    struct timespec tstart, tend;
    double          elapsed_time;
    int             i;

    /* Instantiate workers */
    for (i = 0; i < mtest->num_workers; i++) {
        struct mtest_worker *w = &mtest->workers[i];

        w->mtest = mtest;
        w->wnum = i;
        rc = pthread_create(&w->threadid, NULL, launch_thread, w);
        if (rc) {
            perror("pthread_create");
            exit(-1);
        }
    }

    /* Get starting time */
    rc = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tstart);
    if (rc) {
        perror("clock_gettime");
        exit(-1);
    }

    /* Let workers run, then wait for completion */
    starting_gate(mtest);
    finish_line(mtest);

    /* Get ending time */
    rc = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tend);
    if (rc) {
        perror("clock_gettime");
        exit(-1);
    }

    elapsed_time = (tend.tv_sec + tend.tv_nsec * 1e-9) - (tstart.tv_sec + tstart.tv_nsec * 1e-9);

    /* Join workers */
    for (i = 0; i < mtest->num_workers; i++) {
        struct mtest_worker *w = &mtest->workers[i];
        void *               result;

        rc = pthread_join(w->threadid, &result);
        if (rc) {
            perror("pthread_join");
            exit(-1);
        }
    }

    if (mtest->report_func)
        mtest->report_func(mtest->user_context, elapsed_time);
}
