/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/platform.h>
#include <hse_util/workqueue.h>
#include <hse_util/logging.h>

int verbose = 0;

MTF_BEGIN_UTEST_COLLECTION(workqueue_test);

MTF_DEFINE_UTEST(workqueue_test, create)
{
    struct workqueue_struct *q;

    q = alloc_workqueue(NULL, 0, 0);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, 0);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, 1);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test%d", 0, 1, 19);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, WQ_DFL_ACTIVE);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, WQ_MAX_ACTIVE);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, -1);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, WQ_MAX_ACTIVE + 1);
    ASSERT_TRUE(q);
    destroy_workqueue(q);
}

atomic_t counter;
atomic_t counter2;

void
simple_worker(struct work_struct *wstruct)
{
    atomic_inc(&counter);
}

struct wait_work {
    struct work_struct work;
    int                wait_counter;
    ulong              delay_ms;
};

void
wait_worker(struct work_struct *wstruct)
{
    struct wait_work *work = (void *)wstruct;

    if (work->wait_counter)
        while (atomic_read(&counter) != work->wait_counter)
            usleep(10 * 1000);

    if (work->delay_ms)
        usleep(work->delay_ms * 1000);
}

struct mywork {
    struct work_struct       wstruct;
    struct delayed_work      dwstruct;
    struct workqueue_struct *wqueue;
    int                      id;
    int                      counter;
    int                      chain;
};

void
myworker(struct work_struct *wstruct)
{
    struct mywork *w = (struct mywork *)wstruct;

    atomic_inc(&counter);
    w->counter += 1;

    if (verbose)
        printf("W%d: count=%d chain=%d\n", w->id, w->counter, w->chain);

    if (w->chain > 0) {
        w->chain -= 1;
        queue_work(w->wqueue, wstruct);
    } else {
        memset(w, 0xff, sizeof(struct mywork));
        free(w);
    }
}

void
myworker_delayed(struct work_struct *wstruct)
{
    struct mywork *w = container_of(wstruct, struct mywork, dwstruct.work);

    atomic_inc(&counter);
    w->counter += 1;

    if (verbose)
        printf("W%d: count=%d chain=%d\n", w->id, w->counter, w->chain);

    memset(w, 0xff, sizeof(struct mywork));
    free(w);
}

MTF_DEFINE_UTEST(workqueue_test, run)
{
    struct workqueue_struct *q = NULL;
    struct mywork **         myworks = NULL;
    const int                num_works = 32;
    int                      max_active = 5;
    int                      i, expected, actual;

    expected = 0;
    atomic_set(&counter, 0);

    q = alloc_workqueue("test", 0, max_active);
    ASSERT_TRUE(q);

    myworks = calloc(num_works, sizeof(void *));
    ASSERT_TRUE(myworks != 0);

    for (i = 0; i < num_works; i++) {
        myworks[i] = calloc(1, sizeof(struct mywork));
        ASSERT_TRUE(myworks[i] != 0);

        myworks[i]->wqueue = q;
        myworks[i]->id = i;
        myworks[i]->chain = i;
        myworks[i]->counter = 0;

        expected += myworks[i]->chain + 1;

        INIT_WORK(&myworks[i]->wstruct, myworker);
        queue_work(q, &myworks[i]->wstruct);
    }

    hse_log(HSE_DEBUG "Running  %d jobs", expected);
    for (i = 0; i < expected * 3; ++i) {
        if (atomic_read(&counter) >= expected)
            break;
        usleep(1000);
    }
    actual = atomic_read(&counter);
    hse_log(HSE_DEBUG "Finished %d of %d delayed jobs in %d milliseconds",
            actual, expected, i);
    ASSERT_EQ(expected, actual);

    destroy_workqueue(q);
    free(myworks);
}

MTF_DEFINE_UTEST(workqueue_test, run_delay)
{
    struct workqueue_struct *q = NULL;
    struct mywork **         myworks = NULL;
    const int                num_works = 10;
    int                      max_active = 5;
    int                      i, expected, actual;
    u_long                   delta, deltamax;
    bool                     b;

    expected = 0;
    atomic_set(&counter, 0);

    q = alloc_workqueue("test", 0, max_active);
    ASSERT_TRUE(q);

    myworks = calloc(num_works, sizeof(void *));
    ASSERT_TRUE(myworks != 0);

    expected = 0;
    atomic_set(&counter, 0);

    for (i = 0; i < num_works; i++) {
        myworks[i] = calloc(1, sizeof(struct mywork));
        ASSERT_TRUE(myworks[i] != 0);

        myworks[i]->wqueue = q;
        myworks[i]->id = i;
        myworks[i]->chain = 0;
        myworks[i]->counter = 0;

        expected += myworks[i]->chain + 1;

        delta = get_time_ns();
        deltamax = msecs_to_jiffies(i * 10);

        INIT_DELAYED_WORK(&myworks[i]->dwstruct, myworker_delayed);
        b = queue_delayed_work(q, &myworks[i]->dwstruct, msecs_to_jiffies(i * 10));
        ASSERT_TRUE(b);
    }

    hse_log(HSE_DEBUG "Running %d delayed jobs", expected);
    for (i = 0; i < expected * 333; ++i) {
        if (atomic_read(&counter) >= expected)
            break;
        usleep(1000);
    }
    delta = nsecs_to_jiffies(get_time_ns() - delta);
    actual = atomic_read(&counter);
    hse_log(HSE_DEBUG "Finished %d of %d delayed jobs in %d milliseconds",
            actual, expected, i);
    ASSERT_EQ(expected, actual);
    ASSERT_GE(delta, deltamax);

    destroy_workqueue(q);
    free(myworks);
}

MTF_DEFINE_UTEST(workqueue_test, t_delayed_work)
{
    struct workqueue_struct *q;
    struct delayed_work      work;

    ulong worker_delay_ms, delta;
    int   cnt;
    int   i;
    bool  b;

    q = alloc_workqueue("test", 0, 5);
    ASSERT_TRUE(q);

    atomic_set(&counter, 0);

    worker_delay_ms = 500;

    delta = get_time_ns();
    INIT_DELAYED_WORK(&work, simple_worker);
    b = queue_delayed_work(q, &work, msecs_to_jiffies(worker_delay_ms));
    ASSERT_TRUE(b);

    /* Counter should be zero since worker is delayed. */
    cnt = atomic_read(&counter);
    ASSERT_EQ(cnt, 0);

    /* Delay, then verify counter is set to one. */
    for (i = 0; i < worker_delay_ms * 2 && !cnt; ++i) {
        usleep(1000);
        cnt = atomic_read(&counter);
    }
    delta = nsecs_to_jiffies(get_time_ns() - delta);
    ASSERT_EQ(cnt, 1);
    ASSERT_GE(delta, msecs_to_jiffies(worker_delay_ms));

    destroy_workqueue(q);
}

MTF_DEFINE_UTEST(workqueue_test, t_cancel_delayed_work)
{
    struct workqueue_struct *q = NULL;

    struct delayed_work *workv;
    int                  workc = 1;
    int                  max_active = 1;
    ulong                worker_delay_ms;
    int                  cnt;
    int                  i;
    bool                 b;

    workv = calloc(workc, sizeof(*workv));
    ASSERT_TRUE(workv != NULL);

    q = alloc_workqueue("test", 0, max_active);
    ASSERT_TRUE(q);

    atomic_set(&counter, 0);

    worker_delay_ms = 50000;

    INIT_DELAYED_WORK(&workv[0], simple_worker);

    b = queue_delayed_work(q, &workv[0], msecs_to_jiffies(worker_delay_ms));
    ASSERT_TRUE(b);

    b = queue_delayed_work(q, &workv[0], msecs_to_jiffies(0));
    ASSERT_FALSE(b);

    b = cancel_delayed_work(&workv[0]);
    ASSERT_TRUE(b);

    cnt = atomic_read(&counter);
    ASSERT_EQ(cnt, 0);

    b = cancel_delayed_work(&workv[0]);
    ASSERT_FALSE(b);

    b = queue_delayed_work(q, &workv[0], msecs_to_jiffies(0));
    ASSERT_TRUE(b);

    for (i = 0; i < 10000; ++i) {
        cnt = atomic_read(&counter);
        if (!cnt)
            usleep(1000);
    }
    ASSERT_EQ(cnt, 1);

    b = cancel_delayed_work(&workv[0]);
    ASSERT_FALSE(b);

    destroy_workqueue(q);
    free(workv);
}

MTF_DEFINE_UTEST(workqueue_test, t_queue_work_twice)
{
    struct workqueue_struct *q = NULL;
    struct wait_work *       workv;
    int                      max_active = 1;
    int                      workc = 4 * max_active;
    int                      i;
    bool                     enqueued;

    workv = calloc(workc, sizeof(*workv));
    ASSERT_TRUE(workv != NULL);

    /* Create alloc_workqueue w/ one thread. */
    q = alloc_workqueue("test", 0, max_active);
    ASSERT_TRUE(q);

    /* Queue up several jobs that wait for counter to go non-zero. */
    atomic_set(&counter, 0);

    for (i = 0; i < workc; i++) {
        workv[i].wait_counter = 1;
        workv[i].delay_ms = 0;
        INIT_WORK(&workv[i].work, wait_worker);
        enqueued = queue_work(q, &workv[i].work);
        ASSERT_TRUE(enqueued);
    }

    /* First work item is waiting on counter.  The others should
     * be in the queue.  Verify at least one attempt to requeue the
     * existing work items returns false.
     */
    for (i = 0; i < workc; i++) {
        enqueued = queue_work(q, &workv[i].work);
        if (!enqueued)
            break;
    }
    ASSERT_FALSE(enqueued);

    /* unblock workers */
    atomic_set(&counter, 1);

    destroy_workqueue(q);
    free(workv);
}

/* simple destroy workqueue tests */
MTF_DEFINE_UTEST(workqueue_test, t_destroy_workqueue1)
{
    struct workqueue_struct *q;

    destroy_workqueue(NULL);

    q = alloc_workqueue("test", 0, 0);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, 1);
    ASSERT_TRUE(q);
    destroy_workqueue(q);

    q = alloc_workqueue("test", 0, 10);
    ASSERT_TRUE(q);
    destroy_workqueue(q);
}

/* destroy workqueue with work in the queue */
MTF_DEFINE_UTEST(workqueue_test, t_destroy_workqueue2)
{
    struct workqueue_struct *q = NULL;
    struct wait_work *       workv;
    int                      max_active = 1;
    int                      workc = 4 * max_active;
    int                      i;
    bool                     enqueued;

    workv = calloc(workc, sizeof(*workv));
    ASSERT_TRUE(workv != NULL);

    /* Create alloc_workqueue w/ one thread. */
    q = alloc_workqueue("test", 0, max_active);
    ASSERT_TRUE(q);

    atomic_set(&counter, 0);

    /* Queue up several jobs that wait for counter to go non-zero. */
    for (i = 0; i < workc; i++) {
        workv[i].wait_counter = 1;
        workv[i].delay_ms = 500;
        INIT_WORK(&workv[i].work, wait_worker);
        enqueued = queue_work(q, &workv[i].work);
        ASSERT_TRUE(enqueued);
    }

    /* Unblock workers.  Delay_ms should ensure some of them linger
     * on the work queue, which should force destroy_workqueue to wait for
     * them.
     */
    atomic_set(&counter, 1);

    destroy_workqueue(q);
    free(workv);
}

/* Try to destroy a workqueue with delayed work that hasn't yet expired.
 */
MTF_DEFINE_UTEST(workqueue_test, t_destroy_workqueue3)
{
    struct workqueue_struct *q = NULL;

    struct delayed_work *workv;
    int                  workc = 1;
    int                  max_active = 1;
    ulong                worker_delay_ms;
    ulong                my_delay_ms;
    int                  cnt;
    bool                 b;

    workv = calloc(workc, sizeof(*workv));
    ASSERT_TRUE(workv != NULL);

    q = alloc_workqueue("test", 0, max_active);
    ASSERT_TRUE(q);

    atomic_set(&counter, 0);

    worker_delay_ms = 2000;
    my_delay_ms = 100;

    INIT_DELAYED_WORK(&workv[0], simple_worker);
    b = queue_delayed_work(q, &workv[0], msecs_to_jiffies(worker_delay_ms));
    ASSERT_TRUE(b);

    usleep(my_delay_ms * 1000);
    cnt = atomic_read(&counter);
    ASSERT_EQ(cnt, 0);

    destroy_workqueue(q);

    b = cancel_delayed_work(&workv[0]);
    ASSERT_TRUE(b);

    cnt = atomic_read(&counter);
    ASSERT_EQ(cnt, 0);

    destroy_workqueue(q);
    free(workv);
}

/**
 * sleep_and_count()
 * Sleep and increment the global job tracker counter
 */
static void
sleep_and_count(struct work_struct *wstruct)
{
    usleep(10000);
    atomic_inc(&counter);
}

/*
 * Test work items queued before flush_workqueue() is called
 * can all complete, once flush_workqueue() returns
 */
MTF_DEFINE_UTEST(workqueue_test, flush_test)
{
    struct workqueue_struct *q = NULL;
    const int                num_works = 32;
    struct work_struct *     myworks;
    int                      i, actual;
    bool                     b;

    q = alloc_workqueue("test_flush", 0, num_works);
    ASSERT_TRUE(q);

    /* Test that a nil workqueue doesn't crash us...
     */
    flush_workqueue(NULL);

    myworks = calloc(num_works, sizeof(*myworks));
    ASSERT_TRUE(myworks != 0);
    atomic_set(&counter, 0);

    for (i = 0; i < num_works; i++) {
        INIT_WORK(&myworks[i], sleep_and_count);
        b = queue_work(q, &myworks[i]);
        ASSERT_TRUE(b);
    }

    flush_workqueue(q);

    actual = atomic_read(&counter);
    hse_log(HSE_DEBUG "Finished flush %d jobs", actual);
    ASSERT_EQ(num_works, actual);

    destroy_workqueue(q);
    free(myworks);
}

static void
destroy_test_cb(struct work_struct *work)
{
    struct mywork *w = container_of(work, struct mywork, wstruct);

    usleep(1000);
    if (w->chain-- > 0)
        if (!queue_work(w->wqueue, &w->wstruct))
            abort();
    atomic_inc(&counter);
}

/* destroy_workqueue() called on a work queue with pending requests
 * should not return until all pending requests have completed.
 */
MTF_DEFINE_UTEST(workqueue_test, destroy_test)
{
    struct workqueue_struct *wq;
    struct mywork *          workv;
    int                      i, n;
    bool                     b;

    workv = calloc(128, sizeof(*workv));
    ASSERT_TRUE(workv != NULL);

    /* First test (workers >= jobs)
     */
    for (n = 0; n < 32; ++n) {
        int workc = (n / 8) + 1;
        int actual;

        atomic_set(&counter, 0);

        wq = alloc_workqueue("test_destroy", 0, n + 1);
        ASSERT_TRUE(wq);

        for (i = 0; i < workc; i++) {
            struct mywork *w = workv + i;

            w->wqueue = wq;
            w->chain = 2;
            INIT_WORK(&w->wstruct, destroy_test_cb);
            b = queue_work(wq, &w->wstruct);
            ASSERT_TRUE(b);
        }

        workc *= 3;

        hse_log(
            HSE_DEBUG "Waiting for %d of %d jobs to complete by %d workers",
            workc - atomic_read(&counter),
            workc,
            n + 1);

        flush_workqueue(wq);

        hse_log(
            HSE_DEBUG "Waiting for %d of %d jobs to complete by %d workers",
            workc - atomic_read(&counter),
            workc,
            n + 1);

        flush_workqueue(wq);

        hse_log(
            HSE_DEBUG "Waiting for %d of %d jobs to complete by %d workers",
            workc - atomic_read(&counter),
            workc,
            n + 1);

        destroy_workqueue(wq);

        actual = atomic_read(&counter);
        ASSERT_EQ(workc, actual);
    }

    /* Now test (jobs >= workers)
     */
    for (n = 0; n < 32; ++n) {
        int workc = (n * 5) / 2 + 7;
        int actual;

        atomic_set(&counter, 0);

        wq = alloc_workqueue("test_destroy", 0, n + 1);
        ASSERT_TRUE(wq);

        for (i = 0; i < workc; i++) {
            struct mywork *w = workv + i;

            w->wqueue = wq;
            w->chain = 2;
            INIT_WORK(&w->wstruct, destroy_test_cb);
            b = queue_work(wq, &w->wstruct);
            ASSERT_TRUE(b);
        }

        workc *= 3;

        hse_log(
            HSE_DEBUG "Waiting for %d of %d jobs to complete by %d workers",
            workc - atomic_read(&counter),
            workc,
            n + 1);

        flush_workqueue(wq);

        hse_log(
            HSE_DEBUG "Waiting for %d of %d jobs to complete by %d workers",
            workc - atomic_read(&counter),
            workc,
            n + 1);

        flush_workqueue(wq);

        hse_log(
            HSE_DEBUG "Waiting for %d of %d jobs to complete by %d workers",
            workc - atomic_read(&counter),
            workc,
            n + 1);

        destroy_workqueue(wq);

        actual = atomic_read(&counter);
        ASSERT_EQ(workc, actual);
    }

    free(workv);
}

#if HSE_MOCKING

/* Curiously, relwithdebug build defines NDEBUG, grrr...
 */
#ifdef NDEBUG
#undef assert
#define assert(_expr) \
    do {              \
        if (!(_expr)) \
            abort();  \
    } while (0)
#endif

static void
flush_destroy_cb(struct work_struct *work)
{
    struct mywork *w = container_of(work, struct mywork, wstruct);

    usleep(33 * 1000);
    ++w->counter;
}

static void *
flush_destroy_main(void *arg)
{
    struct workqueue_struct *wq = arg;
    struct mywork            work;
    bool                     b;

    memset(&work, 0, sizeof(work));

    INIT_WORK(&work.wstruct, flush_destroy_cb);
    b = queue_work(wq, &work.wstruct);
    assert(b);

    atomic_inc(&counter);

    flush_workqueue(wq);

    assert(work.counter == 1);
    atomic_inc(&counter2);

    return NULL;
}

/* Test that we can call destroy_workqueue() while there
 * are many pending flush_workqueue() operations.
 */
MTF_DEFINE_UTEST(workqueue_test, flush_destroy)
{
    const int itermax = 5;
    const int tdmax = 17;
    int       wqtdmax;
    int       i, j;
    int       rc;

    for (i = 0; i < itermax; ++i) {
        struct workqueue_struct *wq;

        atomic_set(&counter, 0);
        atomic_set(&counter2, 0);
        mapi_calls_clear(mapi_idx_queue_work_locked);

        wqtdmax = (tdmax / 2) * i + 1;

        wq = alloc_workqueue(__func__, 0, wqtdmax);
        ASSERT_TRUE(wq);

        for (j = 0; j < tdmax; ++j) {
            pthread_t tid;

            rc = pthread_create(&tid, NULL, flush_destroy_main, wq);
            ASSERT_EQ(0, rc);

            rc = pthread_detach(tid);
            ASSERT_EQ(0, rc);
        }

        hse_log(HSE_DEBUG "%s: iter %d, wqtdmax %d", __func__, i, wqtdmax);

        /* Wait for each thread to call queue_work() and flush-
         * _workqueue(), but dont wait too long as we want to call
         * destroy_workqueue() while most of this work is pending.
         */
        while (atomic_read(&counter) < tdmax)
            usleep(100);

        destroy_workqueue(wq);

        /* Wait up to 30 seconds for all threads to return from
         * flush_workqueue() (they should already have returned).
         */
        for (j = 0; j < 30000; ++j) {
            if (atomic_read(&counter2) >= tdmax)
                break;
            usleep(1000);
        }
        ASSERT_EQ(atomic_read(&counter2), tdmax);
    }
}
#endif /* HSE_MOCKING */

static void *
flush_party_main(void *arg)
{
    struct workqueue_struct *wq = arg;

    while (atomic_read(&counter) > 0) {
        flush_workqueue(wq);
        usleep(1);
    }

    return NULL;
}

static void
flush_party_cb(struct work_struct *work)
{
    atomic_dec(&counter);
}

/* Test concurrent workqueue flushing in the presence of delayed work
 * that expires periodically in small batches.  This should generate
 * many iterations of multiple barriers on the pending list with and
 * without intervening real work items.
 */
MTF_DEFINE_UTEST(workqueue_test, flush_party)
{
    struct mywork *workv;
    const int      workmax = 1000;
    const int      itermax = 30;
    const int      tdmax = 13;
    pthread_t      tdv[tdmax];
    int            wqtdmax;
    int            i, j;
    int            rc;

    workv = calloc(workmax, sizeof(*workv));
    ASSERT_TRUE(workv != NULL);

    for (i = 0; i < itermax; ++i) {
        struct workqueue_struct *wq;

        atomic_set(&counter, workmax);

        wqtdmax = (itermax / 3) * i + 1;

        wq = alloc_workqueue(__func__, 0, wqtdmax);
        ASSERT_TRUE(wq);

        for (j = 0; j < tdmax; ++j) {
            rc = pthread_create(tdv + j, NULL, flush_party_main, wq);
            ASSERT_EQ(0, rc);
        }

        for (j = 0; j < workmax; ++j) {
            struct mywork *w = workv + j;

            INIT_DELAYED_WORK(&w->dwstruct, flush_party_cb);
            queue_delayed_work(wq, &w->dwstruct, usecs_to_jiffies(j * 133));
        }

        hse_log(HSE_DEBUG "%s: iter %d, tdwqmax %d", __func__, i, wqtdmax);

        for (j = 0; j < tdmax; ++j)
            (void)pthread_join(tdv[j], NULL);

        destroy_workqueue(wq);
    }

    free(workv);
}

static void
requeue_cb(struct work_struct *work)
{
    struct mywork *w = container_of(work, struct mywork, wstruct);

    while (atomic_read(&counter) < 1)
        usleep(1000);

    ++w->counter;
}

static void
drequeue_cb(struct work_struct *work)
{
    struct mywork *w = container_of(work, struct mywork, dwstruct.work);

    while (atomic_read(&counter) < 1)
        usleep(1000);

    ++w->counter;
}

/* Test that attempting to re-enqueue an enqueued/pending
 * work and dwork returns false (i.e., it's pending).
 */
MTF_DEFINE_UTEST(workqueue_test, requeue)
{
    struct workqueue_struct *wq;

    struct mywork *workv, *w;
    const int      workmax = 3;
    bool           b;

    workv = calloc(workmax, sizeof(*workv));
    ASSERT_TRUE(workv != NULL);

    atomic_set(&counter, 0);

    wq = alloc_workqueue(__func__, 0, 1);
    ASSERT_TRUE(wq);

    /* Enqueue workv[0] to tie up our one worker thread.
     */
    w = workv;
    INIT_WORK(&w->wstruct, requeue_cb);
    b = queue_work(wq, &w->wstruct);
    ASSERT_TRUE(b);

    /* Enqueue work 1, should be pending because there
     * are no available workqueue workers.
     */
    ++w;
    INIT_WORK(&w->wstruct, requeue_cb);
    b = queue_work(wq, &w->wstruct);
    ASSERT_TRUE(b);

    /* Try to re-enqueue work 1, should fail.
     */
    b = queue_work(wq, &w->wstruct);
    ASSERT_FALSE(b);

    /* Enqueue a delayed work item.
     */
    ++w;
    INIT_DELAYED_WORK(&w->dwstruct, drequeue_cb);
    b = queue_delayed_work(wq, &w->dwstruct, 1);
    ASSERT_TRUE(b);

    /* Try to re-enqueue it, should fail.
     */
    b = queue_delayed_work(wq, &w->dwstruct, 1);
    ASSERT_FALSE(b);

    /* Shouldn't be possible to cancel after timer has expired.
     */
    usleep(100 * 1000);
    b = cancel_delayed_work(&w->dwstruct);
    ASSERT_FALSE(b);

    /* Let the callback run and pending work complete.
     */
    atomic_set(&counter, 1);
    destroy_workqueue(wq);

    ASSERT_EQ(workv[0].counter, 1);
    ASSERT_EQ(workv[1].counter, 1);
    ASSERT_EQ(workv[2].counter, 1);

    free(workv);
}

MTF_END_UTEST_COLLECTION(workqueue_test)
