/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <logging/logging.h>
#include <hse_util/spinlock.h>

#include <mtf/framework.h>

#include "multithreaded_tester.h"
#include "thread_tester.h"

struct thread_test *   spinlock_tester;
struct thread_test_ops spinlock_test_ops;

struct thread_state {
    int expected_value;
};

struct spinlock_test_data {
    /* config */
    int sltest_iters;

    /* global/shared state */
    int         sltest_num_threads;
    int *       sltest_protected_var;
    int *       sltest_unprotected_var;
    spinlock_t  sltest_spinlock2;
    spinlock_t *sltest_lock;

    /* private/per-thread state */
    struct thread_state *sltest_thread_state[MAX_THREADS];
};

static struct spinlock_test_data slock_test_data;

/*
 * An artifice to thwart compiler optimization.
 */
static void
spinlock_test_add(int *sum, int addend)
{
    *sum += addend;
}

void
spinlock_test_init(struct thread_test *stester, void *test_data, int num_threads)
{
    struct spinlock_test_data *stest_data = test_data;

    int i;

    stest_data->sltest_num_threads = num_threads;

    VERIFY_GT(num_threads, 0);
    VERIFY_LT(num_threads, MAX_THREADS);

    for (i = 0; i < num_threads; i++)
        stest_data->sltest_thread_state[i] = mtest_alloc(sizeof(struct thread_state));

    stest_data->sltest_protected_var = mtest_alloc(sizeof(stest_data->sltest_protected_var));
    stest_data->sltest_unprotected_var = mtest_alloc(sizeof(stest_data->sltest_unprotected_var));

    spin_lock_init(&stest_data->sltest_spinlock2);

    stest_data->sltest_lock = &stest_data->sltest_spinlock2;
}

void
spinlock_test_fini(struct thread_test *stester, void *test_data)
{
    struct spinlock_test_data *stest_data = test_data;

    int i;

    free(stest_data->sltest_unprotected_var);
    free(stest_data->sltest_protected_var);
    for (i = 0; i < stest_data->sltest_num_threads; i++)
        free(stest_data->sltest_thread_state[i]);
}

void
spinlock_test_thread(struct thread_test *stester, void *test_data, int id)
{
    struct spinlock_test_data *stest_data = test_data;

    int i;

    /*
     * Continuing the artifice to thwart compiler optimization.
     */
    void (*addfunc)(int *, int) = spinlock_test_add;

    VERIFY_GE(id, 0);
    VERIFY_LT(id, MAX_THREADS);

    struct thread_state *ts = stest_data->sltest_thread_state[id];

    VERIFY_GT(stest_data->sltest_iters, 0);

    /* update the expected value */
    ts->expected_value += stest_data->sltest_iters;

    stester->thtst_ops->thread_test_barrier(stester);

    /* slam the unprotected var */
    for (i = 0; i < stest_data->sltest_iters; i++)
        addfunc(stest_data->sltest_unprotected_var, 1);

    stester->thtst_ops->thread_test_barrier(stester);

    /* slam the protected var */
    for (i = 0; i < stest_data->sltest_iters; i++) {
        spin_lock(stest_data->sltest_lock);
        addfunc(stest_data->sltest_protected_var, 1);
        spin_unlock(stest_data->sltest_lock);
    }
}

void
spinlock_test_report(struct thread_test *stester, void *test_data, double elapsed_time)
{
    struct spinlock_test_data *stest_data = test_data;

    /* calculate results -- each thread's run() method has terminated */
    int expected_value = 0;
    int i;

    for (i = 0; i < stest_data->sltest_num_threads; i++) {
        struct thread_state *ts = stest_data->sltest_thread_state[i];

        expected_value += ts->expected_value;
    }

    log_info(
        "Test: Threads=%d Iterations=%d Time=%f secs:"
        " EV=%d, Protected=%d UnProtected=%d\n",
        stest_data->sltest_num_threads,
        stest_data->sltest_iters,
        elapsed_time,
        expected_value,
        *stest_data->sltest_protected_var,
        *stest_data->sltest_unprotected_var);

    VERIFY_EQ(expected_value, *stest_data->sltest_protected_var);
}

int
platform_pre(struct mtf_test_info *ti)
{
    spinlock_tester = malloc(sizeof(struct thread_test));

    if (!spinlock_tester)
        return 1;

    spinlock_test_ops = thtest_ops;

    spinlock_test_ops.thread_test_init = spinlock_test_init;
    spinlock_test_ops.thread_test_fini = spinlock_test_fini;
    spinlock_test_ops.thread_test_thread = spinlock_test_thread;
    spinlock_test_ops.thread_test_report = spinlock_test_report;

    spinlock_tester->thtst_ops = &spinlock_test_ops;

    spinlock_tester->thtst_ops->thread_test_ctor(spinlock_tester);

    return 0;
}

int
platform_post(struct mtf_test_info *ti)
{
    spinlock_tester->thtst_ops->thread_test_dtor(spinlock_tester);
    free(spinlock_tester);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(spinlock_test, platform_pre, platform_post);

/*
 * One thread, one iteration - to sanity check logic
 */
MTF_DEFINE_UTEST(spinlock_test, l2_thrd1_iter1)
{
    slock_test_data.sltest_iters = 1;

    spinlock_tester->thtst_ops->thread_test_run(spinlock_tester, &slock_test_data, 1);
}

MTF_DEFINE_UTEST(spinlock_test, l2_thrd1_iter100000)
{
    slock_test_data.sltest_iters = 100000;

    spinlock_tester->thtst_ops->thread_test_run(spinlock_tester, &slock_test_data, 1);
}

MTF_DEFINE_UTEST(spinlock_test, l2_thrd2_iter100000)
{
    slock_test_data.sltest_iters = 100000;

    spinlock_tester->thtst_ops->thread_test_run(spinlock_tester, &slock_test_data, 2);
}

MTF_DEFINE_UTEST(spinlock_test, l2_thrd4_iter100000)
{
    slock_test_data.sltest_iters = 100000;

    spinlock_tester->thtst_ops->thread_test_run(spinlock_tester, &slock_test_data, 4);
}

MTF_DEFINE_UTEST(spinlock_test, l2_thrd8_iter100000)
{
    slock_test_data.sltest_iters = 100000;

    spinlock_tester->thtst_ops->thread_test_run(spinlock_tester, &slock_test_data, 8);
}

MTF_DEFINE_UTEST(spinlock_test, l2_thrd16_iter100000)
{
    slock_test_data.sltest_iters = 100000;

    spinlock_tester->thtst_ops->thread_test_run(spinlock_tester, &slock_test_data, 16);
}

static void *
trylock_thr(void *arg)
{
    spinlock_t *lockp = (spinlock_t *)arg;

    if (spin_trylock(lockp))
        return NULL;

    return arg;
}

MTF_DEFINE_UTEST(spinlock_test, trylock_test)
{
    spinlock_t morlock;
    pthread_t  tid;
    int        rc;
    void *     trylock_status;

    spin_lock_init(&morlock);

    rc = spin_trylock(&morlock);
    ASSERT_NE(rc, 0);

    rc = pthread_create(&tid, NULL, trylock_thr, &morlock);
    ASSERT_EQ(0, rc);

    (void)pthread_join(tid, &trylock_status);

    ASSERT_NE(trylock_status, NULL);

    spin_unlock(&morlock);
}

MTF_END_UTEST_COLLECTION(spinlock_test)
