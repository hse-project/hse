/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "multithreaded_tester.h"

#include <mtf/framework.h>

#include <hse_util/rwsem.h>

DECLARE_RWSEM(rwsem1);

struct worker_state {
    int      expected_value;
    int      contribution;
    unsigned writes, reads, bad_reads;
};

struct test_params {
    int iters; /* number of iterations */
    int ltype; /* 1=use rwsem1; 2=use rswem2; */
    int lock;  /* 1=use lock; 0=do not use lock; */
    int tcnt;  /* thread count */
};

struct test {

    /* test infrastructure */
    struct mtest *        mtest;
    struct mtf_test_info *mtf;

    /* test params */
    struct test_params p;

    /* global/shared state */
    int *                shared_var;
    struct rw_semaphore  rwsem2;
    struct rw_semaphore *rwsem;

    /* private/per-thread state */
    struct worker_state **wstate;
};

static void
worker(void *context, int id);
static void
report(void *context, double elapsed_time);

static void
test_create(struct test **test_out, struct mtf_test_info *lcl_ti, struct test_params *params)
{
    struct test *test;
    int          i;

    ASSERT_GT(params->tcnt, 0);
    ASSERT_LT(params->tcnt, 100);

    test = calloc(1, sizeof(struct test));
    ASSERT_TRUE(test);

    test->p = *params;
    test->mtf = lcl_ti;

    test->wstate = mtest_alloc(test->p.tcnt * sizeof(void *));
    ASSERT_TRUE(test->wstate);

    for (i = 0; i < test->p.tcnt; i++) {
        test->wstate[i] = (struct worker_state *)mtest_alloc(sizeof(struct worker_state));
        ASSERT_TRUE(test->wstate[i]);
    }

    test->shared_var = (int *)mtest_alloc(sizeof(int));
    init_rwsem(&test->rwsem2);
    test->rwsem = test->p.ltype == 1 ? &rwsem1 : &test->rwsem2;

    test->mtest = mtest_create(test->p.tcnt, worker, report, test);
    ASSERT_TRUE(test->mtest);

    *test_out = test;
}

static void
test_destroy(struct test *test)
{
    int i;

    free(test->shared_var);
    for (i = 0; i < test->p.tcnt; i++)
        free(test->wstate[i]);

    free(test->wstate);
    mtest_destroy(test->mtest);
    free(test);
}

static void
worker(void *context, int id)
{
    struct test *         test = (struct test *)context;
    struct mtf_test_info *lcl_ti = test->mtf;
    struct worker_state * ts = test->wstate[id];
    struct mtest *        mtest = test->mtest;

    int write_iter = id;
    int iter;
    int i;

    /* All threads verify shared var is initially zero. */
    ASSERT_EQ(*test->shared_var, 0);
    mtest_barrier(mtest);

    /*
     * Suppose there are 8 threads, then each thread
     * does the "write" operaton every 8 iterations.
     */

    for (iter = 0; iter < test->p.iters; iter++) {

        if (iter == write_iter) {
            /*
             * Write operation:
             * The shared_var is incremented by
             * one an even number of times.  It
             * is incremented in a loop to expose
             * odd values along the way (readers
             * should never see odd values).
             */
            int add, init, final;

            if (test->p.lock)
                down_write(test->rwsem);

            add = 2 * (id + 1);
            init = *test->shared_var;
            for (i = 0; i < add; i++)
                *test->shared_var += 1;

            final = *test->shared_var;

            /* Verify shared_var has increased by
             * expected amount. */
            if (test->p.lock)
                ASSERT_EQ(init + add, final);

            ts->contribution += add;
            ts->writes += 1;

            /* Schedule next write. */
            write_iter += test->p.tcnt;

            if (test->p.lock)
                up_write(test->rwsem);
        } else {
            /*
             * Read operation: Verify shared_var is
             * not an odd value.
             */
            if (test->p.lock)
                down_read(test->rwsem);
            if (test->p.lock)
                ASSERT_EQ(*test->shared_var & 1, 0);
            else if (*test->shared_var & 1)
                ts->bad_reads += 1;
            ts->reads += 1;
            if (test->p.lock)
                up_read(test->rwsem);
        }
    }
}

/* calculate results -- each thread's run() method has terminated */
static void
report(void *context, double elapsed_time)
{
    struct test *         test = (struct test *)context;
    struct mtf_test_info *lcl_ti = test->mtf;

    int expected_value = 0;
    int i;

    for (i = 0; i < test->p.tcnt; i++) {
        struct worker_state *ts = test->wstate[i];

        expected_value += ts->contribution;
        printf(
            "  T%02d: Wr/Rd/Contr/Bad = %d %d %d %d\n",
            i,
            ts->writes,
            ts->reads,
            ts->contribution,
            ts->bad_reads);
    }
    printf(
        "Test: Threads=%d Iterations=%d Time=%f secs:"
        " Expected/Actual Values = %d/%d\n",
        test->p.tcnt,
        test->p.iters,
        elapsed_time,
        expected_value,
        *test->shared_var);
    if (test->p.lock)
        ASSERT_EQ(expected_value, *test->shared_var);
}

static void
runtest(struct mtf_test_info *lcl_ti, struct test_params *params)
{
    struct test *test = NULL;

    test_create(&test, lcl_ti, params);
    ASSERT_TRUE(test);
    mtest_run(test->mtest);
    test_destroy(test);
}

#define RUN(P1, P2, P3, P4)                         \
    ({                                              \
        struct test_params tp = { P1, P2, P3, P4 }; \
        runtest(lcl_ti, &tp);                       \
    })

MTF_BEGIN_UTEST_COLLECTION(rwsem_test);

/* One thread, one iteration - to sanity check logic */
MTF_DEFINE_UTEST(rwsem_test, t1_i1_p1_l1)
{
    RUN(.iters = 1, .ltype = 1, .lock = 1, .tcnt = 1);
}
MTF_DEFINE_UTEST(rwsem_test, t1_i1_p2_l1)
{
    RUN(.iters = 1, .ltype = 2, .lock = 1, .tcnt = 1);
}

/* More iters */
MTF_DEFINE_UTEST(rwsem_test, t1_i10000_p1_l1)
{
    RUN(.iters = 10000, .ltype = 1, .lock = 1, .tcnt = 1);
}
MTF_DEFINE_UTEST(rwsem_test, t1_i10000_p2_l1)
{
    RUN(.iters = 10000, .ltype = 2, .lock = 1, .tcnt = 1);
}

/* Multiple Threads */
MTF_DEFINE_UTEST(rwsem_test, t8_i10000_p1_l1)
{
    RUN(.iters = 10000, .ltype = 1, .lock = 1, .tcnt = 8);
}
MTF_DEFINE_UTEST(rwsem_test, t8_i10000_p2_l1)
{
    RUN(.iters = 10000, .ltype = 2, .lock = 1, .tcnt = 8);
}

/* Multiple Threads w/o locks */
MTF_DEFINE_UTEST(rwsem_test, t8_i10000_p1_l0)
{
    RUN(.iters = 10000, .ltype = 1, .lock = 0, .tcnt = 8);
}

MTF_END_UTEST_COLLECTION(rwsem_test)
