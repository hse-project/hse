/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>

#include "multithreaded_tester.h"
#include <mtf/framework.h>

MTF_BEGIN_UTEST_COLLECTION(atomic_test);

/*
 * ================================================================
 *
 * Single-threaded basic tests
 *
 * ================================================================
 */

MTF_DEFINE_UTEST(atomic_test, basic)
{
    int old_val, new_val;
    atomic_int v;
    bool b;

    atomic_set(&v, 23);
    ASSERT_EQ(atomic_read(&v), 23);

    atomic_add(&v, 2);
    ASSERT_EQ(atomic_read(&v), 25);

    atomic_sub(&v, 3);
    ASSERT_EQ(atomic_read(&v), 22);

    atomic_inc(&v);
    ASSERT_EQ(atomic_read(&v), 23);

    atomic_dec(&v);
    ASSERT_EQ(atomic_read(&v), 22);

    atomic_set(&v, 10);
    ASSERT_EQ(atomic_read(&v), 10);

    ASSERT_EQ(atomic_inc_return(&v), 11);
    ASSERT_EQ(atomic_dec_return(&v), 10);

    atomic_set(&v, 32);
    old_val = 32;
    new_val = 50;
    b = atomic_cmpxchg(&v, &old_val, new_val);
    ASSERT_TRUE(b);
    ASSERT_EQ(atomic_read(&v), new_val);

    old_val = 49;
    new_val = 32;
    b = atomic_cmpxchg(&v, &old_val, new_val);
    ASSERT_FALSE(b);
    ASSERT_EQ(atomic_read(&v), 50);
}

MTF_DEFINE_UTEST(atomic_test, basic64)
{
    atomic_long v;
    long        i;
    u64         s;

    ASSERT_EQ(sizeof(i), 8);
    ASSERT_EQ(sizeof(v), 8);

    atomic_set(&v, ~1L);
    ASSERT_EQ(atomic_read(&v), ~1L);

    atomic_set(&v, 3);
    ASSERT_EQ(atomic_read(&v), 3L);

    atomic_add(&v, 0x100000000L);
    ASSERT_EQ(atomic_read(&v), 0x100000003L);
    atomic_sub(&v, 3);
    ASSERT_EQ(atomic_read(&v), 0x100000000L);

    atomic_add(&v, 5L);
    ASSERT_EQ(atomic_read(&v), 0x100000005L);

    atomic_sub(&v, 5L);
    ASSERT_EQ(atomic_read(&v), 0x100000000L);

    atomic_set(&v, 0xFFFFFFFFL);
    atomic_inc(&v);
    ASSERT_EQ(atomic_read(&v), 0x100000000L);

    atomic_inc(&v);
    ASSERT_EQ(atomic_read(&v), 0x100000001L);

    atomic_dec(&v);
    ASSERT_EQ(atomic_read(&v), 0x100000000L);

    atomic_dec(&v);
    ASSERT_EQ(atomic_read(&v), 0xFFFFFFFFL);

    atomic_inc(&v);
    ASSERT_EQ(atomic_read(&v), 0x100000000L);

    atomic_set(&v, 0xFFFFFFFFL);
    ASSERT_EQ(atomic_read(&v), 0xFFFFFFFFL);
    ASSERT_EQ(atomic_inc_return(&v), 0x100000000L);
    ASSERT_EQ(atomic_inc_return(&v), 0x100000001L);
    ASSERT_EQ(atomic_dec_return(&v), 0x100000000L);

    atomic_set(&v, 0xFFFFFFFFL);
    s = atomic_fetch_add(&v, 1);
    ASSERT_EQ(s, 0xFFFFFFFFUL);

    s = atomic_read(&v);
    ASSERT_EQ(s, 0x100000000UL);

    s = atomic_fetch_add(&v, 2);
    ASSERT_EQ(s, 0x100000000UL);

    s = atomic_read(&v);
    ASSERT_EQ(s, 0x100000002UL);

    atomic_set(&v, 2L);
    s = atomic_fetch_add(&v, 0xFFFFFFFF);
    ASSERT_EQ(s, 2UL);

    s = atomic_fetch_add(&v, 1);
    ASSERT_EQ(s, 0x100000001UL);

    atomic_set(&v, ~1L);
    s = atomic_fetch_add(&v, 1);
    ASSERT_EQ(s, ~1UL);

    s = atomic_fetch_add(&v, 1);
    ASSERT_EQ(s, ~0UL);

    s = atomic_fetch_add(&v, 2);
    ASSERT_EQ(s, 0UL);
}

/*
 * ================================================================
 *
 * Multi-threaded tests
 *
 * ================================================================
 */
enum test_case {
    TC_INC,
    TC_DEC,
    TC_ADD,
    TC_SUB,
    TC_UPDOWN,
    TC_MIXED,
};

struct worker_state {
    int  ev32; /* expected value for 32-bit tests */
    long ev64; /* expected value for 64-bit tests */
};

struct test_params {
    enum test_case tc;
    int            width;
    int            iters;
    int            threads;
};

struct test {
    /* test infrastructure */
    struct mtest *        mtest;
    struct mtf_test_info *mtf;

    /* test params */
    struct test_params p;

    /* global/shared state
     * - ptrs to shared vars
     */
    int *        nav32; /* 32-bit non-atomic */
    atomic_int  *av32;  /* 32-bit atomic */
    long *       nav64; /* 64-bit non-atomic */
    atomic_long *av64;  /* 64-bit atomic */

    /* per-worker state */
    struct worker_state **wstate;
};

const char *
tc_str(enum test_case tc)
{
    switch (tc) {
        case TC_INC:
            return "INC";
        case TC_DEC:
            return "DEC";
        case TC_ADD:
            return "ADD";
        case TC_SUB:
            return "SUB";
        case TC_UPDOWN:
            return "UPDOWN";
        case TC_MIXED:
            return "MIXED";
    }
    return "Invalid!!!!";
}

#define UPDATE32(X)                   \
    do {                              \
        t->wstate[tnum]->ev32 += (X); \
        *t->nav32 += (X);             \
    } while (0)

#define UPDATE64(X)                   \
    do {                              \
        t->wstate[tnum]->ev64 += (X); \
        *t->nav64 += (X);             \
    } while (0)

void
test_thread(void *context, int tnum)
{
    struct test *t = (struct test *)context;

    int i;

    switch (t->p.tc) {

        case TC_INC:
            if (t->p.width == 64) {
                for (i = 0; i < t->p.iters; i++)
                    atomic_inc(t->av64);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE64(1);
            } else {
                for (i = 0; i < t->p.iters; i++)
                    atomic_inc(t->av32);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE32(1);
            }
            break;

        case TC_DEC:
            if (t->p.width == 64) {
                for (i = 0; i < t->p.iters; i++)
                    atomic_dec(t->av64);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE64(-1);
            } else {
                for (i = 0; i < t->p.iters; i++)
                    atomic_dec(t->av32);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE32(-1);
            }
            break;

        case TC_ADD:
            if (t->p.width == 64) {
                for (i = 0; i < t->p.iters; i++)
                    atomic_add(t->av64, 4);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE64(4);
            } else {
                for (i = 0; i < t->p.iters; i++)
                    atomic_add(t->av32, 4);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE32(4);
            }
            break;

        case TC_SUB:
            if (t->p.width == 64) {
                for (i = 0; i < t->p.iters; i++)
                    atomic_sub(t->av64, 4);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE64(-4);
            } else {
                for (i = 0; i < t->p.iters; i++)
                    atomic_sub(t->av32, 4);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE32(-4);
            }
            break;

        case TC_UPDOWN:
            if (t->p.width == 64) {
                for (i = 0; i < t->p.iters; i++)
                    atomic_add(t->av64, i);
                for (i = 0; i < t->p.iters; i++)
                    atomic_sub(t->av64, i);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE64(i);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE64(-i);
            } else {
                for (i = 0; i < t->p.iters; i++)
                    atomic_add(t->av32, i);
                for (i = 0; i < t->p.iters; i++)
                    atomic_sub(t->av32, i);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE32(i);
                for (i = 0; i < t->p.iters; i++)
                    UPDATE32(-i);
            }
            break;

        case TC_MIXED:
            for (i = 0; i < t->p.iters; i++) {
                if (t->p.width == 64) {
                    atomic_inc(t->av64);
                    UPDATE64(1);
                    atomic_inc(t->av64);
                    UPDATE64(1);
                    atomic_add(t->av64, 10);
                    UPDATE64(10);
                    atomic_sub(t->av64, 2);
                    UPDATE64(-2);
                    atomic_dec(t->av64);
                    UPDATE64(-1);
                    atomic_dec(t->av64);
                    UPDATE64(-1);
                    atomic_add(t->av64, tnum);
                    UPDATE64(tnum);
                    atomic_add(t->av64, i + 20);
                    UPDATE64(i + 20);
                    atomic_sub(t->av64, i + 10);
                    UPDATE64(-(i + 10));
                } else {
                    atomic_inc(t->av32);
                    UPDATE32(1);
                    atomic_inc(t->av32);
                    UPDATE32(1);
                    atomic_add(t->av32, 10);
                    UPDATE32(10);
                    atomic_sub(t->av32, 2);
                    UPDATE32(-2);
                    atomic_dec(t->av32);
                    UPDATE32(-1);
                    atomic_dec(t->av32);
                    UPDATE32(-1);
                    atomic_add(t->av32, tnum);
                    UPDATE32(tnum);
                    atomic_add(t->av32, i + 20);
                    UPDATE32(i + 20);
                    atomic_sub(t->av32, i + 10);
                    UPDATE32(-(i + 10));
                }
            }
            break;
    }
}

void
test_report(void *context, double elapsed_time)
{
    int                   i;
    struct test *         t = (struct test *)context;
    struct mtf_test_info *lcl_ti = t->mtf;

    if (t->p.width == 64) {
        long ev64 = 0;

        for (i = 0; i < t->p.threads; i++)
            ev64 += t->wstate[i]->ev64;
        printf(
            "Test: %8s_64 :: expected = %12ld, atomic = %12ld,"
            " non_atomic = %12ld\n",
            tc_str(t->p.tc),
            ev64,
            atomic_read(t->av64),
            *t->nav64);
        ASSERT_EQ(atomic_read(t->av64), ev64);
    } else {
        int ev32 = 0;

        for (i = 0; i < t->p.threads; i++)
            ev32 += t->wstate[i]->ev32;
        printf(
            "Test: %8s_32 :: expected = %12d, atomic = %12d,"
            " non_atomic = %12d;\n",
            tc_str(t->p.tc),
            ev32,
            atomic_read(t->av32),
            *t->nav32);
        ASSERT_EQ(atomic_read(t->av32), ev32);
    }
}

static void
test_init(struct test *t, struct test_params *params, struct mtf_test_info *lcl_ti)
{
    int wnum;

    memset(t, 0, sizeof(*t));
    t->p = *params;
    t->mtf = lcl_ti;
    log_info("Test Params: %s width=%d iters=%d workers=%d",
             tc_str(t->p.tc),
             t->p.width,
             t->p.iters,
             t->p.threads);

    ASSERT_GT(t->p.iters, 0);

    t->wstate = mtest_alloc(t->p.threads * sizeof(struct worker_state *));
    ASSERT_TRUE(t->wstate != NULL);

    for (wnum = 0; wnum < t->p.threads; wnum++) {
        t->wstate[wnum] = (struct worker_state *)mtest_alloc(sizeof(struct worker_state));
        ASSERT_TRUE(t->wstate[wnum] != NULL);
    }

    /* allocate shared vars on separate cache lines */
    t->nav32 = (int *)mtest_alloc(sizeof(*t->nav32));
    t->nav64 = (long *)mtest_alloc(sizeof(*t->nav64));
    t->av32 = (atomic_int *)mtest_alloc(sizeof(*t->av32));
    t->av64 = (atomic_long *)mtest_alloc(sizeof(*t->av64));

    /* intialize shared vars */
    *t->nav32 = 0;
    *t->nav64 = 0L;
    atomic_set(t->av32, 0);
    atomic_set(t->av64, 0);

    t->mtest = mtest_create(t->p.threads, test_thread, test_report, t);
    ASSERT_TRUE(t->mtest);
}

void
test_fini(struct test *t)
{
    int wnum;

    mtest_destroy(t->mtest);

    for (wnum = 0; wnum < t->p.threads; wnum++)
        free(t->wstate[wnum]);
    free(t->wstate);

    free(t->nav32);
    free(t->av32);
    free(t->nav64);
    free(t->av64);
}

#define MY_DEFINE_TEST(N1, V1, N2, V2, N3, V3, N4, V4)                 \
    MTF_DEFINE_UTEST(atomic_test, V1##_##N2##V2##_##N3##V3##_##N4##V4) \
    {                                                                  \
        struct test_params tp = {                                      \
            .N1 = V1, .N2 = V2, .N3 = V3, .N4 = V4,                    \
        };                                                             \
        struct test test;                                              \
        test_init(&test, &tp, lcl_ti);                                 \
        mtest_run(test.mtest);                                         \
        test_fini(&test);                                              \
    }

#define MY_TEST(N1, V1, N2, V2)                               \
    MY_DEFINE_TEST(tc, TC_INC, width, 32, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_DEC, width, 32, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_ADD, width, 32, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_SUB, width, 32, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_UPDOWN, width, 32, N1, V1, N2, V2); \
    MY_DEFINE_TEST(tc, TC_MIXED, width, 32, N1, V1, N2, V2);  \
                                                              \
    MY_DEFINE_TEST(tc, TC_INC, width, 64, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_DEC, width, 64, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_ADD, width, 64, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_SUB, width, 64, N1, V1, N2, V2);    \
    MY_DEFINE_TEST(tc, TC_UPDOWN, width, 64, N1, V1, N2, V2); \
    MY_DEFINE_TEST(tc, TC_MIXED, width, 64, N1, V1, N2, V2)

/* One thread, one iteration - to sanity check logic */
MY_TEST(iters, 1, threads, 1);

/* One thread,  many iterations - also a sanity check */
MY_TEST(iters, 10000, threads, 1);

/* Progressively more threads */
MY_TEST(iters, 10000, threads, 2);
MY_TEST(iters, 10000, threads, 4);
MY_TEST(iters, 10000, threads, 24);

MTF_END_UTEST_COLLECTION(atomic_test)
