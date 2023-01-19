/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <mtf/framework.h>

#include <hse/util/base.h>
#include <hse/util/xrand.h>

int
compare_u64(const void *ptr_a, const void *ptr_b)
{
    uint64_t a = *(uint64_t *)ptr_a;
    uint64_t b = *(uint64_t *)ptr_b;

    if (a < b)
        return -1;

    if (a > b)
        return +1;

    return 0;
}

/* Keep SEQUENCE_LEN_TLS small to avoid false test failures (see
 * other comments for more info).  SEQUENCE_LEN can be longer, but
 * doesn't add much value and will increase the time it takes to run
 * the test.
 */
#define SEQUENCE_LEN     (10 * 1000)
#define SEQUENCE_LEN_TLS (100)

MTF_BEGIN_UTEST_COLLECTION(xrand_test);

MTF_DEFINE_UTEST(xrand_test, seed_test)
{
    uint64_t seedv[] = { 1, 2, 1234, (uint64_t)-1234, UINT64_MAX, (uint64_t)INT64_MAX };
    uint seedc = sizeof(seedv) / sizeof(seedv[0]);
    uint iters = SEQUENCE_LEN;

    struct xrand xr1, xr2;
    uint64_t v1, v2, s1, s2;

    /* Same seed ==> same sequence. */
    for (uint sx = 0; sx < seedc; sx++) {
        s1 = seedv[sx];
        s2 = seedv[sx];
        xrand_init(&xr1, s1);
        xrand_init(&xr2, s2);
        printf("\nseeds  0x%016lx  0x%016lx\n", (ulong)s1, (ulong)s2);
        for (uint i = 0; i < iters; i++) {
            v1 = xrand64(&xr1);
            v2 = xrand64(&xr2);
            if (i < 10)
                printf("> rvs  0x%016lx  0x%016lx\n", (ulong)v1, (ulong)v2);
            ASSERT_EQ(v1, v2);
        }
    }

    /* Different seed ==> different sequence.
     * Strictly speaking this is not a valid test because random
     * sequences with different seeds can have common values.  But it
     * should be rare with a good PRNG and we are using fixed seed
     * values so the results should be repeatable.
     */
    for (uint sx = 0; sx < seedc; sx++) {
        s1 = seedv[sx];
        s2 = seedv[sx] + 1;
        xrand_init(&xr1, s1);
        xrand_init(&xr2, s2);
        printf("\nseeds  0x%016lx  0x%016lx\n", (ulong)s1, (ulong)s2);
        for (uint i = 0; i < iters; i++) {
            v1 = xrand64(&xr1);
            v2 = xrand64(&xr2);
            if (i < 10)
                printf("> rvs  0x%016lx  0x%016lx\n", (ulong)v1, (ulong)v2);
            ASSERT_NE(v1, v2);
        }
    }
}

/* This test verifies there are no repeated values in the first
 * SEQUENCE_LEN values.  Strictly speaking this is not a valid test
 * because random sequences can have duplicates.  But we are using
 * fixed seed values so the results should be repeatable.
 */
MTF_DEFINE_UTEST(xrand_test, norepeat)
{
    struct xrand xr;
    uint64_t seedv[] = { 0, 1234 };
    uint seedc = sizeof(seedv) / sizeof(seedv[0]);
    uint iters = SEQUENCE_LEN;
    uint64_t *values;

    values = mapi_safe_malloc(iters * sizeof(uint64_t));
    ASSERT_TRUE(values != NULL);

    for (uint sx = 0; sx < seedc; sx++) {

        printf("\nseed  0x%016lx\n", (ulong)seedv[sx]);

        xrand_init(&xr, seedv[sx]);

        for (uint i = 0; i < iters; i++)
            values[i] = xrand64(&xr);

        qsort(values, iters, sizeof(uint64_t), compare_u64);

        for (uint i = 0; i + 1 < iters; i++) {

            if (i < 5)
                printf("> rv  0x%016lx\n", (ulong)values[i]);
            else if (i == 5)
                printf("> rv  ...\n");
            else if (i > iters - 5)
                printf("> rv  0x%016lx\n", (ulong)values[i + 1]);

            ASSERT_NE(values[i], values[i + 1]);
        }
    }

    mapi_safe_free(values);
}

/* This test checks for repeats in the TLS PRNG.
 * Strictly speaking this is not a valid test because random sequences
 * can have duplicates.  Other tests in this file get around this by
 * using fixed seeds, which at least makes the test repeatable.  But
 * we can't control the seed in the TLS PRNG, so instead we reduce the
 * chance of inadvertent failure by only checking the first
 * SEQUENCE_LEN_TLS values from the PRNG.
 */
MTF_DEFINE_UTEST(xrand_test, tls_norepeat)
{
    uint iters = SEQUENCE_LEN_TLS;
    uint64_t *values;

    values = mapi_safe_malloc(iters * sizeof(uint64_t));
    ASSERT_TRUE(values != NULL);

    for (uint i = 0; i < iters; i++)
        values[i] = xrand64_tls();

    qsort(values, iters, sizeof(uint64_t), compare_u64);

    for (uint i = 0; i + 1 < iters; i++) {

        if (i < 5)
            printf("> rv  0x%016lx\n", (ulong)values[i]);
        else if (i == 5)
            printf("> rv  ...\n");
        else if (i > iters - 5)
            printf("> rv  0x%016lx\n", (ulong)values[i + 1]);

        ASSERT_NE(values[i], values[i + 1]);
    }

    mapi_safe_free(values);
}

struct tinfo {
    pthread_t tid;
    uint64_t values[SEQUENCE_LEN_TLS];
};

void *
generate(void *rock)
{
    struct tinfo *p = rock;

    for (uint i = 0; i < NELEM(p->values); i++)
        p->values[i] = xrand64_tls();

    return NULL;
}

/* This test verifies the TLS PRNG returns a different sequence in
 * each thread.  Actually, this is a lazy test and checks a much more
 * strict condition which can result in inadvertent failures.  We
 * attempt to minimize that by using a short sequence of random
 * values.
 */
MTF_DEFINE_UTEST(xrand_test, tls_correctness)
{
    const uint threads = 3;
    struct tinfo tinfo[threads];
    const uint nvals = NELEM(tinfo[0].values);
    int rc;

    for (uint tx = 0; tx < threads; tx++) {
        rc = pthread_create(&tinfo[tx].tid, NULL, generate, &tinfo[tx]);
        ASSERT_TRUE(rc == 0);
    }

    for (uint tx = 0; tx < threads; tx++) {
        rc = pthread_join(tinfo[tx].tid, NULL);
        ASSERT_TRUE(rc == 0);
    }

    for (uint i = 0; i < nvals; i++) {
        printf("rv %d: 0x%016lx", i, tinfo[0].values[i]);
        for (uint tx = 1; tx < threads; tx++) {
            printf("  0x%016lx", tinfo[tx].values[i]);
            ASSERT_NE(tinfo[0].values[i], tinfo[tx].values[i]);
        }
        printf("\n");
    }
}

MTF_END_UTEST_COLLECTION(xrand_test)
