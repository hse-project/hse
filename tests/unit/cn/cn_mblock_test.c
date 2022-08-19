/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/platform.h>
#include <hse_util/log2.h>
#include <logging/logging.h>

#include <hse_ikvdb/limits.h>

#include <cn/cn_mblocks.h>

#define KiB (((size_t)1) << 10)
#define MiB (((size_t)1) << 20)
#define GiB (((size_t)1) << 30)

/* VEB_SIZE should match mpool's VEB size (MPOOL_DEV_VEBLOCKBY_DEFAULT).
 */
#define VEB_SIZE (4 * MiB)

#define rup2(VAL) roundup_pow_of_two(VAL)

#define rup(VAL, ALIGN) ((ALIGN) * (((VAL) + (ALIGN)-1) / (ALIGN)))

int
init(struct mtf_test_info *info)
{
    log_info("Assuming mpool VEB size == %zu bytes", VEB_SIZE);
    return 0;
}

int
fini(struct mtf_test_info *info)
{
    return 0;
}

int
pre(struct mtf_test_info *info)
{
    return 0;
}

int
post(struct mtf_test_info *info)
{
    return 0;
}

bool
runtest(
    struct mtf_test_info *lcl_ti,
    size_t                max_size,
    size_t                alloc_unit,
    size_t                wlen,
    uint                  flags,
    size_t                expect)
{
    size_t result;

    result = cn_mb_est_alen(max_size, alloc_unit, wlen, flags);

    log_info(
        "Test: (maxsz = %10zu, aunit = %10zu, wlen = %10zu,"
        " flags = 0x%02x) ==> (expect = %10zu, result = %10zu)%s",
        max_size,
        alloc_unit,
        wlen,
        flags,
        expect,
        result,
        expect == result ? "" : " ***ERROR***");

    return result == expect;
}

#define RUNTEST(MS, AU, WL, FL, EXP)                                \
    ({                                                              \
        bool succ = runtest(lcl_ti, (MS), (AU), (WL), (FL), (EXP)); \
        ASSERT_TRUE(succ);                                          \
    })

MTF_BEGIN_UTEST_COLLECTION_PREPOST(test, init, fini);

MTF_DEFINE_UTEST_PREPOST(test, t_cn_mb_est_typical_kblock, pre, post)
{
    uint flags = CN_MB_EST_FLAGS_POW2;

    log_info("Test group: "
             "typical kblock use cases (pow2)");

    ASSERT_EQ(KBLOCK_MAX_SIZE, 32 * MiB);
    ASSERT_EQ(VEB_SIZE, 4 * MiB);

    /* All allocation less than VEB (4M) are rounded to 4M */
    RUNTEST(32 * MiB, 4 * MiB, 1, flags, 4 * MiB);
    RUNTEST(32 * MiB, 4 * MiB, 4 * MiB, flags, 4 * MiB);

    /* 4+ to 8 --> 8M */
    RUNTEST(32 * MiB, 4 * MiB, 4 * MiB + 1, flags, 8 * MiB);
    RUNTEST(32 * MiB, 4 * MiB, 8 * MiB, flags, 8 * MiB);

    /* 8+ to 16 --> 16M */
    RUNTEST(32 * MiB, 4 * MiB, 8 * MiB + 1, flags, 16 * MiB);
    RUNTEST(32 * MiB, 4 * MiB, 16 * MiB, flags, 16 * MiB);

    /* 16+ to 32 --> 12M */
    RUNTEST(32 * MiB, 4 * MiB, 16 * MiB + 1, flags, 32 * MiB);
    RUNTEST(32 * MiB, 4 * MiB, 32 * MiB, flags, 32 * MiB);
}

MTF_DEFINE_UTEST_PREPOST(test, t_cn_mb_est_typical_vblock, pre, post)
{
    size_t msize = VBLOCK_MAX_SIZE;
    size_t aunit = VEB_SIZE;
    uint   flags = CN_MB_EST_FLAGS_PREALLOC;

    size_t lo, hi, exp;

    log_info("Test group: "
             "typical vblock use cases");

    lo = 4096;
    hi = msize;
    exp = msize;

    RUNTEST(msize, aunit, lo, flags, exp);
    RUNTEST(msize, aunit, hi, flags, exp);

    lo = msize + 4096;
    hi = 2 * msize;
    exp = 2 * msize;

    RUNTEST(msize, aunit, lo, flags, exp);
    RUNTEST(msize, aunit, hi, flags, exp);

    lo = 99 * msize + 4096;
    hi = 100 * msize;
    exp = 100 * msize;

    RUNTEST(msize, aunit, lo, flags, exp);
    RUNTEST(msize, aunit, hi, flags, exp);
}

MTF_DEFINE_UTEST_PREPOST(test, t_cn_mb_est_bogus_input, pre, post)
{
    size_t msize = 32 * MiB;
    size_t aunit = 4 * MiB;
    size_t wlen = 1 * MiB;
    uint   flags = CN_MB_EST_FLAGS_NONE;

    log_info("Test group: "
             "bogus input, expect 0");

    RUNTEST(0, aunit, wlen, flags, 0);
    RUNTEST(msize, 0, wlen, flags, 0);
    RUNTEST(msize, aunit, 0, flags, 0);

    RUNTEST(0, 0, wlen, flags, 0);
    RUNTEST(0, aunit, 0, flags, 0);
    RUNTEST(msize, 0, 0, flags, 0);

    RUNTEST(0, 0, 0, flags, 0);
}

MTF_DEFINE_UTEST_PREPOST(test, t_cn_mb_est_normal, pre, post)
{
    uint i;
    struct {
        char *desc;
        uint  flags;
    } test_cases[] = {

        { "no flags", CN_MB_EST_FLAGS_NONE },

        { "truncate", CN_MB_EST_FLAGS_TRUNCATE },

        { "truncate + prellocate", CN_MB_EST_FLAGS_PREALLOC | CN_MB_EST_FLAGS_TRUNCATE },
    };

    for (i = 0; i < NELEM(test_cases); i++) {
        char *desc = test_cases[i].desc;
        uint  flags = test_cases[i].flags;

        log_info("Test group: %s, expect wlen rounded to alloc_unit", desc);

        /*      msize,  aunit,       wlen, flags,     expect */
        RUNTEST(1048576, 100, 1, flags, 100);
        RUNTEST(1048576, 1001, 1, flags, 1001);
        RUNTEST(1048576, 100, 1048500, flags, 1048500);
        RUNTEST(1048576, 100, 1048501, flags, 1048600);
        RUNTEST(1048576, 100, 1048599, flags, 1048600);
        RUNTEST(1048576, 100, 1048599, flags, 1048600);
        RUNTEST(2223456, 100, 331048599, flags, 331048600);

        /*      msize,  aunit,       wlen,  flags,     expect */
        RUNTEST(2223456, 1000, 1, flags, 1000);
        RUNTEST(2223456, 10001, 1, flags, 10001);
        RUNTEST(2223456, 1000, 2223000, flags, 2223000);
        RUNTEST(2223456, 1000, 2223001, flags, 2224000);
        RUNTEST(2223456, 1000, 2223999, flags, 2224000);
        RUNTEST(2223456, 1000, 332223999, flags, 332224000);
    }
}

MTF_DEFINE_UTEST_PREPOST(test, t_cn_mb_est_normal_pow2, pre, post)
{
    uint i;
    struct {
        char *desc;
        uint  flags;
    } test_cases[] = {

        { "pow2", CN_MB_EST_FLAGS_POW2 | CN_MB_EST_FLAGS_NONE },

        { "truncate + pow2", CN_MB_EST_FLAGS_POW2 | CN_MB_EST_FLAGS_TRUNCATE },

        { "truncate + prellocate + pow2",
          CN_MB_EST_FLAGS_POW2 | CN_MB_EST_FLAGS_PREALLOC | CN_MB_EST_FLAGS_TRUNCATE },
    };

    for (i = 0; i < NELEM(test_cases); i++) {
        char *desc = test_cases[i].desc;
        uint  flags = test_cases[i].flags;

        log_info(
            "Test group: %s, expect wlen"
            " rounded to pow2 then to alloc_unit"
            " (max_size has no effect on result)",
            desc);

        /*      msize,  aunit,   wlen, flags,     expect */
        RUNTEST(1234, 100, 1, flags, 100);
        RUNTEST(1048576, 100, 1, flags, 100);
        RUNTEST(9900000, 100, 1, flags, 100);

        RUNTEST(91034, 100, 64, flags, 100);
        RUNTEST(1048576, 100, 65, flags, 200);

        RUNTEST(91034, 1000, 512, flags, 1000);
        RUNTEST(91034, 1000, 513, flags, 2000);
    }
}

MTF_DEFINE_UTEST_PREPOST(test, t_cn_mb_est_prealloc, pre, post)
{
    uint flags = CN_MB_EST_FLAGS_PREALLOC;

    log_info("Test group:"
             " prealloc w/o truncate, expect max_size"
             " rounded to allocation unit");

    /*       msize,   aunit,        wlen, flags,   expect */
    RUNTEST(1110123, 1000, 1, flags, 1111000);

    RUNTEST(1110123, 1000, 1111000 - 1, flags, 1111000);
    RUNTEST(1110123, 1000, 1111000, flags, 1111000);
    RUNTEST(1110123, 1000, 1111000 + 1, flags, 2222000);

    RUNTEST(1110123, 1000, 2222000 - 1, flags, 2222000);
    RUNTEST(1110123, 1000, 2222000, flags, 2222000);
    RUNTEST(1110123, 1000, 2222000 + 1, flags, 3333000);

    RUNTEST(1110123, 1000, 8888000 - 1, flags, 8888000);
    RUNTEST(1110123, 1000, 8888000, flags, 8888000);
    RUNTEST(1110123, 1000, 8888000 + 1, flags, 9999000);
}

MTF_DEFINE_UTEST_PREPOST(test, t_cn_mb_est_prealloc_pow2, pre, post)
{
    uint flags = CN_MB_EST_FLAGS_PREALLOC | CN_MB_EST_FLAGS_POW2;
    uint n;

    log_info("Test group:"
             " prealloc w/o truncate w/ pow2, expect result"
             " rounded to pow2 then to allocation unit");

    /* msize=1000, aunit=100:
     * mblock alen will be rup(rup2(1000),100 == 1100
     *
     *        msize,  aunit,   wlen,  flags,    expect
     */
    RUNTEST(1000, 100, 1, flags, 1100);
    RUNTEST(1000, 100, 1100, flags, 1100);

    RUNTEST(1000, 100, 1100 + 1, flags, 2200);
    RUNTEST(1000, 100, 2200, flags, 2200);

    n = 99;
    RUNTEST(1000, 100, (n - 1) * 1100 + 1, flags, n * 1100);
    RUNTEST(1000, 100, n * 1100, flags, n * 1100);

    n = 1234;
    RUNTEST(1000, 100, (n - 1) * 1100 + 1, flags, n * 1100);
    RUNTEST(1000, 100, n * 1100, flags, n * 1100);

    /* msize=10*MiB, aunit=4*MiB:
     * mblock alen will be rup(rup2(10M),4M == 16M
     *
     *        msize,  aunit,   wlen,  flags,    expect
     */
    RUNTEST(10 * MiB, 4 * MiB, 1, flags, 16 * MiB);
    RUNTEST(10 * MiB, 4 * MiB, 16 * MiB, flags, 16 * MiB);

    RUNTEST(10 * MiB, 4 * MiB, 16 * MiB + 1, flags, 32 * MiB);
    RUNTEST(10 * MiB, 4 * MiB, 32 * MiB, flags, 32 * MiB);

    n = 14;
    RUNTEST(10 * MiB, 4 * MiB, (n - 1) * 16 * MiB + 1, flags, n * 16 * MiB);
    RUNTEST(10 * MiB, 4 * MiB, n * 16 * MiB, flags, n * 16 * MiB);

    n = 14353;
    RUNTEST(10 * MiB, 4 * MiB, (n - 1) * 16 * MiB + 1, flags, n * 16 * MiB);
    RUNTEST(10 * MiB, 4 * MiB, n * 16 * MiB, flags, n * 16 * MiB);
}

MTF_END_UTEST_COLLECTION(test)
