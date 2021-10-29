/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <hse_util/log2.h>

MTF_BEGIN_UTEST_COLLECTION(log2);

struct testparms {
    u32  e_log2;
    bool e_pow2;
    u64  e_rup2;
    u64  e_rdown2;
};

void
test_macros(struct mtf_test_info *lcl_ti)
{
    u32 res;

    res = ilog2(1);
    ASSERT_EQ(0, res);
    res = ilog2(31);
    ASSERT_EQ(4, res);
    res = ilog2(32);
    ASSERT_EQ(5, res);
    res = ilog2(33);
    ASSERT_EQ(5, res);
    res = ilog2(70);
    ASSERT_EQ(6, res);

    res = roundup_pow_of_two(0);
    ASSERT_EQ(1, res);
    res = roundup_pow_of_two(1);
    ASSERT_EQ(1, res);
    res = roundup_pow_of_two(31);
    ASSERT_EQ(32, res);
    res = roundup_pow_of_two(32);
    ASSERT_EQ(32, res);
    res = roundup_pow_of_two(33);
    ASSERT_EQ(64, res);
    res = roundup_pow_of_two(70);
    ASSERT_EQ(128, res);

    res = rounddown_pow_of_two(0);
    ASSERT_EQ(1, res);
    res = rounddown_pow_of_two(1);
    ASSERT_EQ(1, res);
    res = rounddown_pow_of_two(31);
    ASSERT_EQ(16, res);
    res = rounddown_pow_of_two(32);
    ASSERT_EQ(32, res);
    res = rounddown_pow_of_two(33);
    ASSERT_EQ(32, res);
    res = rounddown_pow_of_two(70);
    ASSERT_EQ(64, res);
}

void
test_runtime(u64 val, struct testparms *parm, struct mtf_test_info *lcl_ti)
{
    u32  res;
    bool pow2;

    res = ilog2(val);
    ASSERT_EQ(parm->e_log2, res);

    pow2 = is_power_of_2(val);
    ASSERT_EQ(parm->e_pow2, pow2);

    res = roundup_pow_of_two(val);
    ASSERT_EQ(parm->e_rup2, res);

    res = rounddown_pow_of_two(val);
    ASSERT_EQ(parm->e_rdown2, res);
}

MTF_DEFINE_UTEST(log2, log2_test)
{
    struct testparms p;
    int              i;

    test_macros(lcl_ti);

    p.e_log2 = 0;
    p.e_pow2 = true;
    p.e_rup2 = 1;
    p.e_rdown2 = 1;
    test_runtime(1, &p, lcl_ti);

    p.e_log2 = 4;
    p.e_pow2 = false;
    p.e_rup2 = 32;
    p.e_rdown2 = 16;
    test_runtime(31, &p, lcl_ti);

    p.e_log2 = 5;
    p.e_pow2 = true;
    p.e_rup2 = 32;
    p.e_rdown2 = 32;
    test_runtime(32, &p, lcl_ti);

    p.e_log2 = 5;
    p.e_pow2 = false;
    p.e_rup2 = 64;
    p.e_rdown2 = 32;
    test_runtime(33, &p, lcl_ti);

    p.e_log2 = 6;
    p.e_pow2 = false;
    p.e_rup2 = 128;
    p.e_rdown2 = 64;
    test_runtime(70, &p, lcl_ti);

    /* Check all powers of two from (1 << 0) to (1 << 63).
     */
    for (i = 1; i < 64; ++i) {
        p.e_log2 = i - 1;
        p.e_pow2 = true;
        p.e_rup2 = 1ul << p.e_log2;
        p.e_rdown2 = p.e_rup2;
        test_runtime(p.e_rup2, &p, lcl_ti);
    }

    /* Check all powers-of-two-minus-one from
     * ((1 << 2) - 1) to ((1 << 63) - 1)
     */
    for (i = 3; i < 64; ++i) {
        p.e_log2 = i - 2;
        p.e_pow2 = false;
        p.e_rup2 = 1ul << (p.e_log2 + 1);
        p.e_rdown2 = 1ul << p.e_log2;
        test_runtime(p.e_rup2 - 1, &p, lcl_ti);
    }

    /* Check all powers-of-two-plus-one from
     * ((1 << 2) + 1) to ((1 << 62) + 1)
     */
    for (i = 2; i < 63; ++i) {
        p.e_log2 = i;
        p.e_pow2 = false;
        p.e_rup2 = 1ul << (p.e_log2 + 1);
        p.e_rdown2 = 1ul << p.e_log2;
        test_runtime(p.e_rdown2 + 1, &p, lcl_ti);
    }
}

MTF_END_UTEST_COLLECTION(log2)

/* The following functions exist only for the purpose of examining
 * the generated code with objdump.
 */
static __attribute__((const, used)) u32
ilog2_test(u64 n)
{
    return ilog2(n);
}

static __attribute__((const, used)) bool
is_power_of_2_test(u64 n)
{
    return is_power_of_2(n);
}

static __attribute__((const, used)) u64
roundup_pow_of_two_test(u64 n)
{
    return roundup_pow_of_two(n);
}
