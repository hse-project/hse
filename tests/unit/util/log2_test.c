/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/util/log2.h>

#include <hse/test/mtf/framework.h>

MTF_BEGIN_UTEST_COLLECTION(log2);

struct testparms {
    uint32_t e_log2;
    bool e_pow2;
    uint64_t e_rup2;
    uint64_t e_rdown2;
};

void
test_macros(struct mtf_test_info *lcl_ti)
{
    unsigned long res;

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
test_runtime(uint64_t val, struct testparms *parm, struct mtf_test_info *lcl_ti)
{
    unsigned long res;

    res = ilog2(val);
    ASSERT_EQ(parm->e_log2, res);

    res = roundup_pow_of_two(val);
    ASSERT_EQ(parm->e_rup2, res);

    res = rounddown_pow_of_two(val);
    ASSERT_EQ(parm->e_rdown2, res);
}

MTF_DEFINE_UTEST(log2, log2_test)
{
    struct testparms p;
    int i;

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
static HSE_CONST HSE_USED unsigned long
ilog2_test(uint64_t n)
{
    return ilog2(n);
}

static HSE_CONST HSE_USED unsigned long
roundup_pow_of_two_test(uint64_t n)
{
    return roundup_pow_of_two(n);
}
