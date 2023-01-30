/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/util/err_ctx.h>
#include <hse/util/parse_num.h>
#include <hse/util/storage.h>

#include <hse/test/mtf/framework.h>

#define HSE_SUCCESS 0

#define PB ((uint64_t)1024 * TB)

struct test_u64 {
    struct {
        const char *str;
        const char *endptr;
    } input;

    struct {
        merr_t status;
        uint64_t result;
    } output;
};

struct test_s64 {
    struct {
        const char *str;
        const char *endptr;
    } input;

    struct {
        merr_t status;
        int64_t    result;
    } output;
};

struct test_size {
    struct {
        const char *str;
        const char *endptr;
    } input;

    struct {
        merr_t status;
        uint64_t result;
    } output;
};

#define DO_TEST(_func, _t, _i, _j, _fmt, _fmtx)                                          \
    do {                                                                                 \
        merr_t err;                                                                      \
        char *endptr;                                                                    \
        char buf[256];                                                                   \
                                                                                         \
        printf(                                                                          \
            "test[%02d.%d]: %s(\"%s\", use_endptr=\"%s\")\n",                            \
            _i,                                                                          \
            _j,                                                                          \
            #_func,                                                                      \
            _t->input.str,                                                               \
            _t->input.endptr ? "yes" : "no");                                            \
                                                                                         \
        result = ~_t->output.result;                                                     \
                                                                                         \
        err = (*_func)(_t->input.str, _t->input.endptr ? &endptr : NULL, 0, 0, &result); \
        merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);                     \
                                                                                         \
        printf(                                                                          \
            "-> "_fmtx                                                                   \
            " ("_fmt                                                                     \
            ") end=\"%s\" %s\n",                                                         \
            result,                                                                      \
            result,                                                                      \
            _t->input.endptr ? endptr : "n/a",                                           \
            buf);                                                                        \
                                                                                         \
        ASSERT_EQ(_t->output.status, merr_errno(err));                                   \
        if (EINVAL == merr_errno(err))                                                   \
            ASSERT_EQ(0, result);                                                        \
        else                                                                             \
            ASSERT_EQ(_t->output.result, result);                                        \
                                                                                         \
        if (_t->input.endptr)                                                            \
            ASSERT_EQ(*_t->input.endptr, *endptr);                                       \
    } while (0)

#define DO_TEST_SIZE(_func, _t, _i, _j, _fmt, _fmtx)                          \
    do {                                                                      \
        merr_t err;                                                           \
        char buf[256];                                                        \
                                                                              \
        printf("test[%02d.%d]: %s(\"%s\")\n", _i, _j, #_func, _t->input.str); \
                                                                              \
        result = ~_t->output.result;                                          \
                                                                              \
        err = (*_func)(_t->input.str, 0, 0, &result);                         \
        merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);          \
                                                                              \
        printf(                                                               \
            "-> "_fmtx                                                        \
            " ("_fmt                                                          \
            ") %s\n",                                                         \
            result,                                                           \
            result,                                                           \
            buf);                                                             \
                                                                              \
        ASSERT_EQ(_t->output.status, merr_errno(err));                        \
        if (EINVAL == merr_errno(err))                                        \
            ASSERT_EQ(0, result);                                             \
        else                                                                  \
            ASSERT_EQ(_t->output.result, result);                             \
                                                                              \
    } while (0)

MTF_BEGIN_UTEST_COLLECTION(parse_num_basic);

MTF_DEFINE_UTEST(parse_num_basic, test_parse_u64_range)
{
    uint64_t result;
    int i;

    struct test_u64 tests[] = {

        /* simple positive */
        { { "0", NULL }, { HSE_SUCCESS, 0 } },
        { { "1", NULL }, { HSE_SUCCESS, 1 } },
        { { "2", NULL }, { HSE_SUCCESS, 2 } },
        { { "1234", NULL }, { HSE_SUCCESS, 1234 } },

        /* simple negative */
        { { "-1", NULL }, { HSE_SUCCESS, (uint64_t)-1 } },
        { { "-2", NULL }, { HSE_SUCCESS, (uint64_t)-2 } },
        { { "-3", NULL }, { HSE_SUCCESS, (uint64_t)-3 } },
        { { "-1234", NULL }, { HSE_SUCCESS, (uint64_t)-1234 } },

        /* +/- variations */
        { { "+0x555", NULL }, { HSE_SUCCESS, 0x555 } },
        { { "-0x555", NULL }, { HSE_SUCCESS, -0x555 } },
        { { "+555", NULL }, { HSE_SUCCESS, 555 } },
        { { "-555", NULL }, { HSE_SUCCESS, -555 } },

        /* uint32_t boundary */
        { { "0x0fffffffe", NULL }, { HSE_SUCCESS, ((uint64_t)UINT32_MAX) - 1 } },
        { { "0x0ffffffff", NULL }, { HSE_SUCCESS, ((uint64_t)UINT32_MAX) } },
        { { "0x100000000", NULL }, { HSE_SUCCESS, ((uint64_t)UINT32_MAX) + 1 } },

        /* int64_t min/max */
        { { "0x7fffffffffffffff", NULL }, { HSE_SUCCESS, (uint64_t)INT64_MAX } },

        /* uint64_t boundary */
        { { "0xfffffffffffffffe", NULL }, { HSE_SUCCESS, UINT64_MAX - 1 } },
        { { "0xffffffffffffffff", NULL }, { HSE_SUCCESS, UINT64_MAX } },
        { { "18446744073709551614", NULL }, { HSE_SUCCESS, UINT64_MAX - 1 } },
        { { "18446744073709551615", NULL }, { HSE_SUCCESS, UINT64_MAX } },
        { { "0x8000000000000000", NULL }, { HSE_SUCCESS, UINT64_MAX / 2 + 1 } },

        /* long prefix of 0's */
        { { "0x00000000000000000000000000000000000000000000000000001", NULL }, { HSE_SUCCESS, 1 } },

        /* octal */
        { { "0111", NULL }, { HSE_SUCCESS, 0111 } },
        { { "-0111", NULL }, { HSE_SUCCESS, -0111 } },

        { { "01777777777777777777777", NULL }, { HSE_SUCCESS, UINT64_MAX } },

        { { "000000001777777777777777777777", NULL }, { HSE_SUCCESS, UINT64_MAX } },

        /* too big */
        { { "18446744073709551616", NULL }, { ERANGE, UINT64_MAX } },
        { { "0xffffffffffffffff1", NULL }, { ERANGE, UINT64_MAX } },
        { { "0x1ffffffffffffffff", NULL }, { ERANGE, UINT64_MAX } },

        /* invalid input */
        { { "ffff", NULL }, { EINVAL, 0 } },
        { { "123a", NULL }, { EINVAL, 0 } },
        { { "0xfffggg", NULL }, { EINVAL, 0 } },
        { { "zzz", NULL }, { EINVAL, 0 } },
        { { "", NULL }, { EINVAL, 0 } },
        { { "0x", NULL }, { EINVAL, 0 } },

        /* success with endptr */
        { { "18446744073709551615:", ":" }, { HSE_SUCCESS, UINT64_MAX } },
        { { "0xffffffffffffffff:", ":" }, { HSE_SUCCESS, UINT64_MAX } },
        { { "10:20,30", ":" }, { HSE_SUCCESS, 10 } },
    };

    printf("\nparse_u64_range:\n");
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {

        struct test_u64 *t = tests + i;

        DO_TEST(parse_u64_range, t, i, 0, "%lu", "0x%lx");

        if (t->output.status == HSE_SUCCESS) {
            const char *save_end = t->input.endptr;

            if (t->input.endptr == NULL) {
                t->input.endptr = "";
                DO_TEST(parse_u64_range, t, i, 1, "%lu", "0x%lx");
            } else {
                t->input.endptr = NULL;
                t->output.status = EINVAL;
                DO_TEST(parse_u64_range, t, i, 2, "%lu", "0x%lx");
            }
            t->input.endptr = save_end;
            t->output.status = HSE_SUCCESS;
        }
    }
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_s64_range)
{
    int64_t result;
    int i;

    struct test_s64 tests[] = {

        /* simple positive */
        { { "0", NULL }, { HSE_SUCCESS, 0 } },
        { { "1", NULL }, { HSE_SUCCESS, 1 } },
        { { "2", NULL }, { HSE_SUCCESS, 2 } },
        { { "1234", NULL }, { HSE_SUCCESS, 1234 } },

        /* simple negative */
        { { "-1", NULL }, { HSE_SUCCESS, (int64_t)-1 } },
        { { "-2", NULL }, { HSE_SUCCESS, (int64_t)-2 } },
        { { "-3", NULL }, { HSE_SUCCESS, (int64_t)-3 } },
        { { "-1234", NULL }, { HSE_SUCCESS, (int64_t)-1234 } },

        /* +/- variations */
        { { "+0x555", NULL }, { HSE_SUCCESS, 0x555 } },
        { { "-0x555", NULL }, { HSE_SUCCESS, -0x555 } },
        { { "+555", NULL }, { HSE_SUCCESS, 555 } },
        { { "-555", NULL }, { HSE_SUCCESS, -555 } },

        /* s32 boundary */
        { { "0x0fffffffe", NULL }, { HSE_SUCCESS, ((int64_t)UINT32_MAX) - 1 } },
        { { "0x0ffffffff", NULL }, { HSE_SUCCESS, ((int64_t)UINT32_MAX) } },
        { { "0x100000000", NULL }, { HSE_SUCCESS, ((int64_t)UINT32_MAX) + 1 } },

        /* int64_t limits */
        { { "0x7fffffffffffffff", NULL }, { HSE_SUCCESS, INT64_MAX } },
        { { "9223372036854775807", NULL }, { HSE_SUCCESS, INT64_MAX } },
        { { "-0x8000000000000000", NULL }, { HSE_SUCCESS, INT64_MIN } },
        { { "-9223372036854775808", NULL }, { HSE_SUCCESS, INT64_MIN } },

        /* long prefix of 0's */
        { { "0x00000000000000000000000000000000000000000000000000001", NULL }, { HSE_SUCCESS, 1 } },

        /* octal */
        { { "0111", NULL }, { HSE_SUCCESS, 0111 } },
        { { "-0111", NULL }, { HSE_SUCCESS, -0111 } },

        /* too big */
        { { "9223372036854775808", NULL }, { ERANGE, INT64_MAX } },
        { { "-9223372036854775809", NULL }, { ERANGE, INT64_MIN } },

        /*
         * this fails b/c it's bigger than INT64_MAX and has no negative
         * sign
         */
        { { "0x8000000000000000", NULL }, { ERANGE, INT64_MAX } },

        /* invalid input */
        { { "ffff", NULL }, { EINVAL, 0 } },
        { { "123a", NULL }, { EINVAL, 0 } },
        { { "0xfffggg", NULL }, { EINVAL, 0 } },
        { { "zzz", NULL }, { EINVAL, 0 } },
        { { "0x", NULL }, { EINVAL, 0 } },

        /* success with endptr */
        { { "9223372036854775807:", ":" }, { HSE_SUCCESS, INT64_MAX } },
        { { "-1:", ":" }, { HSE_SUCCESS, -1 } },
        { { "10:20,30", ":" }, { HSE_SUCCESS, 10 } },
    };

    printf("\nparse_s64_range:\n");
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {

        struct test_s64 *t = tests + i;

        DO_TEST(parse_s64_range, t, i, 0, "%ld", "0x%lx");

        if (t->output.status == HSE_SUCCESS) {
            const char *save_end = t->input.endptr;

            if (t->input.endptr == NULL) {
                t->input.endptr = "";
                DO_TEST(parse_s64_range, t, i, 1, "%ld", "0x%lx");
            } else {
                t->input.endptr = NULL;
                t->output.status = EINVAL;
                DO_TEST(parse_s64_range, t, i, 2, "%ld", "0x%lx");
            }
            t->input.endptr = save_end;
            t->output.status = HSE_SUCCESS;
        }
    }
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_size_range)
{
    uint64_t result;
    int i;

    struct test_size tests[] = {

        { { "0k", NULL }, { HSE_SUCCESS, 0 } },
        { { "0m", NULL }, { HSE_SUCCESS, 0 } },
        { { "0g", NULL }, { HSE_SUCCESS, 0 } },
        { { "0t", NULL }, { HSE_SUCCESS, 0 } },
        { { "0p", NULL }, { HSE_SUCCESS, 0 } },

        { { "6k", NULL }, { HSE_SUCCESS, 6 * KB } },
        { { "5m", NULL }, { HSE_SUCCESS, 5 * MB } },
        { { "4g", NULL }, { HSE_SUCCESS, 4 * GB } },
        { { "3t", NULL }, { HSE_SUCCESS, 3 * TB } },
        { { "2p", NULL }, { HSE_SUCCESS, 2 * PB } },

        /* hex */
        { { "0x123m", NULL }, { HSE_SUCCESS, 0x123 * MB } },

        /* overflow */
        { { "0xffffffffffffffffk", NULL }, { ERANGE, UINT64_MAX } },
        { { "10000000p", NULL }, { ERANGE, UINT64_MAX } },

        { { "18014398509481983k", NULL }, { HSE_SUCCESS, 18014398509481983ULL * 1024 } },

        { { "18014398509481984k", NULL }, { ERANGE, UINT64_MAX } },

        /* invalid suffix */
        { { "0n", NULL }, { EINVAL, 0 } },
        { { "1n", NULL }, { EINVAL, 0 } },
    };

    printf("\nparse_size_range:\n");
    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {

        struct test_size *t = tests + i;

        DO_TEST_SIZE(parse_size_range, t, i, 0, "%lu", "0x%lx");

        if (t->output.status == HSE_SUCCESS) {
            const char *save_end = t->input.endptr;

            if (t->input.endptr == NULL) {
                t->input.endptr = "";
                DO_TEST_SIZE(parse_size_range, t, i, 1, "%lu", "0x%lx");
            } else {
                t->input.endptr = NULL;
                t->output.status = EINVAL;
                DO_TEST_SIZE(parse_size_range, t, i, 2, "%lu", "0x%lx");
            }
            t->input.endptr = save_end;
            t->output.status = HSE_SUCCESS;
        }
    }
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_u8)
{
    merr_t err;
    uint8_t val;
    char buf[256];
    const char *input;

    printf("\nparse_u8:\n");

    input = "255";
    val = 0;
    err = parse_u8(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_u8(\"%s\") -> 0x%02x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(255, val);

    input = "256";
    val = 0;
    err = parse_u8(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_u8(\"%s\") -> 0x%02x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));

    input = "100:";
    val = 0;
    err = parse_u8("100:", &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_u8(\"%s\") -> 0x%02x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_s8)
{
    merr_t err;
    int8_t val;
    char buf[256];
    const char *input;

    printf("\nparse_s8:\n");

    input = "127";
    val = 0;
    err = parse_s8(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_s8(\"%s\") -> 0x%02x (%d) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(127, val);

    input = "-128";
    val = 0;
    err = parse_s8(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_s8(\"%s\") -> 0x%02x (%d) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(-128, val);

    input = "128";
    val = 0;
    err = parse_s8(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_s8(\"%s\") -> 0x%02x (%d) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));

    input = "100:";
    val = 0;
    err = parse_s8(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_s8(\"%s\") -> 0x%02x (%d) %s\n", input, val, val, buf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_uint)
{
    merr_t err;
    unsigned val;
    char buf[256];
    const char *input;

    printf("\nparse_uint:\n");

    if (sizeof(val) != 4)
        return;

    input = "0xffffffff";
    val = 0;
    err = parse_uint(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_uint(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(UINT_MAX, val);

    input = "4294967295";
    val = 0;
    err = parse_uint(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_uint(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(UINT_MAX, val);

    /* over by 1 */
    input = "0x100000000";
    val = 0;
    err = parse_uint(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_uint(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(0, val);

    /* over by 1 */
    input = "4294967296";
    val = 0;
    err = parse_uint(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_uint(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(0, val);

    input = "100:";
    val = 0;
    err = parse_uint("100:", &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_uint(\"%s\") -> 0x%02x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_int)
{
    int val;
    merr_t err;
    char buf[256];
    const char *input;

    printf("\nparse_int:\n");

    if (sizeof(val) != 4)
        return;

    input = "0x7fffffff";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(INT_MAX, val);

    input = "2147483647";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(INT_MAX, val);

    /* over by 1 */
    input = "0x80000000";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(0, val);

    /* over by 1 */
    input = "2147483648";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(0, val);

    /*
     * "-0x80000000" => okay
     * "0x80000000"  => fail
     */
    input = "-0x80000000";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(INT_MIN, val);

    input = "0x80000000";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(0, val);

    input = "-2147483648";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(HSE_SUCCESS, err);
    ASSERT_EQ(INT_MIN, val);

    /* under by 1 */
    input = "-0x80000001";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(0, val);

    /* under by 1 */
    input = "-2147483649";
    val = 0;
    err = parse_int(input, &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(0, val);

    /* invalid */
    input = "100:";
    val = 0;
    err = parse_int("100:", &val);
    merr_strinfo(err, buf, sizeof(buf), err_ctx_strerror, NULL);
    printf("parse_int(\"%s\") -> 0x%02x (%u) %s\n", input, val, val, buf);
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_EQ(0, val);
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_s64_range_bounds)
{
    const char *underflow = "-18446744073709551619";
    const char *overflow = "18446744073709551619";
    merr_t      err;
    int64_t         r;

    r = 666;
    err = parse_s64_range("8", NULL, -3, 7, &r);
    ASSERT_NE(0, err);
    ASSERT_EQ(7, r);

    r = 666;
    err = parse_s64_range(overflow, NULL, -3, 7, &r);
    ASSERT_NE(0, err);
    ASSERT_EQ(7, r);

    r = 666;
    err = parse_s64_range("-4", NULL, -3, 7, &r);
    ASSERT_NE(0, err);
    ASSERT_EQ(-3, r);

    r = 666;
    err = parse_s64_range(underflow, NULL, -3, 7, &r);
    ASSERT_NE(0, err);
    ASSERT_EQ(-3, r);
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_u64_range_bounds)
{
    const char *overflow = "18446744073709551619";
    merr_t      err;
    uint64_t    r;

    r = 666;
    err = parse_u64_range("8", NULL, 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(7, r);

    r = 666;
    err = parse_u64_range(overflow, NULL, 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(7, r);

    r = 666;
    err = parse_u64_range("2", NULL, 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(3, r);

    r = 666;
    err = parse_u64_range("-1", NULL, 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(7, r);
}

MTF_DEFINE_UTEST(parse_num_basic, test_parse_size_range_bounds)
{
    const char *overflow = "18446744073709551619";
    merr_t      err;
    uint64_t    r;

    r = 666;
    err = parse_size_range("8", 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(7, r);

    r = 666;
    err = parse_size_range(overflow, 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(7, r);

    r = 666;
    err = parse_size_range("2", 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(3, r);

    r = 666;
    err = parse_size_range("-1", 3, 7, &r);
    ASSERT_EQ(ERANGE, merr_errno(err));
    ASSERT_EQ(7, r);
}

MTF_END_UTEST_COLLECTION(parse_num_basic)
