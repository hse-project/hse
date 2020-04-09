/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/fmt.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(fmt);

/* must declare as arrays so sizeof() gets the strlen of each buffer */
const char input[] = "hi,\thow are you?\n";
const char out_fmt_pe[] = "hi%2c%09how%20are%20you%3f%0a";
const char out_fmt_hex[] = "0x68692c09686f7720-61726520796f753f-0a";
const char out_fmt_hexp1[] = "68692c09686f772061726520796f753f0a";
const char out_fmt_hexp2[] = "<6869 2c09 686f 7720 6172 6520 796f 753f 0a>";

const size_t input_len = (sizeof(input) - 1); /* do not want NULL byte */

/* table driven test */
struct test_case_defn {
    const char *name;
    const char *full_out;
    size_t      full_out_len;
};

struct test_case_defn test_cases[] = {
    { "fmt_pe", out_fmt_pe, sizeof(out_fmt_pe) },
    { "fmt_hex", out_fmt_hex, sizeof(out_fmt_hex) },
    { "fmt_hexp", out_fmt_hexp1, sizeof(out_fmt_hexp1) },
    { "fmt_hexp_custom", out_fmt_hexp2, sizeof(out_fmt_hexp2) },
};

/* well, not *fully* table driven... */
enum test_case { test_case_0, test_case_1, test_case_2, test_case_3 };

size_t
call_fmt_func(
    enum test_case tcx,
    void *         out,
    size_t         out_sz,
    const void *   input,
    const size_t   input_sz)
{
    size_t n;

    switch (tcx) {

        case test_case_0:
            n = fmt_pe(out, out_sz, input, input_sz);
            break;

        case test_case_1:
            n = fmt_hex(out, out_sz, input, input_sz);
            break;

        case test_case_2:
            n = fmt_hexp(out, out_sz, input, input_sz, 0, 0, 0, 0);
            break;

        case test_case_3:
            n = fmt_hexp(out, out_sz, input, input_sz, "<", 2, " ", ">");
            break;

        default:
            n = (size_t)-1;
            break;
    }

    return n;
}

MTF_DEFINE_UTEST(fmt, fmt_test)
{
    size_t alloc_len = 0;
    char * buf;
    int    tcx, tsx;
    size_t n;

    for (tcx = 0; tcx < NELEM(test_cases); tcx++) {

        struct test_case_defn *tc = test_cases + tcx;

        if (tc->full_out_len > alloc_len)
            alloc_len = tc->full_out_len;
    }

    /* pad so we can check for overflow */
    alloc_len += 1;

    buf = mapi_safe_malloc(alloc_len);
    ASSERT_TRUE(buf != 0);

    for (tcx = 0; tcx < NELEM(test_cases); tcx++) {

        struct test_case_defn *tc = test_cases + tcx;

        /* "correct" output len does not include null byte */
        const size_t clen = tc->full_out_len;

        /* test with various output buffer lengths */
        size_t test_sizes[] = {
            1,        2,        clen / 2, clen - 1, /* small buffers */
            clen,                                   /* exact fit */
            clen + 1, clen + 10                     /* oversize buffers */
        };

        printf("Test Case: %s\n", tc->name);

        /* zero len output buffer --> return expected output strlen */
        n = call_fmt_func(tcx, buf, 0, input, input_len);
        ASSERT_EQ(n, clen - 1);

        /* same as above but w/ null ptr to input buffer */
        n = call_fmt_func(tcx, 0, 0, input, input_len);
        ASSERT_EQ(n, clen - 1);

        for (tsx = 0; tsx < NELEM(test_sizes); tsx++) {

            size_t bufsz = test_sizes[tsx];
            bool   too_small = bufsz <= strlen(tc->full_out);

            memset(buf, 0xff, alloc_len);

            n = call_fmt_func(tcx, buf, bufsz, input, input_len);
            ASSERT_EQ(n, clen - 1);

            printf("bufsize: %zu %s\n", bufsz, too_small ? "(too small)" : "(big enough)");
            printf("expect: '%.*s'\n", (int)bufsz - 1, tc->full_out);
            printf("actual: '%s'\n\n", buf);
            ASSERT_EQ(n, strlen(tc->full_out));
            if (bufsz <= strlen(tc->full_out)) {
                /* buffer too small */
                ASSERT_EQ(0, buf[bufsz - 1]); /* null byte */
                ASSERT_EQ(0xff, buf[bufsz]);  /* overrun */
            } else {
                /* buffer big enough */
                ASSERT_EQ(0, buf[n]);        /* null byte */
                ASSERT_EQ(0xff, buf[n + 1]); /* overrun */
            }
            ASSERT_EQ(0, strncmp(buf, tc->full_out, bufsz - 1));
        }
    }

    mapi_safe_free(buf);
}

MTF_DEFINE_UTEST(fmt, time0)
{
    struct timespec ts = { 1513271583, 123456789 };
    u64             t64 = 1513271583123456789ULL;
    char            expect[] = "2017-12-14T11:13:03.123456";
    char            buf[256];
    int             rc;
    char *          tm;

    rc = fmt_time(buf, sizeof(buf), t64);
    printf("t64: %s\n", buf);
    ASSERT_LE(rc, sizeof(buf));
    ASSERT_EQ(0, buf[rc]);
    rc = strcmp(buf, expect);
    if (rc) {
        printf("expect: (%s)\n", expect);
        printf("buf     (%s)\n", buf);
    }
    ASSERT_EQ(0, rc);

    rc = fmt_time(buf, sizeof(buf), ts.tv_sec);
    printf("tv_sec: %s\n", buf);
    ASSERT_LE(rc, sizeof(buf));
    ASSERT_EQ(0, buf[rc]);

    tm = "2017-12-14T11:13:03.000000";
    rc = strcmp(buf, tm);
    if (rc) {
        printf("Time miscompare; if the error is just in the hours\n"
               "place this could be just a bad time zone setting\n");
        printf("expect: (%s)\n", tm);
        printf("buf     (%s)\n", buf);
    }
    ASSERT_EQ(0, rc);

    rc = fmt_time(buf, sizeof(buf), 0);
    printf("now: %s\n", buf);
    ASSERT_LE(rc, sizeof(buf));
    ASSERT_EQ(0, buf[rc]);
    ASSERT_NE(0, strcmp(buf, "2017-12-14T11:13:03"));
}

MTF_END_UTEST_COLLECTION(fmt);
