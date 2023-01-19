/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2023 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse/error/merr.h>
#include <hse/util/err_ctx.h>

extern uint8_t __start_hse_merr;
extern uint8_t __stop_hse_merr;

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(hse_err_test);

static const char *
ctx_strerror(const unsigned int ctx)
{
    switch (ctx) {
    case 1:
        return "Hello World";
    default:
        abort();
    }
}

MTF_DEFINE_UTEST(hse_err_test, merr_test_1)
{
    char errinfo[256];
    char errbuf[300], *errmsg;
    const char *file;
    int rval, i;
    merr_t err;

    rval = 0;
    err = merr(rval);
    ASSERT_EQ(err, 0);

    for (i = 0; i < EHWPOISON; ++i) {
        size_t sz1, sz2;

        sz1 = merr_strerror(i, NULL, 0);
        ASSERT_GT(sz1, 0);

        sz2 = merr_strerror(i, errbuf, sizeof(errbuf));
        ASSERT_EQ(sz1, sz2);
        ASSERT_EQ(sz2, strlen(errbuf));
    }

    merr_strinfo(err, errinfo, sizeof(errinfo), ctx_strerror, NULL);
    ASSERT_EQ(0, strcmp(errinfo, "success"));

    rval = EINVAL;
    err = merr(rval);
    ASSERT_EQ(__LINE__ - 1, merr_lineno(err)); /* Hardcoded __LINE__-1 */
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_NE(NULL, strstr(_hse_merr_file, merr_file(err)));

    merr_strinfo(err, errinfo, sizeof(errinfo), ctx_strerror, NULL);
    errmsg = strerror_r(merr_errno(err), errbuf, sizeof(errbuf));
    ASSERT_EQ(0, strncmp(strstr(errinfo, "I"), errmsg, strlen(errmsg)));

    file = hse_merr_base;
    err = merr_pack(EAGAIN, 0, file, 456);
    ASSERT_EQ(EAGAIN, merr_errno(err));
    ASSERT_EQ(456, merr_lineno(err));
    ASSERT_EQ(NULL, merr_file(err));

    /* testing an invalid file pointer out side the merr section */
    file = (char *)&__stop_hse_merr;
    err = merr_pack(EAGAIN, 0, file, 456);
    ASSERT_EQ(EAGAIN, merr_errno(err));
    ASSERT_EQ(456, merr_lineno(err));
    ASSERT_EQ(0, strcmp(merr_file(err), hse_merr_bug0));

    /*
     * testing a file pointer that is within merr the section
     * that is not properly aligned
     */
    err = merr_pack(EBUG, 0, (char *)&__start_hse_merr + 1, 123);
    ASSERT_EQ(EBUG, merr_errno(err));
    ASSERT_EQ(123, merr_lineno(err));
    ASSERT_EQ(0, strcmp(merr_file(err), hse_merr_bug1));

    err = merr(EBUG);
    ASSERT_EQ(__LINE__ - 1, merr_lineno(err)); /* Hardcoded __LINE__-1 */
    ASSERT_EQ(EBUG, merr_errno(err));
    ASSERT_NE(NULL, strstr(_hse_merr_file, merr_file(err)));
    merr_strerror(merr_errno(err), errbuf, sizeof(errbuf));
    ASSERT_EQ(0, strcmp(errbuf, "HSE software bug"));

    err = 0;
    ASSERT_EQ(0, merr_file(err));

    err = 1;
    ASSERT_EQ(NULL, merr_file(err));
}

MTF_DEFINE_UTEST(hse_err_test, ctx)
{
    int rc;
    int ctx;
    int line;
    merr_t err;
    int actual_sz;
    size_t needed_sz;
    char actual[256], expected[256];

    err = merr(EUSERS);
    ASSERT_EQ(0, merr_ctx(err));

    err = merrx(ERESTART, 1);
    line = __LINE__;
    rc = merr_errno(err);
    ctx = merr_ctx(err);
    ASSERT_EQ(ERESTART, rc);
    ASSERT_EQ(1, ctx);

    actual_sz = snprintf(
        expected, sizeof(expected), "%s:%d: %s (%d): %s (%u)", REL_FILE(__FILE__), line,
        strerror(rc), rc, ctx_strerror(ctx), ctx);
    merr_strinfo(err, actual, sizeof(actual), ctx_strerror, &needed_sz);
    ASSERT_EQ(actual_sz, needed_sz);
    ASSERT_STREQ(expected, actual);

    actual_sz = snprintf(
        expected, sizeof(expected), "%s:%d: %s (%d)", REL_FILE(__FILE__), line, strerror(rc), rc);
    merr_strinfo(err, actual, sizeof(actual), NULL, &needed_sz);
    ASSERT_STREQ(expected, actual);
    ASSERT_EQ(actual_sz, needed_sz);
}

MTF_DEFINE_UTEST(hse_err_test, no_buf)
{
    merr_t err;
    size_t needed_sz;

    err = merr(EINVAL);
    merr_strinfo(err, NULL, 0, ctx_strerror, &needed_sz);
    ASSERT_EQ(55, needed_sz);

    err = merr(EBUG);
    merr_strinfo(err, NULL, 0, ctx_strerror, &needed_sz);
    ASSERT_EQ(56, needed_sz);
}

MTF_END_UTEST_COLLECTION(hse_err_test)
