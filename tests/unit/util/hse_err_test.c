/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/hse_err.h>

MTF_MODULE_UNDER_TEST(hse_platform);

int
merr_test_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
merr_test_post(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(hse_err_test, merr_test_pre, merr_test_post);

MTF_DEFINE_UTEST(hse_err_test, merr_test_1)
{
    char   errinfo[MERR_INFO_SZ];
    char   errbuf[300], *errmsg;
    const char *file;
    int    rval, i;
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

    (void)merr_strinfo(err, errinfo, sizeof(errinfo), 0);
    ASSERT_EQ(0, strcmp(errinfo, "success"));

    rval = -EINVAL;
    err = merr(rval);
    ASSERT_EQ(__LINE__ - 1, merr_lineno(err)); /* Hardcoded __LINE__-1 */
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_NE(NULL, strstr(_hse_merr_file, merr_file(err)));

    (void)merr_strinfo(err, errinfo, sizeof(errinfo), 0);
    errmsg = strerror_r(merr_errno(err), errbuf, sizeof(errbuf));
    ASSERT_EQ(0, strcmp(strstr(errinfo, "I"), errmsg));

    /* merr_pack() should only be called via merr(), but check
     * to see that it returns the correct diagnostic information
     * given invalid arguments.
     */
    err = merr_pack(EBUG, NULL, 123);
    ASSERT_EQ(EBUG, merr_errno(err));
    ASSERT_EQ(123, merr_lineno(err));
    ASSERT_EQ(NULL, merr_file(err));

    file = hse_merr_base;
    err = merr_pack(EAGAIN, file, 456);
    ASSERT_EQ(EAGAIN, merr_errno(err));
    ASSERT_EQ(456, merr_lineno(err));
    ASSERT_EQ(NULL, merr_file(err));

    err = merr_pack(EBUG, (char *)1, 123);
    ASSERT_EQ(EBUG, merr_errno(err));
    ASSERT_EQ(123, merr_lineno(err));
    ASSERT_EQ(0, strcmp(merr_file(err), hse_merr_bug0));

    file = hse_merr_base + sizeof(file);
    err = merr_pack(EAGAIN, file, 456);
    ASSERT_EQ(EAGAIN, merr_errno(err));
    ASSERT_EQ(456, merr_lineno(err));
    ASSERT_EQ(0, strcmp(merr_file(err), hse_merr_bug1));

    err = merr(EBUG);
    ASSERT_EQ(__LINE__ - 1, merr_lineno(err)); /* Hardcoded __LINE__-1 */
    ASSERT_EQ(EBUG, merr_errno(err));
    ASSERT_NE(NULL, strstr(_hse_merr_file, merr_file(err)));
    merr_strerror(merr_errno(err), errbuf, sizeof(errbuf));
    ASSERT_EQ(0, strcmp(errbuf, "HSE software bug"));

    err = -1;
    ASSERT_EQ(NULL, merr_file(err));

    err = 0;
    ASSERT_EQ(0, merr_file(err));

    err = 1;
    ASSERT_EQ(NULL, merr_file(err));
}

MTF_END_UTEST_COLLECTION(hse_err_test)
