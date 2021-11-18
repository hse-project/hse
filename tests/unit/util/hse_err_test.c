/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/hse_err.h>

extern uint8_t __start_hse_merr;
extern uint8_t __stop_hse_merr;

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

    rval = EINVAL;
    err = merr(rval);
    ASSERT_EQ(__LINE__ - 1, merr_lineno(err)); /* Hardcoded __LINE__-1 */
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_NE(NULL, strstr(_hse_merr_file, merr_file(err)));

    (void)merr_strinfo(err, errinfo, sizeof(errinfo), 0);
    errmsg = strerror_r(merr_errno(err), errbuf, sizeof(errbuf));
    ASSERT_EQ(0, strncmp(strstr(errinfo, "I"), errmsg, strlen(errmsg)));

    file = hse_merr_base;
    err = merr_pack(EAGAIN, 0, file, 456);
    ASSERT_EQ(EAGAIN, merr_errno(err));
    ASSERT_EQ(456, merr_lineno(err));
    ASSERT_EQ(NULL, merr_file(err));

    /* testing an invalid file pointer out side the merr section */
    file = (char*)&__stop_hse_merr;
    err = merr_pack(EAGAIN, 0, file, 456);
    ASSERT_EQ(EAGAIN, merr_errno(err));
    ASSERT_EQ(456, merr_lineno(err));
    ASSERT_EQ(0, strcmp(merr_file(err), hse_merr_bug0));

    /*
     * testing a file pointer that is within merr the section
     * that is not properly aligned
     */
    err = merr_pack(EBUG, 0, (char*)&__start_hse_merr + 1, 123);
    ASSERT_EQ(EBUG, merr_errno(err));
    ASSERT_EQ(123, merr_lineno(err));
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

MTF_DEFINE_UTEST(hse_err_test, ctx)
{
    merr_t err;

    err = merr(EUSERS);
    ASSERT_EQ(0, merr_ctx(err));

    err = merrx(ERESTART, HSE_ERR_CTX_MAX);
    ASSERT_EQ(HSE_ERR_CTX_MAX, merr_ctx(err));
}

MTF_END_UTEST_COLLECTION(hse_err_test)
