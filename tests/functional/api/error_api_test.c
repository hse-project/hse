/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <string.h>

#include <mtf/framework.h>

#include <hse/hse.h>

MTF_BEGIN_UTEST_COLLECTION(error_api_test)

MTF_DEFINE_UTEST(error_api_test, err_ctx)
{
    unsigned int matches = 0;

    for (enum hse_err_ctx i = HSE_ERR_CTX_BASE; i < HSE_ERR_CTX_MAX; i++) {
        switch (i) {
        case HSE_ERR_CTX_NONE:
        case HSE_ERR_CTX_TXN_EXPIRED:
            matches++;
            break;
        }
    }

    ASSERT_EQ(HSE_ERR_CTX_MAX - HSE_ERR_CTX_BASE, matches);
}

MTF_DEFINE_UTEST(error_api_test, to_errno_no_err_is_0)
{
    int rc;

    rc = hse_err_to_errno(0);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST(error_api_test, to_errno_errno_is_errno)
{
    int rc;

    rc = hse_err_to_errno(EINVAL);
    ASSERT_EQ(EINVAL, rc);
}

MTF_DEFINE_UTEST(error_api_test, to_ctx_no_err_is_0)
{
    enum hse_err_ctx ctx;

    ctx = hse_err_to_errno(0);
    ASSERT_EQ(HSE_ERR_CTX_NONE, ctx);
}

MTF_DEFINE_UTEST(error_api_test, strerror_no_err_is_success)
{
    char buf[256];
    size_t n;

    n = hse_strerror(0, buf, sizeof(buf));
    ASSERT_STREQ("success", buf);
    ASSERT_LT(n, sizeof(buf));
}

MTF_DEFINE_UTEST(error_api_test, strerror_format)
{
    char buf[256];
    char fmt[64];
    char file[512] = {};
    char found_reason[256] = {};
    const char *actual_reason;
    size_t actual_reason_len;
    int rc = -1, lineno = -1, num_parsed;
    size_t n;
    hse_err_t err;

    err = hse_kvdb_close(NULL);
    ASSERT_NE(0, hse_err_to_errno(err));

    actual_reason = strerror(hse_err_to_errno(err));
    actual_reason_len = strlen(actual_reason);
    ASSERT_LT(actual_reason_len, sizeof(found_reason));

    n = hse_strerror(err, buf, sizeof(buf));
    ASSERT_LT(n, sizeof(buf));

    snprintf(fmt, sizeof(fmt), "%%%lu[^:]:%%d: %%%luc (%%d)", sizeof(file) - 1, actual_reason_len);

    num_parsed = sscanf(buf, fmt, file, &lineno, found_reason, &rc);
    ASSERT_EQ(4, num_parsed);
    ASSERT_NE(0, strnlen(file, sizeof(file)));
    ASSERT_GT(lineno, 0);
    ASSERT_STREQ(actual_reason, found_reason);
    ASSERT_EQ(rc, hse_err_to_errno(err));
}

MTF_END_UTEST_COLLECTION(error_api_test)
