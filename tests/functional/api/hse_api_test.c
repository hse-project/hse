/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>

#include <mtf/framework.h>

#include <hse/hse.h>

int
test_collection_setup(struct mtf_test_info * const lcl_ti)
{
    hse_fini();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(hse_api_test, test_collection_setup)

MTF_DEFINE_UTEST(hse_api_test, param_null_param)
{
    hse_err_t err;

    err = hse_param_get(NULL, NULL, 0, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(hse_api_test, param_mismatched_buf_buf_sz)
{
    hse_err_t err;

    err = hse_param_get("logging.destination", NULL, 1, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(hse_api_test, param_dne)
{
    hse_err_t err;
    size_t needed_sz;
    char buf[16];

    err = hse_param_get("does.not.exist", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

/* This works because we have previously initialized HSE which sets up the
 * global hse_gparams struct even though HSE is not currently initialized when
 * this test is run.
 */
MTF_DEFINE_UTEST(hse_api_test, param_success)
{
    hse_err_t err;
    size_t needed_sz;
    char buf[16];

    err = hse_param_get("logging.destination", NULL, 0, &needed_sz);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_EQ(8, needed_sz);

    err = hse_param_get("logging.destination", buf, sizeof(buf), &needed_sz);
    ASSERT_EQ(0, hse_err_to_errno(err));
    ASSERT_STREQ("\"syslog\"", buf);
    ASSERT_EQ(8, needed_sz);
}

MTF_DEFINE_UTEST(hse_api_test, init_config_dne)
{
    hse_err_t err;

    err = hse_init("/does-not-exist", 0, NULL);
    ASSERT_EQ(ENOENT, hse_err_to_errno(err));
}

MTF_DEFINE_UTEST(hse_api_test, init_mismatched_paramc_paramv)
{
    hse_err_t err;

    err = hse_init(NULL, 1, NULL);
    ASSERT_EQ(EINVAL, hse_err_to_errno(err));
}

MTF_END_UTEST_COLLECTION(hse_api_test)
