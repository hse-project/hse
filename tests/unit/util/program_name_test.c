/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/string.h>
#include <hse_util/program_name.h>
#include <hse_util/slab.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(program_name);

MTF_DEFINE_UTEST(program_name, basic)
{
    char*  name = NULL;
    char*  base = NULL;
    merr_t err;
    int    rc;
    char*  expect = "program_name_test";
    char*  cp = NULL;

    err = hse_program_name(&name, &base);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, name);
    ASSERT_NE(NULL, base);
    ASSERT_NE(name, base);

    rc = strncmp(base, expect, strlen(expect) + 1);
    ASSERT_EQ(0, rc);

    free(name);
    name = NULL;

    err = hse_program_name(&name, NULL);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, name);

    cp = strstr(name, expect);
    ASSERT_NE(NULL, cp);

    free(name);
    name = NULL;
}

MTF_END_UTEST_COLLECTION(program_name);
