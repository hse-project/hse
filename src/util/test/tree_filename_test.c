/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <string.h>

#include <hse_ut/framework.h>

#include <hse_util/tree_filename_enum.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(tree_filename);

MTF_DEFINE_UTEST(tree_filename, sourcefile_to_enum_test)
{
    enum hse_src_file_enum ev;

    ev = sourcefile_to_enum(__FILE__);
    ASSERT_NE(0, ev);

    ev = sourcefile_to_enum("some_file_that_will_never_exist.c");
    ASSERT_EQ(0, ev);
}

MTF_END_UTEST_COLLECTION(tree_filename);
