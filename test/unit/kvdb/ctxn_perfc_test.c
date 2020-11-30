/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_ikvdb/ctxn_perfc.h>

MTF_BEGIN_UTEST_COLLECTION(ctxn_perfc_test)

MTF_DEFINE_UTEST(ctxn_perfc_test, basic)
{
    ctxn_perfc_init();
    ctxn_perfc_fini();
}

MTF_END_UTEST_COLLECTION(ctxn_perfc_test);
