/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <errno.h>
#include <hse_ut/fixtures.h>

/* Globals */
struct hse_kvdb *kvdb_handle;

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    int                        rc;

    rc = mtf_kvdb_setup(lcl_ti, &kvdb_handle, 0);
    ASSERT_EQ_RET(rc, 0, -1);
    ASSERT_NE_RET(kvdb_handle, NULL, -1);

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *lcl_ti)
{
    int rc;
    rc = mtf_kvdb_teardown(lcl_ti);
    ASSERT_EQ_RET(rc, 0, -1);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvdb_api, test_collection_setup, test_collection_teardown);

/* [HSE_REVISIT] when libmpool is available, add a test to create a KVDB */
MTF_DEFINE_UTEST(kvdb_api, kvdb_create_exists)
{
    hse_err_t err;

    /* TC: Trying to create a KVDB on an already open KVDB returns EEXIST */
    err = hse_kvdb_create(home, 0, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EEXIST);
}

MTF_DEFINE_UTEST(kvdb_api, kvdb_close)
{
    hse_err_t        err;

    /* TC: hse_kvdb_close(NULL) --> EINVAL */
    err = hse_kvdb_close(NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);
}

MTF_END_UTEST_COLLECTION(kvdb_api)
