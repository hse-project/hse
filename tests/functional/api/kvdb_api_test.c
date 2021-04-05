/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <errno.h>
#include <hse_ut/fixtures.h>

/* Globals */
char *           mpool_name;
struct hse_kvdb *kvdb_handle;

int
test_collection_setup(struct mtf_test_info *lcl_ti)
{
    int                        rc;
    struct mtf_test_coll_info *coll_info = lcl_ti->ti_coll;

    if (coll_info->tci_argc != 2) {
        return -1;
    }

    mpool_name = coll_info->tci_argv[1];

    rc = mtf_kvdb_setup(lcl_ti, NULL, &kvdb_handle, 0);
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
MTF_DEFINE_UTEST(kvdb_api, kvdb_make_busy)
{
    hse_err_t err;

    /* TC: Trying to create a KVDB on an alredy open KVDB returns EBUSY */
    err = hse_kvdb_make(mpool_name, NULL);
    ASSERT_EQ(hse_err_to_errno(err), EBUSY);
}

MTF_DEFINE_UTEST(kvdb_api, kvdb_make_no_mpool)
{
    hse_err_t err;

    /* TC: A KVDB cannot be created on a non-existing MPOOL */
    err = hse_kvdb_make("non_existing_mpool", NULL);
    ASSERT_EQ(hse_err_to_errno(err), ENOENT);
}

MTF_DEFINE_UTEST(kvdb_api, kvdb_handle_no_mpool)
{
    hse_err_t        err;
    struct hse_kvdb *kvdb = NULL;

    /* TC: A KVDB that is NULL cannot be opened */
    err = hse_kvdb_open("test_mpool", NULL, &kvdb);
    ASSERT_EQ(hse_err_to_errno(err), ENOENT);

    /* TC: hse_kvdb_close(NULL) --> EINVAL */
    err = hse_kvdb_close(NULL);
    ASSERT_EQ(hse_err_to_errno(err), EINVAL);
}

MTF_END_UTEST_COLLECTION(kvdb_api)
