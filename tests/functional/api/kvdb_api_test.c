/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <errno.h>

/* Globals */
char *mpool_name;

int
test_collection_setup(struct mtf_test_info *info)
{
    hse_err_t                  rc;
    struct mtf_test_coll_info *coll_info = info->ti_coll;
    hse_openlog("kvdb_api_test", 1);

    if (coll_info->tci_argc != 2) {
        hse_log(HSE_ERR "Usage:  %s <mpool_name>", coll_info->tci_argv[0]);
        return -1;
    }

    mpool_name = coll_info->tci_argv[1];

    rc = hse_kvdb_init();
    if (hse_err_to_errno(rc))
        return -1;

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    hse_kvdb_fini();
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvdb_api_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_make_testcase)
{
    hse_err_t rc;

    // TC: A KVDB with a valid name can be created on an existing MPOOL
    rc = hse_kvdb_make(mpool_name, NULL);
    ASSERT_NE(hse_err_to_errno(rc), EACCES);
    ASSERT_EQ(hse_err_to_errno(rc), EEXIST);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_make_no_mpool_testcase)
{
    hse_err_t rc;

    // TC: A KVDB cannot be created on a non-existing MPOOL
    rc = hse_kvdb_make("fake_mpool", NULL);
    ASSERT_EQ(hse_err_to_errno(rc), ENOENT);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_handle_no_mpool_testcase)
{
    struct hse_kvdb *kvdb_handle = NULL;
    hse_err_t        rc;

    // TC: A non-existing KVDB cannot be opened
    rc = hse_kvdb_open("fake_mpool", NULL, &kvdb_handle);
    ASSERT_EQ(hse_err_to_errno(rc), ENOENT);

    // TC: A non-existing KVDB cannot be closed
    rc = hse_kvdb_close(kvdb_handle);
    ASSERT_EQ(hse_err_to_errno(rc), EINVAL);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_valid_testcase)
{
    struct hse_kvdb *kvdb_handle;
    hse_err_t        rc;

    // TC: An existing KVDB can be opened
    rc = hse_kvdb_open(mpool_name, NULL, &kvdb_handle);
    ASSERT_EQ(hse_err_to_errno(rc), EXIT_SUCCESS);

    // TC: An opened KVDB return a valid handle
    ASSERT_NE(kvdb_handle, NULL);

    // TC: An opened KVDB can be closed
    rc = hse_kvdb_close(kvdb_handle);
    ASSERT_EQ(hse_err_to_errno(rc), EXIT_SUCCESS);
}

MTF_END_UTEST_COLLECTION(kvdb_api_test)