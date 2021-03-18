/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/compression_lz4.h>

#include <hse_ut/framework.h>

#include <errno.h>

/* Globals */
char *           MPOOL_NAME;
struct hse_kvdb *KVDB_HANDLE = NULL;

int
test_collection_setup(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *coll_info = info->ti_coll;
    hse_openlog("kvdb_api_test", 1);

    if (coll_info->tci_argc != 2) {
        hse_log(HSE_ERR "Usage:  %s <mpool_name>", coll_info->tci_argv[0]);
        return -1;
    }

    MPOOL_NAME = coll_info->tci_argv[1];

    hse_kvdb_init();

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
    // TC: A KVDB with a valid name can be created on an existing MPOOL...

    hse_err_t rc;

    rc = hse_kvdb_make(MPOOL_NAME, NULL);

    if (hse_err_to_errno(rc) == EACCES) {
        fprintf(stderr, "Invalid permissions");
        exit(1);
    }

    ASSERT_EQ(hse_err_to_errno(rc), EXIT_SUCCESS);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_open_testcase_no_mpool)
{
    // TC: A non-existing KVDB cannot be opened...

    hse_err_t rc;

    rc = hse_kvdb_open("fake_mpool", NULL, &KVDB_HANDLE);

    ASSERT_EQ(hse_err_to_errno(rc), ENOENT);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_close_testcase_no_kvdb)
{
    // TC: A non-existing KVDB cannot be closed...

    hse_err_t rc;

    rc = hse_kvdb_close(KVDB_HANDLE);

    ASSERT_EQ(hse_err_to_errno(rc), EINVAL);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_make_testcase_no_mpool)
{
    // TC: A KVDB cannot be created on a non-existing MPOOL...

    hse_err_t rc;

    rc = hse_kvdb_make("fake_mpool", NULL);

    ASSERT_EQ(hse_err_to_errno(rc), ENOENT);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_close_testcase)
{
    // TC: An existing KVDB which is open can be closed...

    hse_err_t rc;

    rc = hse_kvdb_open(MPOOL_NAME, NULL, &KVDB_HANDLE);
    if (hse_err_to_errno(rc))
        exit(1);

    rc = hse_kvdb_close(KVDB_HANDLE);
    KVDB_HANDLE = NULL;

    ASSERT_EQ(hse_err_to_errno(rc), EXIT_SUCCESS);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_open_testcase)
{
    // TC: An existing KVDB can be opened...

    hse_err_t rc;

    rc = hse_kvdb_open(MPOOL_NAME, NULL, &KVDB_HANDLE);

    ASSERT_EQ(hse_err_to_errno(rc), EXIT_SUCCESS);
}

MTF_DEFINE_UTEST(kvdb_api_test, kvdb_valid_handle_testcase)
{
    // TC: An opened KVDB returns a valid handle...

    ASSERT_NE(KVDB_HANDLE, NULL);
}

MTF_END_UTEST_COLLECTION(kvdb_api_test)