/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/logging.h>

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/limits.h>

#include <kvdb/kvdb_log.h>
#include <kvdb/kvdb_kvs.h>
#include <kvdb/kvdb_omf.h>

#include <mocks/mock_mpool.h>

char         data_path[PATH_MAX / 2];
static char *mdc_data;
static int   mdc_len;

int
kvdb_log_test_collection_setup(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *coll_info = info->ti_coll;

    if (coll_info->tci_argc > 1) {
        int len = strlen(coll_info->tci_argv[1]);

        if (coll_info->tci_argv[1][len - 1] == '/')
            coll_info->tci_argv[1][len - 1] = 0;
        strncpy(data_path, coll_info->tci_argv[1], sizeof(data_path) - 1);
    } else
        data_path[0] = 0;

    mock_mpool_set();

    return 0;
}

int
kvdb_log_test_collection_teardown(struct mtf_test_info *info)
{
    mock_mpool_unset();
    return 0;
}

static struct mpool *mock_ds = (void *)-1;

/* ------------------------------------------------------------
 * Unit tests
 */

int
load_log(char *file)
{
    char path[PATH_MAX];

    snprintf(path, sizeof(path), "%s/%s", data_path, file);
    return mpm_mdc_load_file(path, &mdc_data, &mdc_len);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    kvdb_log_test,
    kvdb_log_test_collection_setup,
    kvdb_log_test_collection_teardown);

MTF_DEFINE_UTEST(kvdb_log_test, empty_log_test)
{
    struct kvdb_log *log;
    merr_t           err;

    load_log("empty.klog");

    err = kvdb_log_open(data_path, mock_ds, O_RDWR, &log);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(log);

    err = kvdb_log_replay(log);
    ASSERT_EQ(0, err);

    err = kvdb_log_close(log);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST(kvdb_log_test, orphan_test)
{
    union kvdb_mdu  mdu = {};
    bool            isdone;
    merr_t          err;
    void *          p;
    struct kvdb_log log = {};

    mdu.h.mdh_type = KVDB_LOG_TYPE_MDC;
    mdu.c.mdc_disp = KVDB_LOG_DISP_CREATE_DONE;

    isdone = kvdb_log_finished(&mdu);
    ASSERT_EQ(true, isdone);

    mdu.c.mdc_disp = KVDB_LOG_DISP_CREATE;
    isdone = kvdb_log_finished(&mdu);
    ASSERT_EQ(false, isdone);

    err = kvdb_log_disp_set(&mdu, KVDB_LOG_DISP_REPLACE_DONE);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_LOG_DISP_REPLACE_DONE, mdu.c.mdc_disp);

    memset(&mdu, 0, sizeof(mdu));
    err = kvdb_log_disp_set(&mdu, KVDB_LOG_DISP_DESTROY_DONE);
    ASSERT_EQ(0, err);
    p = memchr(&mdu, KVDB_LOG_DISP_DESTROY_DONE, sizeof(mdu));
    ASSERT_EQ(NULL, p);

    mapi_inject(mapi_idx_mpool_mdc_append, 0);
    err = kvdb_log_create(&log, 1048576, NULL);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1048576, log.kl_captgt);
    mapi_inject_unset(mapi_idx_mpool_mdc_append);
}

MTF_END_UTEST_COLLECTION(kvdb_log_test)
