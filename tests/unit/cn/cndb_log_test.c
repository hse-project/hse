/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mtf/conditions.h>

#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/inttypes.h>

#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/cn_node_loc.h>

#include <cn/omf.h>
#include <cn/cn_tree.h>
#include <cn/kvset.h>
#include <cn/cndb_omf.h>
#include <cn/cndb_internal.h>
#include <cn/bloom_reader.h>

#include <mocks/mock_kvset.h>
#include <mocks/mock_mpool.h>

char data_path[PATH_MAX / 2];

/*
 * The functions with leading underscores are the mocked variants.
 *
 * The idea of this mock is to replicate the omf log as an in-core array,
 * with readers simply reading from this log, and writers laying down
 * a parallel log for comparison.
 */

static struct cndb *      mock_cndb;
static struct mpool *     mock_ds = (void *)-1;
static struct kvdb_health mock_health;

/*
 * There are pointers to the loaded data, for corruption and comparison.
 * They are not allocated directly, and should not be freed.
 */
static char *mdc_data;
static int   mdc_len;

int
test_collection_setup(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *coll_info = info->ti_coll;
    int                        idx = coll_info->tci_optind;
    int                        len = strlen(coll_info->tci_argv[idx]);

    if (coll_info->tci_argc - coll_info->tci_optind != 1) {
        fprintf(stderr, "Usage: %s [test framework options] <data-dir>\n", coll_info->tci_argv[0]);
        return EINVAL;
    }

    if (coll_info->tci_argv[idx][len - 1] == '/')
        coll_info->tci_argv[idx][len - 1] = 0;
    strncpy(data_path, coll_info->tci_argv[idx], sizeof(data_path) - 1);

    mock_mpool_set();
    mock_kvset_set();

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    mock_mpool_unset();
    mock_kvset_unset();
    return 0;
}

merr_t
load_log(char *file)
{
    char path[PATH_MAX];

#if HSE_OMF_BYTE_ORDER == __ORDER_BIG_ENDIAN__
    const char *suffix = "cndblog-be";
#else
    const char *suffix = "cndblog";
#endif

    snprintf(path, sizeof(path), "%s/%s.%s", data_path, file, suffix);

    return mpm_mdc_load_file(path, &mdc_data, &mdc_len);
}

static u64 seqno;

/* ------------------------------------------------------------
 * Unit tests
 */

MTF_BEGIN_UTEST_COLLECTION_PREPOST(cndb_log_test, test_collection_setup, test_collection_teardown);

static size_t
getlen(void *buf, size_t len)
{
    assert(len >= sizeof(struct cndb_hdr_omf));
    return omf_cnhdr_len(buf) + sizeof(struct cndb_hdr_omf);
}

MTF_DEFINE_UTEST(cndb_log_test, rollforward)
{
    merr_t err;
    size_t expect_workc = 0;
    size_t expect_keepc = 66;
    u64    ingestid, txhorizon;

    err = load_log("missing_ackds");
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDWR, 0, 2, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    /* [HSE_REVISIT] cndb_validate_vector() could check more than it does */
    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDONLY, 0, 2, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_abort);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);
}

MTF_DEFINE_UTEST(cndb_log_test, rollbackward)
{
    merr_t err;
    size_t expect_workc = 0;
    size_t expect_keepc = 58;
    u64    ingestid, txhorizon;

    err = load_log("missing_ackc");
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDWR, 0, 3, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDONLY, 0, 2, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_abort);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);
}

MTF_DEFINE_UTEST(cndb_log_test, wrongingestid)
{
    merr_t err;
    u64    ingestid, txhorizon;

    err = load_log("wrongingestid");
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDWR, 0, 2, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    /*
     * cndb should not check ingest ids. It is normal for them not to
     * be increasing order.
     */
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_abort);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);
}

/* drops a cn and one or more TXCs from each of two transactions */
MTF_DEFINE_UTEST(cndb_log_test, simpledrop)
{
    merr_t err;
    size_t expect_workc = 0;
    size_t expect_keepc = 42;
    size_t final_workc = 0;
    size_t final_keepc = 26;
    u64    drop_cnid = 2;
    u64    ingestid, txhorizon;
    size_t blobsz;
    char * blob = NULL;
    int    rc;
    char   expectblob[] = { 0x21, 0x12, 0x12, 0x21 };

    err = load_log("simpledrop");
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDWR, 0, 2, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 0);
    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_cn_drop(mock_cndb, drop_cnid);
    ASSERT_EQ(0, err);
    ASSERT_EQ(final_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(final_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_cnv_get(mock_cndb, drop_cnid, NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = cndb_cn_blob_get(mock_cndb, 4, &blobsz, (void *)&blob);
    ASSERT_EQ(0, err);
    ASSERT_EQ(4, blobsz);
    rc = memcmp(blob, expectblob, blobsz);
    ASSERT_EQ(0, rc);
    free(blob);

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mdc_usage);
    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_abort);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);
}

/* Drops a cn and its single transsaction */
MTF_DEFINE_UTEST(cndb_log_test, simpledrop2)
{
    merr_t err;
    size_t expect_workc = 0;
    size_t expect_keepc = 42;
    size_t final_workc = 0;
    size_t final_keepc = 36;
    u64    drop_cnid = 3;
    u64    ingestid, txhorizon;

    err = load_log("simpledrop");
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDWR, 0, 2, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 0);
    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_cn_drop(mock_cndb, drop_cnid);
    ASSERT_EQ(0, err);
    ASSERT_EQ(final_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(final_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_cnv_get(mock_cndb, drop_cnid, NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mdc_usage);
    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_abort);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);
}

/* Performs recovery, which drops a cn and its single transsaction */
MTF_DEFINE_UTEST(cndb_log_test, simpledrop_recovery)
{
    merr_t err;
    size_t expect_workc = 0;
    size_t expect_keepc = 36;
    u64    drop_cnid = 3;
    u64    ingestid, txhorizon;

    err = load_log("simpledrop_recovery");
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDWR, 0, 0, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 0);
    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_cnv_get(mock_cndb, drop_cnid, NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mdc_usage);
    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_abort);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);
}

#if HSE_OMF_BYTE_ORDER == __ORDER_LITTLE_ENDIAN__

/* putbin_v11 can no longer be generated and hence do not exist in big endian format as it
 * was not available at that time...
 */

MTF_DEFINE_UTEST(cndb_log_test, info_v11_test)
{
    merr_t err;
    size_t expect_workc = 0;
    size_t expect_keepc = 4;
    u64    ingestid, txhorizon;

    err = load_log("putbin_v11");
    ASSERT_EQ(0, err);

    err = cndb_open(mock_ds, CNDB_OPEN_RDWR, 0, 0, 0, 0, &mock_health, NULL, &mock_cndb);
    ASSERT_EQ(0, err);

    err = mpm_mdc_set_getlen(mock_cndb->cndb_mdc, getlen);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_mpool_mblock_props_get, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    mapi_inject(mapi_idx_mpool_mdc_usage, 0);
    err = cndb_replay(mock_cndb, &seqno, &ingestid, &txhorizon);
    ASSERT_EQ(0, err);

    ASSERT_EQ(expect_workc, mock_cndb->cndb_workc);
    cndb_validate_vector(mock_cndb->cndb_workv, mock_cndb->cndb_workc);
    ASSERT_EQ(expect_keepc, mock_cndb->cndb_keepc);
    cndb_validate_vector(mock_cndb->cndb_keepv, mock_cndb->cndb_keepc);

    err = cndb_close(mock_cndb);
    ASSERT_EQ(0, err);

    mapi_inject_unset(mapi_idx_mpool_mdc_usage);
    mapi_inject_unset(mapi_idx_mpool_mblock_props_get);
    mapi_inject_unset(mapi_idx_mpool_mblock_abort);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);
}

#endif /* little endian */

MTF_END_UTEST_COLLECTION(cndb_log_test)
