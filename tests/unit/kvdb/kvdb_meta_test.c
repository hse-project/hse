/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include "hse_util/hse_err.h"
#include <mtf/framework.h>

#include <hse_ikvdb/kvdb_meta.h>
#include <hse_ikvdb/omf_version.h>
#include <mpool/mpool.h>

#include <bsd/string.h>

/* cJSON seems incapable of parsing a number value greater than UINT64_MAX for
 * some reason even though DBL_MAX is much larger than UINT64_MAX. All overflow
 * tests againt uint64_t values have been commented out.
 */

static char test_home[PATH_MAX];

int
collection_pre(struct mtf_test_info *info)
{
    kvdb_meta_destroy(home);
    return !(info->ti_coll->tci_argc == 4);
}

int
test_pre(struct mtf_test_info *info)
{
    snprintf(test_home, sizeof(test_home), "%s/%s", info->ti_coll->tci_argv[3], info->ti_name);
    return 0;
}

int
destroy_post(struct mtf_test_info *info)
{
    kvdb_meta_destroy(home);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(kvdb_meta_test, collection_pre)

MTF_DEFINE_UTEST_POST(kvdb_meta_test, serde, destroy_post)
{
    struct kvdb_meta meta;
    merr_t           err;
    int              i;

    meta.km_version = KVDB_META_VERSION;
    meta.km_omf_version = GLOBAL_OMF_VERSION;
    meta.km_cndb.oid1 = 1;
    meta.km_cndb.oid2 = 2;
    meta.km_wal.oid1 = 3;
    meta.km_wal.oid2 = 4;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        strlcpy(meta.km_storage[i].path, mpool_mclass_to_string[i],
                sizeof(meta.km_storage[i].path));

    err = kvdb_meta_create(home);
    ASSERT_EQ(0, err);

    err = kvdb_meta_serialize(&meta, home);
    ASSERT_EQ(0, err);

    memset(&meta, 0, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    ASSERT_EQ(1, meta.km_cndb.oid1);
    ASSERT_EQ(2, meta.km_cndb.oid2);
    ASSERT_EQ(3, meta.km_wal.oid1);
    ASSERT_EQ(4, meta.km_wal.oid2);
    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(mpool_mclass_to_string[i], meta.km_storage[i].path);
}

MTF_DEFINE_UTEST_POST(kvdb_meta_test, null_storage_paths, destroy_post)
{
    struct kvdb_meta meta = {};
    char             zero[PATH_MAX];
    merr_t           err;
    int              i;

    memset(zero, 0, sizeof(zero));

    strlcpy(meta.km_storage[HSE_MCLASS_CAPACITY].path, "capacity",
            sizeof(meta.km_storage[HSE_MCLASS_CAPACITY].path));

    err = kvdb_meta_create(home);
    ASSERT_EQ(0, err);

    meta.km_version = KVDB_META_VERSION;
    meta.km_omf_version = GLOBAL_OMF_VERSION;

    err = kvdb_meta_serialize(&meta, home);
    ASSERT_EQ(0, err);

    memset(&meta, 1, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    for (i = HSE_MCLASS_STAGING; i < HSE_MCLASS_PMEM; i++)
        ASSERT_EQ(0, memcmp(meta.km_storage[i].path, zero, sizeof(zero)));
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_root_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_cndb_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_cndb_oid1_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_cndb_oid2_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_wal_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_wal_oid1_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_wal_oid2_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_storage_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_storage_capacity_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_storage_capacity_path_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_storage_staging_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, incorrect_storage_staging_path_type, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_cndb, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_cndb_oid1, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_cndb_oid2, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_wal, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_wal_oid1, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_wal_oid2, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_storage, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_storage_capacity, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_storage_capacity_path, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_storage_staging, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, missing_storage_staging_path, test_pre)
{

    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, root_unknown_key, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, cndb_unknown_key, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, wal_unknown_key, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, storage_unknown_key, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, storage_capacity_unknown_key, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, storage_staging_unknown_key, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, bad_format, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, does_not_exist, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_cndb_oid1_nonwhole, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

/*
MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_cndb_oid1_overflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}
*/

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_cndb_oid1_underflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_cndb_oid2_nonwhole, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

/*
MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_cndb_oid2_overflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}
*/

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_cndb_oid2_underflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_version_nonwhole, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_version_underflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_version_overflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_omf_version_nonwhole, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_omf_version_underflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_omf_version_overflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_wal_oid1_nonwhole, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

/*
MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_wal_oid1_overflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}
*/

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_wal_oid1_underflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_wal_oid2_nonwhole, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

/*
MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_wal_oid2_overflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}
*/

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, invalid_wal_oid2_underflow, test_pre)
{
    struct kvdb_meta meta;
    merr_t           err;

    err = kvdb_meta_deserialize(&meta, test_home);
    ASSERT_NE(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, from_mpool_cparams_absolute, test_pre)
{
    struct mpool_cparams params;
    struct kvdb_meta     meta;
    const char *paths[HSE_MCLASS_COUNT] = {"/home/my_capacity", "/home/my_staging", "/home/my_pmem"};
    int i;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        strlcpy(params.mclass[i].path, paths[i], sizeof(params.mclass[i].path));

    kvdb_meta_from_mpool_cparams(&meta, test_home, &params);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(meta.km_storage[i].path, params.mclass[i].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, from_mpool_cparams_relative, test_pre)
{
    struct mpool_cparams params;
    struct kvdb_meta     meta;
    const char *paths[HSE_MCLASS_COUNT] = {"./my_capacity", "1/2/my_staging", "1/2/my_pmem"};
    int   i;
    char *homedup;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        strlcpy(params.mclass[i].path, paths[i], sizeof(params.mclass[i].path));

    kvdb_meta_from_mpool_cparams(&meta, test_home, &params);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(meta.km_storage[i].path, params.mclass[i].path);

    homedup = strdup(test_home);
    ASSERT_NE(homedup, NULL);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        snprintf(params.mclass[i].path, sizeof(params.mclass[i].path), "%s/%s", homedup, paths[i]);
        meta.km_storage[i].path[0] = '\0';
    }

    kvdb_meta_from_mpool_cparams(&meta, test_home, &params);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(meta.km_storage[i].path, params.mclass[i].path);

    free(homedup);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, meta_storage_add_absolute, test_pre)
{
    struct mpool_cparams params;
    const char *paths[HSE_MCLASS_COUNT] = { "/home/my_capacity", "/home/my_staging", "/home/my_pmem" };
    struct kvdb_meta     meta = {
        .km_version = KVDB_META_VERSION,
        .km_omf_version = GLOBAL_OMF_VERSION,
        .km_cndb = {
            .oid1 = 1,
            .oid2 = 2,
        },
        .km_wal = {
            .oid1 = 3,
            .oid2 = 4,
        },
        .km_storage = {
            { .path = "/home/my_capacity" },
        },
    };
    merr_t err;
    int    i;

    err = kvdb_meta_create(home);
    ASSERT_EQ(0, err);

    err = kvdb_meta_serialize(&meta, home);
    ASSERT_EQ(0, err);

    memset(&meta, 0, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    params.mclass[HSE_MCLASS_CAPACITY].path[0] = '\0';
    for (i = HSE_MCLASS_STAGING; i < HSE_MCLASS_COUNT; i++)
        strlcpy(params.mclass[i].path, paths[i], sizeof(params.mclass[i].path));

    err = kvdb_meta_storage_add(&meta, home, &params);
    ASSERT_EQ(0, err);

    memset(&meta, 0, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    ASSERT_STREQ(meta.km_storage[HSE_MCLASS_CAPACITY].path, paths[HSE_MCLASS_CAPACITY]);
    for (i = HSE_MCLASS_STAGING; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(meta.km_storage[i].path, paths[i]);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, meta_storage_add_relative, test_pre)
{
    struct mpool_cparams params;
    const char *paths[HSE_MCLASS_COUNT] = { "my_capacity", "1/2/my_staging", "1/2/my_pmem" };
    struct kvdb_meta     meta = {
        .km_version = KVDB_META_VERSION,
        .km_omf_version = GLOBAL_OMF_VERSION,
        .km_cndb = {
            .oid1 = 1,
            .oid2 = 2,
        },
        .km_wal = {
            .oid1 = 3,
            .oid2 = 4,
        },
        .km_storage = {
            { .path = "my_capacity" },
        },
    };
    merr_t err;
    char *homedup;
    int   i;

    err = kvdb_meta_create(home);
    ASSERT_EQ(0, err);

    err = kvdb_meta_serialize(&meta, home);
    ASSERT_EQ(0, err);

    memset(&meta, 0, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    homedup = strdup(home);
    ASSERT_NE(homedup, NULL);

    params.mclass[HSE_MCLASS_CAPACITY].path[0] = '\0';
    for (i = HSE_MCLASS_STAGING; i < HSE_MCLASS_COUNT; i++)
        snprintf(params.mclass[i].path, sizeof(params.mclass[i].path) - strlen(paths[i]) - 1,
                 "%s/%s", homedup, paths[i]);

    err = kvdb_meta_storage_add(&meta, home, &params);
    ASSERT_EQ(0, err);

    memset(&meta, 0, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    ASSERT_STREQ(meta.km_storage[HSE_MCLASS_CAPACITY].path, paths[HSE_MCLASS_CAPACITY]);
    for (i = HSE_MCLASS_STAGING; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(meta.km_storage[i].path, params.mclass[i].path);

    free(homedup);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_mpool_rparams_relative, test_pre)
{
    merr_t               err;
    struct mpool_rparams params;
    struct kvdb_meta     meta = {
        .km_storage = {
            { .path = "my_capacity" },
            { .path = "my_staging" },
            { .path = "my_pmem" },
        },
    };
    char paths[HSE_MCLASS_COUNT][2 * PATH_MAX];
    int  i;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", test_home, meta.km_storage[i].path);

    err = kvdb_meta_to_mpool_rparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(paths[i], params.mclass[i].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_mpool_rparams_absolute, test_pre)
{
	merr_t               err;
    struct mpool_rparams params;
    struct kvdb_meta     meta = {
        .km_storage = {
            { .path = "/my_capacity" },
            { .path = "/my_staging" },
            { .path = "/my_pmem" },
        },
    };
    int i;

    err = kvdb_meta_to_mpool_rparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(meta.km_storage[i].path, params.mclass[i].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_mpool_rparams_null, test_pre)
{
	merr_t               err;
    struct mpool_rparams params;
    struct kvdb_meta     meta = {
        .km_storage = {
            { .path = "/my_capacity" },
            { .path = { 0 } },
            { .path = { 0 } },
        },
    };
    int i;

    const char null[sizeof(params.mclass[HSE_MCLASS_BASE].path)] = {};

    err = kvdb_meta_to_mpool_rparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);

    ASSERT_STREQ("/my_capacity", params.mclass[HSE_MCLASS_CAPACITY].path);
    for (i = HSE_MCLASS_STAGING; i < HSE_MCLASS_COUNT; i++)
        ASSERT_EQ(0, memcmp(null, params.mclass[i].path, sizeof(null)));
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_mpool_dparams_relative, test_pre)
{
    merr_t               err;
    struct mpool_dparams params;
    struct kvdb_meta     meta = {
        .km_storage = {
            { .path = "my_capacity" },
            { .path = "my_staging" },
            { .path = "my_pmem" },
        },
    };
    char paths[HSE_MCLASS_COUNT][2 * PATH_MAX];
    int i;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", test_home, meta.km_storage[i].path);

    err = kvdb_meta_to_mpool_dparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(paths[i], params.mclass[i].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_mpool_dparams_absolute, test_pre)
{
	merr_t               err;
    struct mpool_dparams params;
    struct kvdb_meta     meta = {
        .km_storage = {
            { .path = "/my_capacity" },
            { .path = "/my_staging" },
            { .path = "/my_pmem" },
        },
    };
    int i;

    err = kvdb_meta_to_mpool_dparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++)
        ASSERT_STREQ(meta.km_storage[i].path, params.mclass[i].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_mpool_dparams_null, test_pre)
{
	merr_t               err;
    struct mpool_dparams params;
    struct kvdb_meta     meta = {
        .km_storage = {
            { .path = "/my_capacity" },
            { .path = { 0 } },
            { .path = { 0 } },
        },
    };
    int i;

    const char null[sizeof(params.mclass[HSE_MCLASS_BASE].path)] = {};

    err = kvdb_meta_to_mpool_dparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);

    ASSERT_STREQ("/my_capacity", params.mclass[HSE_MCLASS_CAPACITY].path);
    for (i = HSE_MCLASS_STAGING; i < HSE_MCLASS_COUNT; i++)
        ASSERT_EQ(0, memcmp(null, params.mclass[i].path, sizeof(null)));
}

MTF_END_UTEST_COLLECTION(kvdb_meta_test)
