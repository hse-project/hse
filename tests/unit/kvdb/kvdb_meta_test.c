/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include "hse_ut/conditions.h"
#include "hse_util/hse_err.h"
#include "mapi_idx.h"
#include "mpool/mpool_structs.h"
#include <hse_ut/framework.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvdb_dparams.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_meta.h>
#include <mpool/mpool.h>

#include <bsd/string.h>

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

    meta.km_cndb.oid1 = 1;
    meta.km_cndb.oid2 = 2;
    meta.km_wal.oid1 = 3;
    meta.km_wal.oid2 = 4;
    strlcpy(
        meta.km_storage[MP_MED_CAPACITY].path,
        "capacity",
        sizeof(meta.km_storage[MP_MED_CAPACITY].path));
    strlcpy(
        meta.km_storage[MP_MED_STAGING].path,
        "staging",
        sizeof(meta.km_storage[MP_MED_STAGING].path));

    err = kvdb_meta_create(home);
    ASSERT_EQ(0, err);

    err = kvdb_meta_serialize(&meta, home);
    printf("%s:%d %d\n", merr_file(err), merr_lineno(err), merr_errno(err));
    ASSERT_EQ(0, err);

    memset(&meta, 0, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    ASSERT_EQ(1, meta.km_cndb.oid1);
    ASSERT_EQ(2, meta.km_cndb.oid2);
    ASSERT_EQ(3, meta.km_wal.oid1);
    ASSERT_EQ(4, meta.km_wal.oid2);
    ASSERT_STREQ("capacity", meta.km_storage[MP_MED_CAPACITY].path);
    ASSERT_STREQ("staging", meta.km_storage[MP_MED_STAGING].path);
}

MTF_DEFINE_UTEST_POST(kvdb_meta_test, null_storage_paths, destroy_post)
{
    struct kvdb_meta meta = {};
    char             zero[PATH_MAX];
    merr_t           err;

    memset(zero, 0, sizeof(zero));

    strlcpy(
        meta.km_storage[MP_MED_CAPACITY].path,
        "capacity",
        sizeof(meta.km_storage[MP_MED_CAPACITY].path));

    err = kvdb_meta_create(home);
    ASSERT_EQ(0, err);

    err = kvdb_meta_serialize(&meta, home);
    ASSERT_EQ(0, err);

    memset(&meta, 1, sizeof(meta));

    err = kvdb_meta_deserialize(&meta, home);
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, memcmp(meta.km_storage[MP_MED_STAGING].path, zero, sizeof(zero)));
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

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, usage, test_pre)
{
    uint64_t bytes;
    merr_t   err;

    err = kvdb_meta_usage(test_home, &bytes);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(bytes > 0);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, from_cparams, test_pre)
{
    struct kvdb_cparams params = kvdb_cparams_defaults();
    struct kvdb_meta    meta = {
		.km_cndb = {
			.oid1 = 1,
			.oid2 = 2,
		},
		.km_wal = {
			.oid1 = 3,
			.oid2 = 4,
		},
	};

    strlcpy(
        params.storage.mclass[MP_MED_CAPACITY].path,
        "my_capacity",
        sizeof(params.storage.mclass[MP_MED_CAPACITY].path));
    strlcpy(
        params.storage.mclass[MP_MED_STAGING].path,
        "my_staging",
        sizeof(params.storage.mclass[MP_MED_CAPACITY].path));

    kvdb_meta_from_kvdb_cparams(&meta, test_home, &params);

    ASSERT_STREQ(
        meta.km_storage[MP_MED_CAPACITY].path, params.storage.mclass[MP_MED_CAPACITY].path);
    ASSERT_STREQ(meta.km_storage[MP_MED_STAGING].path, params.storage.mclass[MP_MED_STAGING].path);

    kvdb_cparams_resolve(&params, test_home);

    kvdb_meta_from_kvdb_cparams(&meta, test_home, &params);

    ASSERT_STREQ(meta.km_storage[MP_MED_CAPACITY].path, "my_capacity");
    ASSERT_STREQ(meta.km_storage[MP_MED_STAGING].path, "my_staging");
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_kvdb_rparams_defaults, test_pre)
{
    merr_t              err;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvdb_meta    meta = {
		.km_storage = {
			{ .path = "my_capacity" },
			{ .path = "my_staging" },
		},
	};
    char capacity[2 * PATH_MAX];
    char staging[2 * PATH_MAX];

    snprintf(capacity, sizeof(capacity), "%s/%s", test_home, meta.km_storage[MP_MED_CAPACITY].path);
    snprintf(staging, sizeof(staging), "%s/%s", test_home, meta.km_storage[MP_MED_STAGING].path);

    err = kvdb_meta_to_kvdb_rparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(capacity, params.storage.mclass[MP_MED_CAPACITY].path);
    ASSERT_STREQ(staging, params.storage.mclass[MP_MED_STAGING].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_kvdb_rparams_non_defaults, test_pre)
{
	merr_t              err;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvdb_meta    meta = {
		.km_storage = {
			{ .path = "my_capacity" },
			{ .path = "my_staging" },
		},
	};

    char capacity[2 * PATH_MAX];
    char staging[2 * PATH_MAX];
	strlcpy(params.storage.mclass[MP_MED_CAPACITY].path, "my_capacity", sizeof(params.storage.mclass[MP_MED_CAPACITY].path));
	strlcpy(params.storage.mclass[MP_MED_STAGING].path, "my_staging", sizeof(params.storage.mclass[MP_MED_CAPACITY].path));

	strlcpy(capacity, params.storage.mclass[MP_MED_CAPACITY].path, sizeof(capacity));
	strlcpy(staging, params.storage.mclass[MP_MED_STAGING].path, sizeof(staging));

    err = kvdb_meta_to_kvdb_rparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(capacity, params.storage.mclass[MP_MED_CAPACITY].path);
    ASSERT_STREQ(staging, params.storage.mclass[MP_MED_STAGING].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_kvdb_dparams_defaults, test_pre)
{
    merr_t              err;
    struct kvdb_dparams params = kvdb_dparams_defaults();
    struct kvdb_meta    meta = {
		.km_storage = {
			{ .path = "my_capacity" },
			{ .path = "my_staging" },
		},
	};
    char capacity[2 * PATH_MAX];
    char staging[2 * PATH_MAX];

    snprintf(capacity, sizeof(capacity), "%s/%s", test_home, meta.km_storage[MP_MED_CAPACITY].path);
    snprintf(staging, sizeof(staging), "%s/%s", test_home, meta.km_storage[MP_MED_STAGING].path);

    err = kvdb_meta_to_kvdb_dparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(capacity, params.storage.mclass[MP_MED_CAPACITY].path);
    ASSERT_STREQ(staging, params.storage.mclass[MP_MED_STAGING].path);
}

MTF_DEFINE_UTEST_PRE(kvdb_meta_test, to_kvdb_dparams_non_defaults, test_pre)
{
	merr_t              err;
    struct kvdb_rparams params = kvdb_rparams_defaults();
    struct kvdb_meta    meta = {
		.km_storage = {
			{ .path = "my_capacity" },
			{ .path = "my_staging" },
		},
	};
    char capacity[2 * PATH_MAX];
    char staging[2 * PATH_MAX];

	strlcpy(params.storage.mclass[MP_MED_CAPACITY].path, "my_capacity", sizeof(params.storage.mclass[MP_MED_CAPACITY].path));
	strlcpy(params.storage.mclass[MP_MED_STAGING].path, "my_staging", sizeof(params.storage.mclass[MP_MED_CAPACITY].path));

	strlcpy(capacity, params.storage.mclass[MP_MED_CAPACITY].path, sizeof(capacity));
	strlcpy(staging, params.storage.mclass[MP_MED_STAGING].path, sizeof(staging));

    err = kvdb_meta_to_kvdb_rparams(&meta, test_home, &params);
    ASSERT_EQ(0, err);
    ASSERT_STREQ(capacity, params.storage.mclass[MP_MED_CAPACITY].path);
    ASSERT_STREQ(staging, params.storage.mclass[MP_MED_STAGING].path);
}

MTF_DEFINE_UTEST_POST(kvdb_meta_test, meta_sync, destroy_post)
{
	merr_t              err;
    struct kvdb_rparams params = kvdb_rparams_defaults();
	struct kvdb_meta    meta_new;
	struct kvdb_meta    meta_orig = {
		.km_storage = {
			{ .path = "orig_capacity" },
		},
	};

	strlcpy(params.storage.mclass[MP_MED_CAPACITY].path, "my_capacity", sizeof(params.storage.mclass[MP_MED_CAPACITY].path));
	strlcpy(params.storage.mclass[MP_MED_STAGING].path, "my_staging", sizeof(params.storage.mclass[MP_MED_CAPACITY].path));

	err = kvdb_meta_create(home);
	ASSERT_EQ(0, err);

	err = kvdb_meta_sync(&meta_orig, home, &params);
	ASSERT_EQ(0, err);

	err = kvdb_meta_deserialize(&meta_new, home);
	ASSERT_EQ(0, err);

	ASSERT_STREQ(params.storage.mclass[MP_MED_CAPACITY].path, meta_new.km_storage[MP_MED_CAPACITY].path);
	ASSERT_STREQ(params.storage.mclass[MP_MED_STAGING].path, meta_new.km_storage[MP_MED_STAGING].path);
}

MTF_END_UTEST_COLLECTION(kvdb_meta_test)
