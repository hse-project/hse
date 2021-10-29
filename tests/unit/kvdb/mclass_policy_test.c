/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <mpool/mpool.h>

/*
 * Pre and Post Functions
 */
static int
general_pre(struct mtf_test_info *ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(mclass_policy_test)

MTF_DEFINE_UTEST_PRE(mclass_policy_test, mclass_policy_default, general_pre)
{
    int                  i, j, k, l;
    merr_t               err;
    struct kvdb_rparams  params = kvdb_rparams_defaults();
    struct mclass_policy dpolicies[4];
    const char * const   paramv[] = { "mclass_policies=[{\"name\": \"test_only\", \"config\": "
                       "{\"internal\": {\"values\": [\"capacity\"]}}}]" };

    /* Capacity only media class policy, use capacity for all combinations */
    strcpy(dpolicies[0].mc_name, "capacity_only");
    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++) {
            dpolicies[0].mc_table[i][j][0] = HSE_MPOLICY_MEDIA_CAPACITY;
            dpolicies[0].mc_table[i][j][1] = HSE_MPOLICY_MEDIA_INVALID;
        }

    /* Staging only media class policy, use staging for all combinations  */
    strcpy(dpolicies[1].mc_name, "staging_only");
    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++) {
            dpolicies[1].mc_table[i][j][0] = HSE_MPOLICY_MEDIA_STAGING;
            dpolicies[1].mc_table[i][j][1] = HSE_MPOLICY_MEDIA_INVALID;
        }

    /*
     * staging_max_capacity - only internal and leaf values use capacity.
     */
    strcpy(dpolicies[2].mc_name, "staging_max_capacity");
    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++) {
            dpolicies[2].mc_table[i][j][0] = HSE_MPOLICY_MEDIA_STAGING;
            dpolicies[2].mc_table[i][j][1] = HSE_MPOLICY_MEDIA_INVALID;
        }
    dpolicies[2].mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][0] =
        HSE_MPOLICY_MEDIA_CAPACITY;
    dpolicies[2].mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][0] =
        HSE_MPOLICY_MEDIA_CAPACITY;

    /*
     * staging_min_capacity - only root nodes use staging.
     */
    strcpy(dpolicies[3].mc_name, "staging_min_capacity");
    for (i = 0; i < HSE_MPOLICY_AGE_INTERNAL; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++) {
            dpolicies[3].mc_table[i][j][0] = HSE_MPOLICY_MEDIA_STAGING;
            dpolicies[3].mc_table[i][j][1] = HSE_MPOLICY_MEDIA_INVALID;
        }

    for (i = HSE_MPOLICY_AGE_INTERNAL; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++) {
            dpolicies[3].mc_table[i][j][0] = HSE_MPOLICY_MEDIA_CAPACITY;
            dpolicies[3].mc_table[i][j][1] = HSE_MPOLICY_MEDIA_INVALID;
        }

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(0, err);

    /* Validate that the parsed policies match the hardcoded matrices for the default policies. */
    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++)
            for (k = 0; k < HSE_MPOLICY_MEDIA_CNT; k++)
                for (l = 0; l < 4; l++) {
                    enum hse_mclass_policy_media hse_mtype;
                    enum mpool_mclass            mpool_mtype;

                    hse_mtype = params.mclass_policies[l].mc_table[i][j][k];

                    ASSERT_EQ(hse_mtype, dpolicies[l].mc_table[i][j][k]);
                    ASSERT_EQ(strcmp(params.mclass_policies[l].mc_name, dpolicies[l].mc_name), 0);

                    mpool_mtype = mclass_policy_get_type(&params.mclass_policies[l], i, j, k);
                    if (hse_mtype == HSE_MPOLICY_MEDIA_INVALID)
                        ASSERT_EQ(mpool_mtype, MP_MED_INVALID);
                    else if (hse_mtype == HSE_MPOLICY_MEDIA_STAGING)
                        ASSERT_EQ(mpool_mtype, MP_MED_STAGING);
                    else
                        ASSERT_EQ(mpool_mtype, MP_MED_CAPACITY);
                }

    /*
     * Initialize hse params from a test policy that specifies only <internal, leaf>
     * and validate that the remaining entries are populated from the default template
     * i.e. staging_capacity_nofallback
     */
    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(strcmp(params.mclass_policies[4].mc_name, "test_only"), 0);

    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++)
            for (k = 0; k < HSE_MPOLICY_MEDIA_CNT; k++) {
                enum hse_mclass_policy_media hse_mtype;
                enum mpool_mclass            mpool_mtype;

                hse_mtype = params.mclass_policies[4].mc_table[i][j][k];

                if (!((i == HSE_MPOLICY_AGE_INTERNAL) && (j == HSE_MPOLICY_DTYPE_VALUE))) {
                    /* Media type should match staging_capacity_nofallback */
                    ASSERT_EQ(hse_mtype, dpolicies[2].mc_table[i][j][k]);
                } else if (k == 0) {
                    /* <internal, leaf> first preference is capacity */
                    ASSERT_EQ(hse_mtype, HSE_MPOLICY_MEDIA_CAPACITY);
                } else {
                    /* <internal, leaf> no second preference */
                    ASSERT_EQ(hse_mtype, HSE_MPOLICY_MEDIA_INVALID);
                }

                mpool_mtype = mclass_policy_get_type(&params.mclass_policies[4], i, j, k);
                if (hse_mtype == HSE_MPOLICY_MEDIA_INVALID)
                    ASSERT_EQ(mpool_mtype, MP_MED_INVALID);
                else if (hse_mtype == HSE_MPOLICY_MEDIA_STAGING)
                    ASSERT_EQ(mpool_mtype, MP_MED_STAGING);
                else
                    ASSERT_EQ(mpool_mtype, MP_MED_CAPACITY);
            }
}

MTF_DEFINE_UTEST(mclass_policy_test, overwrite_default_policy)
{
    const char *  const paramv[] = { "mclass_policies=[{\"name\": \"staging_only\", \"config\": "
                       "{\"internal\": {\"values\": [\"capacity\"]}}}]" };
    struct kvdb_rparams params = kvdb_rparams_defaults();
    merr_t              err;

    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv), paramv, &params);
    ASSERT_NE(err, 0);
}

MTF_DEFINE_UTEST(mclass_policy_test, incorrect_schema)
{
    struct kvdb_rparams params = kvdb_rparams_defaults();
    merr_t              err;

    const char * const paramv_policy_unknown_key[] = {
        "mclass_policies=[{\"name\": \"staging_only\", \"hello\": \"world\", \"config\": "
        "{\"internal\": {\"values\": [\"capacity\"]}}}]"
    };
    const char * const paramv_age_unknown_key[] = {
        "mclass_policies=[{\"name\": \"staging_only\", \"config\": {\"hello\": \"world\", "
        "\"internal\": {\"values\": [\"capacity\"]}}}]"
    };
    const char * const paramv_dtype_unknown_key[] = {
        "mclass_policies=[{\"name\": \"staging_only\", \"config\": {\"internal\": {\"hello\": "
        "\"world\", \"values\": [\"capacity\"]}}}]"
    };

    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_policy_unknown_key), paramv_policy_unknown_key, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_age_unknown_key), paramv_age_unknown_key, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_dtype_unknown_key), paramv_dtype_unknown_key, &params);
    ASSERT_NE(err, 0);

    const char * const paramv_mclass_policies_schema[] = { "mclass_policies={}" };
    const char * const paramv_policy_name_schema[] = {
        "mclass_policies=[{\"name\": [], \"config\": {\"internal\": {\"values\": [\"capacity\"]}}}]"
    };
    const char * const paramv_policy_config_schema[] = {
        "mclass_policies=[{\"name\": \"test_only\", \"config\": []}]"
    };
    const char * const paramv_age_schema[] = {
        "mclass_policies=[{\"name\": \"test_only\", \"config\": {\"internal\": []}}]"
    };
    const char * const paramv_dtype_schema1[] = {
        "mclass_policies=[{\"name\": \"test_only\", \"config\": {\"internal\": {\"values\": {}}}}]"
    };
    const char * const paramv_dtype_schema2[] = { "mclass_policies=[{\"name\": \"test_only\", \"config\": "
                                     "{\"internal\": {\"values\": [2, 1]}}}]" };
    const char * const paramv_dtype_schema3[] = {
        "mclass_policies[{\"name\": \"test_only\", \"config\": {\"internal\": {\"values\": []}}}]"
    };
    const char * const paramv_dtype_schema4[] = { "mclass_policies=[{\"name\": \"test_only\", \"config\": "
                                     "{\"internal\": {\"values\": [\"test\"]}}}]" };

    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_mclass_policies_schema), paramv_mclass_policies_schema, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_policy_name_schema), paramv_policy_name_schema, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_policy_config_schema), paramv_policy_config_schema, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(NELEM(paramv_age_schema), paramv_age_schema, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_dtype_schema1), paramv_dtype_schema1, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_dtype_schema2), paramv_dtype_schema2, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_dtype_schema3), paramv_dtype_schema3, &params);
    ASSERT_NE(err, 0);
    err = argv_deserialize_to_kvdb_rparams(
        NELEM(paramv_dtype_schema4), paramv_dtype_schema4, &params);
    ASSERT_NE(err, 0);
}

MTF_END_UTEST_COLLECTION(mclass_policy_test);
