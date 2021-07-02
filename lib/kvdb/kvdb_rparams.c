/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <mpool/mpool_structs.h>
#include <mpool/mpool.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/home.h>
#include <hse_ikvdb/wal.h>
#include <hse_util/storage.h>
#include <hse_util/compiler.h>
#include <hse_util/string.h>

/**
 * Set the default media class policies
 *{
 *    {
 *        "name": "capacity_only",
 *        "config": {
 *            "sync": {
 *                "keys": [ "capacity" ],
 *                "values": [ "capacity" ]
 *            },
 *            "root": {
 *                "keys": [ "capacity" ],
 *                "values": [ "capacity" ]
 *            },
 *            "internal": {
 *                "keys": [ "capacity" ],
 *                "values": [ "capacity" ]
 *            },
 *            "leaf": {
 *                "keys": [ "capacity" ],
 *                "values": [ "capacity" ]
 *            }
 *        }
 *    },
 *    {
 *        "name": "staging_only",
 *        "config": {
 *            "sync": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "root": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "internal": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "leaf": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            }
 *        }
 *    },
 *    {
 *        "name": "staging_max_capacity",
 *        "config": {
 *            "sync": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "root": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "internal": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "leaf": {
 *                "keys": [ "staging" ],
 *                "values": [ "capacity" ]
 *            }
 *        }
 *    },
 *    {
 *        "name": "staging_min_capacity",
 *        "config": {
 *            "sync": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "root": {
 *                "keys": [ "staging" ],
 *                "values": [ "staging" ]
 *            },
 *            "internal": {
 *                "keys": [ "capacity" ],
 *                "values": [ "capacity" ]
 *            },
 *            "leaf": {
 *                "keys": [ "capacity" ],
 *                "values": [ "capacity" ]
 *            }
 *        }
 *    }
 *}
 */
static void
mclass_policies_default_builder(const struct param_spec *ps, void *data)
{
    struct mclass_policy *mclass_policies = data;
    struct mclass_policy *policy;

    assert(mclass_policy_get_num_default_policies() == 4);

    /* Setup capacity_only */
    policy = &mclass_policies[0];
    strlcpy(policy->mc_name, "capacity_only", sizeof("capacity_only"));
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][0] =
        HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][0] =
        HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;

    /* Setup staging_only */
    policy = &mclass_policies[1];
    strlcpy(policy->mc_name, "staging_only", sizeof("staging_only"));
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][0] =
        HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][0] =
        HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;

    /* Setup staging_max_capacity */
    policy = &mclass_policies[2];
    strlcpy(policy->mc_name, "staging_max_capacity", sizeof("staging_max_capacity"));
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][0] =
        HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][0] =
        HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;

    /* Setup staging_min_capacity */
    policy = &mclass_policies[3];
    strlcpy(policy->mc_name, "staging_min_capacity", sizeof("staging_min_capacity"));
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_SYNC][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_STAGING;
    policy->mc_table[HSE_MPOLICY_AGE_ROOT][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][0] =
        HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_KEY][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][0] =
        HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_INTERNAL][HSE_MPOLICY_DTYPE_VALUE][1] =
        HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_KEY][1] = HSE_MPOLICY_MEDIA_INVALID;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][0] = HSE_MPOLICY_MEDIA_CAPACITY;
    policy->mc_table[HSE_MPOLICY_AGE_LEAF][HSE_MPOLICY_DTYPE_VALUE][1] = HSE_MPOLICY_MEDIA_INVALID;

    /* Set default policy for rest of the policies
     * {
     *     "name": "default_policy",
     *     "config": {
     *         "sync": {
     *             "keys": [ "staging" ],
     *             "values": [ "staging" ]
     *         },
     *         "root": {
     *             "keys": [ "staging" ],
     *             "values": [ "staging" ]
     *         },
     *         "internal": {
     *             "keys": [ "staging" ],
     *             "values": [ "staging" ]
     *         },
     *         "leaf": {
     *             "keys": [ "staging" ],
     *             "values": [ "capacity" ]
     *         }
     *     }
     * }
     */
    for (int i = mclass_policy_get_num_default_policies(); i < ps->ps_bounds.as_array.ps_max_len;
         i++) {
        const size_t HSE_MAYBE_UNUSED sz =
            strlcpy(mclass_policies[i].mc_name, HSE_MPOLICY_DEFAULT_NAME, HSE_MPOLICY_NAME_LEN_MAX);
        assert(sz == strlen(HSE_MPOLICY_DEFAULT_NAME));
        for (int age = 0; age < (int)HSE_MPOLICY_AGE_CNT; age++) {
            for (int dtype = 0; dtype < (int)HSE_MPOLICY_DTYPE_CNT; dtype++) {
                if (age == (int)HSE_MPOLICY_AGE_LEAF && dtype == (int)HSE_MPOLICY_DTYPE_VALUE) {
                    mclass_policies[i].mc_table[age][dtype][0] = HSE_MPOLICY_MEDIA_CAPACITY;
                    mclass_policies[i].mc_table[age][dtype][1] = HSE_MPOLICY_MEDIA_INVALID;
                } else {
                    mclass_policies[i].mc_table[age][dtype][0] = HSE_MPOLICY_MEDIA_STAGING;
                    mclass_policies[i].mc_table[age][dtype][1] = HSE_MPOLICY_MEDIA_INVALID;
                }
            }
        }
    }
}

static bool
mclass_policies_converter(const struct param_spec *ps, const cJSON *node, void *data)
{
    assert(ps);
    assert(node);
    assert(data);
    assert(mclass_policy_get_num_fields() == 3);

    if (!cJSON_IsArray(node))
        return false;

    static const char *policy_allowed_keys[] = { "name", "config" };

    struct mclass_policy *          policies = data;
    const struct mclass_policy_map *agegroup_map = mclass_policy_get_map(0);
    const unsigned int              agegroup_map_sz = mclass_policy_get_num_map_entries(0);
    const struct mclass_policy_map *dtype_map = mclass_policy_get_map(1);
    const unsigned int              dtype_map_sz = mclass_policy_get_num_map_entries(1);
    const struct mclass_policy_map *mclasses_map = mclass_policy_get_map(2);
    const unsigned int              mclasses_map_sz = mclass_policy_get_num_map_entries(2);

    int i = mclass_policy_get_num_default_policies();
    for (cJSON *policy_json = node->child; policy_json; policy_json = policy_json->next, i++) {
        if (i >= HSE_MPOLICY_COUNT)
            return false;
        if (!cJSON_IsObject(policy_json))
            return false;

        /* Make sure there are no unknown keys */
        for (cJSON *n = policy_json->child; n; n = n->next) {
            bool found = false;
            for (size_t i = 0; i < NELEM(policy_allowed_keys); i++) {
                if (!strcmp(policy_allowed_keys[i], n->string)) {
                    found = true;
                    break;
                }
            }
            if (!found)
                return false;
        }

        const cJSON *policy_name = cJSON_GetObjectItemCaseSensitive(policy_json, "name");
        if (!policy_name || !cJSON_IsString(policy_name))
            return false;
        const cJSON *policy_config = cJSON_GetObjectItemCaseSensitive(policy_json, "config");
        if (!policy_config || !cJSON_IsObject(policy_config))
            return false;

        if (strlen(cJSON_GetStringValue(policy_name)) >= HSE_MPOLICY_NAME_LEN_MAX)
            return false;

        strlcpy(policies[i].mc_name, cJSON_GetStringValue(policy_name), HSE_MPOLICY_NAME_LEN_MAX);

        for (cJSON *agegroup_json = policy_config->child; agegroup_json;
             agegroup_json = agegroup_json->next) {
            if (!cJSON_IsObject(agegroup_json))
                return false;

            int agegroup = -1;
            for (int j = 0; j < agegroup_map_sz; j++) {
                if (!strcmp(agegroup_json->string, agegroup_map[j].mc_kname)) {
                    agegroup = agegroup_map[j].mc_enum;
                    break;
                }
            }
            if (agegroup == -1)
                return false;

            for (cJSON *dtype_json = agegroup_json->child; dtype_json;
                 dtype_json = dtype_json->next) {
                if (!cJSON_IsArray(dtype_json))
                    return false;

                int dtype = -1;
                for (int j = 0; j < dtype_map_sz; j++) {
                    if (!strcmp(dtype_json->string, dtype_map[j].mc_kname)) {
                        dtype = dtype_map[j].mc_enum;
                        break;
                    }
                }
                if (dtype == -1)
                    return false;

                const int sz = cJSON_GetArraySize(dtype_json);
                if (sz > HSE_MPOLICY_MEDIA_CNT)
                    return false;

                for (int j = 0; j < sz; j++) {
                    const cJSON *media_json = cJSON_GetArrayItem(dtype_json, j);
                    if (!cJSON_IsString(media_json))
                        return false;

                    int media = -1;
                    for (int k = 0; k < mclasses_map_sz; k++) {
                        if (!strcmp(cJSON_GetStringValue(media_json), mclasses_map[k].mc_kname)) {
                            media = mclasses_map[k].mc_enum;
                            break;
                        }
                    }
                    if (media == -1)
                        return false;

                    policies[i].mc_table[agegroup][dtype][j] = media;
                }
            }
        }
    }

    return true;
}

static bool
mclass_policies_validator(const struct param_spec *ps, const void *data)
{
    assert(ps);
    assert(data);

    const struct mclass_policy *policies = data;
    unsigned int                times_matched[HSE_MPOLICY_COUNT] = { 0 };

    /* Make sure all policies have unique names */
    for (size_t i = 0; i < ps->ps_bounds.as_array.ps_max_len; i++) {
        if (!strcmp(policies[i].mc_name, HSE_MPOLICY_DEFAULT_NAME))
            break;

        for (size_t j = 0; j < ps->ps_bounds.as_array.ps_max_len; j++) {
            if (!strcmp(policies[i].mc_name, HSE_MPOLICY_DEFAULT_NAME))
                break;
            if (!strcmp(policies[j].mc_name, policies[i].mc_name))
                times_matched[i]++;

            if (times_matched[i] > 1)
                return false;
        }
    }

    return true;
}

static const struct param_spec pspecs[] = {
    {
        .ps_name = "read_only",
        .ps_description = "readonly flag",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_rparams, read_only),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->read_only),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "perfc_enable",
        .ps_description = "0: disable, [123]: enable",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_rparams, perfc_enable),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->perfc_enable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 2,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 3,
            },
        },
    },
    {
        .ps_name = "c0_cheap_cache_sz_max",
        .ps_description = "max size of c0 cheap cache (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, c0_cheap_cache_sz_max),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_cheap_cache_sz_max),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_C0_CCACHE_SZ_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = HSE_C0_CCACHE_SZ_MAX,
            },
        },
    },
    {
        .ps_name = "c0_cheap_sz",
        .ps_description = "set c0 cheap size (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, c0_cheap_sz),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_cheap_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_C0_CHEAP_SZ_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = HSE_C0_CHEAP_SZ_MIN,
                .ps_max = HSE_C0_CHEAP_SZ_MAX,
            },
        },
    },
    {
        .ps_name = "c0_debug",
        .ps_description = "c0 debug flags",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_rparams, c0_debug),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_debug),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        },
    },
    {
        .ps_name = "c0_diag_mode",
        .ps_description = "disable c0 spill",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_rparams, c0_diag_mode),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_diag_mode),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "c0_ingest_width",
        .ps_description = "set c0 kvms width",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, c0_ingest_width),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_ingest_width),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_C0_INGEST_WIDTH_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = HSE_C0_INGEST_WIDTH_MIN,
                .ps_max = HSE_C0_INGEST_WIDTH_DFLT,
            },
        },
    },
    {
        .ps_name = "txn_timeout",
        .ps_description = "transaction timeout (ms)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, txn_timeout),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->txn_timeout),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1000 * 60 * 5,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "txn_commit_abort_pct",
        .ps_description = "pct of commits to abort ((pct * 16384) / 100)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U16,
        .ps_offset = offsetof(struct kvdb_rparams, txn_commit_abort_pct),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->txn_commit_abort_pct),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT16_MAX,
            },
        },
    },
    {
        .ps_name = "csched_policy",
        .ps_description = "csched (compaction scheduler) policy",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, csched_policy),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_policy),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 3,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "csched_debug_mask",
        .ps_description = "csched debug (bit mask)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_debug_mask),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_debug_mask),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_samp_max",
        .ps_description = "csched max space amp (0x100)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_samp_max),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_samp_max),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 150,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_lo_th_pct",
        .ps_description = "csched low water mark percentage",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_lo_th_pct),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_lo_th_pct),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 25,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 100,
            },
        },
    },
    {
        .ps_name = "csched_hi_th_pct",
        .ps_description = "csched hwm water mark percentage",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_hi_th_pct),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_hi_th_pct),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 75,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 100,
            },
        },
    },
    {
        .ps_name = "csched_leaf_pct",
        .ps_description = "csched percent data in leaves",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_leaf_pct),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_leaf_pct),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 90,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 100,
            },
        },
    },
    {
        .ps_name = "csched_vb_scatter_pct",
        .ps_description = "csched vblock scatter pct. in leaves",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_vb_scatter_pct),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_vb_scatter_pct),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 100,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 100,
            },
        },
    },
    {
        .ps_name = "csched_qthreads",
        .ps_description = "csched queue threads",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_qthreads),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_qthreads),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_node_len_max",
        .ps_description = "csched max kvsets per node",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_node_len_max),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_node_len_max),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_rspill_params",
        .ps_description = "root node spill params [min,max]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_rspill_params),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_rspill_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_ispill_params",
        .ps_description = "internal node spill params [min,max]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_ispill_params),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_ispill_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_leaf_comp_params",
        .ps_description = "leaf compact params [poppct,min,max]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_leaf_comp_params),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_leaf_comp_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_leaf_len_params",
        .ps_description = "leaf length params [idlem,idlec,kvcompc,min,max]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_leaf_len_params),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_leaf_len_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "csched_node_min_ttl",
        .ps_description = "Min. time-to-live for cN nodes (secs)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, csched_node_min_ttl),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->csched_node_min_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 17,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "dur_enable",
        .ps_description = "0: disable durability, 1:enable durability",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, dur_enable),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->dur_enable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "dur_intvl_ms",
        .ps_description = "durability lag in ms",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, dur_intvl_ms),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->dur_intvl_ms),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = HSE_WAL_DUR_MS_MAX,
            },
        },
    },
    {
        .ps_name = "dur_buf_sz",
        .ps_description = "durability buffer size in bytes",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, dur_buf_sz),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->dur_buf_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = HSE_WAL_DUR_BYTES_MAX,
            },
        },
    },
    {
        .ps_name = "dur_delay_pct",
        .ps_description = "durability delay percent",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, dur_delay_pct),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->dur_delay_pct),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 30,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 100,
            },
        },
    },
    {
        .ps_name = "dur_throttle_lo_th",
        .ps_description = "low watermark for throttling in percentage",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, dur_throttle_lo_th),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->dur_throttle_lo_th),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 90,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 100,
            },
        },
    },
    {
        .ps_name = "dur_throttle_hi_th",
        .ps_description = "high watermark for throttling in percentage",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, dur_throttle_hi_th),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->dur_throttle_hi_th),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 150,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 200,
            },
        },
    },
    {
        .ps_name = "dur_throttle_enable",
        .ps_description = "enable durablity throttling",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, dur_throttle_enable),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->dur_throttle_enable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "throttle_disable",
        .ps_description = "disable sleep throttle",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_disable),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_disable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "throttle_update_ns",
        .ps_description = "throttle update sensors time in ns",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_update_ns),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_update_ns),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 25 * 1000 * 1000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "throttle_relax",
        .ps_description = "allow c0 boost to disable throttling",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_relax),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_relax),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "throttle_debug",
        .ps_description = "throttle debug",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_debug),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_debug),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "throttle_debug_intvl_s",
        .ps_description = "throttle debug interval (secs)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_debug_intvl_s),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_debug_intvl_s),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 300,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "throttle_sleep_min_ns",
        .ps_description = "nanosleep time overhead (nsecs)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_sleep_min_ns),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_sleep_min_ns),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "throttle_c0_hi_th",
        .ps_description = "throttle sensor: c0 high water mark (MiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_c0_hi_th),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_c0_hi_th),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1024 * 8,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1024 * 16,
            },
        },
    },
    {
        .ps_name = "throttle_init_policy",
        .ps_description = "throttle initialization policy",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_ENUM,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_init_policy),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_enum = "default",
        },
        .ps_bounds = {
            .as_enum = {
                .ps_values = {
                    "light",
                    "medium",
                    "default",
                },
                .ps_num_values = 3,
            },
        },
    },
    {
        .ps_name = "throttle_burst",
        .ps_description = "initial throttle burst size (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_burst),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_burst),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 10ul << 20,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "throttle_rate",
        .ps_description = "initial throttle rate (bytes/sec)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, throttle_rate),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->throttle_rate),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 10ul << 20,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "log_lvl",
        .ps_description = "log message verbosity. Range: 0 to 7.",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, log_lvl),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->log_lvl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_LOG_PRI_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 7,
            },
        },
    },
    {
        .ps_name = "log_squelch_ns",
        .ps_description = "drop messages repeated within nsec window",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, log_squelch_ns),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->log_squelch_ns),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_LOG_SQUELCH_NS_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "txn_wkth_delay",
        .ps_description = "delay for transaction worker thread",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvdb_rparams, txn_wkth_delay),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->txn_wkth_delay),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 1000 * 60,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cndb_entries",
        .ps_description = "number of entries in cndb's in-core representation (0: let system choose)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, cndb_entries),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->cndb_entries),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "cndb_debug",
        .ps_description = "enable cndb debug logs",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, cndb_debug),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->cndb_debug),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "c0_maint_threads",
        .ps_description = "max number of maintenance threads",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, c0_maint_threads),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_maint_threads),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_C0_MAINT_THREADS_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "c0_ingest_threads",
        .ps_description = "max number of c0 ingest threads",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, c0_ingest_threads),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_ingest_threads),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = HSE_C0_INGEST_THREADS_DFLT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "c0_mutex_pool_sz",
        .ps_description = "max locks in c0 ingest sync pool",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, c0_mutex_pool_sz),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->c0_mutex_pool_sz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "keylock_entries",
        .ps_description = "number of keylock entries in a table",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, keylock_entries),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->keylock_entries),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 22397,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "keylock_tables",
        .ps_description = "number of keylock tables",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, keylock_tables),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->keylock_tables),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 293,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "low_mem",
        .ps_description = "configure for a constrained memory environment",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvdb_rparams, low_mem),
        .ps_size = sizeof(((struct kvdb_rparams *) 0)->low_mem),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 1,
            },
        },
    },
    {
        .ps_name = "mclass_policies",
        .ps_description = "media class policy definitions",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_ARRAY,
        .ps_offset = offsetof(struct kvdb_rparams, mclass_policies),
        .ps_convert = mclass_policies_converter,
        .ps_validate = mclass_policies_validator,
        .ps_default_value = {
            .as_builder = mclass_policies_default_builder,
        },
        .ps_bounds = {
            .as_array = {
                .ps_max_len = HSE_MPOLICY_COUNT,
            }
        },
    },
    {
        .ps_name = "storage.capacity.path",
        .ps_description = "Storage path for capacity mclass",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_NULLABLE,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_rparams, storage.mclass[MP_MED_CAPACITY].path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_string = MPOOL_CAPACITY_MCLASS_DEFAULT_PATH,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len =
                    sizeof(((struct kvdb_rparams *)0)->storage.mclass[MP_MED_CAPACITY].path),
            },
        },
    },
        {
        .ps_name = "storage.staging.path",
        .ps_description = "Storage path for staging mclass",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_NULLABLE,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_rparams, storage.mclass[MP_MED_STAGING].path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_string = NULL,
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len =
                    sizeof(((struct kvdb_rparams *)0)->storage.mclass[MP_MED_STAGING].path),
            },
        },
    },
    {
        .ps_name = "socket.path",
        .ps_description = "UNIX socket path",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvdb_rparams, socket.path),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_default_value = {
            .as_string = "hse.sock",
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = sizeof(((struct kvdb_rparams *)0)->socket.path),
            },
        },
    },
};

static_assert(sizeof(((struct kvdb_rparams *) 0)->storage.mclass[MP_MED_CAPACITY].path) == sizeof(((struct kvdb_cparams *)0)->storage.mclass[MP_MED_CAPACITY].path), "buffer sizes for capacity path should match");
static_assert(sizeof(((struct kvdb_rparams *) 0)->storage.mclass[MP_MED_STAGING].path) == sizeof(((struct kvdb_cparams *)0)->storage.mclass[MP_MED_STAGING].path), "buffer sizes for staging path should match");

const struct param_spec *
kvdb_rparams_pspecs_get(size_t *pspecs_sz)
{
    if (pspecs_sz)
        *pspecs_sz = NELEM(pspecs);
    return pspecs;
}

struct kvdb_rparams
kvdb_rparams_defaults()
{
    struct kvdb_rparams params;
    const union params p = { .as_kvdb_rp = &params };
    param_default_populate(pspecs, NELEM(pspecs), p);
    return params;
}

merr_t
kvdb_rparams_resolve(struct kvdb_rparams *params, const char *home)
{
    assert(params);
    assert(home);

    char buf[PATH_MAX];
    size_t n;

    n = kvdb_home_storage_capacity_path_get(home, params->storage.mclass[MP_MED_CAPACITY].path,
                                            buf, sizeof(buf));
    if (n >= sizeof(buf))
        return merr(ENAMETOOLONG);
    strlcpy(params->storage.mclass[MP_MED_CAPACITY].path, buf,
            sizeof(params->storage.mclass[MP_MED_CAPACITY].path));

    n = kvdb_home_storage_staging_path_get(home, params->storage.mclass[MP_MED_STAGING].path,
                                           buf, sizeof(buf));
    if (n >= sizeof(buf))
        return merr(ENAMETOOLONG);
    strlcpy(params->storage.mclass[MP_MED_STAGING].path, buf,
            sizeof(params->storage.mclass[MP_MED_STAGING].path));

    n = kvdb_home_socket_path_get(home, params->socket.path, buf, sizeof(buf));
    if (n >= sizeof(buf))
        return merr(ENAMETOOLONG);
    strlcpy(params->socket.path, buf, sizeof(params->socket.path));

    return 0;
}
