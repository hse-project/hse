/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdlib.h>
#include <hse_util/string.h>
#include <hse_util/assert.h>
#include <hse_util/base.h>
#include <mpool/mpool.h>

#include <hse_ikvdb/mclass_policy.h>

/* clang-format off */
static const char * default_mclass_policies = \
    "api_version: 1\n"
    "mclass_policies:\n"
    "  capacity_only:\n"
    "    sync:\n"
    "      keys: [ capacity ]\n"
    "      values: [ capacity ]\n"
    "    root:\n"
    "      keys: [ capacity ]\n"
    "      values: [ capacity ]\n"
    "    internal:\n"
    "      keys: [ capacity ]\n"
    "      values: [ capacity ]\n"
    "    leaf:\n"
    "      keys: [ capacity ]\n"
    "      values: [ capacity ]\n"
    "  staging_only:\n"
    "    sync:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    root:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    internal:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    leaf:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "  staging_max_capacity:\n"
    "    sync:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    root:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    internal:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    leaf:\n"
    "      keys: [ staging ]\n"
    "      values: [ capacity ]\n"
    "  staging_min_capacity:\n"
    "    sync:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    root:\n"
    "      keys: [ staging ]\n"
    "      values: [ staging ]\n"
    "    internal:\n"
    "      keys: [ capacity ]\n"
    "      values: [ capacity ]\n"
    "    leaf:\n"
    "      keys: [ capacity ]\n"
    "      values: [ capacity ]";
/* clang-format on */

const char *mclass_policy_names[] = { "capacity_only",
                                      "staging_only",
                                      "staging_max_capacity",
                                      "staging_min_capacity" };

const char *
mclass_policy_get_default_policies()
{
    return default_mclass_policies;
}

const char **
mclass_policy_get_default_policy_names()
{
    return mclass_policy_names;
}

int
mclass_policy_get_num_default_policies()
{
    return NELEM(mclass_policy_names);
}

static const struct mclass_policy_map agegroups[] = {
    { HSE_MPOLICY_AGE_SYNC, "sync" },
    { HSE_MPOLICY_AGE_ROOT, "root" },
    { HSE_MPOLICY_AGE_INTERNAL, "internal" },
    { HSE_MPOLICY_AGE_LEAF, "leaf" },
};

static const struct mclass_policy_map dtypes[] = {
    { HSE_MPOLICY_DTYPE_KEY, "keys" },
    { HSE_MPOLICY_DTYPE_VALUE, "values" },
};

static const struct mclass_policy_map mclasses[] = {
    {
        HSE_MPOLICY_MEDIA_STAGING,
        "staging",
    },
    { HSE_MPOLICY_MEDIA_CAPACITY, "capacity" },
};

static const struct mclass_policy_map *mclass_policy_fields[] = { agegroups, dtypes, mclasses };

static const unsigned int mclass_policy_nentries[] = { NELEM(agegroups),
                                                       NELEM(dtypes),
                                                       NELEM(mclasses) };

static const struct mclass_policy mclass_policy_default =
    { .mc_name = "default_policy",
      .mc_table = {
          {
              { HSE_MPOLICY_MEDIA_STAGING, HSE_MPOLICY_MEDIA_INVALID },
              { HSE_MPOLICY_MEDIA_STAGING, HSE_MPOLICY_MEDIA_INVALID },
          },
          {
              { HSE_MPOLICY_MEDIA_STAGING, HSE_MPOLICY_MEDIA_INVALID },
              { HSE_MPOLICY_MEDIA_STAGING, HSE_MPOLICY_MEDIA_INVALID },
          },
          {
              { HSE_MPOLICY_MEDIA_STAGING, HSE_MPOLICY_MEDIA_INVALID },
              { HSE_MPOLICY_MEDIA_STAGING, HSE_MPOLICY_MEDIA_INVALID },
          },
          {
              { HSE_MPOLICY_MEDIA_STAGING, HSE_MPOLICY_MEDIA_INVALID },
              { HSE_MPOLICY_MEDIA_CAPACITY, HSE_MPOLICY_MEDIA_INVALID },
          },
      } };

unsigned int
mclass_policy_get_num_fields()
{
    return NELEM(mclass_policy_fields);
}

const struct mclass_policy_map *
mclass_policy_get_map(int index)
{
    if (index < mclass_policy_get_num_fields()) {
        return mclass_policy_fields[index];
    }

    return 0;
}

unsigned int
mclass_policy_get_num_map_entries(int index)
{
    if (index < mclass_policy_get_num_fields())
        return mclass_policy_nentries[index];

    return 0;
}

void
mclass_policy_init_from_string(struct mclass_policy *policy, const char *key, const char *value)
{
    int                         i, mclass = HSE_MPOLICY_MEDIA_INVALID, idx[3];
    const int                   n = NELEM(idx);
    const char *                iter = value, *start = value, *split;
    const struct mclass_policy *dflt = &mclass_policy_default;

    /* Initialize all entries to invalid. */
    for (idx[0] = 0; idx[0] < HSE_MPOLICY_AGE_CNT; idx[0]++)
        for (idx[1] = 0; idx[1] < HSE_MPOLICY_DTYPE_CNT; idx[1]++)
            for (idx[2] = 0; idx[2] < HSE_MPOLICY_MEDIA_CNT; idx[2]++)
                policy->mc_table[idx[0]][idx[1]][idx[2]] = HSE_MPOLICY_MEDIA_INVALID;

    /* A policy name may contain . as well */
    split = strchr(key, '.');
    strlcpy(policy->mc_name, split ? split + 1 : key, sizeof(policy->mc_name));

    /*
     * Parse media class policy values of the form:
     * agegroup.dtype.preference=mclass; ..<entries>.. ;agegroup.dtype.pref=mclass
     */
    i = 0;
    idx[0] = idx[1] = idx[2] = 0;

    while (*iter != '\0') {
        if (*iter == '.' || *iter == '=') {
            if (i < n) {
                char *end = NULL;
                long  temp = strtol(start, &end, 10);

                errno = 0;

                if (end != start && errno != ERANGE && temp >= 0) {
                    if (i == 0 && temp < HSE_MPOLICY_AGE_CNT) {
                        idx[0] = (int)temp;
                    } else if (i == 1 && temp < HSE_MPOLICY_DTYPE_CNT) {
                        idx[1] = (int)temp;
                    } else if (i == 2 && temp < HSE_MPOLICY_MEDIA_CNT) {
                        idx[2] = (int)temp;
                    }
                }
                start = iter + 1;
                i++;
            }

        } else if (*iter == ';' || *(iter + 1) == '\0') {
            if (i == n) {
                char *end = NULL;
                long  temp = strtol(start, &end, 10);

                errno = 0;

                if (end != start && errno != ERANGE && temp >= 0) {
                    if (temp < HSE_MPOLICY_MEDIA_CNT) {
                        mclass = (int)temp;
                        policy->mc_table[idx[0]][idx[1]][idx[2]] = mclass;
                    }
                }
            }

            i = 0;
            start = iter + 1;
        }

        iter++;
    }

    /*
     * If any <agegroup,datatype> value is uninitialized, use the default
     * policy to fill in the missing values (default is staging_capacity_nofallback)
     */
    for (idx[0] = 0; idx[0] < HSE_MPOLICY_AGE_CNT; idx[0]++)
        for (idx[1] = 0; idx[1] < HSE_MPOLICY_DTYPE_CNT; idx[1]++)
            if (policy->mc_table[idx[0]][idx[1]][0] == HSE_MPOLICY_MEDIA_INVALID) {
                policy->mc_table[idx[0]][idx[1]][0] = dflt->mc_table[idx[0]][idx[1]][0];
                policy->mc_table[idx[0]][idx[1]][1] = dflt->mc_table[idx[0]][idx[1]][1];
            }
}

enum mp_media_classp
mclass_policy_get_type(struct mclass_policy *policy, u8 age, u8 dtype, u8 retries)
{
    enum hse_mclass_policy_media mtype = HSE_MPOLICY_MEDIA_INVALID;

    assert(age < HSE_MPOLICY_AGE_CNT);
    assert(dtype < HSE_MPOLICY_DTYPE_CNT);
    assert(retries < HSE_MPOLICY_MEDIA_CNT);

    if (age < HSE_MPOLICY_AGE_CNT && dtype < HSE_MPOLICY_DTYPE_CNT &&
        retries < HSE_MPOLICY_MEDIA_CNT)
        mtype = policy->mc_table[age][dtype][retries];

    if (mtype == HSE_MPOLICY_MEDIA_STAGING)
        return MP_MED_STAGING;
    else if (mtype == HSE_MPOLICY_MEDIA_CAPACITY)
        return MP_MED_CAPACITY;

    return MP_MED_INVALID;
}
