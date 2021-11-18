/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/assert.h>
#include <hse_util/base.h>
#include <hse_util/inttypes.h>

#include <mpool/mpool.h>

#include <hse_ikvdb/mclass_policy.h>

const char *mclass_policy_names[] = { "capacity_only",
                                      "staging_only",
                                      "staging_max_capacity",
                                      "staging_min_capacity",
                                      "pmem_only",
                                      "pmem_staging",
                                      "pmem_capacity",
                                      "pmem_staging_capacity"};

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
    { HSE_MPOLICY_AGE_ROOT, "root" },
    { HSE_MPOLICY_AGE_INTERNAL, "internal" },
    { HSE_MPOLICY_AGE_LEAF, "leaf" },
};

static const struct mclass_policy_map dtypes[] = {
    { HSE_MPOLICY_DTYPE_KEY, "keys" },
    { HSE_MPOLICY_DTYPE_VALUE, "values" },
};

static const struct mclass_policy_map *mclass_policy_fields[] = { agegroups, dtypes };

static const unsigned int mclass_policy_nentries[] = {
    NELEM(agegroups),
    NELEM(dtypes),
};

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

enum mpool_mclass
mclass_policy_get_type(struct mclass_policy *policy, u8 age, u8 dtype)
{
    enum mpool_mclass mtype = MP_MED_INVALID;

    assert(age < HSE_MPOLICY_AGE_CNT);
    assert(dtype < HSE_MPOLICY_DTYPE_CNT);

    if (age < HSE_MPOLICY_AGE_CNT && dtype < HSE_MPOLICY_DTYPE_CNT)
        mtype = policy->mc_table[age][dtype];

    return mtype;
}
