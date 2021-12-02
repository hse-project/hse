/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/assert.h>
#include <hse_util/base.h>
#include <hse_util/inttypes.h>
#include <hse_util/event_counter.h>

#include <mpool/mpool.h>

#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/ikvdb.h>

const char *mclass_policy_names[] = { "capacity_only",
                                      "staging_only",
                                      "staging_max_capacity",
                                      "staging_min_capacity",
                                      "pmem_only",
                                      "pmem_staging",
                                      "pmem_capacity",
                                      "pmem_staging_capacity"};

/*
 * Expressed using 3 bits:
 * bit 0: capacity
 * bit 1: staging
 * bit 2: pmem
 *
 * Valid KVDB mclass configs:
 * [0] 000 - invalid (no media classes)
 * [1] 001 - capacity only
 * [2] 010 - invalid (staging only)
 * [3] 011 - capacity + staging
 * [4] 100 - pmem only
 * [5] 101 - capacity + pmem
 * [6] 110 - invalid (pmem + staging)
 * [7] 111 - capacity + staging + pmem
 */
const char *mclass_policy_defaults[] = { "invalid",
                                         "capacity_only",
                                         "invalid",
                                         "staging_max_capacity",
                                         "pmem_only",
                                         "pmem_capacity",
                                         "invalid",
                                         "pmem_staging_capacity"};

const char **
mclass_policy_names_get()
{
    return mclass_policy_names;
}

int
mclass_policy_names_cnt()
{
    return NELEM(mclass_policy_names);
}

const char *
mclass_policy_default_get(struct ikvdb *handle)
{
    struct mpool *mp;
    int i;
    u8  config = 0;

    INVARIANT(handle);

    mp = ikvdb_mpool_get(handle);
    if (!mp)
        return NULL;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        merr_t err;

        err = mpool_mclass_props_get(mp, i, NULL);
        if (!err)
            config |= (1 << i);
        else if (merr_errno(err) != ENOENT)
            return NULL;
    }

    if (ev(config >= NELEM(mclass_policy_defaults))) {
        assert(config < NELEM(mclass_policy_defaults));
        return NULL;
    }

    return mclass_policy_defaults[config];
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

enum hse_mclass
mclass_policy_get_type(struct mclass_policy *policy, u8 age, u8 dtype)
{
    enum hse_mclass mtype = HSE_MCLASS_INVALID;

    assert(age < HSE_MPOLICY_AGE_CNT);
    assert(dtype < HSE_MPOLICY_DTYPE_CNT);

    if (age < HSE_MPOLICY_AGE_CNT && dtype < HSE_MPOLICY_DTYPE_CNT)
        mtype = policy->mc_table[age][dtype];

    return mtype;
}
