/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_MCLASS_POLICY_H
#define HSE_MCLASS_POLICY_H

#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

#define HSE_MPOLICY_DEFAULT_NAME "default_policy"

enum hse_mclass_policy_age {
    HSE_MPOLICY_AGE_ROOT,
    HSE_MPOLICY_AGE_INTERNAL,
    HSE_MPOLICY_AGE_LEAF,
    HSE_MPOLICY_AGE_CNT,
};

enum hse_mclass_policy_dtype {
    HSE_MPOLICY_DTYPE_KEY,
    HSE_MPOLICY_DTYPE_VALUE,
    HSE_MPOLICY_DTYPE_CNT,
};

enum hse_mclass_policy_media {
    HSE_MPOLICY_MEDIA_STAGING,
    HSE_MPOLICY_MEDIA_CAPACITY,
    HSE_MPOLICY_MEDIA_CNT,
    HSE_MPOLICY_MEDIA_INVALID = HSE_MPOLICY_MEDIA_CNT,
};

/* Max mclass policy name length */
#define HSE_MPOLICY_NAME_LEN_MAX 32

/* Number of mclass policies */
#define HSE_MPOLICY_COUNT 24

struct mclass_policy {
    char mc_name[HSE_MPOLICY_NAME_LEN_MAX];
    u8   mc_table[HSE_MPOLICY_AGE_CNT][HSE_MPOLICY_DTYPE_CNT][HSE_MPOLICY_MEDIA_CNT];
};

/**
 * mclass_policy_get_default_policy_names() - returns default policy names
 */
const char **
mclass_policy_get_default_policy_names() HSE_RETURNS_NONNULL;

/**
 * mclass_policy_get_num_default_policies() - number of default policies
 */
int
mclass_policy_get_num_default_policies();

/**
 * mclass_policy_get_type() - get the media type to use for the
 *                            <agegroup,datatype,trial#>
 * @agegroup: age group (see hse_mclass_policy_age)
 * @datatype: data type (see hse_mclass_policy_dtype)
 * @iteration: number of tries. Retries happen on alloc failures.
 */
enum mpool_mclass
mclass_policy_get_type(struct mclass_policy *policy, u8 agegroup, u8 datatype, u8 iteration);

/*
 * The following are used by the YAML parser to validate the media
 * class policy fields and encode a policy as a value.
*/

/**
 * struct mclass_policy_map
 *
 * @mc_name:    field name
 * @mc_enum:    mapping from field name to mclass enum
 */
struct mclass_policy_map {
    int   mc_enum;
    char *mc_kname;
};

/**
 * mclass_policy_get_num_fields() - get the number of valid fields in
 *                                  an mclass policy entry
 */
unsigned int
mclass_policy_get_num_fields();

/**
 * mclass_policy_get_map() - retrieve the valid entries for the field
 *                           and their mappings for encoding as a value
 * @index: index of the field
 */
const struct mclass_policy_map *
mclass_policy_get_map(int index);

/**
 * mclass_policy_get_num_map_entries() - get the number of valid entries
 *                                       in a map returned by get_map()
 * @index: index of the field
 */
unsigned int
mclass_policy_get_num_map_entries(int index);

#endif
