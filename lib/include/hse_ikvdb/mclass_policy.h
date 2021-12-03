/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_MCLASS_POLICY_H
#define HSE_MCLASS_POLICY_H

#include <stdint.h>

#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

#include <mpool/mpool.h>

struct ikvdb;

#define HSE_MPOLICY_DEFAULT_NAME "default_policy"
#define HSE_MPOLICY_AUTO_NAME    "auto"
#define HSE_MPOLICY_PMEM_ONLY    "pmem_only"

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

/* Max mclass policy name length */
#define HSE_MPOLICY_NAME_LEN_MAX 32

/* Number of mclass policies */
#define HSE_MPOLICY_COUNT 24

struct mclass_policy {
    char    mc_name[HSE_MPOLICY_NAME_LEN_MAX];
    uint8_t mc_table[HSE_MPOLICY_AGE_CNT][HSE_MPOLICY_DTYPE_CNT];
};

/**
 * mclass_policy_names_get() - returns pre-defined mclass policy names
 */
const char **
mclass_policy_names_get() HSE_RETURNS_NONNULL;

/**
 * mclass_policy_names_cnt() - number of pre-defined mclass policy names
 */
int
mclass_policy_names_cnt();

/**
 * mclass_policy_default_get() - returns default policy for a KVDB
 */
const char *
mclass_policy_default_get(struct ikvdb *handle);

/**
 * mclass_policy_get_type() - get the media type to use for the
 *                            <agegroup,datatype,trial#>
 * @agegroup: age group (see hse_mclass_policy_age)
 * @datatype: data type (see hse_mclass_policy_dtype)
 */
enum hse_mclass
mclass_policy_get_type(struct mclass_policy *policy, uint8_t agegroup, uint8_t datatype);

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
