/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PARAMS_INTERNAL_H
#define HSE_PARAMS_INTERNAL_H

struct hse_params;

#include <hse_util/hse_err.h>

#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/mclass_policy.h>

/**
 * hse_params_to_kvdb_cparams() - convert params to kvdb cparams
 * @params: fixed configuration parameters
 * @ref:    reference struct (optional)
 * @out:    [out] configured kvdb creation paramerters
 */
merr_t
hse_params_to_kvdb_cparams(
    const struct hse_params *params,
    struct kvdb_cparams *    ref,
    struct kvdb_cparams *    out);

/**
 * hse_params_to_kvdb_rparams() - convert params to kvdb rparams
 * @params: fixed configuration parameters
 * @ref:    reference struct (optional)
 * @out:    [out] configured kvdb runtime paramerters
 */
merr_t
hse_params_to_kvdb_rparams(
    const struct hse_params *params,
    struct kvdb_rparams *    ref,
    struct kvdb_rparams *    out);

/**
 * hse_params_to_kvs_cparams() - convert params to kvs cparams
 * @params:   fixed configuration parameters
 * @kvs_name: name of kvs
 * @ref:      reference struct (optional)
 * @out:      [out] configured kvs creation paramerters
 */
merr_t
hse_params_to_kvs_cparams(
    const struct hse_params *params,
    const char *             kvs_name,
    struct kvs_cparams *     ref,
    struct kvs_cparams *     out);

/**
 * hse_params_to_kvs_rparams() - convert params to kvs rparams
 * @params:   fixed configuration parameters
 * @kvs_name: name of kvs
 * @ref:      reference struct (optional)
 * @out:      [out] configured kvs runtime paramerters
 */
merr_t
hse_params_to_kvs_rparams(
    const struct hse_params *params,
    const char *             kvs_name,
    struct kvs_rparams *     ref,
    struct kvs_rparams *     out);

/**
 * hse_params_to_mclass_policies() - convert params to media class policies
 * @params:   fixed configuration parameters
 * @policies: pointer to table of media class policies
 * @entries:  number of entries in table
 */
void
hse_params_to_mclass_policies(
    const struct hse_params *params,
    struct mclass_policy *   policies,
    int                      entries);

/**
 * hse_params_clone() - clone a params sturct
 * @params: hse params to clone
 *
 * Return NULL if input @params is NULL or if memory allocation
 * fails.  Otherwise return cloned copy of @params.  Returned
 * pointer should be freed with hse_params_free().
 */
struct hse_params *
hse_params_clone(const struct hse_params *params);

void
hse_params_free(struct hse_params *params);

#endif /* HSE_PARAMS_INTERNAL_H */
