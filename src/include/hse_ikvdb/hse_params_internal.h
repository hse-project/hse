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

/**
 * hse_params_to_kvdb_cparams() - convert params to kvdb cparams
 * @params: fixed configuration parameters
 * @ref:    reference struct (optional)
 */
struct kvdb_cparams
hse_params_to_kvdb_cparams(struct hse_params *params, struct kvdb_cparams *ref);

/**
 * hse_params_to_kvdb_rparams() - convert params to kvdb rparams
 * @params: fixed configuration parameters
 * @ref:    reference struct (optional)
 */
struct kvdb_rparams
hse_params_to_kvdb_rparams(struct hse_params *params, struct kvdb_rparams *ref);

/**
 * hse_params_to_kvs_cparams() - convert params to kvs cparams
 * @params:   fixed configuration parameters
 * @kvs_name: name of kvs
 * @ref:      reference struct (optional)
 */
struct kvs_cparams
hse_params_to_kvs_cparams(struct hse_params *params, const char *kvs_name, struct kvs_cparams *ref);

/**
 * hse_params_to_kvs_rparams() - convert params to kvs rparams
 * @params:   fixed configuration parameters
 * @kvs_name: name of kvs
 * @ref:      reference struct (optional)
 */
struct kvs_rparams
hse_params_to_kvs_rparams(struct hse_params *params, const char *kvs_name, struct kvs_rparams *ref);

#endif /* HSE_PARAMS_INTERNAL_H */
