/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_KVS_PARAMS_H
#define HSE_KVS_KVS_PARAMS_H

#include <hse_util/hse_err.h>

struct kvs_rparams;
struct kvs_cparams;

/**
 * kvs_rparams_add_to_dt() -
 * @kvdb_name: kvdb name
 * @kvs_name:  kvs name
 * @p:         runtime parameters
 *
 * Add all kvs run-time parameters to the config subtree of the data tree
 */
merr_t
kvs_rparams_add_to_dt(const char *kvdb_name, const char *kvs_name, struct kvs_rparams *p);

/**
 * kvs_rparams_remove_from_dt() -
 * @kvdb_name: kvdb name
 * @kvs_name:  kvs name
 *
 * Remove the KVS's subtree under /data/config
 */
merr_t
kvs_rparams_remove_from_dt(const char *kvdb, const char *kvs);

#endif
