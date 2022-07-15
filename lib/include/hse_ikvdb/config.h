/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_CONFIG_H
#define HSE_CONFIG_CONFIG_H

#include <error/merr.h>

struct config;
struct hse_gparams;
struct kvdb_rparams;
struct kvs_rparams;

/**
 * Deserialize a config object to HSE gparams
 *
 * @param config: Config object
 * @param params: HSE global params
 */
merr_t
config_deserialize_to_hse_gparams(const struct config *conf, struct hse_gparams *params);

/**
 * Deserialize a config object into KVDB rparams
 *
 * @param config: Config object
 * @param params: KVDB rparams
 */
merr_t
config_deserialize_to_kvdb_rparams(const struct config *conf, struct kvdb_rparams *params);

/**
 * Deserialize a config object into KVS rparams
 *
 * @param config: Config object
 * @param kvs_name: Name of KVS
 * @param params: KVS rparams
 */
merr_t
config_deserialize_to_kvs_rparams(
    const struct config *conf,
    const char *         kvs_name,
    struct kvs_rparams * params);

/**
 * Create a config object from a configuration file
 *
 * @param config: Path to a global configuration file
 * @param[out] config: Config object
 */
merr_t
config_from_hse_conf(const char *config, struct config **conf);

/**
 * Create a config object from a kvdb.conf file located in a KVDB home directory
 *
 * @param kvdb_home: KVDB home directory
 * @param[out] config: Config object
 */
merr_t
config_from_kvdb_conf(const char *kvdb_home, struct config **conf);

/**
 * Destroy a config object
 *
 * @param conf: Config object
 */
void
config_destroy(struct config *conf);

#endif /* HSE_CONFIG_CONFIG_H */
