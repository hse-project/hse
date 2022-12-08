/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_CONFIG_H
#define HSE_CONFIG_CONFIG_H

#include <cjson/cJSON.h>

#include <hse/error/merr.h>

typedef merr_t config_validator_t(cJSON *config);

/**
 * Get a config object from a file path
 *
 * @param path Path to the config file
 * @param[out] config Config object
 */
merr_t
config_open(const char *path, config_validator_t *validate, cJSON **config);

#endif /* HSE_CONFIG_CONFIG_H */
