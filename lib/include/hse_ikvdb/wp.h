/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_WP_H
#define HSE_IKVDB_WP_H

#include <hse_util/hse_err.h>

#include <hse/hse_limits.h>

#define WP_FILE 0
#define WP_STRING 1

struct hse_params;

/**
 * wp_parse() -
 * @profile: profile contents
 * @params: hse params handle
 * @flag: specify file or string
 *
 * Parses profile and populates hse params
 *
 * Return: EINVAL on failure
 */
merr_t
wp_parse(const char *profile, struct hse_params *params, int flag);

#endif /* HSE_IKVDB_WP_H */
