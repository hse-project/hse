/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_HSE_HOME_H
#define HSE_CONFIG_HSE_HOME_H

#include <limits.h>

#include <hse_ikvdb/hse_gparams.h>
#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

/**
 * Set HSE runtime home directory
 *
 * @param home: HSE runtime home directory
 * @returns error status
 */
merr_t
runtime_home_set(const char *home);

/**
 * Get handle to HSE runtime home directory
 *
 * @returns HSE runtime home directory
 */
const char *
runtime_home_get(void) HSE_RETURNS_NONNULL;

/**
 * Get the socket path relative to the HSE runtime home directory
 *
 * @param runtime_home: HSE runtime home directory
 * @param params: HSE global params
 * @param buf: buffer
 * @param buf_sz: size of the buffer
 * @returns error status
 */
merr_t
runtime_home_socket_path_get(
    const char *              runtime_home,
    const struct hse_gparams *params,
    char *                    buf,
    size_t                    buf_sz);

/**
 * Get the logging path relative to the HSE runtime home directory
 *
 * @param runtime_home: HSE runtime home directory
 * @param params: HSE global params
 * @param buf: buffer
 * @param buf_sz: size of the buffer
 * @returns error status
 */
merr_t
runtime_home_logging_path_get(
    const char *              runtime_home,
    const struct hse_gparams *params,
    char *                    buf,
    size_t                    buf_sz);

#endif
