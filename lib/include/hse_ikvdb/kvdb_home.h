/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_HOME_H
#define HSE_KVDB_HOME_H

#include <stddef.h>

#include <hse_util/hse_err.h>

/**
 * Translates a nullable home to a non-nullable absolute path
 * @param home: user-provided home directory
 * @param buf: buffer for translated directory
 * @param buf_sz: buffer size
 * @returns error status
 */
merr_t
kvdb_home_resolve(const char *home, char *buf, const size_t buf_sz);

/**
 * Converts the storage capacity path to be an absolute path
 *
 * @param home: home directory
 * @param capacity_path: parameter-supplied capacity path
 * @param buf: buffer
 * @param buf_sz: size of the buffer
 * @returns error status
 */
merr_t
kvdb_home_storage_capacity_path_get(
    const char * home,
    const char * capacity_path,
    char *       buf,
    const size_t buf_sz);

/**
 * Converts the storage staging path to be an absolute path
 *
 * @param home: home directory
 * @param staging_path: parameter-supplied staging path
 * @param buf: buffer
 * @param buf_sz: size of the buffer
 * @returns error status
 */
merr_t
kvdb_home_storage_staging_path_get(
    const char * home,
    const char * staging_path,
    char *       buf,
    const size_t buf_sz);

/**
 * Puts the path to the hse.pid file in the buffer
 *
 * @param home: home directory
 * @param buf: buffer
 * @param buf_sz: size of the buffer
 * @returns error status
 */
merr_t
kvdb_home_pidfile_path_get(
	const char *home,
	char *buf,
	const size_t buf_sz
);

#endif
