/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_HOME_H
#define HSE_KVDB_HOME_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include <hse/error/merr.h>

#include <hse_ikvdb/kvdb_modes.h>

/**
 * Converts the storage path to an absolute path
 *
 * @param home: home directory
 * @param path: parameter-supplied path
 * @param buf: buffer
 * @param buf_sz: size of the buffer
 * @returns error status
 */
merr_t
kvdb_home_storage_path_get(
    const char * home,
    const char * path,
    char *       buf,
    const size_t buf_sz);

/**
 * Converts the storage path to an absolute real path
 *
 * @param home: home directory
 * @param path: parameter-supplied path
 * @param buf: buffer
 * @param resolved_path: is the path already resolved with home
 * @returns error status
 */
merr_t
kvdb_home_storage_realpath_get(
    const char * home,
    const char * path,
    char         buf[PATH_MAX],
    bool         resolved_path);

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
	const size_t buf_sz);

/**
 * Checks whether KVDB home is on a DAX filesystem
 *
 * @param home:  home directory
 * @param isdax: set to true if home is on a DAX fs (output)
 */
merr_t
kvdb_home_is_fsdax(const char *home, bool *isdax);

/**
 * Checks whether KVDB home has appropriate permissions for the specified access mode
 *
 * @param home: home directory
 * @param mode: kvdb open mode
 */
merr_t
kvdb_home_check_access(const char *home, enum kvdb_open_mode mode);

#endif
