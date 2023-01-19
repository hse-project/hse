/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CLI_UTIL_H
#define CLI_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#include <hse/types.h>

hse_err_t
kvdb_info_print(const char *kvdb_home, const size_t paramc, const char * const *paramv);

bool
kvdb_storage_info_print(const char *kvdb_home, const size_t paramc, const char * const *paramv);

int
kvdb_compact_request(const char *kvdb_home, const char *request_type, unsigned timeout_sec);

#endif
