/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2016 Micron Technology, Inc.
 */

#ifndef CLI_UTIL_H
#define CLI_UTIL_H

#include <stdbool.h>
#include <stddef.h>

#include <hse/types.h>

hse_err_t
kvdb_info_print(
    const char *         kvdb_home,
    const size_t         paramc,
    const char *const *  paramv);

bool
kvdb_storage_info_print(
    const char *         kvdb_home,
    const size_t         paramc,
    const char *const *  paramv);

enum kvdb_compact_request {
    REQ_STATUS,
    REQ_COMPACT,
    REQ_COMPACT_FULL,
    REQ_CANCEL,
};

int
kvdb_compact_request(
    const char *kvdb_home,
    enum kvdb_compact_request request,
    unsigned timeout_sec);

#endif
