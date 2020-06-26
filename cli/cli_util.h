/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2016-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef CLI_UTIL_H
#define CLI_UTIL_H

struct hse_params;

int
hse_kvdb_params(const char *mpool, bool get);

int
kvdb_list_print(
    const char *         mpname,
    struct hse_params *  params,
    struct yaml_context *yc,
    bool                 verbose,
    int *                count);

int
kvdb_compact_request(
    const char *       mpool,
    struct hse_params *params,
    const char *       request_type,
    unsigned           timeout_sec);
#endif
