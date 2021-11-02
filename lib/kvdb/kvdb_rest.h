/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>

struct ikvdb;
struct kvdb_kvs;
struct yaml_context;

merr_t
kvdb_rest_register(struct ikvdb *kvdb);

merr_t
kvdb_rest_deregister(struct ikvdb *kvdb);

merr_t
kvs_rest_register(struct ikvdb *kvdb, const char *kvs_name, void *kvs);

merr_t
kvs_rest_deregister(struct ikvdb *kvdb, const char *kvs_name);

merr_t
kvs_rest_query_tree(struct kvdb_kvs *kvs, struct yaml_context *yc, int fd, bool list);
