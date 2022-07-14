/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <error/merr.h>

struct ikvdb;
struct kvdb_kvs;
struct yaml_context;

merr_t
kvdb_rest_register(struct ikvdb *kvdb);

merr_t
kvdb_rest_deregister(struct ikvdb *kvdb);

merr_t
kvs_rest_register(struct ikvdb *kvdb, const char *kvs_name, struct kvdb_kvs *kvs);

merr_t
kvs_rest_deregister(struct ikvdb *kvdb, const char *kvs_name);

merr_t
kvs_rest_query_tree(struct kvdb_kvs *kvs, struct yaml_context *yc, bool blkids, bool nodesonly);
