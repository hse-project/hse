/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/error/merr.h>

struct ikvdb;
struct kvdb_kvs;

merr_t
kvdb_rest_add_endpoints(struct ikvdb *kvdb);

void
kvdb_rest_remove_endpoints(struct ikvdb *kvdb);

merr_t
kvs_rest_add_endpoints(struct ikvdb *kvdb, struct kvdb_kvs *kvs);

void
kvs_rest_remove_endpoints(struct ikvdb *kvdb, struct kvdb_kvs *kvs);
