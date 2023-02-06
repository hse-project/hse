/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
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
