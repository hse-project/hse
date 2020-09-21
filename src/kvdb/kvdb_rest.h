/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include <hse_util/data_tree.h>
#include <hse_util/rest_api.h>
#include <hse_util/spinlock.h>
#include <hse_util/string.h>

#include <hse_ikvdb/kvset_view.h>

merr_t
kvdb_rest_register(const char *mp_name, void *kvdb);

merr_t
kvdb_rest_deregister(const char *mp_name);

merr_t
kvs_rest_register(const char *mp_name, const char *kvs_name, void *kvs);

merr_t
kvs_rest_deregister(const char *mp_name, const char *kvs_name);

merr_t
kvs_rest_query_tree(struct kvdb_kvs *kvs, struct yaml_context *yc, int fd, bool list);
