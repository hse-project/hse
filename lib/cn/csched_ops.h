/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_OPS_H
#define HSE_KVDB_CN_CSCHED_OPS_H

#include <hse_util/inttypes.h>

#include <hse_ikvdb/sched_sts.h>

struct csched_ops;
struct cn_tree;
struct throttle_sensor;
struct hse_kvdb_compact_status;

struct csched_ops {

    void (*cs_tree_add)(struct csched_ops *, struct cn_tree *);

    void (*cs_tree_remove)(struct csched_ops *, struct cn_tree *, bool);

    void (*cs_notify_ingest)(struct csched_ops *, struct cn_tree *, size_t alen);

    void (*cs_throttle_sensor)(struct csched_ops *, struct throttle_sensor *);

    void (*cs_compact_request)(struct csched_ops *, int);

    void (*cs_compact_status_get)(struct csched_ops *, struct hse_kvdb_compact_status *);

    void (*cs_destroy)(struct csched_ops *);
};

#endif
