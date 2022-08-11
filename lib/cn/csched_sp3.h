/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_SP3_H
#define HSE_KVDB_CN_CSCHED_SP3_H

#include <rbtree.h>

#include <hse_util/atomic.h>
#include <hse/error/merr.h>
#include <hse_util/list.h>

#include "csched_sp3_work.h"

/* MTF_MOCK_DECL(csched_sp3) */

#define CN_THROTTLE_MAX (THROTTLE_SENSOR_SCALE_MED + 50)

struct kvdb_rparams;
struct mpool;
struct kvdb_health;
struct csched;
struct cn_tree;
struct cn_tree_node;
struct throttle_sensor;
struct hse_kvdb_compact_status;
struct cn_compaction_work;

struct sp3_rbe {
    struct rb_node rbe_node;
    uint64_t       rbe_weight;
};

struct sp3_node {
    struct sp3_rbe   spn_rbe[wtype_MAX];
    struct list_head spn_rlink;
    struct list_head spn_alink;
    struct list_head spn_dlink;
    bool             spn_initialized;
    uint             spn_cgen;
};

struct sp3_tree {
    struct list_head spt_tlink;
    uint             spt_job_cnt;
    atomic_int       spt_enabled;
    atomic_ulong     spt_ingest_alen;
    atomic_ulong     spt_ingest_wlen;

    /* Dirty node list */
    struct mutex     spt_dlist_lock;
    struct list_head spt_dlist;;
};

/* MTF_MOCK */
merr_t
sp3_create(
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         kvdb_alias,
    struct kvdb_health * health,
    struct csched      **handle);

void
sp3_destroy(struct csched *handle);

void
sp3_throttle_sensor(struct csched *handle, struct throttle_sensor *sensor);

void
sp3_compact_request(struct csched *handle, int flags);

void
sp3_compact_status_get(struct csched *handle, struct hse_kvdb_compact_status *status);

void
sp3_notify_ingest(struct csched *handle, struct cn_tree *tree, size_t alen, size_t wlen);

void
sp3_tree_add(struct csched *handle, struct cn_tree *tree);

void
sp3_tree_remove(struct csched *handle, struct cn_tree *tree, bool cancel);

#if HSE_MOCKING
#include "csched_sp3_ut.h"
#endif /* HSE_MOCKING */

#endif
