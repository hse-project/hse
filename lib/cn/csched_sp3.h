/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_SP3_H
#define HSE_KVDB_CN_CSCHED_SP3_H

#include <rbtree.h>

#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>
#include <hse_util/list.h>

/* MTF_MOCK_DECL(csched_sp3) */

#define RBT_MAX 5
#define CN_THROTTLE_MAX (THROTTLE_SENSOR_SCALE_MED + 50)

struct kvdb_rparams;
struct csched_ops;
struct mpool;
struct kvdb_health;

/* MTF_MOCK */
merr_t
sp3_create(
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         kvdb_alias,
    struct kvdb_health * health,
    struct csched_ops ** handle);

struct sp3_rbe {
    s64            rbe_weight;
    struct rb_node rbe_node;
};

struct sp3_node {
    struct sp3_rbe spn_rbe[RBT_MAX];
    u32            spn_ttl;
    u64            spn_timeout;
    bool           spn_initialized;
};

struct sp3_tree {
    struct list_head spt_tlink;
    uint             spt_job_cnt;
    atomic_t         spt_enabled;
    atomic_t         spt_ingest_count;
    atomic64_t       spt_ingest_alen;
    atomic64_t       spt_ingest_wlen;
};

#if HSE_MOCKING
#include "csched_sp3_ut.h"
#endif /* HSE_MOCKING */

#endif
