/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_SP3_H
#define HSE_KVDB_CN_CSCHED_SP3_H

#include <rbtree.h>

#include <hse/util/atomic.h>
#include <hse/error/merr.h>
#include <hse/util/list.h>

#include "csched_sp3_work.h"

/* MTF_MOCK_DECL(csched_sp3) */

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
    bool             spn_managed;
};

/* Each sp3_tree maintains a list of dirty nodes (spt_dnode_listv).
 * If the dirty node list is not empty then the tree will be linked
 * into sp's dirty tree list (sp_dtree_listv) via spt_dtree_linkv.
 */
struct sp3_tree {
    struct list_head spt_tlink;
    uint             spt_job_cnt;
    atomic_bool      spt_enabled;
    atomic_ulong     spt_ingest_alen;
    atomic_ulong     spt_ingest_wlen;

    struct list_head spt_dnode_listv[2] HSE_L1D_ALIGNED;
    struct list_head spt_dtree_linkv[2];
};

static inline void
sp3_node_init(struct sp3_node *spn)
{
    for (size_t tx = 0; tx < NELEM(spn->spn_rbe); ++tx)
        RB_CLEAR_NODE(&spn->spn_rbe[tx].rbe_node);

    INIT_LIST_HEAD(&spn->spn_rlink);
    INIT_LIST_HEAD(&spn->spn_alink);
}

/* MTF_MOCK */
merr_t
sp3_create(
    struct kvdb_rparams *rp,
    const char *         kvdb_alias,
    struct kvdb_health * health,
    struct csched      **handle);

void
sp3_destroy(struct csched *handle);

void
sp3_throttle_sensor(struct csched *handle, struct throttle_sensor *sensor);

void
sp3_compact_request(struct csched *handle, unsigned int flags);

void
sp3_compact_status_get(struct csched *handle, struct hse_kvdb_compact_status *status);

void
sp3_notify_ingest(struct csched *handle, struct cn_tree *tree, size_t alen);

void
sp3_tree_add(struct csched *handle, struct cn_tree *tree);

void
sp3_tree_remove(struct csched *handle, struct cn_tree *tree, bool cancel);

#if HSE_MOCKING
#include "csched_sp3_ut.h"
#endif /* HSE_MOCKING */

#endif
