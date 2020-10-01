/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_CSCHED_H
#define HSE_IKVDB_CSCHED_H

#include <hse_util/inttypes.h>

#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/csched_rp.h>

/* MTF_MOCK_DECL(csched) */

struct csched;
struct kvdb_rparams;
struct cn_tree;
struct throttle_sensor;
struct cn_samp_stats;
struct mpool;
struct hse_kvdb_compact_status;
struct kvdb_health;

/**
 * enum csched_policy - compaction scheduler policy
 * csched_policy_old:  Do not use csched.  Use old tree walker scheduler.
 * csched_policy_noop: Disable scheduler.
 */
enum csched_policy { csched_policy_old = 0, csched_policy_sp3 = 3, csched_policy_noop = 0xff };

/**
 * csched_create() - create a scheduler for kvdb compaction work
 * @policy:
 * @ds:      dataset handle to access mpool qos
 * @rp:      kvdb run-time parameters
 * @mp_name: mpool name
 * @db_name: kvdb name
 * @csched:     (out) handle
 */
/* MTF_MOCK */
merr_t
csched_create(
    enum csched_policy   policy,
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         mp_name,
    struct kvdb_health  *health,
    struct csched **     csched);

/* MTF_MOCK */
void
csched_destroy(struct csched *csched);

/* MTF_MOCK */
void
csched_notify_ingest(struct csched *handle, struct cn_tree *tree, size_t alen, size_t wlen);

/* MTF_MOCK */
void
csched_tree_add(struct csched *csched, struct cn_tree *tree);

/* MTF_MOCK */
void
csched_tree_remove(struct csched *csched, struct cn_tree *tree, bool cancel);

/* MTF_MOCK */
void
csched_throttle_sensor(struct csched *csched, struct throttle_sensor *input);

/* MTF_MOCK */
void
csched_compact_request(struct csched *handle, int flags);

/* MTF_MOCK */
void
csched_compact_status_get(struct csched *handle, struct hse_kvdb_compact_status *status);

/* MTF_MOCK */
struct tbkt *
csched_tbkt_maint_get(struct csched *handle);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "csched_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
