/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_CSCHED_H
#define HSE_IKVDB_CSCHED_H

#include <hse_util/inttypes.h>

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

/* clang-format off */

/* work queues */
#define SP3_QNUM_ROOT           (0)
#define SP3_QNUM_INTERN         (1)
#define SP3_QNUM_NODELEN        (2)
#define SP3_QNUM_LEAF           (3)
#define SP3_QNUM_LEAFBIG        (4)
#define SP3_QNUM_LSCAT          (5)
#define SP3_QNUM_SHARED         (6)
#define SP3_NUM_QUEUES          (6) /* excludes SP3_QNUM_SHARED */

/* queue thread counts */
#define SP3_QTHREADS_ROOT       (3ul)
#define SP3_QTHREADS_INTERN     (5ul) /* these jobs don't use shared queue */
#define SP3_QTHREADS_NODELEN    (3ul)
#define SP3_QTHREADS_LEAF       (4ul) /* these jobs don't use shared queue */
#define SP3_QTHREADS_LEAFBIG    (4ul) /* these jobs don't use shared queue */
#define SP3_QTHREADS_LSCAT      (2ul)
#define SP3_QTHREADS_SHARED     (4ul)

/* Default value CSCHED_QTHREADS rparam.
 */
#define CSCHED_QTHREADS_DEFAULT                                         \
    ((SP3_QTHREADS_ROOT << (8 * SP3_QNUM_ROOT)) |                       \
     (SP3_QTHREADS_INTERN << (8 * SP3_QNUM_INTERN)) |                   \
     (SP3_QTHREADS_NODELEN << (8 * SP3_QNUM_NODELEN)) |                 \
     (SP3_QTHREADS_LEAF << (8 * SP3_QNUM_LEAF)) |                       \
     (SP3_QTHREADS_LEAFBIG << (8 * SP3_QNUM_LEAFBIG)) |                 \
     (SP3_QTHREADS_LSCAT << (8 * SP3_QNUM_LSCAT)) |                     \
     (SP3_QTHREADS_SHARED << (8 * SP3_QNUM_SHARED)))

/* clang-format on */

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
 * @kvdb_home: kvdb home
 * @db_name: kvdb home
 * @csched:     (out) handle
 */
/* MTF_MOCK */
merr_t
csched_create(
    enum csched_policy   policy,
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         kvdb_home,
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

#if HSE_MOCKING
#include "csched_ut.h"
#endif /* HSE_MOCKING */

#endif
