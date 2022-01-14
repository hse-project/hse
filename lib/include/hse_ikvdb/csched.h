/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
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
enum sp3_qnum {
    SP3_QNUM_ROOT,
    SP3_QNUM_INTERN,
    SP3_QNUM_NODELEN,
    SP3_QNUM_LGARB,
    SP3_QNUM_LSIZE,
    SP3_QNUM_SHARED,
    SP3_QNUM_MAX
};

/* Default threads-per-queue for csched_qthreads kvdb rparam.
 */
#define CSCHED_QTHREADS_DEFAULT                 \
    ((5ul << (8 * SP3_QNUM_ROOT)) |             \
     (5ul << (8 * SP3_QNUM_INTERN)) |           \
     (5ul << (8 * SP3_QNUM_NODELEN)) |          \
     (1ul << (8 * SP3_QNUM_LGARB)) |            \
     (1ul << (8 * SP3_QNUM_LSIZE)) |            \
     (2ul << (8 * SP3_QNUM_SHARED)))

/* clang-format on */

/**
 * csched_create() - create a scheduler for kvdb compaction work
 * @ds:      dataset handle to access mpool qos
 * @rp:      kvdb run-time parameters
 * @kvdb_home: kvdb home
 * @db_name: kvdb home
 * @csched:     (out) handle
 */
/* MTF_MOCK */
merr_t
csched_create(
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
