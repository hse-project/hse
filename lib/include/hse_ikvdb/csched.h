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
    SP3_QNUM_LLEN,
    SP3_QNUM_LGARB,
    SP3_QNUM_LSCAT,
    SP3_QNUM_LSIZE,
    SP3_QNUM_SHARED,
    SP3_QNUM_MAX
};

enum cn_comp_rule {
    CN_CR_NONE = 0u,
    CN_CR_INGEST,         /* normal c0 spill */
    CN_CR_RSPILL,         /* normal root spill */
    CN_CR_RTINY,          /* tiny root spill */
    CN_CR_LBIG,           /* big leaf (near pop threshold) */
    CN_CR_LBIG_ONE,       /* big leaf, compact one kvset */
    CN_CR_LGARB,          /* leaf garbage (reducing space amp) */
    CN_CR_LLONG,          /* long leaf */
    CN_CR_LIDXF,          /* short leaf, full index node compaction */
    CN_CR_LIDXP,          /* short leaf, partial index node compaction */
    CN_CR_LIDLE_IDX,      /* idle leaf, index node */
    CN_CR_LIDLE_SIZE,     /* idle leaf, tiny node */
    CN_CR_LIDLE_TOMB,     /* idle leaf, mostly tombs */
    CN_CR_LSCATF,         /* vgroup scatter remediation (full node) */
    CN_CR_LSCATP,         /* vgroup scatter remediation (partial node) */
};

static inline const char *
cn_comp_rule2str(enum cn_comp_rule rule)
{
    switch (rule) {
    case CN_CR_NONE:
        return "none";
    case CN_CR_INGEST:
        return "ingest";
    case CN_CR_RSPILL:
        return "rspill";
    case CN_CR_RTINY:
        return "rtiny";
    case CN_CR_LBIG:
        return "lbig";
    case CN_CR_LBIG_ONE:
        return "lbig1";
    case CN_CR_LGARB:
        return "lgarb";
    case CN_CR_LLONG:
        return "llong";
    case CN_CR_LIDXF:
        return "lidxf";
    case CN_CR_LIDXP:
        return "lidxp";
    case CN_CR_LIDLE_IDX:
        return "idlidx";
    case CN_CR_LIDLE_SIZE:
        return "idlsiz";
    case CN_CR_LIDLE_TOMB:
        return "idltmb";
    case CN_CR_LSCATF:
        return "lscatf";
    case CN_CR_LSCATP:
        return "lscatp";
    }

    return "invalid";
}

/* Default threads-per-queue for csched_qthreads kvdb rparam.
 */
#define CSCHED_QTHREADS_DEFAULT                 \
    ((5ul << (8 * SP3_QNUM_ROOT)) |             \
     (5ul << (8 * SP3_QNUM_LLEN)) |             \
     (1ul << (8 * SP3_QNUM_LGARB)) |            \
     (1ul << (8 * SP3_QNUM_LSCAT)) |            \
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
