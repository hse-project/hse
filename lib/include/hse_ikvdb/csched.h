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
struct cn_tree_node;

/* clang-format off */

/* work queues */
enum sp3_qnum {
    SP3_QNUM_ROOT,
    SP3_QNUM_LENGTH,
    SP3_QNUM_GARBAGE,
    SP3_QNUM_SCATTER,
    SP3_QNUM_SPLIT,
    SP3_QNUM_SHARED,
    SP3_QNUM_MAX
};

/* Add new rules to the end of the list because rules are persisted
 * in the omf.
 */
enum cn_rule {
    CN_RULE_NONE = 0u,
    CN_RULE_INGEST,     /* normal c0 spill */
    CN_RULE_RSPILL,     /* normal root spill */
    CN_RULE_TSPILL,     /* tiny root spill */
    CN_RULE_ZSPILL,     /* zero writeamp root spill */
    CN_RULE_LENGTHK,    /* long leaf, k-compact */
    CN_RULE_LENGTHV,    /* long tiny leaf, kv-compact */
    CN_RULE_INDEXF,     /* short leaf, full index node compaction */
    CN_RULE_INDEXP,     /* short leaf, partial index node compaction */
    CN_RULE_IDLE_INDEX, /* idle leaf, index node */
    CN_RULE_IDLE_SIZE,  /* idle leaf, tiny node */
    CN_RULE_IDLE_TOMB,  /* idle leaf, mostly tombs */
    CN_RULE_SCATTERF,   /* vgroup scatter remediation (full node) */
    CN_RULE_SCATTERP,   /* vgroup scatter remediation (partial node) */
    CN_RULE_GARBAGE,    /* leaf garbage (reducing space amp) */
    CN_RULE_SPLIT,      /* big leaf (near split threshold) */
};

static inline const char *
cn_rule2str(enum cn_rule rule)
{
    switch (rule) {
    case CN_RULE_NONE:
        return "none";
    case CN_RULE_INGEST:
        return "ingest";
    case CN_RULE_RSPILL:
        return "rspill";
    case CN_RULE_TSPILL:
        return "tspill";
    case CN_RULE_ZSPILL:
        return "zspill";
    case CN_RULE_LENGTHK:
        return "lenk";
    case CN_RULE_LENGTHV:
        return "lenv";
    case CN_RULE_INDEXF:
        return "idxf";
    case CN_RULE_INDEXP:
        return "idxp";
    case CN_RULE_IDLE_INDEX:
        return "idlidx";
    case CN_RULE_IDLE_SIZE:
        return "idlsiz";
    case CN_RULE_IDLE_TOMB:
        return "idltmb";
    case CN_RULE_SCATTERF:
        return "scatf";
    case CN_RULE_SCATTERP:
        return "scatp";
    case CN_RULE_GARBAGE:
        return "garb";
    case CN_RULE_SPLIT:
        return "split";
    }

    return "invalid";
}

/* Default threads-per-queue for csched_qthreads kvdb rparam.
 */
#define CSCHED_QTHREADS_DEFAULT                   \
    ((5ul << (8 * SP3_QNUM_ROOT)) |               \
     (5ul << (8 * SP3_QNUM_LENGTH)) |             \
     (1ul << (8 * SP3_QNUM_GARBAGE)) |            \
     (1ul << (8 * SP3_QNUM_SCATTER)) |            \
     (1ul << (8 * SP3_QNUM_SPLIT)) |              \
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
