/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_SP3_WORK_H
#define HSE_KVDB_CN_CSCHED_SP3_WORK_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

#include "csched_sp3.h"

/* MTF_MOCK_DECL(csched_sp3_work) */

/* clang-format off */

struct kvset;
struct cn_tree_node;
struct cn_compaction_work;

enum sp3_work_type {
    wtype_rspill,       /* root node: spill */
    wtype_node_len,     /* all nodes: number of kvsets */
    wtype_node_idle,    /* internal+leaf nodes: kcompact/kvcompact */
    wtype_leaf_garbage, /* leaf nodes: garbage */
    wtype_leaf_scatter, /* leaf nodes: vgroup scatter */
    wtype_leaf_size,    /* leaf nodes: size */
};

struct sp3_thresholds {
    u8 rspill_kvsets_min;
    u8 rspill_kvsets_max;
    u8 lcomp_kvsets_max;
    u8 lcomp_pop_pct;       /* leaf node spill-by-clen percentage threshold */
    u8 lcomp_pop_keys;      /* leaf node spill-by-keys threshold (units of 4 million) */
    u8 lscat_hwm;
    u8 lscat_runlen_max;
    u8 llen_runlen_min;
    u8 llen_runlen_max;
    u8 llen_idlec;
    u8 llen_idlem;
};

/* root spill requires at least 1 kvset,
 * node length reduction requires at least 2 kvsets.
 */
#define SP3_RSPILL_KVSETS_MIN   ((u8)1)
#define SP3_LLEN_RUNLEN_MIN     ((u8)2)

/* clang-format on */

/* MTF_MOCK */
merr_t
sp3_work(
    struct sp3_node *           spn,
    struct sp3_thresholds *     thresholds,
    enum sp3_work_type          wtype,
    uint                        debug,
    struct cn_compaction_work **wp);

#if HSE_MOCKING
#include "csched_sp3_work_ut.h"
#endif /* HSE_MOCKING */

#endif
