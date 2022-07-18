/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_SP3_WORK_H
#define HSE_KVDB_CN_CSCHED_SP3_WORK_H

#include <error/merr.h>
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
    uint8_t  rspill_runlen_min;
    uint8_t  rspill_runlen_max;
    uint16_t rspill_sizemb_max;
    uint8_t  lcomp_runlen_max;
    uint8_t  lcomp_pop_pct;       /* leaf node spill-by-clen percentage threshold */
    uint8_t  lcomp_pop_keys;      /* leaf node spill-by-keys threshold (units of 4 million) */
    uint8_t  lscat_hwm;
    uint8_t  lscat_runlen_max;
    uint8_t  llen_runlen_min;
    uint8_t  llen_runlen_max;
    uint8_t  llen_idlec;
    uint8_t  llen_idlem;
};

/* root spill requires at least 1 kvset,
 * node length reduction requires at least 2 kvsets.
 */
#define SP3_RSPILL_RUNLEN_MIN   (1u)
#define SP3_RSPILL_RUNLEN_MAX   (16u)
#define SP3_RSPILL_SIZEMB_MIN   (4u * 1024)
#define SP3_RSPILL_SIZEMB_MAX   (32u * 1024)
#define SP3_LLEN_RUNLEN_MIN     (2u)
#define SP3_LLEN_RUNLEN_MAX     (16u)

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
