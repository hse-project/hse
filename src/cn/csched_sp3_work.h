/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CSCHED_SP3_WORK_H
#define HSE_KVDB_CN_CSCHED_SP3_WORK_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

#include "csched_sp3.h"

/* MTF_MOCK_DECL(csched_sp3_work) */

struct cn_tree_node;
struct cn_compaction_work;

enum sp3_work_type {
    wtype_rspill,       /* root node: spill */
    wtype_ispill,       /* root or internal nodes: spill */
    wtype_leaf_garbage, /* leaf nodes: garbage */
    wtype_leaf_size,    /* leaf nodes: size */
    wtype_node_len,     /* all nodes: numbrer of kvsets */
    wtype_leaf_scatter, /* leaf nodes: scatter */
};
#define wtype_MAX (wtype_leaf_scatter + 1)

struct sp3_thresholds {
    u8 rspill_kvsets_min;
    u8 rspill_kvsets_max;
    u8 rspill_vautilpct;
    u8 ispill_kvsets_min;
    u8 ispill_kvsets_max;
    u8 lcomp_kvsets_min;
    u8 lcomp_kvsets_max;
    u8 lcomp_pop_pct;
    u8 lscatter_pct;
    u8 llen_runlen_min;
    u8 llen_runlen_max;
    u8 llen_kvcompc;
    u8 llen_idlec;
    u8 llen_idlem;
};

/* rspill and ispill require at least 1 kvset,
 * lcomp and llen require at lease 2 kvsets.
 */
#define SP3_RSPILL_KVSETS_MIN ((u8)1)
#define SP3_ISPILL_KVSETS_MIN ((u8)1)
#define SP3_LCOMP_KVSETS_MIN ((u8)2)
#define SP3_LLEN_RUNLEN_MIN ((u8)2)
#define SP3_LSCAT_THRESH_MIN ((u8)2)

/* MTF_MOCK */
merr_t
sp3_work(
    struct sp3_node *           spn,
    struct sp3_thresholds *     thresholds,
    enum sp3_work_type          wtype,
    uint                        debug,
    uint *                      qnum_out,
    struct cn_compaction_work **wp);

/* work queues */
#define SP3_QNUM_UNUSED 0
#define SP3_QNUM_INTERN 1
#define SP3_QNUM_LEAF 2
#define SP3_QNUM_LEAFBIG 3
#define SP3_QNUM_LSCAT 4
#define SP3_NUM_QUEUES 5

/* queue thread counts */
#define SP3_QTHREADS_INTERN 4ul
#define SP3_QTHREADS_LEAF 4ul    /* these jobs don't use shared queue */
#define SP3_QTHREADS_LEAFBIG 4ul /* these jobs don't use shared queue */
#define SP3_QTHREADS_LSCAT 2ul
#define SP3_QTHREADS_SHARED 20ul

/* Default value CSCHED_QTHREADS rparam.
 */
#define CSCHED_QTHREADS_DEFAULT                                                                    \
    ((SP3_QTHREADS_INTERN << (8 * SP3_QNUM_INTERN)) | (SP3_QTHREADS_LEAF << (8 * SP3_QNUM_LEAF)) | \
     (SP3_QTHREADS_LEAFBIG << (8 * SP3_QNUM_LEAFBIG)) |                                            \
     (SP3_QTHREADS_LSCAT << (8 * SP3_QNUM_LSCAT)) | (SP3_QTHREADS_SHARED << (8 * SP3_NUM_QUEUES)))

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "csched_sp3_work_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
