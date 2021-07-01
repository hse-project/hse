/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_C0_INGEST_WORK_H
#define HSE_KVS_C0_INGEST_WORK_H

#include <hse/limits.h>

#include <hse_util/platform.h>

#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/lc.h>

/**
 * struct c0_ingest_work - description of ingest work to be performed
 * @c0iw_c0:            struct c0 in whose context the ingest is occuring
 * @c0iw_kvms_minheap:
 * @c0iw_sources:
 * @c0iw_kvms_iterv:
 * @c0iw_coalscedbldrs:
 * @c0iw_bldrs:
 * @c0iw_mblocks:
 * @c0iw_c0kvms:        struct c0_kvmultiset being ingested
 * @c0iw_c0:
 * @c0iw_kvms_iterc:
 * @c0iw_tenqueued:
 * @c0iw_coalescec:
 * @c0iw_tingesting:    time of most recent call to c0kvms_ingesting()
 * @c0iw_usage:         finalized usage metrics
 *
 * [HSE_REVISIT]
 */
struct c0_ingest_work {
    struct work_struct       c0iw_work;
    struct c0sk *            c0iw_c0sk;
    struct bin_heap2 *       c0iw_kvms_minheap;
    struct element_source *  c0iw_kvms_sourcev[HSE_C0_INGEST_WIDTH_MAX];
    struct c0_kvset_iterator c0iw_kvms_iterv[HSE_C0_INGEST_WIDTH_MAX];
    struct bin_heap2 *       c0iw_lc_minheap;
    struct lc_ingest_iter    c0iw_lc_iterv[LC_SOURCE_CNT_MAX];
    struct element_source *  c0iw_lc_sourcev[LC_SOURCE_CNT_MAX];
    struct kvset_builder *   c0iw_bldrs[HSE_KVS_COUNT_MAX];
    struct kvset_mblocks     c0iw_mblocks[HSE_KVS_COUNT_MAX];
    struct c0_kvmultiset *   c0iw_c0kvms;
    u32                      c0iw_kvms_iterc;
    u32                      c0iw_lc_iterc;
    struct kvset_mblocks *   c0iw_mbv[HSE_KVS_COUNT_MAX];

    struct c0_usage c0iw_usage;
    u64             c0iw_tenqueued;
    u64             c0iw_tingesting;

    /* Debug stats produced by c0_ingest_worker().
     */
    u64 t0, t3, t4, t5, t6, t7, t8, t9, t10;
    u64 gencur, gen;

    /* Establishing view for ingest */
    u64 c0iw_ingest_max_seqno;
    u64 c0iw_ingest_min_seqno;
    u64 c0iw_ingest_order;

    /* c0iw_magic is last field to verify it didn't get clobbered
     * by c0kvs_reset().
     */
    uintptr_t c0iw_magic;
};

merr_t
c0_ingest_work_init(struct c0_ingest_work *c0iw);

void
c0_ingest_work_fini(struct c0_ingest_work *c0iw);

#endif
