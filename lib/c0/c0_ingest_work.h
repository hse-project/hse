/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_C0_INGEST_WORK_H
#define HSE_KVS_C0_INGEST_WORK_H

#include <hse/hse_limits.h>

#include <hse_util/platform.h>

#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset_iterator.h>
#include <hse_ikvdb/sched_sts.h>

/**
 * struct c0_ingest_work - description of ingest work to be performed
 * @c0iw_c0:            struct c0 in whose context the ingest is occuring
 * @c0iw_minheap:
 * @c0iw_sources:
 * @c0iw_iterv:
 * @c0iw_coalscedkvms:
 * @c0iw_coalscedbldrs:
 * @c0iw_bldrs:
 * @c0iw_mblocks:
 * @c0iw_c0kvms:        struct c0_kvmultiset being ingested
 * @c0iw_c0:
 * @c0iw_iterc:
 * @c0iw_tenqueued:
 * @c0iw_coalescec:
 * @c0iw_tingesting:    time of most recent call to c0kvms_ingesting()
 * @c0iw_usage:         finalized usage metrics
 *
 * [HSE_REVISIT]
 */
struct c0_ingest_work {
    struct work_struct          c0iw_work;
    void                       *c0iw_c0;
    struct bin_heap2           *c0iw_minheap;
    struct element_source      *c0iw_sourcev[HSE_C0_KVSET_ITER_MAX];
    struct c0_kvset_iterator    c0iw_iterv[HSE_C0_KVSET_ITER_MAX];
    struct c0_kvmultiset       *c0iw_coalscedkvms[HSE_C0_KVSET_ITER_MAX];
    struct kvset_builder       *c0iw_bldrs[HSE_KVS_COUNT_MAX];
    struct kvset_mblocks        c0iw_mblocks[HSE_KVS_COUNT_MAX];
    struct c0_kvmultiset       *c0iw_c0kvms;
    u32                         c0iw_iterc;
    u32                         c0iw_coalescec;
    struct c0_ingest_work      *c0iw_next;
    struct c0_ingest_work     **c0iw_tailp;
    int                         c0iw_mbc[HSE_KVS_COUNT_MAX];
    struct kvset_mblocks       *c0iw_mbv[HSE_KVS_COUNT_MAX];
    u32                         c0iw_cmtv[HSE_KVS_COUNT_MAX];

    struct c0_usage c0iw_usage;
    u64             c0iw_tenqueued;
    u64             c0iw_tingesting;

    /* Debug stats produced by c0_ingest_worker().
     */
    u64 t0, t3, t4, t5, t6, t7;
    u64 taddkey;
    u64 taddval;
    u64 gen;
    u64 gencur;

    /* c0iw_magic is last field to verify it didn't get clobbered
     * by c0kvs_reset().
     */
    uintptr_t c0iw_magic;
};

merr_t
c0_ingest_work_init(struct c0_ingest_work *c0iw);

void
c0_ingest_work_fini(struct c0_ingest_work *c0iw);

void
c0_ingest_work_reset(struct c0_ingest_work *c0iw);

#endif
