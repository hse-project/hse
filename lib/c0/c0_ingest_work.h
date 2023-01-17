/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_C0_INGEST_WORK_H
#define HSE_KVS_C0_INGEST_WORK_H

#include <hse/limits.h>

#include <hse/util/platform.h>

#include <hse/ikvdb/c0_kvset.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/kvset_builder.h>
#include <hse/ikvdb/c0_kvmultiset.h>
#include <hse/ikvdb/c0_kvset_iterator.h>
#include <hse/ikvdb/lc.h>

/* clang-format off */

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
    struct c0sk             *c0iw_c0sk;
    struct element_source   *c0iw_kvms_sourcev[HSE_C0_INGEST_WIDTH_MAX];
    struct c0_kvset_iterator c0iw_kvms_iterv[HSE_C0_INGEST_WIDTH_MAX];
    struct lc_ingest_iter    c0iw_lc_iterv[LC_SOURCE_CNT_MAX];
    struct element_source   *c0iw_lc_sourcev[LC_SOURCE_CNT_MAX];
    struct kvset_builder    *c0iw_bldrs[HSE_KVS_COUNT_MAX];
    struct kvset_mblocks     c0iw_mblocks[HSE_KVS_COUNT_MAX];
    uint64_t                 c0iw_kvsetidv[HSE_KVS_COUNT_MAX];
    struct c0_kvmultiset    *c0iw_c0kvms;
    uint32_t                 c0iw_kvms_iterc;
    uint32_t                 c0iw_lc_iterc;
    struct kvset_mblocks    *c0iw_mbv[HSE_KVS_COUNT_MAX];

    BIN_HEAP_DEFINE(c0iw_kvms_minheap, HSE_C0_INGEST_WIDTH_MAX);
    BIN_HEAP_DEFINE(c0iw_lc_minheap, LC_SOURCE_CNT_MAX);

    struct c0_usage c0iw_usage;
    uint64_t        c0iw_tenqueued;
    uint64_t        c0iw_tingesting;

    /* Debug stats produced by c0_ingest_worker().
     */
    uint64_t t0, t3, t4, t5, t6, t7, t8, t9, t10;
    uint64_t gencur, gen;

    /* Establishing view for ingest */
    uint64_t c0iw_ingest_max_seqno;
    uint64_t c0iw_ingest_min_seqno;
    uint64_t c0iw_ingest_order;

    /* c0iw_magic is last field to verify it didn't get clobbered
     * by c0kvs_reset().
     */
    uintptr_t c0iw_magic;
};

/* clang-format on */

void
c0_ingest_work_init(struct c0_ingest_work *c0iw);

void
c0_ingest_work_fini(struct c0_ingest_work *c0iw);

#endif
