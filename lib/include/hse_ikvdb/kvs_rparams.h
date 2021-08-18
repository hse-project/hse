/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_RPARAMS_H
#define HSE_KVS_RPARAMS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <hse_ikvdb/param.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/vcomp_params.h>

/*
 * Steps to add a new KVS parameter:
 * 1. Add a new struct element to struct kvs_params.
 * 2. Add a new entry to pspecs[].
 */

/**
 * struct kvs_rparams  - kvs runtime parameters
 * @cn_cursor_debug: 1=counters, 2=latencies, 4=summaries
 *
 * The following tunable parameters can have a major impact on the way KVDB
 * operates.  Test thoroughly after any modifications.
 *
 * To improve cacheline utilization, group frequently accessed fields
 * towards the beginning of this structure, and rarely accesssed
 * fields towards the end.
 */
struct kvs_rparams {
    uint64_t kvs_debug;
    uint64_t kvs_cursor_ttl;
    bool     transactions_enable;

    bool     cn_maint_disable;
    uint64_t cn_maint_delay;
    uint64_t cn_maint_threads;
    uint64_t cn_compaction_debug; /* 1=compact, 2=ingest */

    uint64_t cn_compact_kblk_ra;
    uint64_t cn_compact_vblk_ra;
    uint64_t cn_compact_vra;

    uint64_t cn_node_size_lo;
    uint64_t cn_node_size_hi;

    uint64_t cn_capped_ttl;
    uint64_t cn_capped_vra;

    uint64_t cn_cursor_vra;
    uint64_t cn_cursor_kra;
    uint64_t cn_cursor_seq;

    uint64_t cn_mcache_wbt;
    uint64_t cn_mcache_vmin;
    uint64_t cn_mcache_vmax;
    uint64_t cn_mcache_vminlvl;

    uint64_t cn_mcache_kra_params;
    uint64_t cn_mcache_vra_params;

    bool     cn_bloom_create;
    uint64_t cn_bloom_lookup;
    uint64_t cn_bloom_prob;
    uint64_t cn_bloom_capped;
    uint64_t cn_bloom_preload;

    uint64_t cn_kcachesz;
    uint64_t kblock_size;
    uint64_t vblock_size;

    uint64_t capped_evict_ttl;

    uint64_t cn_io_threads;
    uint64_t cn_close_wait;
    bool     cn_diag_mode;
    bool     cn_verify;

    bool kv_print_config;
    bool rdonly;

    char mclass_policy[HSE_MPOLICY_NAME_LEN_MAX];

    uint64_t             vcompmin;
    enum vcomp_algorithm value_compression;
};

const struct param_spec *
kvs_rparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct kvs_rparams
kvs_rparams_defaults() HSE_CONST;

#endif /* HSE_KVS_RPARAMS_H */
