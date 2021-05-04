/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_RPARAMS_H
#define HSE_KVDB_RPARAMS_H

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/throttle.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/compiler.h>

#include <mpool/mpool_structs.h>

/*
 * Steps to add a new KVDB parameter:
 * 1. Add a new struct element to struct kvdb_params.
 * 2. Add a new entry to pspecs[].
 */

/**
 * struct kvdb_rparams -
 * @read_only:        readonly flag
 * @throttle_disable: disable put/del throttling
 * @perfc_enable:     perf counter verbosity
 * @c0_diag_mode:     disable c0 spill
 * @c0_debug:         c0 debug flags (see param_debug_flags.h)
 * @log_lvl:          log level for hse_log.
 * @log_squelch_ns:   log squelch window in nsec
 * @keylock_tables:   number of keylock hash tables
 * @keylock_entries:  number of entries in the keylock hash table
 * @txn_wkth_delay:        delay (msecs) to invoke transaction worker thread
 * @cndb_entries:     max number of entries CNDB's in memory structures. Note
 *                    that this does not affect the MDC's size.
 *
 * The following tunable parameters can have a major impact on the way KVDB
 * operates.  Test thoroughly after any modifications.
 *
 * To improve cacheline utilization, group frequently accessed fields
 * towards the beginning of this structure, and rarely accesssed
 * fields towards the end.
 */
struct kvdb_rparams {
    uint8_t  read_only;
    uint8_t  throttle_disable;
    uint8_t  perfc_enable;
    uint8_t  c0_diag_mode;
    uint8_t  c0_debug;
    uint16_t txn_commit_abort_pct;

    uint64_t c0_heap_cache_sz_max;
    uint64_t c0_heap_sz;
    uint32_t c0_ingest_width;

    uint64_t txn_heap_sz;
    uint32_t txn_ingest_width;
    uint64_t txn_timeout;

    uint32_t csched_policy;
    uint64_t csched_debug_mask;
    uint64_t csched_node_len_max;
    uint64_t csched_qthreads;
    uint64_t csched_samp_max;
    uint64_t csched_lo_th_pct;
    uint64_t csched_hi_th_pct;
    uint64_t csched_leaf_pct;
    uint64_t csched_vb_scatter_pct;
    uint64_t csched_rspill_params;
    uint64_t csched_ispill_params;
    uint64_t csched_leaf_comp_params;
    uint64_t csched_leaf_len_params;
    uint64_t csched_node_min_ttl;

    uint64_t dur_enable;
    uint64_t dur_intvl_ms;
    uint64_t dur_buf_sz;
    uint64_t dur_delay_pct;
    uint64_t dur_throttle_enable;
    uint64_t dur_throttle_lo_th;
    uint64_t dur_throttle_hi_th;

    uint64_t throttle_update_ns;
    uint32_t throttle_relax;
    uint32_t throttle_debug;
    uint32_t throttle_debug_intvl_s;
    uint64_t throttle_c0_hi_th;
    uint64_t throttle_sleep_min_ns;
    uint64_t throttle_burst;
    uint64_t throttle_rate;
    char     throttle_init_policy[THROTTLE_INIT_POLICY_NAME_LEN_MAX];

    /* The following fields are typically only accessed by kvdb open
     * and hence are extremely cold.
     */
    uint64_t log_squelch_ns;
    uint64_t txn_wkth_delay;
    uint32_t log_lvl;
    uint32_t cndb_entries;
    uint32_t cndb_debug;
    uint32_t c0_maint_threads;
    uint32_t c0_ingest_threads;
    uint32_t c0_mutex_pool_sz;

    uint32_t keylock_entries;
    uint32_t keylock_tables;
    uint32_t low_mem;

    struct mclass_policy mclass_policies[HSE_MPOLICY_COUNT];

    struct mpool_rparams storage;

    struct {
        char path[PATH_MAX];
    } socket;
};

const struct param_spec *
kvdb_rparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct kvdb_rparams
kvdb_rparams_defaults() HSE_CONST;

merr_t
kvdb_rparams_resolve(struct kvdb_rparams *params, const char *home);

#endif /* HSE_KVDB_PARAMS_H */
