/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_RPARAMS_H
#define HSE_KVDB_RPARAMS_H

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <cjson/cJSON.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/kvdb_modes.h>
#include <hse/ikvdb/mclass_policy.h>
#include <hse/ikvdb/throttle.h>
#include <hse/logging/logging.h>
#include <hse/mpool/mpool_structs.h>
#include <hse/util/compiler.h>

/*
 * Steps to add a new KVDB parameter:
 * 1. Add a new struct element to struct kvdb_params.
 * 2. Add a new entry to pspecs[].
 */

/**
 * struct kvdb_rparams -
 * @throttle_disable: disable put/del throttling
 * @perfc_level:      perf counter engagement level
 * @c0_diag_mode:     disable c0 spill
 * @c0_debug:         c0 debug flags (see param_debug_flags.h)
 * @keylock_tables:   number of keylock hash tables
 * @txn_wkth_delay:        delay (msecs) to invoke transaction worker thread
 *
 * The following tunable parameters can have a major impact on the way KVDB
 * operates.  Test thoroughly after any modifications.
 *
 * To improve cacheline utilization, group frequently accessed fields
 * towards the beginning of this structure, and rarely accesssed
 * fields towards the end.
 */
struct kvdb_rparams {
    bool throttle_disable;
    uint8_t perfc_level;
    uint8_t perfc_enable;
    bool c0_diag_mode;
    uint8_t c0_debug;

    uint32_t c0_ingest_width;

    uint64_t txn_timeout;

    uint64_t csched_debug_mask;
    uint64_t csched_qthreads;
    uint64_t csched_samp_max;
    uint32_t csched_policy;
    uint8_t csched_lo_th_pct;
    uint8_t csched_hi_th_pct;
    uint8_t csched_leaf_pct;
    uint8_t csched_gc_pct;
    uint16_t csched_lscat_hwm;
    uint8_t csched_lscat_runlen_max;
    uint64_t csched_rspill_params;
    uint64_t csched_leaf_comp_params;
    uint64_t csched_leaf_len_params;
    uint64_t csched_node_min_ttl;
    bool csched_full_compact;

    uint32_t dur_bufsz_mb;
    uint32_t dur_intvl_ms;
    uint32_t dur_size_bytes;
    bool dur_enable;
    bool dur_buf_managed;
    bool dur_replay_force;
    uint8_t dur_throttle_lo_th;
    uint8_t dur_throttle_hi_th;
    uint8_t dur_mclass;

    uint64_t throttle_update_ns;
    uint throttle_init_policy; /* [HSE_REVISIT]: Make this a fixed width type */
    uint32_t throttle_debug;
    uint32_t throttle_debug_intvl_s;
    uint64_t throttle_burst;
    uint64_t throttle_rate;

    /* The following fields are typically only accessed by kvdb open
     * and hence are extremely cold.
     */
    uint64_t txn_wkth_delay;
    uint32_t c0_maint_threads;
    uint32_t c0_ingest_threads;
    uint16_t cn_maint_threads;
    uint16_t cn_io_threads;
    double cndb_compact_hwm_pct;

    uint32_t keylock_tables;
    enum kvdb_open_mode mode;

    bool dio_enable[HSE_MCLASS_COUNT];
    struct mclass_policy mclass_policies[HSE_MPOLICY_COUNT];
};

const struct param_spec *
kvdb_rparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct kvdb_rparams
kvdb_rparams_defaults(void) HSE_CONST;

merr_t
kvdb_rparams_get(
    const struct kvdb_rparams *params,
    const char *param,
    char *buf,
    size_t buf_sz,
    size_t *needed_sz);

merr_t
kvdb_rparams_set(struct kvdb_rparams *params, const char *param, const char *value);

/**
 * Deserialize a config into KVDB rparams
 *
 * @param params KVDB rparams
 * @param config Configuration
 */
merr_t
kvdb_rparams_from_config(struct kvdb_rparams *params, cJSON *config);

/**
 * Deserialize list of key=value parameters to KVDB rparams
 *
 * @param params params struct
 * @param paramc number of parameters
 * @param paramv list of key=value strings
 *
 * @returns Error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
kvdb_rparams_from_paramv(struct kvdb_rparams *params, size_t paramc, const char * const *paramv);

cJSON *
kvdb_rparams_to_json(const struct kvdb_rparams *params) HSE_WARN_UNUSED_RESULT;

#endif /* HSE_KVDB_PARAMS_H */
