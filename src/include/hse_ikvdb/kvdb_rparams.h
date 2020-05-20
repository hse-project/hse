/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_RPARAMS_H
#define HSE_KVDB_RPARAMS_H

#include <stddef.h>

/**
 * struct kvdb_rparams -
 * @read_only:        readonly flag
 * @throttle_disable: disable put/del throttling
 * @perfc_enable:     priority level. 0 implies default(2).
 * @log_lvl:          log level for hse_log.
 * @log_squelch_ns:   log squelch window in nsec
 * @keylock_tables:   number of keylock hash tables
 * @keylock_entries:  number of entries in the keylock hash table
 * @txn_wkth_delay:        delay (msecs) to invoke transaction worker thread
 * @cndb_entries:     max number of entries CNDB's in memory structures. Note
 *                    that this does not affect the MDC's size.
 * @pct_bandwidth:    qos, %  mpoolbandwidth for the kvdb
 * @iotag2vq:         qos, association iotags to mpool qos virtual queues.
 * @vq_w:             qos, virtual queues weights
 *
 * The following tunable parameters can have a major impact on the way KVDB
 * operates.  Test thoroughly after any modifications.
 *
 * To improve cacheline utilization, group frequently accessed fields
 * towards the beginning of this structure, and rarely accesssed
 * fields towards the end.
 */
struct kvdb_rparams {
    unsigned int read_only;
    unsigned int throttle_disable;
    unsigned int perfc_enable;

    unsigned long throttle_update_ns;
    unsigned long sos_log;

    unsigned long c0_heap_cache_sz_max;
    unsigned long c0_heap_sz;
    unsigned int  c0_debug;
    unsigned int  c0_diag_mode;
    unsigned long c0_ingest_delay;
    unsigned long c0_ingest_width;
    unsigned long c0_coalesce_sz;

    unsigned long txn_heap_sz;
    unsigned long txn_ingest_delay;
    unsigned long txn_ingest_width;
    unsigned long txn_timeout;

    unsigned int  csched_policy;
    unsigned long csched_debug_mask;
    unsigned long csched_node_len_max;
    unsigned long csched_qthreads;
    unsigned long csched_samp_max;
    unsigned long csched_lo_th_pct;
    unsigned long csched_hi_th_pct;
    unsigned long csched_leaf_pct;
    unsigned long csched_vb_scatter_pct;
    unsigned long csched_rspill_params;
    unsigned long csched_ispill_params;
    unsigned long csched_leaf_comp_params;
    unsigned long csched_leaf_len_params;
    unsigned long csched_node_min_ttl;

    unsigned long csched_wr_burst_sz;
    unsigned long csched_wr_rate_max;

    unsigned long dur_enable;
    unsigned long dur_intvl_ms;
    unsigned long dur_buf_sz;
    unsigned long dur_vbb;
    unsigned long dur_delay_pct;
    unsigned long dur_throttle_enable;
    unsigned long dur_throttle_lo_th;
    unsigned long dur_throttle_hi_th;

    unsigned int  throttle_relax;
    unsigned int  throttle_debug;
    unsigned long throttle_c0_hi_th;
    unsigned long throttle_sleep_min_ns;

    /* The following fields are typically only accessed by kvdb open
     * and hence are extrememly cold.
     */
    unsigned int  log_lvl;
    unsigned long log_squelch_ns;
    unsigned long txn_wkth_delay;
    unsigned int  cndb_entries;
    unsigned int  c0_maint_threads;
    unsigned int  c0_ingest_threads;
    unsigned int  c0_mutex_pool_sz;

    unsigned int keylock_entries;
    unsigned int keylock_tables;
    unsigned int low_mem;
    unsigned int excl;
    unsigned int staging_policy;

    unsigned int rpmagic;
};

void
kvdb_rparams_table_reset(void);

struct param_inst *
kvdb_rparams_table(void);

/**
 * kvdb_rparams_parse() -
 * @argc: Number of argv elements
 * @argv: Vector of argument strings
 * @params: Structure to be populated
 * @next_arg: An index into the the argv elements, will be set to first arg
 *            in list that is not a param
 *
 * Parse the parameters in argv and populate the structure 'params'
 * accordingly
 */
int
kvdb_rparams_parse(int argc, char **argv, struct kvdb_rparams *params, int *next_arg);

void
kvdb_rparams_free(struct kvdb_rparams *rparams);

/**
 * kvdb_rparams_help() -
 * @buf: Buffer to be filled with the help message
 * @buf_len: Length of buf
 * @rparams: pointer to a kvdb_rparams struct that holds the custom default
 *           values. If this arg is NULL, system
 *           defaults(kvdb_rparams_defaults) will be used
 *
 * Fills buf with a help string
 *
 * Return: a pointer to the buffer buf
 */
char *
kvdb_rparams_help(char *buf, size_t buf_len, struct kvdb_rparams *rparams);

/**
 * kvdb_rparams_validate() -
 * @params:
 *
 * Check if the parameters are valid
 */
int
kvdb_rparams_validate(struct kvdb_rparams *params);

/**
 * kvdb_rparams_print() -
 * @rp:
 *
 * Prints all parameter values to the log
 */
void
kvdb_rparams_print(struct kvdb_rparams *rp);

/**
 * kvdb_rparams_defaults() -
 *
 * Returns a kvdb_rparams structure set to default values
 */
struct kvdb_rparams
kvdb_rparams_defaults(void);

/**
 * kvdb_get_num_rparams() - get total number of runtime parameters
 */
unsigned int
kvdb_get_num_rparams(void);

/**
 * kvdb_rparams_diff() - invokes callback for non-default values
 * @rp: rparams to compare against
 * @arg: optional callback argument
 * @callback: invoked as callback(key, value, arg) for non-default values
 */
void
kvdb_rparams_diff(
    struct kvdb_rparams *rp,
    void *               arg,
    void (*callback)(const char *, const char *, void *));

#endif /* HSE_KVDB_RPARAMS_H */
