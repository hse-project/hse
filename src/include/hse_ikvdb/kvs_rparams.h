/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_RPARAMS_H
#define HSE_KVS_RPARAMS_H

#include <stdlib.h>

#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/vcomp_params.h>

#include <hse_util/hse_err.h>

/**
 * struct kvs_rparams  - kvs runtime parameters
 * @cn_cursor_debug: 1=counters, 2=latencies, 4=summaries
 *
 * See kvs_rparams_help() and 'struct param_inst kvs_rp_table[]'
 * in kvs_rparams.c for descriptions of the runtime parameters.
 *
 * The following tunable parameters can have a major impact on the way KVDB
 * operates.  Test thoroughly after any modifications.
 *
 * To improve cacheline utilization, group frequently accessed fields
 * towards the beginning of this structure, and rarely accesssed
 * fields towards the end.
 */
struct kvs_rparams {
    unsigned long kvs_debug;
    unsigned long c0_cursor_ttl;
    unsigned long cn_cursor_ttl;

    unsigned long cn_maint_delay;
    unsigned long cn_maint_disable;
    unsigned long cn_maint_threads;
    unsigned long cn_compaction_debug; /* 1=compact, 2=ingest */

    unsigned long cn_compact_kblk_ra;
    unsigned long cn_compact_vblk_ra;
    unsigned long cn_compact_vra;

    unsigned long cn_node_size_lo;
    unsigned long cn_node_size_hi;

    unsigned long cn_capped_ttl;
    unsigned long cn_capped_vra;

    unsigned long cn_cursor_vra;
    unsigned long cn_cursor_kra;
    unsigned long cn_cursor_seq;

    unsigned long cn_mcache_wbt;
    unsigned long cn_mcache_vmin;
    unsigned long cn_mcache_vmax;
    unsigned long cn_mcache_vminlvl;

    unsigned long cn_mcache_kra_params;
    unsigned long cn_mcache_vra_params;

    unsigned long cn_bloom_create;
    unsigned long cn_bloom_lookup;
    unsigned long cn_bloom_prob;
    unsigned long cn_bloom_capped;
    unsigned long cn_bloom_preload;

    unsigned long cn_verify;
    unsigned long cn_kcachesz;
    unsigned long kblock_size_mb;
    unsigned long vblock_size_mb;

    unsigned long capped_evict_ttl;

    unsigned long c1_vblock_cap;
    unsigned long c1_vblock_size_mb;
    unsigned long c1_vblock_cappct;

    unsigned long cn_io_threads;
    unsigned long cn_close_wait;
    unsigned long cn_diag_mode;

    unsigned long vblock_asyncio;
    unsigned long vblock_asyncio_ctxswi;

    unsigned long kv_print_config;
    unsigned long rdonly;

    char mclass_policy[HSE_MPOLICY_NAME_LEN_MAX];
    char value_compression[VCOMP_PARAM_STR_SZ];

    unsigned long rpmagic;
};

void
kvs_rparams_table_reset(void);

struct param_inst *
kvs_rparams_table(void);

/**
 * kvs_rparams_parse() -
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
kvs_rparams_parse(int argc, char **argv, struct kvs_rparams *params, int *next_arg);

/**
 * kvs_rparams_help() -
 * @buf: Buffer to be filled with the help message
 * @buf_len: Length of buf
 * @rparams: pointer to a kvs_rparams struct that holds the custom default
 *           values. If this arg is NULL, system
 *           defaults(kvs_rparams_defaults) will be used
 *
 * Fills buf with a help string
 *
 * Return: a pointer to the buffer buf
 */
char *
kvs_rparams_help(char *buf, size_t buf_len, struct kvs_rparams *rparams);

/**
 * kvs_rparams_validate() -
 * @params:
 *
 * Check if the parameters are valid
 */
merr_t
kvs_rparams_validate(struct kvs_rparams *params);

/**
 * kvs_rparams_print() -
 * @rp:
 *
 * Prints all parameter values to the log
 */
void
kvs_rparams_print(struct kvs_rparams *rp);

/**
 * kvs_rparams_defaults() -
 *
 * Returns a kvs_rparams structure set to default values
 */
struct kvs_rparams
kvs_rparams_defaults(void);

/**
 * kvs_get_num_rparams() - get total number of runtime parameters
 */
unsigned int
kvs_get_num_rparams(void);

/**
 * kvs_rparams_diff() - invokes callback for non-default values
 * @rp: rparams to compare against
 * @arg: optional callback argument
 * @callback: invoked as callback(key, value, arg) for non-default values
 */
void
kvs_rparams_diff(
    struct kvs_rparams *rp,
    void *              arg,
    void (*callback)(const char *, const char *, void *));

#endif /* HSE_KVS_RPARAMS_H */
