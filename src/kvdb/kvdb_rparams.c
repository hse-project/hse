/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/logging.h>
#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/config.h>
#include <hse_util/param.h>
#include <hse_util/rest_api.h>
#include <hse_util/string.h>
#include <hse_util/slab.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0_kvset.h>

#include <mpool/mpool.h>

#define RPARAMS_MAGIC (('K' << 24) | ('D' << 16) | ('R' << 8) | 'P')

#define KVDB_PARAM(_name, _desc) PARAM_INST_U64(kvdb_rp_ref._name, #_name, _desc)

#define KVDB_PARAM_EXP(_name, _desc) PARAM_INST_U64_EXP(kvdb_rp_ref._name, #_name, _desc)

#define KVDB_PARAM_U8(_name, _desc) PARAM_INST_U8(kvdb_rp_ref._name, #_name, _desc)
#define KVDB_PARAM_U32(_name, _desc) PARAM_INST_U32(kvdb_rp_ref._name, #_name, _desc)

#define KVDB_PARAM_U8_EXP(_name, _desc) PARAM_INST_U8_EXP(kvdb_rp_ref._name, #_name, _desc)
#define KVDB_PARAM_U32_EXP(_name, _desc) PARAM_INST_U32_EXP(kvdb_rp_ref._name, #_name, _desc)

#define KVDB_PARAM_STR(_name, _desc) \
    PARAM_INST_STRING(kvdb_rp_ref._name, sizeof(kvdb_rp_ref._name), #_name, _desc)

/*
 * Steps to add a new kvdb run-time parameter(rparam):
 * 1. Add a new struct element to struct kvdb_rparams.
 * 2. Add a new entry to kvdb_rp_table[].
 * 3. Add a new initial value to the struct in kvdb_rparams_defaults()
 * 4. (optionally) In kvdb_uu_interface.c, expand handle_params() if the
 *    parameter needs to be handled at that stage.
 * 5. (optionally) Expand kvdb_rparams_validate() if the parameter needs to
 *    follow certain constraints.
 */

struct kvdb_rparams
kvdb_rparams_defaults(void)
{
    struct kvdb_rparams k = {
        .read_only = 0,
        .perfc_enable = 2,

        .c0_heap_cache_sz_max = HSE_C0_CCACHE_SZ_MAX,
        .c0_heap_sz = 0,
        .c0_debug = 0,
        .c0_diag_mode = 0,
        .c0_ingest_delay = HSE_C0_INGEST_DELAY_DFLT,
        .c0_ingest_width = 0,
        .c0_mutex_pool_sz = 7,
        .c0_coalesce_sz = 128,

        .txn_heap_sz = HSE_C0_CHEAP_SZ_MAX,
        .txn_ingest_delay = HSE_C0_INGEST_DELAY_DFLT,
        .txn_ingest_width = HSE_C0_INGEST_WIDTH_DFLT,
        .txn_timeout = 1000 * 60 * 5,

        .csched_policy = 3,
        .csched_debug_mask = 0,
        .csched_samp_max = 150,
        .csched_lo_th_pct = 25,
        .csched_hi_th_pct = 75,
        .csched_leaf_pct = 90,
        .csched_vb_scatter_pct = 100,
        .csched_qthreads = 0,
        .csched_node_len_max = 0,
        .csched_rspill_params = 0,
        .csched_ispill_params = 0,
        .csched_leaf_comp_params = 0,
        .csched_leaf_len_params = 0,
        .csched_node_min_ttl = 17,

        .dur_enable = 0,
        .dur_intvl_ms = 500,
        .dur_throttle_enable = 1,
        .dur_buf_sz = 36700160, /* 35 MiB */
        .dur_delay_pct = 30,
        .dur_throttle_lo_th = 90,
        .dur_throttle_hi_th = 150,

        /* Initial burst and rate will be updated by the throttler,
         * but initial values should be low to avoid surprises during startup.
         */
        .throttle_disable = 0,
        .throttle_update_ns = 25 * 1000 * 1000,
        .throttle_burst = 10ul << 20,
        .throttle_rate = 10ul << 20,
        .throttle_relax = 1,
        .throttle_debug = 0,
        .throttle_debug_intvl_s = 300,
        .throttle_c0_hi_th = 1024 * 4,
        .throttle_init_policy = "default",

        .log_lvl = HSE_LOG_PRI_DEFAULT,
        .log_squelch_ns = HSE_LOG_SQUELCH_NS_DEFAULT,
        .txn_wkth_delay = 1000 * 60,
        .cndb_entries = 0,
        .c0_maint_threads = HSE_C0_MAINT_THREADS_DFLT,
        .c0_ingest_threads = HSE_C0_INGEST_THREADS_DFLT,

        .keylock_entries = 19997,
        .keylock_tables = 293,

        .low_mem = 0,

        .rpmagic = RPARAMS_MAGIC,
    };

    return k;
}

static struct kvdb_rparams kvdb_rp_ref;
static struct param_inst   kvdb_rp_table[] = {
    KVDB_PARAM_U8(read_only, "readonly flag"),
    KVDB_PARAM_U8_EXP(perfc_enable, "0: disable, [123]: enable"),

    KVDB_PARAM_EXP(c0_heap_cache_sz_max, "max size of c0 cheap cache (bytes)"),
    KVDB_PARAM_EXP(c0_heap_sz, "max c0 cheap size (bytes)"),
    KVDB_PARAM_U8_EXP(c0_debug, "c0 debug flags"),
    KVDB_PARAM_U8_EXP(c0_diag_mode, "disable c0 spill"),
    KVDB_PARAM_U32_EXP(c0_ingest_delay, "max c0 ingest coalesce delay (seconds)"),
    KVDB_PARAM_U32_EXP(c0_ingest_width, "fix c0 kvms width (min 2), zero for dynamic width"),
    KVDB_PARAM_EXP(c0_coalesce_sz, "max c0 ingest coalesce size (MiB)"),

    KVDB_PARAM_EXP(txn_heap_sz, "max txn cheap size (bytes)"),
    KVDB_PARAM_U32_EXP(txn_ingest_delay, "max ingest coalesce delay (seconds)"),
    KVDB_PARAM_U32_EXP(txn_ingest_width, "number of txn trees in parallel"),
    KVDB_PARAM_EXP(txn_timeout, "transaction timeout (ms)"),

    KVDB_PARAM_U32_EXP(csched_policy, "csched (compaction scheduler) policy"),
    KVDB_PARAM_EXP(csched_debug_mask, "csched debug (bit mask)"),
    KVDB_PARAM_EXP(csched_samp_max, "csched max space amp (0x100)"),
    KVDB_PARAM_EXP(csched_lo_th_pct, "csched low water mark percentage"),
    KVDB_PARAM_EXP(csched_hi_th_pct, "csched hwm water mark percentage"),
    KVDB_PARAM_EXP(csched_leaf_pct, "csched percent data in leaves"),
    KVDB_PARAM_EXP(csched_vb_scatter_pct, "csched vblock scatter pct. in leaves"),
    KVDB_PARAM_EXP(csched_qthreads, "csched queue threads"),
    KVDB_PARAM_EXP(csched_node_len_max, "csched max kvsets per node"),
    KVDB_PARAM_EXP(csched_rspill_params, "root node spill params [min,max]"),
    KVDB_PARAM_EXP(csched_ispill_params, "internal node spill params [min,max]"),
    KVDB_PARAM_EXP(csched_leaf_comp_params, "leaf compact params [poppct,min,max]"),
    KVDB_PARAM_EXP(csched_leaf_len_params, "leaf length params [idlem,idlec,kvcompc,min,max]"),
    KVDB_PARAM_EXP(csched_node_min_ttl, "Min. time-to-live for cN nodes (secs)"),

    KVDB_PARAM_EXP(dur_enable, "0: disable durability, 1:enable durability"),
    KVDB_PARAM(dur_intvl_ms, "durability lag in ms"),
    KVDB_PARAM_EXP(dur_buf_sz, "durability buffer size in bytes"),
    KVDB_PARAM_EXP(dur_delay_pct, "durability delay percent"),
    KVDB_PARAM_EXP(dur_throttle_lo_th, "low watermark for throttling in percentage"),
    KVDB_PARAM_EXP(dur_throttle_hi_th, "high watermark for throttling in percentage"),
    KVDB_PARAM_EXP(dur_throttle_enable, "enable durablity throttling"),

    KVDB_PARAM_U8_EXP(throttle_disable, "disable sleep throttle"),
    KVDB_PARAM_EXP(throttle_update_ns, "throttle update sensors time in ns"),
    KVDB_PARAM_U32_EXP(throttle_relax, "allow c0 boost to disable throttling"),
    KVDB_PARAM_U32_EXP(throttle_debug, "throttle debug"),
    KVDB_PARAM_U32_EXP(throttle_debug_intvl_s, "throttle debug interval (secs)"),
    KVDB_PARAM_EXP(throttle_sleep_min_ns, "nanosleep time overhead (nsecs)"),
    KVDB_PARAM_EXP(throttle_c0_hi_th, "throttle sensor: c0 high water mark (MiB)"),
    KVDB_PARAM_STR(throttle_init_policy, "throttle initialization policy"),
    KVDB_PARAM_EXP(throttle_burst, "initial throttle burst size (bytes)"),
    KVDB_PARAM_EXP(throttle_rate, "initial throttle rate (bytes/sec)"),

    KVDB_PARAM_U32(log_lvl, "log message verbosity. Range: 0 to 7."),
    KVDB_PARAM_EXP(log_squelch_ns, "drop messages repeated within nsec window"),
    KVDB_PARAM_EXP(txn_wkth_delay, "delay for transaction worker thread"),
    KVDB_PARAM_U32_EXP(
        cndb_entries,
        "number of entries in cndb's in-core "
        "representation (0: let system choose)"),
    KVDB_PARAM_U32_EXP(c0_maint_threads, "max number of maintenance threads"),
    KVDB_PARAM_U32_EXP(c0_ingest_threads, "max number of c0 ingest threads"),
    KVDB_PARAM_U32_EXP(c0_mutex_pool_sz, "max locks in c0 ingest sync pool"),

    KVDB_PARAM_U32_EXP(keylock_entries, "number of keylock entries in a table"),
    KVDB_PARAM_U32_EXP(keylock_tables, "number of keylock tables"),
    KVDB_PARAM_U32_EXP(low_mem, "configure for a constrained memory environment"),
    KVDB_PARAM_U32_EXP(excl, "open the kvdb in exclusive mode"),

    PARAM_INST_END
};

static char const *const kvdb_rp_writable[] = {
    "c0_debug",
    "throttle_debug",
    "throttle_debug_intvl_s",
    "throttle_update_ns",
    "throttle_burst",
    "throttle_rate",
    "csched_policy",
    "csched_qthreads",
    "csched_node_len_max",
    "csched_samp_max",
    "csched_lo_th_pct",
    "csched_hi_th_pct",
    "csched_leaf_pct",
    "csched_vb_scatter_pct",
    "csched_rspill_params",
    "csched_ispill_params",
    "csched_leaf_comp_params",
    "csched_leaf_len_params",
    "csched_debug_mask",
};

void
kvdb_rparams_table_reset(void)
{
    kvdb_rp_ref = kvdb_rparams_defaults();
}

struct param_inst *
kvdb_rparams_table(void)
{
    return kvdb_rp_table;
}

u32
kvdb_get_num_rparams(void)
{
    assert(NELEM(kvdb_rp_table) > 0);

    return NELEM(kvdb_rp_table) - 1;
}

static void
get_param_name(int index, char *buf, size_t buf_len)
{
    char *key;
    int   len;

    key = kvdb_rp_table[index].pi_type.param_token;
    len = strcspn(key, "=");

    if (len > buf_len) {
        buf[0] = '\0';
        return;
    }

    strncpy(buf, key, len);
    buf[len] = '\0';
}

char *
kvdb_rparams_help(char *buf, size_t buf_len, struct kvdb_rparams *rparams)
{
    struct kvdb_rparams def;
    int                 n = NELEM(kvdb_rp_table) - 1; /* skip PARAM_INST_END */

    if (!rparams) {
        /* Caller did not provide the default values to be printed.
         * Use system defaults. */
        def = kvdb_rparams_defaults();
        rparams = &def;
    }

    return params_help(
        buf,
        buf_len,
        rparams,
        (struct param_inst *)kvdb_rp_table,
        n,
        (struct kvdb_cparams *)&kvdb_rp_ref);
}

void
kvdb_rparams_print(struct kvdb_rparams *rparams)
{
    int n = NELEM(kvdb_rp_table) - 1; /* skip PARAM_INST_END */

    if (ev(!rparams))
        return;

    params_print(kvdb_rp_table, n, "kvdb_rparams", rparams, (void *)&kvdb_rp_ref);
}

merr_t
kvdb_rparams_validate(struct kvdb_rparams *params)
{
    if (ev(!params))
        return merr(EINVAL);

    if (params->rpmagic != RPARAMS_MAGIC) {
        hse_log(HSE_ERR "runtime parameters struct not properly "
                        "initialized(use kvdb_rparams_defaults())");
        return merr(EINVAL);
    }

    if (params->log_lvl > 7) {
        hse_log(HSE_ERR "log_lvl cannot be greater than 7");
        return merr(EINVAL);
    }

    return 0;
}

merr_t
kvdb_rparams_parse(int argc, char **argv, struct kvdb_rparams *params, int *next_arg)
{
    int                i;
    int                num_elems = NELEM(kvdb_rp_table);
    struct param_inst *pi;
    merr_t             err;

    if (ev(!argv || !params))
        return merr(EINVAL);

    pi = calloc(num_elems, sizeof(*pi));
    if (!pi)
        return merr(ENOMEM);

    /* Create an instance table from the reference table by copying
     * the members, and adjusting value pointers to be relative
     * to the params argument passed by the caller.
     */

    num_elems--; /* do not count PARAM_INST_END */
    for (i = 0; i < num_elems; i++) {
        size_t offset = kvdb_rp_table[i].pi_value - (void *)&kvdb_rp_ref;

        assert(offset < sizeof(kvdb_rp_ref));

        pi[i] = kvdb_rp_table[i];
        pi[i].pi_value = (void *)params + offset;
    }

    memset(&pi[i], 0, sizeof(pi[i]));

    err = process_params(argc, argv, pi, next_arg, 0);

    free(pi);

    return ev(err);
}

struct kvdb_rparams kvdb_rp_dt_defaults;

merr_t
kvdb_rparams_add_to_dt(const char *mp_name, struct kvdb_rparams *p)
{
    int i;
    int num_elems = NELEM(kvdb_rp_table);

    if (!mp_name || !p)
        return merr(ev(EINVAL));

    kvdb_rp_dt_defaults = kvdb_rparams_defaults();

    for (i = 0; i < num_elems - 1; i++) {
        bool          writable = false;
        size_t        offset = kvdb_rp_table[i].pi_value - (void *)&kvdb_rp_ref;
        char          param_name[DT_PATH_ELEMENT_LEN];
        param_show_t *param_showp;
        int           wx;

        get_param_name(i, param_name, sizeof(param_name));

        writable = false;
        for (wx = 0; wx < NELEM(kvdb_rp_writable); wx++) {
            if (!strcmp(param_name, kvdb_rp_writable[wx])) {
                writable = true;
                break;
            }
        }

        param_showp = kvdb_rp_table[i].pi_type.param_val_to_str;

        if (param_showp == show_u8) {
            CFG_U32(
                mp_name,
                param_name,
                (void *)p + offset,
                (void *)&kvdb_rp_dt_defaults + offset,
                NULL,
                p,
                writable);
        } else if (param_showp == show_u32) {
            CFG_U32(
                mp_name,
                param_name,
                (void *)p + offset,
                (void *)&kvdb_rp_dt_defaults + offset,
                NULL,
                p,
                writable);
        } else if (param_showp == show_u64) {
            CFG_U64(
                mp_name,
                param_name,
                (void *)p + offset,
                (void *)&kvdb_rp_dt_defaults + offset,
                NULL,
                p,
                writable);
        } else if (param_showp == show_string) {
            CFG_STR(
                mp_name,
                param_name,
                (void *)p + offset,
                kvdb_rp_table[i].pi_type.param_size,
                (void *)&kvdb_rp_dt_defaults + offset,
                NULL,
                p,
                writable);
        } else {
            return merr(ev(EINVAL));
        }
    }

    return 0;
}

merr_t
kvdb_rparams_remove_from_dt(const char *mpool)
{
    int         rc;
    const char *cfg_path = "/data/config";
#define CFG_PATHLEN 32 /* Must exceed strlen(cfg_path) */
    char path[3 * DT_PATH_ELEMENT_LEN + CFG_PATHLEN];

    snprintf(path, sizeof(path), "%s/%s/%s", cfg_path, COMPNAME, mpool);

    rc = dt_remove_recursive(dt_data_tree, path);

    return merr(-rc);
}

void
kvdb_rparams_diff(
    struct kvdb_rparams *rp,
    void *               arg,
    void (*callback)(const char *, const char *, void *))
{
    int                 i;
    int                 num_elems = NELEM(kvdb_rp_table) - 1;
    struct kvdb_rparams def = kvdb_rparams_defaults();

    for (i = 0; i < num_elems; i++) {
        char   valstr[DT_PATH_ELEMENT_LEN];
        char   param_name[DT_PATH_ELEMENT_LEN];
        size_t n = kvdb_rp_table[i].pi_type.param_size;
        size_t offset = (kvdb_rp_table[i].pi_value - (void *)&kvdb_rp_ref);

        if (bcmp((void *)&def + offset, (void *)rp + offset, n)) {
            get_param_name(i, param_name, sizeof(param_name));
            kvdb_rp_table[i].pi_type.param_val_to_str(
                valstr, sizeof(valstr), (void *)rp + offset, NELEM(valstr));
            callback(param_name, valstr, arg);
        }
    }
}
