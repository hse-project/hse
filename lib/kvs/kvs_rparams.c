/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/logging.h>
#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/config.h>
#include <hse_util/param.h>
#include <hse_util/rest_api.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/vcomp_params.h>

#include <mpool/mpool.h>

#define RPARAMS_MAGIC 0x73766B5052ULL /* ascii RPkvs - no null */

#define KVS_PARAM(name, desc) PARAM_INST_U64(kvs_rp_ref.name, #name, desc)
#define KVS_PARAM_STR(name, desc) \
    PARAM_INST_STRING(kvs_rp_ref.name, sizeof(kvs_rp_ref.name), #name, desc)

#define KVS_PARAM_EXP(name, desc) PARAM_INST_U64_EXP(kvs_rp_ref.name, #name, desc)

/*
 * Steps to add a new kvs run-time parameter(rparam):
 * 1. Add a new struct element to struct kvs_rparams.
 * 2. Add a new entry to kvs_rp_table[].
 * 3. Add a new initial value to the struct in kvs_rparams_defaults()
 * 4. (optionally) In kvs_uu_interface.c, expand handle_params() if the
 *    parameter needs to be handled at that stage.
 * 5. (optionally) Expand kvs_rparams_validate() if the parameter needs to
 *    follow certain constraints.
 */

struct kvs_rparams
kvs_rparams_defaults(void)
{
    struct kvs_rparams k = {
        .kvs_debug = 0,
        .kvs_cursor_ttl = 1000,
        .enable_transactions = 0,

        .cn_maint_disable = 0,
        .cn_diag_mode = 0,
        .cn_bloom_create = 1,
        .cn_bloom_lookup = 1,
        .cn_bloom_prob = 10000,
        .cn_bloom_capped = 0,
        .cn_bloom_preload = 0,

        .cn_node_size_lo = 20 * 1024,
        .cn_node_size_hi = 28 * 1024,

        .cn_compact_vblk_ra = 256 * 1024,
        .cn_compact_kblk_ra = 512 * 1024,
        .cn_compact_vra = 128 * 1024,

        .cn_capped_ttl = 9000,
        .cn_capped_vra = 512 * 1024,

        .cn_cursor_vra = 8 * 1024,
        .cn_cursor_kra = 0,
        .cn_cursor_seq = 0,

        .cn_mcache_wbt = 0,
        .cn_mcache_vmin = 256,
        .cn_mcache_vmax = 4096,

#if defined(HSE_DISTRO_EL6) || defined(HSE_DISTRO_EL7)
        .cn_mcache_vminlvl = 3,
        .cn_mcache_kra_params = (40u << 16) | (3u << 8) | 4u,
        .cn_mcache_vra_params = (40u << 16) | (2u << 8) | 1u,
#else
        .cn_mcache_vminlvl = U16_MAX,
        .cn_mcache_kra_params = (50u << 16) | (4u << 8) | 4u,
        .cn_mcache_vra_params = (40u << 16) | (2u << 8) | 1u,
#endif

        .cn_compaction_debug = 0,
        .cn_io_threads = 13,
        .cn_maint_delay = 100,
        .cn_close_wait = 0,

        .cn_verify = 0,
        .cn_kcachesz = 1024 * 1024,
        .kblock_size_mb = 32,
        .vblock_size_mb = 32,

        .capped_evict_ttl = 120,

        .rdonly = 0,
        .kv_print_config = 1,

        .mclass_policy = "capacity_only",

        .vcompmin = CN_SMALL_VALUE_THRESHOLD,
        .value_compression = VCOMP_PARAM_NONE,

        .rpmagic = RPARAMS_MAGIC,
    };

    return k;
}

static struct kvs_rparams kvs_rp_ref;
static struct param_inst  kvs_rp_table[] = {
    KVS_PARAM_EXP(kvs_debug, "enable kvs debugging"),
    KVS_PARAM_EXP(kvs_cursor_ttl, "cached cursor time-to-live (ms)"),
    KVS_PARAM_EXP(enable_transactions, "enable transactions for the kvs"),

    KVS_PARAM_EXP(cn_node_size_lo, "low end of max node size range (MiB)"),
    KVS_PARAM_EXP(cn_node_size_hi, "high end of max node size range (MiB)"),

    KVS_PARAM_EXP(cn_compact_vblk_ra, "compaction vblk read-ahead (bytes)"),
    KVS_PARAM_EXP(cn_compact_vra, "compaction vblk read-ahead via mcache"),
    KVS_PARAM_EXP(cn_compact_kblk_ra, "compaction kblk read-ahead (bytes)"),

    KVS_PARAM_EXP(cn_capped_ttl, "cn cursor cache TTL (ms) for capped kvs"),
    KVS_PARAM_EXP(cn_capped_vra, "capped cursor vblk madvise-ahead (bytes)"),

    KVS_PARAM_EXP(cn_cursor_vra, "cursor vblk madvise-ahead (bytes)"),
    KVS_PARAM_EXP(cn_cursor_kra, "cursor kblk madvise-ahead (boolean)"),
    KVS_PARAM_EXP(cn_cursor_seq, "optimize cn_tree for longer sequential cursor accesses"),

    KVS_PARAM_EXP(
        cn_mcache_wbt,
        "eagerly cache wbt nodes"
        " (1:internal, 2:leaves, 3:both)"),

    KVS_PARAM_EXP(
        cn_mcache_vminlvl,
        "node depth at/above which to read vmin length values "
        "directly from media"),
    KVS_PARAM_EXP(
        cn_mcache_vmin,
        "value size at/above which to read values directly "
        "from media (subject to vminlvl)"),
    KVS_PARAM_EXP(
        cn_mcache_vmax,
        "value size at/above which to always read values directly "
        "from media"),

    KVS_PARAM_EXP(cn_mcache_kra_params, "kblock readahead [pct][lev1][lev0]"),
    KVS_PARAM_EXP(cn_mcache_vra_params, "vblock readahead [pct][lev1][lev0]"),

    KVS_PARAM_EXP(cn_diag_mode, "enable/disable cn diag mode"),
    KVS_PARAM_EXP(cn_maint_disable, "disable cn maintenance"),
    KVS_PARAM_EXP(cn_bloom_create, "enable bloom creation"),
    KVS_PARAM_EXP(
        cn_bloom_lookup,
        "control bloom lookup"
        " (0:off, 1:mcache, 2:read)"),
    KVS_PARAM_EXP(cn_bloom_prob, "bloom create probability"),
    KVS_PARAM_EXP(cn_bloom_capped, "bloom create probability (capped kvs)"),
    KVS_PARAM_EXP(cn_bloom_preload, "preload mcache bloom filters"),

    KVS_PARAM_EXP(cn_compaction_debug, "cn compaction debug flags"),
    KVS_PARAM_EXP(cn_maint_delay, "ms of delay between checks when idle"),
    KVS_PARAM_EXP(cn_io_threads, "number of cn mblock i/o threads"),
    KVS_PARAM_EXP(
        cn_close_wait,
        "force close to wait until all active"
        " compactions have completed"),

    KVS_PARAM_EXP(cn_verify, "verify kvsets as they are created"),
    KVS_PARAM_EXP(cn_kcachesz, "max per-kvset key cache size (in bytes)"),
    KVS_PARAM_EXP(kblock_size_mb, "preferred kblock size (in MiB)"),
    KVS_PARAM_EXP(vblock_size_mb, "preferred vblock size (in MiB)"),

    KVS_PARAM_EXP(capped_evict_ttl, "capped vblock TTL (seconds)"),

    KVS_PARAM_EXP(kv_print_config, "print kvs runtime params"),
    KVS_PARAM_EXP(rdonly, "open kvs in read-only mode"),

    KVS_PARAM_STR(mclass_policy, "media class policy name"),

    KVS_PARAM_EXP(vcompmin, "value length above which compression is considered"),
    KVS_PARAM_STR(value_compression, "value compression algorithm (lz4 or none)"),

    PARAM_INST_END
};

static char const *const kvs_rp_writable[] = {
    "kvs_debug", "cn_mcache_vmax", "cn_compaction_debug", "cn_maint_disable", "cn_compact_kblk_ra",
};

void
kvs_rparams_table_reset(void)
{
    kvs_rp_ref = kvs_rparams_defaults();
}

struct param_inst *
kvs_rparams_table(void)
{
    return kvs_rp_table;
}

u32
kvs_get_num_rparams(void)
{
    assert(NELEM(kvs_rp_table) > 0);

    return NELEM(kvs_rp_table) - 1;
}

static void
get_param_name(int index, char *buf, size_t buf_len)
{
    char *key;
    int   len;

    key = kvs_rp_table[index].pi_type.param_token;
    len = strcspn(key, "=");

    if (len > buf_len) {
        buf[0] = '\0';
        return;
    }

    strncpy(buf, key, len);
    buf[len] = '\0';
}

char *
kvs_rparams_help(char *buf, size_t buf_len, struct kvs_rparams *rparams)
{
    struct kvs_rparams def;
    int                n = NELEM(kvs_rp_table) - 1; /* skip PARAM_INST_END */

    if (!rparams) {
        /* Caller did not provide the default values to be printed.
         * Use system defaults. */
        def = kvs_rparams_defaults();
        rparams = &def;
    }

    return params_help(
        buf,
        buf_len,
        rparams,
        (struct param_inst *)kvs_rp_table,
        n,
        (struct kvs_cparams *)&kvs_rp_ref);
}

void
kvs_rparams_print(struct kvs_rparams *rparams)
{
    int n = NELEM(kvs_rp_table) - 1; /* skip PARAM_INST_END */

    if (ev(!rparams))
        return;

    params_print(kvs_rp_table, n, "kvs_rparams", rparams, (void *)&kvs_rp_ref);
}

merr_t
kvs_rparams_validate(struct kvs_rparams *params)
{
    size_t sz;

    if (!params)
        return merr(EINVAL);

    if (params->rpmagic != RPARAMS_MAGIC) {
        hse_log(HSE_ERR "runtime parameters struct not properly "
                        "initialized(use kvs_rparams_defaults())");
        return merr_errno(merr(ev(EBADR)));
    }

    if (params->cn_node_size_lo > params->cn_node_size_hi) {
        hse_log(
            HSE_ERR "cn_node_size_lo(%lu) must be less"
                    " than or equal to cn_node_size_hi(%lu)",
            (ulong)params->cn_node_size_lo,
            (ulong)params->cn_node_size_hi);
        return merr(EINVAL);
    }

    if (params->cn_maint_delay < 20) {
        hse_log(HSE_ERR "cn_maint_delay must be greater than 20ms");
        return merr(EINVAL);
    }

    sz = params->kblock_size_mb << 20;
    if (sz < KBLOCK_MIN_SIZE || sz > KBLOCK_MAX_SIZE) {
        hse_log(
            HSE_ERR "kblock_size_mb(%lu) must be in the range "
                    "[%lu, %lu]",
            (ulong)params->kblock_size_mb,
            (ulong)(KBLOCK_MIN_SIZE >> 20),
            (ulong)(KBLOCK_MAX_SIZE >> 20));
        return merr(EINVAL);
    }

    sz = params->vblock_size_mb << 20;
    if (sz < VBLOCK_MIN_SIZE || sz > VBLOCK_MAX_SIZE) {
        hse_log(
            HSE_ERR "vblock_size_mb(%lu) must be in the range "
                    "[%lu, %lu]",
            (ulong)params->vblock_size_mb,
            (ulong)(VBLOCK_MIN_SIZE >> 20),
            (ulong)(VBLOCK_MAX_SIZE >> 20));
        return merr(EINVAL);
    }

    if (!vcomp_param_valid(params)) {
        hse_log(HSE_ERR"invalid setting for value_compression, valid settings are: %s",
            VCOMP_PARAM_SUPPORTED);
        return merr(EINVAL);
    }

    return 0;
}

int
kvs_rparams_parse(int argc, char **argv, struct kvs_rparams *params, int *next_arg)
{
    int                i;
    int                num_elems = NELEM(kvs_rp_table);
    struct param_inst *pi;
    merr_t             err;

    if (!argv || !params)
        return merr_errno(merr(ev(EINVAL)));

    pi = calloc(num_elems, sizeof(*pi));
    if (ev(!pi))
        return ENOMEM;

    /* Create an instance table from the reference table by copying
     * the members, and adjusting value pointers to be relative
     * to the params argument passed by the caller.
     */

    num_elems--; /* do not count PARAM_INST_END */
    for (i = 0; i < num_elems; i++) {
        size_t offset = kvs_rp_table[i].pi_value - (void *)&kvs_rp_ref;

        assert(offset < sizeof(kvs_rp_ref));

        pi[i] = kvs_rp_table[i];
        pi[i].pi_value = (void *)params + offset;
    }

    memset(&pi[i], 0, sizeof(pi[i]));

    err = process_params(argc, argv, pi, next_arg, 0);

    free(pi);
    return ev(err);
}

static struct kvs_rparams kvs_rp_dt_defaults;

merr_t
kvs_rparams_remove_from_dt(const char *mpool, const char *kvs)
{
    const int   pathsize = 8 * DT_PATH_ELEMENT_LEN;
    const char *cfg_path = "/data/config";
    char *      path;
    int         rc;

    path = malloc(pathsize);
    if (!path)
        return merr(ENOMEM);

    rc = snprintf(path, pathsize, "%s/%s/%s/%s", cfg_path, COMPNAME, mpool, kvs);

    if (rc > 0 && rc < pathsize)
        dt_remove_recursive(dt_data_tree, path);

    free(path);

    return (rc > 0 && rc < pathsize) ? 0 : merr(EINVAL);
}

merr_t
kvs_rparams_add_to_dt(const char *mpool, const char *kvs, struct kvs_rparams *p)
{
    int  i;
    int  num_elems = NELEM(kvs_rp_table);
    char path[3 * (DT_PATH_ELEMENT_LEN + 1)];

    if (!mpool || !kvs || !p)
        return merr_errno(merr(ev(EINVAL)));

    kvs_rp_dt_defaults = kvs_rparams_defaults();

    snprintf(path, sizeof(path), "%s/%s", mpool, kvs);

    for (i = 0; i < num_elems - 1; i++) {
        bool          writable = false;
        size_t        offset = kvs_rp_table[i].pi_value - (void *)&kvs_rp_ref;
        char          param_name[DT_PATH_ELEMENT_LEN];
        param_show_t *param_showp;
        int           wx;

        get_param_name(i, param_name, sizeof(param_name));

        writable = false;
        for (wx = 0; wx < NELEM(kvs_rp_writable); wx++) {
            if (!strcmp(param_name, kvs_rp_writable[wx])) {
                writable = true;
                break;
            }
        }

        param_showp = kvs_rp_table[i].pi_type.param_val_to_str;

        if (param_showp == show_u32) {
            CFG_U32(
                path,
                param_name,
                (void *)p + offset,
                (void *)&kvs_rp_dt_defaults + offset,
                NULL,
                p,
                writable);
        } else if (param_showp == show_u64) {
            CFG_U64(
                path,
                param_name,
                (void *)p + offset,
                (void *)&kvs_rp_dt_defaults + offset,
                NULL,
                p,
                writable);
        } else if (param_showp == show_string) {
            CFG_STR(
                path,
                param_name,
                (void *)p + offset,
                kvs_rp_table[i].pi_type.param_size,
                (void *)&kvs_rp_dt_defaults + offset,
                NULL,
                p,
                writable);
        } else {
            return merr(ev(EINVAL));
        }
    }

    return 0;
}

void
kvs_rparams_diff(
    struct kvs_rparams *rp,
    void *              arg,
    void (*callback)(const char *, const char *, void *))
{
    int                i;
    int                num_elems = NELEM(kvs_rp_table) - 1;
    struct kvs_rparams def = kvs_rparams_defaults();

    for (i = 0; i < num_elems; i++) {
        char   valstr[DT_PATH_ELEMENT_LEN];
        char   param_name[DT_PATH_ELEMENT_LEN];
        size_t n = kvs_rp_table[i].pi_type.param_size;
        size_t offset = kvs_rp_table[i].pi_value - (void *)&kvs_rp_ref;

        if (bcmp((void *)&def + offset, (void *)rp + offset, n)) {
            get_param_name(i, param_name, sizeof(param_name));
            kvs_rp_table[i].pi_type.param_val_to_str(
                valstr, sizeof(valstr), (void *)rp + offset, 1);
            callback(param_name, valstr, arg);
        }
    }
}
