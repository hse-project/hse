/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <bsd/string.h>

#include <hse_util/assert.h>
#include <hse_util/compiler.h>
#include <hse/logging/logging.h>
#include <hse_util/perfc.h>
#include <hse_util/storage.h>
#include <hse_util/storage.h>

#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/vcomp_params.h>

/*
 * Steps to add a new kvs run-time parameter(rparam):
 * 1. Add a new struct element to struct kvs_rparams.
 * 2. Add a new entry to pspecs.
 */

static bool HSE_NONNULL(1, 2, 3)
compression_default_converter(
    const struct param_spec *const ps,
    const cJSON *const             node,
    void *const                    data)
{
    const char *value;

    INVARIANT(ps);
    INVARIANT(node);
    INVARIANT(data);

    if (!cJSON_IsString(node))
        return false;

    value = cJSON_GetStringValue(node);
    if (strcmp(value, VCOMP_PARAM_OFF) == 0) {
        *(enum vcomp_default *)data = VCOMP_DEFAULT_OFF;
    } else if (strcmp(value, VCOMP_PARAM_ON) == 0) {
        *(enum vcomp_default *)data = VCOMP_DEFAULT_ON;
    } else {
        log_err("Unknown compression default value: %s", value);
        return false;
    }

    return true;
}

static merr_t
compression_default_stringify(
    const struct param_spec *const ps,
    const void *const              value,
    char *const                    buf,
    const size_t                   buf_sz,
    size_t *const                  needed_sz)
{
    int n;
    enum vcomp_default dflt;
    const char *param = NULL;

    INVARIANT(ps);
    INVARIANT(value);
    INVARIANT(buf);

    dflt = *(enum vcomp_default *)value;

    switch (dflt) {
    case VCOMP_DEFAULT_OFF:
        param = VCOMP_PARAM_OFF;
        break;
    case VCOMP_DEFAULT_ON:
        param = VCOMP_PARAM_ON;
        break;
    }

    assert(param);

    n = snprintf(buf, buf_sz, "\"%s\"", param);
    if (n < 0)
        return merr(EBADMSG);

    if (needed_sz)
        *needed_sz = n;

    return 0;
}

static cJSON *
compression_default_jsonify(const struct param_spec *const ps, const void *const value)
{
    enum vcomp_default dflt;

    INVARIANT(ps);
    INVARIANT(value);

    dflt = *(enum vcomp_default *)value;

    switch (dflt) {
        case VCOMP_DEFAULT_OFF:
            return cJSON_CreateString(VCOMP_PARAM_OFF);
        case VCOMP_DEFAULT_ON:
            return cJSON_CreateString(VCOMP_PARAM_ON);
    }

    abort();
}

static const struct param_spec pspecs[] = {
    {
        .ps_name = "kvs_cursor_ttl",
        .ps_description = "cached cursor time-to-live (ms)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, kvs_cursor_ttl),
        .ps_size = PARAM_SZ(struct kvs_rparams, kvs_cursor_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 1500,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "kvs_sfx_len",
        .ps_description = "Suffix length (used by prefix probe)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvs_rparams, kvs_sfxlen),
        .ps_size = PARAM_SZ(struct kvs_rparams, kvs_sfxlen),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = HSE_KVS_KEY_LEN_MAX,
            },
        },
    },
    {
        .ps_name = "transactions.enabled",
        .ps_description = "enable transactions for the kvs",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct kvs_rparams, transactions_enable),
        .ps_size = PARAM_SZ(struct kvs_rparams, transactions_enable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_bool = false,
        },
    },
    {
        .ps_name = "perfc.level",
        .ps_description = "set kvs perf counter enagagement level (min:0 default:2 max:9)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvs_rparams, perfc_level),
        .ps_size = PARAM_SZ(struct kvs_rparams, perfc_level),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = PERFC_LEVEL_DEFAULT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = PERFC_LEVEL_MIN,
                .ps_max = PERFC_LEVEL_MAX,
            },
        },
    },
    {
        .ps_name = "cn_split_size",
        .ps_description = "node split size (GiB)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvs_rparams, cn_split_size),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_split_size),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 19,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 8,
                .ps_max = 1024,
            },
        },
    },
    {
        .ps_name = "cn_compact_vblk_ra",
        .ps_description = "compaction vblk read-ahead (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_compact_vblk_ra),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_compact_vblk_ra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 256 << KB_SHIFT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 32 << KB_SHIFT,
                .ps_max = 2 << MB_SHIFT,
            },
        },
    },
    {
        .ps_name = "cn_compact_vra",
        .ps_description = "compaction vblk memory map read-ahead",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_compact_vra),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_compact_vra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 128 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_compact_kblk_ra",
        .ps_description = "compaction kblk read-ahead (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_compact_kblk_ra),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_compact_kblk_ra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 128 << KB_SHIFT,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 32 << KB_SHIFT,
                .ps_max = 2 << MB_SHIFT,
            },
        },
    },
    {
        .ps_name = "cn_capped_ttl",
        .ps_description = "cn cursor cache TTL (ms) for capped kvs",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_capped_ttl),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_capped_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 9000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_capped_vra",
        .ps_description = "capped cursor vblk madvise-ahead (bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_capped_vra),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_capped_vra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 512 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_cursor_vra",
        .ps_description = "cursor vblk memory map read-ahead",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_cursor_vra),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_cursor_vra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_cursor_kra",
        .ps_description = "cursor kblk madvise-ahead (boolean)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct kvs_rparams, cn_cursor_kra),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_cursor_kra),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_bool = false,
        },
    },
    {
        .ps_name = "cn_cursor_seq",
        .ps_description = "optimize cn_tree for longer sequential cursor accesses",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_cursor_seq),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_cursor_seq),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        /* [HSE_REVISIT]: convert this to an enum */
        .ps_name = "cn_mcache_wbt",
        .ps_description = "eagerly cache wbt nodes (1:internal, 2:leaves, 3:both)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_wbt),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_mcache_wbt),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = 3,
            },
        },
    },
    {
        .ps_name = "cn_mcache_vmax",
        .ps_description = "value size at/above which to always read values directly from media",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_vmax),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_mcache_vmax),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 4096,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "cn_mcache_kra_params",
        .ps_description = "kblock readahead [willneed]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_kra_params),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_mcache_kra_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        },
    },
    {
        .ps_name = "cn_mcache_vra_params",
        .ps_description = "vblock readahead [willneed]",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvs_rparams, cn_mcache_vra_params),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_mcache_vra_params),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        },
    },
    {
        .ps_name = "cn_maint_disable",
        .ps_description = "disable cn maintenance",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct kvs_rparams, cn_maint_disable),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_maint_disable),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_bool = false,
        },
    },
    {
        .ps_name = "cn_bloom_create",
        .ps_description = "enable bloom creation",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_create),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_bloom_create),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_bool = true,
        },
    },
    {
        .ps_name = "cn_bloom_preload",
        .ps_description = "preload memory mapped bloom filters",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_preload),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_bloom_preload),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = false,
        },
    },
    {
        .ps_name = "cn_bloom_prob",
        .ps_description = "bloom create probability",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_prob),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_bloom_prob),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 10000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_bloom_capped",
        .ps_description = "bloom create probability (capped kvs)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_bloom_capped),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_bloom_capped),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "cn_compaction_debug",
        .ps_description = "cn compaction debug flags",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL | PARAM_FLAG_WRITABLE,
        .ps_type = PARAM_TYPE_U8,
        .ps_offset = offsetof(struct kvs_rparams, cn_compaction_debug),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_compaction_debug),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 0,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT8_MAX,
            },
        },
    },
    {
        .ps_name = "cn_maint_delay",
        .ps_description = "ms of delay between checks when idle",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvs_rparams, cn_maint_delay),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_maint_delay),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 1000,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 20,
                .ps_max = 1000 * 60,
            },
        },
    },
    {
        .ps_name = "cn_close_wait",
        .ps_description = "force close to wait until all active compactions have completed",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_BOOL,
        .ps_offset = offsetof(struct kvs_rparams, cn_close_wait),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_close_wait),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = false,
        },
    },
    {
        .ps_name = "cn_kcachesz",
        .ps_description = "max per-kvset key cache size (in bytes)",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, cn_kcachesz),
        .ps_size = PARAM_SZ(struct kvs_rparams, cn_kcachesz),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 1024 * 1024,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "capped_evict_ttl",
        .ps_description = "",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U64,
        .ps_offset = offsetof(struct kvs_rparams, capped_evict_ttl),
        .ps_size = PARAM_SZ(struct kvs_rparams, capped_evict_ttl),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_uscalar = 120,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = 0,
                .ps_max = UINT64_MAX,
            },
        },
    },
    {
        .ps_name = "mclass.policy",
        .ps_description = "media class policy",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_STRING,
        .ps_offset = offsetof(struct kvs_rparams, mclass_policy),
        .ps_size = PARAM_SZ(struct kvs_rparams, mclass_policy),
        .ps_convert = param_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = param_default_stringify,
        .ps_jsonify = param_default_jsonify,
        .ps_default_value = {
            .as_string = HSE_MPOLICY_AUTO_NAME, /* let HSE pick */
        },
        .ps_bounds = {
            .as_string = {
                .ps_max_len = HSE_MPOLICY_NAME_LEN_MAX,
            },
        },
    },
    {
        .ps_name = "value.compression.default",
        .ps_description = "Default value compression to on or off",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_ENUM,
        .ps_offset = offsetof(struct kvs_rparams, value.compression.dflt),
        .ps_size = PARAM_SZ(struct kvs_rparams, value.compression.dflt),
        .ps_convert = compression_default_converter,
        .ps_validate = param_default_validator,
        .ps_stringify = compression_default_stringify,
        .ps_jsonify = compression_default_jsonify,
        .ps_default_value = {
            .as_enum = VCOMP_DEFAULT_OFF,
        },
        .ps_bounds = {
            .as_uscalar = {
                .ps_min = VCOMP_DEFAULT_OFF,
                .ps_max = VCOMP_DEFAULT_ON,
            },
        },
    },
};

const struct param_spec *
kvs_rparams_pspecs_get(size_t *pspecs_sz)
{
    if (pspecs_sz)
        *pspecs_sz = NELEM(pspecs);
    return pspecs;
}

struct kvs_rparams
kvs_rparams_defaults()
{
    struct kvs_rparams  params;
    const struct params p = {
        .p_params = { .as_kvs_rp = &params },
        .p_type = PARAMS_KVS_RP,
    };

    param_default_populate(pspecs, NELEM(pspecs), &p);

    return params;
}

merr_t
kvs_rparams_get(
    const struct kvs_rparams *const params,
    const char *const               param,
    char *const                     buf,
    const size_t                    buf_sz,
    size_t *const                   needed_sz)
{
    const struct params p = {
        .p_params = { .as_kvs_rp = params },
        .p_type = PARAMS_KVS_RP,
    };

    return param_get(&p, pspecs, NELEM(pspecs), param, buf, buf_sz, needed_sz);
}

merr_t
kvs_rparams_set(
    const struct kvs_rparams *const params,
    const char *const               param,
    const char *const               value)
{
    const struct params p = {
        .p_params = { .as_kvs_rp = params },
        .p_type = PARAMS_KVS_RP,
    };

    if (!params || !param || !value)
        return merr(EINVAL);

    return param_set(&p, pspecs, NELEM(pspecs), param, value);
}

cJSON *
kvs_rparams_to_json(const struct kvs_rparams *const params)
{
    const struct params p = {
        .p_params = { .as_kvs_rp = params },
        .p_type = PARAMS_KVS_RP,
    };

    if (!params)
        return NULL;

    return param_to_json(&p, pspecs, NELEM(pspecs));
}
