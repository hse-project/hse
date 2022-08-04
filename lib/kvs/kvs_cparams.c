/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>
#include <stddef.h>

#include <hse/limits.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_util/base.h>

static const struct param_spec pspecs[] = {
    {
        .ps_name = "prefix.length",
        .ps_description = "Key prefix length",
        .ps_flags = 0,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvs_cparams, pfx_len),
        .ps_size = PARAM_SZ(struct kvs_cparams, pfx_len),
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
                .ps_max = HSE_KVS_PFX_LEN_MAX,
            },
        },
    },
    {
        .ps_name = "kvs_ext01",
        .ps_description = "kvs_ext01",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvs_cparams, kvs_ext01),
        .ps_size = PARAM_SZ(struct kvs_cparams, kvs_ext01),
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
                .ps_max = UINT32_MAX,
            },
        },
    },
    {
        .ps_name = "suffix.length",
        .ps_description = "Key suffix length",
        .ps_flags = PARAM_FLAG_EXPERIMENTAL,
        .ps_type = PARAM_TYPE_U32,
        .ps_offset = offsetof(struct kvs_cparams, sfx_len),
        .ps_size = PARAM_SZ(struct kvs_cparams, sfx_len),
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
                .ps_max = UINT32_MAX,
            }
        }
    }
};

const struct param_spec *
kvs_cparams_pspecs_get(size_t *pspecs_sz)
{
    if (pspecs_sz)
        *pspecs_sz = NELEM(pspecs);
    return pspecs;
}

struct kvs_cparams
kvs_cparams_defaults()
{
    struct kvs_cparams  params;
    const struct params p = { .p_type = PARAMS_KVS_CP, .p_params = { .as_kvs_cp = &params } };

    param_default_populate(pspecs, NELEM(pspecs), &p);
    return params;
}

merr_t
kvs_cparams_get(
    const struct kvs_cparams *const params,
    const char *const               param,
    char *const                     buf,
    const size_t                    buf_sz,
    size_t *const                   needed_sz)
{
    const struct params p = { .p_params = { .as_kvs_cp = params }, .p_type = PARAMS_KVS_CP };

    return param_get(&p, pspecs, NELEM(pspecs), param, buf, buf_sz, needed_sz);
}

cJSON *
kvs_cparams_to_json(const struct kvs_cparams *const params)
{
    if (!params)
        return NULL;

    const struct params p = { .p_params = { .as_kvs_cp = params }, .p_type = PARAMS_KVS_CP };

    return param_to_json(&p, pspecs, NELEM(pspecs));
}
