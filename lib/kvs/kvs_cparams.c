/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <limits.h>
#include <stddef.h>

#include <hse/limits.h>
#include <hse/ikvdb/limits.h>
#include <hse/config/params.h>
#include <hse/ikvdb/kvs_cparams.h>
#include <hse/util/base.h>

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
        .ps_flags = PARAM_EXPERIMENTAL,
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
    struct kvs_cparams params;

    params_from_defaults(&params, NELEM(pspecs), pspecs);

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
    return params_get(params, NELEM(pspecs), pspecs, param, buf, buf_sz, needed_sz);
}

merr_t
kvs_cparams_from_paramv(
    struct kvs_cparams *const params,
    const size_t              paramc,
    const char *const *const  paramv)
{
    assert(params);

    return params_from_paramv(params, paramc, paramv, NELEM(pspecs), pspecs);
}

cJSON *
kvs_cparams_to_json(const struct kvs_cparams *const params)
{
    if (!params)
        return NULL;

    return params_to_json(params, NELEM(pspecs), pspecs);
}
