/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <hse_ikvdb/param.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/hse_gparams.h>
#include <hse_util/compiler.h>
#include <hse/error/merr.h>

#include "logging.h"

MTF_STATIC merr_t
argv_deserialize_to_params(
    const size_t                   paramc,
    const char *const *const       paramv,
    const size_t                   pspecs_sz,
    const struct param_spec *const pspecs,
    const struct params     *const params)
{
    merr_t err = 0;

    assert(pspecs);

    for (size_t i = 0; i < paramc; i++) {
        const char *param = paramv[i];
        if (!param || *param == '\0')
            continue;

        const char *key = param;
        const char *value = strstr(param, "=");
        if (!value || value[1] == '\0') {
            CLOG_ERR("Parameter key/value pairs must be of the form <key=value>");
            err = merr(EINVAL);
            goto out;
        }

        const struct param_spec *ps = NULL;
        for (size_t j = 0; j < pspecs_sz; j++) {
            if (!strncmp(pspecs[j].ps_name, key, value - key)) {
                ps = &pspecs[j];
                break;
            }
        }

        if (!ps) {
            CLOG_ERR("Unknown parameter %s", key);
            err = merr(EINVAL);
            goto out;
        }

        /* Point value at one character past the '=' */
        value++;

        void *data = ((char *)params->p_params.as_generic) + ps->ps_offset;

        cJSON *node = cJSON_Parse(value);
        if (!node) {
            /* If we couldn't successfully parse the value plainly, then convert
             * it to a string by sticking the value in between two quote
             * characters. This happens when we have unquoted strings like
             * 'kvdb.socket.path=/tmp' or malformed JSON like dropping a
             * bracket in an array declaration. When this config string
             * eventually gets deserialized into params objects, we will find
             * the error if one exists after string conversion.
             */

            /* Copy pair into work buffer. Need 3 extra bytes: 1 for NULL
             * termination, and 2 for adding quotes when parsing value.
             */
            const size_t buf_sz = strlen(value) + 3;
            char *       buf = malloc(buf_sz);

            HSE_MAYBE_UNUSED const size_t n = snprintf(buf, buf_sz, "\"%s\"", value);
            assert(n < buf_sz);

            node = cJSON_Parse(buf);
            free(buf);

            if (!node) {
                if (cJSON_GetErrorPtr()) {
                    CLOG_ERR("Failed to parse %s %s: %s", params_logging_context(params), ps->ps_name, param);
                    err = merr(EINVAL);
                } else {
                    err = merr(ENOMEM);
                }
                goto out;
            }
        }

        CLOG_DEBUG("Applying %s %s from paramv", params_logging_context(params), ps->ps_name);

        if (cJSON_IsNull(node) && !(ps->ps_flags & PARAM_FLAG_NULLABLE)) {
            CLOG_ERR("%s %s cannot be null", params_logging_context(params), ps->ps_name);
            cJSON_Delete(node);
            err = merr(EINVAL);
            goto out;
        }

        assert(ps->ps_convert);
        if (!ps->ps_convert(ps, node, data)) {
            CLOG_ERR("Failed to convert %s %s", params_logging_context(params), key);
            cJSON_Delete(node);
            err = merr(EINVAL);
            goto out;
        }

        cJSON_Delete(node);

        /* Some param_specs may not have validate functions if their
         * conversion functions are well thought out, for instance when
         * deserializing an array.
         */
        if (ps->ps_validate && !ps->ps_validate(ps, data)) {
            CLOG_ERR("Failed to validate %s %s", params_logging_context(params), key);
            err = merr(EINVAL);
            goto out;
        }
    }

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec *ps = &pspecs[i];
        if (ps->ps_validate_relations && !ps->ps_validate_relations(ps, params)) {
            CLOG_ERR("Failed to validate parameter relationships for %s %s", params_logging_context(params), ps->ps_name);
            err = merr(EINVAL);
            goto out;
        }
    }

out:
    return err;
}

merr_t
argv_deserialize_to_kvdb_rparams(
    const size_t               paramc,
    const char *const *const   paramv,
    struct kvdb_rparams *const params)
{
    size_t                   pspecs_sz;
    const struct param_spec *pspecs;
    const struct params      p = { .p_type = PARAMS_KVDB_RP, .p_params = { .as_kvdb_rp = params } };

    assert(params);

    pspecs = kvdb_rparams_pspecs_get(&pspecs_sz);

    return argv_deserialize_to_params(paramc, paramv, pspecs_sz, pspecs, &p);
}

merr_t
argv_deserialize_to_kvdb_cparams(
    const size_t               paramc,
    const char *const *const   paramv,
    struct kvdb_cparams *const params)
{
    size_t                   pspecs_sz;
    const struct param_spec *pspecs;
    const struct params      p = { .p_type = PARAMS_KVDB_CP, .p_params = { .as_kvdb_cp = params } };

    assert(params);

    pspecs = kvdb_cparams_pspecs_get(&pspecs_sz);

    return argv_deserialize_to_params(paramc, paramv, pspecs_sz, pspecs, &p);
}

merr_t
argv_deserialize_to_kvs_rparams(
    const size_t              paramc,
    const char *const *const  paramv,
    struct kvs_rparams *const params)
{
    size_t                   pspecs_sz;
    const struct param_spec *pspecs;
    const struct params      p = { .p_type = PARAMS_KVS_RP, .p_params = { .as_kvs_rp = params } };

    assert(params);

    pspecs = kvs_rparams_pspecs_get(&pspecs_sz);

    return argv_deserialize_to_params(paramc, paramv, pspecs_sz, pspecs, &p);
}

merr_t
argv_deserialize_to_kvs_cparams(
    const size_t              paramc,
    const char *const *const  paramv,
    struct kvs_cparams *const params)
{
    size_t                   pspecs_sz;
    const struct param_spec *pspecs;
    const struct params      p = { .p_type = PARAMS_KVS_CP, .p_params = { .as_kvs_cp = params } };

    assert(params);

    pspecs = kvs_cparams_pspecs_get(&pspecs_sz);

    return argv_deserialize_to_params(paramc, paramv, pspecs_sz, pspecs, &p);
}

merr_t
argv_deserialize_to_hse_gparams(
    const size_t              paramc,
    const char *const *const  paramv,
    struct hse_gparams *const params)
{
    size_t                   pspecs_sz;
    const struct param_spec *pspecs;
    const struct params      p = { .p_type = PARAMS_HSE_GP, .p_params = { .as_hse_gp = params } };

    pspecs = hse_gparams_pspecs_get(&pspecs_sz);

    return argv_deserialize_to_params(paramc, paramv, pspecs_sz, pspecs, &p);
}
