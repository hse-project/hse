/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <fenv.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <tgmath.h>

#include <cjson/cJSON.h>
#include <bsd/string.h>

#include <hse_ikvdb/param.h>
#include <hse_ikvdb/hse_gparams.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>

#include <hse_util/assert.h>
#include <hse_util/storage.h>
#include <hse_util/log2.h>

#include "logging.h"

#define IS_WHOLE(_val) (round(_val) == _val)

cJSON *
param_to_json(
    const struct params *const     params,
    const struct param_spec *const pspecs,
    const size_t                   pspecs_sz)
{
    cJSON *root;

    INVARIANT(params);
    INVARIANT(pspecs);
    INVARIANT(pspecs_sz > 0);

    root = cJSON_CreateObject();

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec *ps = &pspecs[i];
        const void *             data = (char *)params->p_params.as_generic + ps->ps_offset;
        cJSON *                  item, *node = root;
        char *                   dup = strdup(ps->ps_name);
        char *                   key = dup;
        char *                   check = strchr(key, '.');
        bool                     res;

        if (!key)
            goto out;

        item = ps->ps_jsonify(ps, data);
        if (!item)
            goto out;

        while (check) {
            cJSON *   stash;
            const int idx = (uintptr_t)(check - key);

            key[idx] = '\0';
            stash = node;
            node = cJSON_GetObjectItemCaseSensitive(stash, key);
            if (!node)
                node = cJSON_AddObjectToObject(stash, key);
            if (!node)
                goto out;
            key[idx] = '.';

            /* Move past the dot */
            key = check + 1;
            assert(key[0] != '\0');

            check = strchr(key, '.');
        }

        res = cJSON_AddItemToObject(node, key, item);
        free(dup);
        if (!res)
            goto out;
    }

    return root;

out:
    cJSON_Delete(root);

    return NULL;
}

void
param_default_populate(
    const struct param_spec *pspecs,
    const size_t             pspecs_sz,
    const struct params *    params)
{
    assert(pspecs);
    assert(pspecs_sz > 0);
    assert(params);

    char *p = (char *)params->p_params.as_generic;

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec ps = pspecs[i];

        void *data = p + ps.ps_offset;
        assert(data);

        /* PARAM_TYPE_ARRAY and PARAM_TYPE_OBJECT must have PARAM_FLAG_DEFAULT_BUILDER */
        if (ps.ps_flags & PARAM_FLAG_DEFAULT_BUILDER) {
            ps.ps_default_value.as_builder(&ps, data);
            continue;
        }

        switch (ps.ps_type) {
            case PARAM_TYPE_BOOL:
                *(bool *)data = ps.ps_default_value.as_bool;
                break;
            case PARAM_TYPE_I8:
                *(int8_t *)data = ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_I16:
                *(int16_t *)data = ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_I32:
                *(int32_t *)data = ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_I64:
                *(int64_t *)data = ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_U8:
                *(uint8_t *)data = ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_U16:
                *(uint16_t *)data = ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_U32:
                *(uint32_t *)data = ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_U64:
                *(uint64_t *)data = ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_INT:
            case PARAM_TYPE_ENUM:
                *(int *)data = ps.ps_default_value.as_enum;
                break;
            case PARAM_TYPE_STRING:
                if (ps.ps_default_value.as_string) {
                    strlcpy(data, ps.ps_default_value.as_string, ps.ps_bounds.as_string.ps_max_len);
                    const size_t HSE_MAYBE_UNUSED n = strlcpy(
                        data, ps.ps_default_value.as_string, ps.ps_bounds.as_string.ps_max_len);
                    assert(n <= ps.ps_bounds.as_string.ps_max_len);
                } else {
                    memset(data, '\0', ps.ps_bounds.as_string.ps_max_len);
                }
                break;
            case PARAM_TYPE_ARRAY:
            case PARAM_TYPE_OBJECT:
                abort();
        }
    }

#ifndef NDEBUG
    /* assert that any relationships between default parameters are valid */
    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec ps = pspecs[i];
        if (ps.ps_validate_relations)
            assert(ps.ps_validate_relations(&ps, params));
    }
#endif
}

bool
param_default_converter(const struct param_spec *ps, const cJSON *node, void *value)
{
    assert(ps);
    assert(node);
    assert(value);

    switch (ps->ps_type) {
        case PARAM_TYPE_BOOL: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsBool(node)) {
                CLOG_ERR("Value of %s must be a boolean", ps->ps_name);
                return false;
            }
            *(bool *)value = cJSON_IsTrue(node);
            break;
        }
        case PARAM_TYPE_INT: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("%s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT_MIN || to_conv > INT_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to %d and less than or equal to "
                    "%d",
                    ps->ps_name,
                    INT_MIN,
                    INT_MAX);
                return false;
            }
            *(int *)value = (int)to_conv;
            break;
        }
        case PARAM_TYPE_I8: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT8_MIN || to_conv > INT8_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to %d and less than or equal to %d",
                    ps->ps_name,
                    INT8_MIN,
                    INT8_MAX);
                return false;
            }
            *(int8_t *)value = (int8_t)to_conv;
            break;
        }
        case PARAM_TYPE_I16: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT16_MIN || to_conv > INT16_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to %d and less than or equal to %d",
                    ps->ps_name,
                    INT16_MIN,
                    INT16_MAX);
                return false;
            }
            *(int16_t *)value = (int16_t)to_conv;
            break;
        }
        case PARAM_TYPE_I32: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT32_MIN || to_conv > INT32_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to %d and less than or equal to %d",
                    ps->ps_name,
                    INT32_MIN,
                    INT32_MAX);
                return false;
            }
            *(int32_t *)value = (int32_t)to_conv;
            break;
        }
        case PARAM_TYPE_I64: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("%s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT64_MIN || to_conv > (double)INT64_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to %ld and less than or equal to "
                    "%ld",
                    ps->ps_name,
                    INT64_MIN,
                    INT64_MAX);
                return false;
            }
            *(int64_t *)value = (int64_t)to_conv;
            break;
        }
        case PARAM_TYPE_U8: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            if (to_conv < 0 || to_conv > UINT8_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT8_MAX);
                return false;
            }
            *(uint8_t *)value = (uint8_t)to_conv;
            break;
        }
        case PARAM_TYPE_U16: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < 0 || to_conv > UINT16_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT16_MAX);
                return false;
            }
            *(uint16_t *)value = (uint16_t)to_conv;
            break;
        }
        case PARAM_TYPE_U32: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < 0 || to_conv > UINT32_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT32_MAX);
                return false;
            }
            *(uint32_t *)value = (uint32_t)to_conv;
            break;
        }
        case PARAM_TYPE_U64: {
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < 0 || to_conv > (double)UINT64_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %lu",
                    ps->ps_name,
                    UINT64_MAX);
                return false;
            }
            *(uint64_t *)value = (uint64_t)to_conv;
            break;
        }
        case PARAM_TYPE_ENUM:
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                CLOG_ERR("Value of %s must be a number", ps->ps_name);
                return false;
            }
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                CLOG_ERR("%s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < ps->ps_bounds.as_enum.ps_min || to_conv > ps->ps_bounds.as_enum.ps_max) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to %lu and less than or equal to "
                    "%lu",
                    ps->ps_name,
                    ps->ps_bounds.as_enum.ps_min,
                    ps->ps_bounds.as_enum.ps_max);
                return false;
            }
            *(int *)value = (int)to_conv;
            break;
        case PARAM_TYPE_STRING:
            if (cJSON_IsNull(node)) {
                memset(value, 0, ps->ps_bounds.as_string.ps_max_len);
            } else {
                if (!cJSON_IsString(node)) {
                    CLOG_ERR("Value of %s must be a string", ps->ps_name);
                    return false;
                }
                const char * to_copy = cJSON_GetStringValue(node);
                const size_t n = strlcpy(value, to_copy, ps->ps_bounds.as_string.ps_max_len);
                if (n >= ps->ps_bounds.as_string.ps_max_len) {
                    CLOG_ERR(
                        "Length of the value of %s must be less that or equal to %lu",
                        ps->ps_name,
                        ps->ps_bounds.as_string.ps_max_len - 1);
                    return false;
                }
            }
            break;
        /* No default converter for array and object types */
        case PARAM_TYPE_ARRAY:
        case PARAM_TYPE_OBJECT:
            abort();
    }

    return true;
}

merr_t
param_default_stringify(
    const struct param_spec *const ps,
    const void *const              value,
    char *const                    buf,
    const size_t                   buf_sz,
    size_t *                       needed_sz)
{
    int n = 0;

    INVARIANT(ps);
    INVARIANT(value);

    switch (ps->ps_type) {
        case PARAM_TYPE_BOOL:
            n = snprintf(buf, buf_sz, "%s", *(bool *)value ? "true" : "false");
            break;
        case PARAM_TYPE_I8:
            n = snprintf(buf, buf_sz, "%d", *(int8_t *)value);
            break;
        case PARAM_TYPE_I16:
            n = snprintf(buf, buf_sz, "%d", *(int16_t *)value);
            break;
        case PARAM_TYPE_I32:
            n = snprintf(buf, buf_sz, "%d", *(int32_t *)value);
            break;
        case PARAM_TYPE_I64:
            n = snprintf(buf, buf_sz, "%ld", *(int64_t *)value);
            break;
        case PARAM_TYPE_U8:
            n = snprintf(buf, buf_sz, "%u", *(uint8_t *)value);
            break;
        case PARAM_TYPE_U16:
            n = snprintf(buf, buf_sz, "%u", *(uint16_t *)value);
            break;
        case PARAM_TYPE_U32:
            n = snprintf(buf, buf_sz, "%u", *(uint32_t *)value);
            break;
        case PARAM_TYPE_U64:
            n = snprintf(buf, buf_sz, "%lu", *(uint64_t *)value);
            break;
        case PARAM_TYPE_INT:
        case PARAM_TYPE_ENUM:
            n = snprintf(buf, buf_sz, "%d", *(int *)value);
            break;
        case PARAM_TYPE_STRING:
            if (((char *)value)[0] == '\0') {
                n = (int)strlcpy(buf, "null", buf_sz);
            } else {
                n = snprintf(buf, buf_sz, "\"%s\"", (char *)value);
            }
            break;
        case PARAM_TYPE_ARRAY:
        case PARAM_TYPE_OBJECT:
            abort();
    }

    if (n < 0)
        return merr(EBADMSG);
    if (needed_sz)
        *needed_sz = n;

    return 0;
}

cJSON *
param_default_jsonify(const struct param_spec *const ps, const void *const value)
{
    INVARIANT(ps);
    INVARIANT(value);

    switch (ps->ps_type) {
        case PARAM_TYPE_BOOL:
            return cJSON_CreateBool(*(bool *)value);
        case PARAM_TYPE_I8:
            return cJSON_CreateNumber(*(int8_t *)value);
        case PARAM_TYPE_I16:
            return cJSON_CreateNumber(*(int16_t *)value);
        case PARAM_TYPE_I32:
            return cJSON_CreateNumber(*(int32_t *)value);
        case PARAM_TYPE_I64:
            return cJSON_CreateNumber(*(int64_t *)value);
        case PARAM_TYPE_U8:
            return cJSON_CreateNumber(*(uint8_t *)value);
        case PARAM_TYPE_U16:
            return cJSON_CreateNumber(*(uint16_t *)value);
        case PARAM_TYPE_U32:
            return cJSON_CreateNumber(*(uint32_t *)value);
        case PARAM_TYPE_U64:
            return cJSON_CreateNumber(*(uint64_t *)value);
        case PARAM_TYPE_INT:
        case PARAM_TYPE_ENUM:
            return cJSON_CreateNumber(*(int *)value);
        case PARAM_TYPE_STRING:
            return cJSON_CreateString(value);
        case PARAM_TYPE_ARRAY:
        case PARAM_TYPE_OBJECT:
            abort();
    }

    return NULL;
}

bool
param_roundup_pow2(const struct param_spec *ps, const cJSON *node, void *value)
{
    double to_conv;

    assert(ps);
    assert(node);
    assert(value);

    if (!cJSON_IsNumber(node))
        return false;

    to_conv = cJSON_GetNumberValue(node);

    switch (ps->ps_type) {
        case PARAM_TYPE_U32:
            if (to_conv < 0 || to_conv > UINT32_MAX) {
                CLOG_ERR(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT32_MAX);
                return false;
            }
            *(uint32_t *)value = roundup_pow_of_two((unsigned long)to_conv);
            break;
        default:
            abort();
    }

    return true;
}

bool
param_default_validator(const struct param_spec *ps, const void *value)
{
    assert(ps);
    assert(value);

    switch (ps->ps_type) {
        case PARAM_TYPE_BOOL:
            /* no bounds to check for boolean values */
            return true;
        case PARAM_TYPE_INT: {
            const int tmp = *(int *)value;
            if (tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %ld and less than or equal to %ld",
                ps->ps_name,
                ps->ps_bounds.as_scalar.ps_min,
                ps->ps_bounds.as_scalar.ps_max);
            break;
        }
        case PARAM_TYPE_I8: {
            const int8_t tmp = *(int8_t *)value;
            if (tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %ld and less than or equal to %ld",
                ps->ps_name,
                ps->ps_bounds.as_scalar.ps_min,
                ps->ps_bounds.as_scalar.ps_max);
            break;
        }
        case PARAM_TYPE_I16: {
            const int16_t tmp = *(int16_t *)value;
            if (tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %ld and less than or equal to %ld",
                ps->ps_name,
                ps->ps_bounds.as_scalar.ps_min,
                ps->ps_bounds.as_scalar.ps_max);
            break;
        }
        case PARAM_TYPE_I32: {
            const int32_t tmp = *(int32_t *)value;
            if (tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %ld and less than or equal to %ld",
                ps->ps_name,
                ps->ps_bounds.as_scalar.ps_min,
                ps->ps_bounds.as_scalar.ps_max);
            break;
        }
        case PARAM_TYPE_I64: {
            const int32_t tmp = *(int32_t *)value;
            if (tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %ld and less than or equal to %ld",
                ps->ps_name,
                ps->ps_bounds.as_scalar.ps_min,
                ps->ps_bounds.as_scalar.ps_max);
            break;
        }
        case PARAM_TYPE_U8: {
            const uint8_t tmp = *(uint8_t *)value;
            if (tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %lu and less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_uscalar.ps_min,
                ps->ps_bounds.as_uscalar.ps_max);
            break;
        }
        case PARAM_TYPE_U16: {
            const uint16_t tmp = *(uint16_t *)value;
            if (tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %lu and less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_uscalar.ps_min,
                ps->ps_bounds.as_uscalar.ps_max);
            break;
        }
        case PARAM_TYPE_U32: {
            const uint32_t tmp = *(uint32_t *)value;
            if (tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %lu and less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_uscalar.ps_min,
                ps->ps_bounds.as_uscalar.ps_max);
            break;
        }
        case PARAM_TYPE_U64: {
            const uint64_t tmp = *(uint64_t *)value;
            if (tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %lu and less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_uscalar.ps_min,
                ps->ps_bounds.as_uscalar.ps_max);
            break;
        }
        case PARAM_TYPE_ENUM: {
            const int tmp = *(int *)value;
            if (tmp >= ps->ps_bounds.as_enum.ps_min && tmp <= ps->ps_bounds.as_enum.ps_max)
                return true;
            CLOG_ERR(
                "Value of %s must be greater than or equal to %lu and less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_uscalar.ps_min,
                ps->ps_bounds.as_uscalar.ps_max);
            break;
        }
        case PARAM_TYPE_STRING: {
            if (strnlen(value, ps->ps_bounds.as_string.ps_max_len) <
                ps->ps_bounds.as_string.ps_max_len)
                return true;
            CLOG_ERR(
                "Length of the value of %s must be less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_string.ps_max_len - 1);
            break;
        }
        /* No default validator for array types */
        case PARAM_TYPE_ARRAY:
        case PARAM_TYPE_OBJECT:
            abort();
    }

    return false;
}

#define STORAGE_CONVERTER(_units)                                                                 \
    bool param_convert_to_bytes_from_##_units(                                                    \
        const struct param_spec *ps, const cJSON *node, void *value)                              \
    {                                                                                             \
        assert(ps);                                                                               \
        assert(node);                                                                             \
        assert(value);                                                                            \
                                                                                                  \
        assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));                                            \
        if (!cJSON_IsNumber(node)) {                                                              \
            CLOG_ERR("Value of %s must be a number", ps->ps_name);                                \
            return false;                                                                         \
        }                                                                                         \
                                                                                                  \
        const int HSE_MAYBE_UNUSED rc = feclearexcept(FE_OVERFLOW | FE_UNDERFLOW);                \
        assert(rc == 0);                                                                          \
                                                                                                  \
        double tmp = cJSON_GetNumberValue(node);                                                  \
        tmp = tmp * _units;                                                                       \
        if (fetestexcept(FE_OVERFLOW)) {                                                          \
            CLOG_ERR("Value of %s is too large", ps->ps_name);                                    \
            feclearexcept(FE_OVERFLOW);                                                           \
            return false;                                                                         \
        } else if (fetestexcept(FE_UNDERFLOW)) {                                                  \
            CLOG_ERR("Value of %s is too small", ps->ps_name);                                    \
            feclearexcept(FE_UNDERFLOW);                                                          \
            return false;                                                                         \
        }                                                                                         \
                                                                                                  \
        switch (ps->ps_type) {                                                                    \
            case PARAM_TYPE_INT:                                                                  \
                if (tmp < INT_MIN || tmp > INT_MAX) {                                             \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of a integer",            \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int *)value = (int)tmp;                                                         \
                break;                                                                            \
            case PARAM_TYPE_I8:                                                                   \
                if (tmp < INT8_MIN || tmp > INT8_MAX) {                                           \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of a signed 8-bit "       \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int8_t *)value = (int8_t)tmp;                                                   \
                break;                                                                            \
            case PARAM_TYPE_I16:                                                                  \
                if (tmp < INT16_MIN || tmp > INT16_MAX) {                                         \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of a signed 16-bit "      \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int16_t *)value = (int16_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_I32:                                                                  \
                if (tmp < INT32_MIN || tmp > INT32_MAX) {                                         \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of a signed 32-bit "      \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int32_t *)value = (int32_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_I64:                                                                  \
                if (tmp < INT64_MIN || tmp > (double)INT64_MAX) {                                 \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of a signed 64-bit "      \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int64_t *)value = (int64_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_U8:                                                                   \
                if (tmp < 0 || tmp > (double)UINT8_MAX) {                                         \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of an unsigned 8-bit "    \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(uint8_t *)value = (uint8_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_U16:                                                                  \
                if (tmp < 0 || tmp > UINT16_MAX) {                                                \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of an unsigned 16-bit "   \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(uint16_t *)value = (uint16_t)tmp;                                               \
                break;                                                                            \
            case PARAM_TYPE_U32:                                                                  \
                if (tmp < 0 || tmp > UINT32_MAX) {                                                \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of an unsigned 8=32-bit " \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int32_t *)value = (uint32_t)tmp;                                                \
                break;                                                                            \
            case PARAM_TYPE_U64:                                                                  \
                if (tmp < 0 || tmp > (double)UINT64_MAX) {                                        \
                    CLOG_ERR(                                                                     \
                        "Number of bytes of %s is not within the bounds of an unsigned 64-bit "   \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int64_t *)value = (uint64_t)tmp;                                                \
                break;                                                                            \
            default:                                                                              \
                abort();                                                                          \
        }                                                                                         \
                                                                                                  \
        return true;                                                                              \
    }

STORAGE_CONVERTER(KB)
STORAGE_CONVERTER(MB)
STORAGE_CONVERTER(GB)
STORAGE_CONVERTER(TB)

#undef STORAGE_CONVERTER

#define STORAGE_STRINGIFY(X)                                                        \
    merr_t param_stringify_bytes_to_##X(                                            \
        const struct param_spec *const ps,                                          \
        const void *const              value,                                       \
        char *const                    buf,                                         \
        const size_t                   buf_sz,                                      \
        size_t *                       needed_sz)                                   \
    {                                                                               \
        int n;                                                                      \
                                                                                    \
        switch (ps->ps_type) {                                                      \
            case PARAM_TYPE_INT:                                                    \
                n = snprintf(buf, buf_sz, "%ld", *(int *)value / (int64_t)X);       \
                break;                                                              \
            case PARAM_TYPE_I8:                                                     \
                n = snprintf(buf, buf_sz, "%ld", *(int8_t *)value / (int64_t)X);    \
                break;                                                              \
            case PARAM_TYPE_I16:                                                    \
                n = snprintf(buf, buf_sz, "%ld", *(int16_t *)value / (int64_t)X);   \
                break;                                                              \
            case PARAM_TYPE_I32:                                                    \
                n = snprintf(buf, buf_sz, "%ld", *(int32_t *)value / (int64_t)X);   \
                break;                                                              \
            case PARAM_TYPE_I64:                                                    \
                n = snprintf(buf, buf_sz, "%ld", *(int64_t *)value / (int64_t)X);   \
                break;                                                              \
            case PARAM_TYPE_U8:                                                     \
                n = snprintf(buf, buf_sz, "%lu", *(uint8_t *)value / (uint64_t)X);  \
                break;                                                              \
            case PARAM_TYPE_U16:                                                    \
                n = snprintf(buf, buf_sz, "%lu", *(uint16_t *)value / (uint64_t)X); \
                break;                                                              \
            case PARAM_TYPE_U32:                                                    \
                n = snprintf(buf, buf_sz, "%lu", *(uint32_t *)value / (uint64_t)X); \
                break;                                                              \
            case PARAM_TYPE_U64:                                                    \
                n = snprintf(buf, buf_sz, "%lu", *(uint64_t *)value / (uint64_t)X); \
                break;                                                              \
            default:                                                                \
                abort();                                                            \
        }                                                                           \
                                                                                    \
        if (n < 0)                                                                  \
            return merr(EBADMSG);                                                   \
        if (needed_sz)                                                              \
            *needed_sz = n;                                                         \
                                                                                    \
        return 0;                                                                   \
    }

STORAGE_STRINGIFY(KB)
STORAGE_STRINGIFY(MB)
STORAGE_STRINGIFY(GB)
STORAGE_STRINGIFY(TB)

#undef STORAGE_STRINGIFY

#define STORAGE_JSONIFY(X)                                                                        \
    cJSON *param_jsonify_bytes_to_##X(const struct param_spec *const ps, const void *const value) \
    {                                                                                             \
        switch (ps->ps_type) {                                                                    \
            case PARAM_TYPE_INT:                                                                  \
                return cJSON_CreateNumber(*(int *)value / (double)X);                             \
            case PARAM_TYPE_I8:                                                                   \
                return cJSON_CreateNumber(*(int8_t *)value / (double)X);                          \
            case PARAM_TYPE_I16:                                                                  \
                return cJSON_CreateNumber(*(int16_t *)value / (double)X);                         \
            case PARAM_TYPE_I32:                                                                  \
                return cJSON_CreateNumber(*(int32_t *)value / (double)X);                         \
            case PARAM_TYPE_I64:                                                                  \
                return cJSON_CreateNumber(*(int64_t *)value / (double)X);                         \
            case PARAM_TYPE_U8:                                                                   \
                return cJSON_CreateNumber(*(uint8_t *)value / (double)X);                         \
            case PARAM_TYPE_U16:                                                                  \
                return cJSON_CreateNumber(*(uint16_t *)value / (double)X);                        \
            case PARAM_TYPE_U32:                                                                  \
                return cJSON_CreateNumber(*(uint32_t *)value / (double)X);                        \
            case PARAM_TYPE_U64:                                                                  \
                return cJSON_CreateNumber(*(uint64_t *)value / (double)X);                        \
            default:                                                                              \
                abort();                                                                          \
        }                                                                                         \
    }

STORAGE_JSONIFY(KB)
STORAGE_JSONIFY(MB)
STORAGE_JSONIFY(GB)
STORAGE_JSONIFY(TB)

merr_t
param_get(
    const struct params *const     params,
    const struct param_spec *const pspecs,
    const size_t                   pspecs_sz,
    const char *const              param,
    char *const                    buf,
    const size_t                   buf_sz,
    size_t *const                  needed_sz)
{
    const struct param_spec *ps = NULL;

    if (!params || !params->p_params.as_generic || !pspecs || !param)
        return merr(EINVAL);

    for (size_t i = 0; i < pspecs_sz; i++)
        if (!strcmp(pspecs[i].ps_name, param))
            ps = &pspecs[i];

    if (!ps)
        return merr(EINVAL);

    assert(ps->ps_stringify);
    return ps->ps_stringify(
        ps, (char *)params->p_params.as_generic + ps->ps_offset, buf, buf_sz, needed_sz);
}

MTF_STATIC size_t
params_size(const struct params *const params)
{
    switch (params->p_type) {
    case PARAMS_HSE_GP:
        return sizeof(struct hse_gparams);
    case PARAMS_KVDB_CP:
        return sizeof(struct kvdb_cparams);
    case PARAMS_KVDB_RP:
        return sizeof(struct kvdb_rparams);
    case PARAMS_KVS_CP:
        return sizeof(struct kvs_cparams);
    case PARAMS_KVS_RP:
        return sizeof(struct kvs_rparams);
    default:
        abort();
    }
}

merr_t
param_set(
    const struct params *const     params,
    const struct param_spec *const pspecs,
    const size_t                   pspecs_sz,
    const char *const              param,
    const char *const              value)
{
    merr_t                   err = 0;
    cJSON *                  node;
    const struct param_spec *ps = NULL;
    size_t                   n;
    void *                   new = NULL;
    void *                   data;
    int                      rc HSE_MAYBE_UNUSED;
    static pthread_mutex_t   lock = PTHREAD_MUTEX_INITIALIZER;

    INVARIANT(params);
    INVARIANT(pspecs);
    INVARIANT(pspecs_sz > 0);
    INVARIANT(param);
    INVARIANT(value);

    node = cJSON_Parse(value);
    if (!node) {
        if (cJSON_GetErrorPtr()) {
            log_err("Failed to parse %s %s: %s", params_logging_context(params), param, value);
            return merr(EINVAL);
        } else {
            return merr(ENOMEM);
        }
    }

    for (size_t i = 0; i < pspecs_sz; i++) {
        if (!strcmp(pspecs[i].ps_name, param)) {
            ps = &pspecs[i];
        }
    }

    if (!ps) {
        log_err("Unknown parameter %s", param);
        err = merr(EINVAL);
        goto out;
    }

    if (!(ps->ps_flags & PARAM_FLAG_WRITABLE)) {
        log_err("%s is not writable", param);
        err = merr(EINVAL);
        goto out;
    }

    n = params_size(params);

    new = malloc(n);
    if (!new) {
        err = merr(ENOMEM);
        goto out;
    }

    memcpy(new, params->p_params.as_generic, n);

    data = (char *)new + ps->ps_offset;

    if (!ps->ps_convert(ps, node, data)) {
        log_err("Failed to convert %s %s", params_logging_context(params), param);
        err = merr(EINVAL);
        goto out;
    }

    if (!ps->ps_validate(ps, data)) {
        log_err("Failed to validate %s %s", params_logging_context(params), param);
        err = merr(EINVAL);
        goto out;
    }

    if (ps->ps_validate_relations &&!ps->ps_validate_relations(ps,
            &(struct params){ .p_params = { .as_generic = new }, .p_type = PARAMS_GEN})) {
        log_err(
            "Failed to validate parameter relationships for %s %s",
            params_logging_context(params),
            ps->ps_name);
        err = merr(EINVAL);
        goto out;
    }

    rc = pthread_mutex_lock(&lock);
    assert(!rc);

    /* [HSE_REVISIT]: This is a race condition. The way params are currently
     * designed doesn't allow for mutexes to be a part of the equation easily.
     * So when we do this memcpy(), there is a chance someone somewhere could be
     * reading the exact same value we are changing. I think one solution we
     * could follow-up with is a registration system, where components register
     * to be notified when values change.
     */

    assert(ps->ps_size > 0);
    memcpy((char *)params->p_params.as_generic + ps->ps_offset, data, ps->ps_size);

    rc = pthread_mutex_unlock(&lock);
    assert(!rc);

out:
    free(new);
    cJSON_Delete(node);

    return err;
}
