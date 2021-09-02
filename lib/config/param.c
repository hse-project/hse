/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <fenv.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <tgmath.h>

#include <cjson/cJSON.h>
#include <bsd/string.h>

#include <hse_ikvdb/param.h>
#include <hse_util/storage.h>
#include <hse_util/log2.h>

#define IS_WHOLE(_val) (nearbyint(_val) == _val)

void
param_default_populate(
    const struct param_spec *pspecs,
    const size_t             pspecs_sz,
    const union params       params)
{
    assert(pspecs);
    assert(pspecs_sz > 0);

    char *p = (char *)params.as_generic;

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
            case PARAM_TYPE_ENUM:
                *(uint32_t *)data = ps.ps_default_value.as_enum;
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
            default:
                assert(false);
                break;
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
            assert(ps->ps_size == sizeof(bool));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsBool(node))
                return false;
            *(bool *)value = cJSON_IsTrue(node);
            break;
        }
        case PARAM_TYPE_I8: {
            assert(ps->ps_size == sizeof(int8_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < (double)INT8_MIN || to_conv > (double)INT8_MAX)
                return false;
            *(int8_t *)value = (int8_t)to_conv;
            break;
        }
        case PARAM_TYPE_I16: {
            assert(ps->ps_size == sizeof(int16_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < (double)INT16_MIN || to_conv > (double)INT16_MAX)
                return false;
            *(int16_t *)value = (int16_t)to_conv;
            break;
        }
        case PARAM_TYPE_I32: {
            assert(ps->ps_size == sizeof(int32_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < (double)INT32_MIN || to_conv > (double)INT32_MAX)
                return false;
            *(int32_t *)value = (int32_t)to_conv;
            break;
        }
        case PARAM_TYPE_I64: {
            assert(ps->ps_size == sizeof(int64_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < (double)INT64_MIN || to_conv > (double)INT64_MAX)
                return false;
            *(int64_t *)value = (int64_t)to_conv;
            break;
        }
        case PARAM_TYPE_U8: {
            assert(ps->ps_size == sizeof(uint8_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < 0 || to_conv > (double)UINT8_MAX)
                return false;
            *(uint8_t *)value = (uint8_t)to_conv;
            break;
        }
        case PARAM_TYPE_U16: {
            assert(ps->ps_size == sizeof(uint16_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < 0 || to_conv > (double)UINT16_MAX)
                return false;
            *(uint16_t *)value = (uint16_t)to_conv;
            break;
        }
        case PARAM_TYPE_U32: {
            assert(ps->ps_size == sizeof(uint32_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < 0 || to_conv > (double)UINT32_MAX)
                return false;
            *(uint32_t *)value = (uint32_t)to_conv;
            break;
        }
        case PARAM_TYPE_U64: {
            assert(ps->ps_size == sizeof(uint64_t));
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < 0 || to_conv > (double)UINT64_MAX)
                return false;
            *(uint64_t *)value = (uint64_t)to_conv;
            break;
        }
        case PARAM_TYPE_ENUM:
            assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));
            if (!cJSON_IsNumber(node))
                return false;
            const double to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv))
                return false;
            if (to_conv < 0 || to_conv > (double)UINT32_MAX)
                return false;
            *(uint32_t *)value = (uint32_t)to_conv;
            break;
        case PARAM_TYPE_STRING:
            if (cJSON_IsNull(node)) {
                memset(value, 0, ps->ps_bounds.as_string.ps_max_len);
            } else {
                if (!cJSON_IsString(node))
                    return false;
                char *       to_copy = cJSON_GetStringValue(node);
                const size_t n = strlcpy(value, to_copy, ps->ps_bounds.as_string.ps_max_len);
                if (n >= ps->ps_bounds.as_string.ps_max_len)
                    return false;
            }
            break;
        /* No default converter for array and object types */
        case PARAM_TYPE_ARRAY:
        case PARAM_TYPE_OBJECT:
        default:
            assert(false);
            break;
    }

    return true;
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
        assert(ps->ps_size == sizeof(uint32_t));
        if (to_conv < 0 || to_conv > UINT32_MAX)
            return false;
        *(uint32_t *)value = roundup_pow_of_two((unsigned long)to_conv);
        break;

    default:
        return false;
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
        case PARAM_TYPE_I8: {
            const int8_t tmp = *((int8_t *)value);
            return tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max;
        }
        case PARAM_TYPE_I16: {
            const int16_t tmp = *((int16_t *)value);
            return tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max;
        }
        case PARAM_TYPE_I32: {
            const int32_t tmp = *((int32_t *)value);
            return tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max;
        }
        case PARAM_TYPE_I64: {
            const int32_t tmp = *((int32_t *)value);
            return tmp >= ps->ps_bounds.as_scalar.ps_min && tmp <= ps->ps_bounds.as_scalar.ps_max;
        }
        case PARAM_TYPE_U8: {
            const uint8_t tmp = *((uint8_t *)value);
            return tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max;
        }
        case PARAM_TYPE_U16: {
            const uint16_t tmp = *((uint16_t *)value);
            return tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max;
        }
        case PARAM_TYPE_U32: {
            const uint32_t tmp = *((uint32_t *)value);
            return tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max;
        }
        case PARAM_TYPE_U64: {
            const uint64_t tmp = *((uint64_t *)value);
            return tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max;
        }
        case PARAM_TYPE_ENUM: {
            const uint32_t tmp = *((uint32_t *)value);
            return tmp >= ps->ps_bounds.as_enum.ps_min && tmp <= ps->ps_bounds.as_enum.ps_max;
        }
        case PARAM_TYPE_STRING: {
            if (strnlen(value, ps->ps_bounds.as_string.ps_max_len) <
                ps->ps_bounds.as_string.ps_max_len)
                return true;

            break;
        }
        /* No default validator for array types */
        case PARAM_TYPE_ARRAY:
        case PARAM_TYPE_OBJECT:
        default:
            assert(false);
            break;
    }

    return false;
}

#define STORAGE_CONVERTER(X)                                                       \
    bool param_convert_to_bytes_from_##X(                                          \
        const struct param_spec *ps, const cJSON *node, void *value)               \
    {                                                                              \
        assert(ps);                                                                \
        assert(node);                                                              \
        assert(value);                                                             \
                                                                                   \
        assert(!(ps->ps_flags & PARAM_FLAG_NULLABLE));                             \
        if (!cJSON_IsNumber(node))                                                 \
            return false;                                                          \
                                                                                   \
        const int HSE_MAYBE_UNUSED rc = feclearexcept(FE_OVERFLOW | FE_UNDERFLOW); \
        assert(rc == 0);                                                           \
                                                                                   \
        double tmp = cJSON_GetNumberValue(node);                                   \
        tmp = tmp * X;                                                             \
        if (fetestexcept(FE_OVERFLOW | FE_UNDERFLOW)) {                            \
            feclearexcept(FE_OVERFLOW | FE_UNDERFLOW);                             \
            return false;                                                          \
        }                                                                          \
                                                                                   \
        switch (ps->ps_type) {                                                     \
            case PARAM_TYPE_I8:                                                    \
                assert(ps->ps_size == sizeof(int8_t));                             \
                if (tmp < (double)INT8_MIN || tmp > (double)INT8_MAX)              \
                    return false;                                                  \
                *(int8_t *)value = (int8_t)tmp;                                    \
                break;                                                             \
            case PARAM_TYPE_I16:                                                   \
                assert(ps->ps_size == sizeof(int16_t));                            \
                if (tmp < (double)INT16_MIN || tmp > (double)INT16_MAX)            \
                    return false;                                                  \
                *(int16_t *)value = (int16_t)tmp;                                  \
                break;                                                             \
            case PARAM_TYPE_I32:                                                   \
                assert(ps->ps_size == sizeof(int32_t));                            \
                if (tmp < (double)INT32_MIN || tmp > (double)INT32_MAX)            \
                    return false;                                                  \
                *(int32_t *)value = (int32_t)tmp;                                  \
                break;                                                             \
            case PARAM_TYPE_I64:                                                   \
                assert(ps->ps_size == sizeof(int64_t));                            \
                if (tmp < (double)INT64_MIN || tmp > (double)INT64_MAX)            \
                    return false;                                                  \
                *(int64_t *)value = (int64_t)tmp;                                  \
                break;                                                             \
            case PARAM_TYPE_U8:                                                    \
                assert(ps->ps_size == sizeof(uint8_t));                            \
                if (tmp < 0 || tmp > (double)UINT8_MAX)                            \
                    return false;                                                  \
                *(uint8_t *)value = (uint8_t)tmp;                                  \
                break;                                                             \
            case PARAM_TYPE_U16:                                                   \
                assert(ps->ps_size == sizeof(uint16_t));                           \
                if (tmp < 0 || tmp > (double)UINT16_MAX)                           \
                    return false;                                                  \
                *(uint16_t *)value = (uint16_t)tmp;                                \
                break;                                                             \
            case PARAM_TYPE_U32:                                                   \
                assert(ps->ps_size == sizeof(uint32_t));                           \
                if (tmp < 0 || tmp > (double)UINT32_MAX)                           \
                    return false;                                                  \
                *(int32_t *)value = (uint32_t)tmp;                                 \
                break;                                                             \
            case PARAM_TYPE_U64:                                                   \
                assert(ps->ps_size == sizeof(uint64_t));                           \
                if (tmp < 0 || tmp > (double)UINT64_MAX)                           \
                    return false;                                                  \
                *(int64_t *)value = (uint64_t)tmp;                                 \
                break;                                                             \
            default:                                                               \
                assert(false);                                                     \
        }                                                                          \
                                                                                   \
        return true;                                                               \
    }

STORAGE_CONVERTER(KB)
STORAGE_CONVERTER(MB)
STORAGE_CONVERTER(GB)
STORAGE_CONVERTER(TB)
