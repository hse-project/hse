/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <fenv.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>

#include <hse/config/params.h>
#include <hse/logging/logging.h>
#include <hse/util/assert.h>
#include <hse/util/log2.h>
#include <hse/util/mutex.h>
#include <hse/util/storage.h>

#define IS_WHOLE(_val) (round(_val) == _val)

/**
 * Walk and deserialize a JSON object recursively
 *
 * @param node Current node to walk through
 * @param params Params object
 * @param pspecs Array of param_spec to search through
 * @param pspecs_sz Size of @p pspecs
 * @param ignore_keys Keys to ignore while recursing
 * @param ignore_keys_sz Size of @p ignore_keys
 * @param prefix Prefix for hierarchical keys (x.y.z)
 * @param bypass Bypass current recurse, so keys don't get prefixed unnecessarily
 *
 * @return error status
 * @retval non-zero on error
 */
static merr_t
json_walk(
    const cJSON *const         node,
    void *const                params,
    const size_t               pspecs_sz,
    const struct param_spec *  pspecs,
    const size_t               ignore_keys_sz,
    const char *const *const   ignore_keys,
    const char *const          prefix,
    const bool                 bypass)
{
    merr_t                   err = 0;
    char *                   key = NULL;
    const struct param_spec *ps = NULL;

    const size_t prefix_sz = prefix ? strlen(prefix) : 0;
    const size_t node_str_sz = node->string ? strlen(node->string) : 0;
    /* +2 for NUL byte and potential '.' separator */
    const size_t key_sz = prefix_sz + node_str_sz + 2;

    INVARIANT(pspecs_sz > 0);
    INVARIANT(pspecs);
    INVARIANT(node);
    INVARIANT(ignore_keys ? ignore_keys_sz > 0 : true);
    INVARIANT(bypass ? cJSON_IsObject(node) : true);

    if (!bypass) {
        /* Protect against configs like { "prefix.length": 5 } */
        if (strchr(node->string, '.')) {
            log_err("Keys in config files cannot contain a '.'");
            err = merr(EINVAL);
            goto out;
        }

        assert(key_sz > 0);
        key = malloc(key_sz);
        if (!key) {
            err = merr(ENOMEM);
            goto out;
        }

        if (prefix) {
            const int overflow = snprintf(key, key_sz, "%s.%s", prefix, node->string);
            assert(overflow == key_sz - 1);
            if (overflow < 0) {
                err = merr(EBADMSG);
                goto out;
            }
        } else {
            HSE_MAYBE_UNUSED const size_t sz = strlcpy(key, node->string, key_sz);
            assert(sz == node_str_sz);
        }

        for (size_t i = 0; i < ignore_keys_sz; i++) {
            const char *ignore_key = ignore_keys[i];
            if (!strcmp(ignore_key, key))
                goto out;
        }

        for (size_t i = 0; i < pspecs_sz; i++) {
            if (!strcmp(pspecs[i].ps_name, key)) {
                ps = &pspecs[i];
                break;
            }
        }
    }

    if ((cJSON_IsObject(node) && !ps) || bypass) {
        for (cJSON *n = node->child; n; n = n->next) {
            err = json_walk(n, params, pspecs_sz, pspecs, ignore_keys_sz, ignore_keys, key, false);
            if (err)
                goto out;
        }
    } else {
        void *data;

        /* Key not found */
        if (!ps) {
            log_err("Unknown parameter %s", key);
            err = merr(EINVAL);
            goto out;
        }

        log_debug("Applying %s from config file", ps->ps_name);

        if (cJSON_IsNull(node) && !(ps->ps_flags & PARAM_NULLABLE)) {
            log_err("%s cannot be null", ps->ps_name);
            err = merr(EINVAL);
            goto out;
        }

        data = (char *)params + ps->ps_offset;

        assert(ps->ps_convert);
        if (!ps->ps_convert(ps, node, data)) {
            log_err("Failed to convert %s", key);
            err = merr(EINVAL);
            goto out;
        }

        /* Some param_specs may not have validate functions if their
         * conversion functions are well thought out, for instance when
         * deserializing an array.
         */
        if (ps->ps_validate && !ps->ps_validate(ps, data)) {
            log_err("Failed to validate %s", key);
            err = merr(EINVAL);
            goto out;
        }
    }

out:
    if (key)
        free(key);

    return err;
}

bool
param_default_converter(const struct param_spec *ps, const cJSON *node, void *value)
{
    assert(ps);
    assert(node);
    assert(value);

    switch (ps->ps_type) {
        case PARAM_TYPE_BOOL: {
            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsBool(node)) {
                log_err("Value of %s must be a boolean", ps->ps_name);
                return false;
            }
            *(bool *)value = cJSON_IsTrue(node);
            break;
        }
        case PARAM_TYPE_INT: {
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("%s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT_MIN || to_conv > INT_MAX) {
                log_err(
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
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT8_MIN || to_conv > INT8_MAX) {
                log_err(
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
            double to_conv;
            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT16_MIN || to_conv > INT16_MAX) {
                log_err(
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
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < INT32_MIN || to_conv > INT32_MAX) {
                log_err(
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
            char *end;
            int64_t tmp;
            char buf[32];
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }

            /* Converting a double to an int64_t is extremely difficult.
             * Confirm that the double is a whole number, convert it to a
             * string, and parse the string to an int64_t.
             */
            snprintf(buf, sizeof(buf), "%.0lf", to_conv);
            errno = 0;
            tmp = strtoll(buf, &end, 10);
            if ((tmp == LLONG_MAX && errno == ERANGE) || *end != '\0') {
                log_err(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %ld",
                    ps->ps_name,
                    INT64_MAX);
                return false;
            }
            *(int64_t *)value = tmp;
            break;
        }
        case PARAM_TYPE_U8: {
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }
            if (to_conv < 0 || to_conv > UINT8_MAX) {
                log_err(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT8_MAX);
                return false;
            }
            *(uint8_t *)value = (uint8_t)to_conv;
            break;
        }
        case PARAM_TYPE_U16: {
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < 0 || to_conv > UINT16_MAX) {
                log_err(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT16_MAX);
                return false;
            }
            *(uint16_t *)value = (uint16_t)to_conv;
            break;
        }
        case PARAM_TYPE_U32: {
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < 0 || to_conv > UINT32_MAX) {
                log_err(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT32_MAX);
                return false;
            }
            *(uint32_t *)value = (uint32_t)to_conv;
            break;
        }
        case PARAM_TYPE_U64: {
            char *end;
            char buf[32];
            uint64_t tmp;
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }

            /* Converting a double to a uint64_t is extremely difficult.
             * Confirm that the double is a whole number, convert it to a
             * string, and parse the string to a uint64_t.
             */
            snprintf(buf, sizeof(buf), "%.0lf", to_conv);
            errno = 0;
            tmp = strtoull(buf, &end, 10);
            if (to_conv < 0 || (tmp == ULLONG_MAX && errno == ERANGE) || *end != '\0') {
                log_err(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %lu",
                    ps->ps_name,
                    UINT64_MAX);
                return false;
            }
            *(uint64_t *)value = tmp;
            break;
        }
        case PARAM_TYPE_SIZE: {
            char *end;
            char buf[32];
            double to_conv;
            unsigned long long tmp;
            unsigned long long error;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("Value of %s must be a whole number", ps->ps_name);
                return false;
            }

            /* Converting a double to a 64-bit size_t is extremely difficult.
             * Confirm that the double is a whole number, convert it to a
             * string, and parse the string to a size_t.
             */
            snprintf(buf, sizeof(buf), "%.0lf", to_conv);
            errno = 0;
#if SIZE_MAX == UINT64_MAX
            error = ULLONG_MAX;
            tmp = strtoull(buf, &end, 10);
#else
            error = ULONG_MAX;
            tmp = strtoul(buf, &end, 10);
#endif
            if (to_conv < 0 || (tmp == error && errno == ERANGE) || tmp > SIZE_MAX ||
                    *end != '\0') {
                log_err(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %zu",
                    ps->ps_name,
                    SIZE_MAX);
                return false;
            }
            *(size_t *)value = tmp;
            break;
        }
        case PARAM_TYPE_ENUM: {
            double to_conv;

            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }

            to_conv = cJSON_GetNumberValue(node);
            if (!IS_WHOLE(to_conv)) {
                log_err("%s must be a whole number", ps->ps_name);
                return false;
            }
            if (to_conv < ps->ps_bounds.as_enum.ps_min || to_conv > ps->ps_bounds.as_enum.ps_max) {
                log_err(
                    "Value of %s must be greater than or equal to %d and less than or equal to "
                    "%d",
                    ps->ps_name,
                    ps->ps_bounds.as_enum.ps_min,
                    ps->ps_bounds.as_enum.ps_max);
                return false;
            }
            *(int *)value = (int)to_conv;
            break;
        }
        case PARAM_TYPE_DOUBLE:
            assert(!(ps->ps_flags & PARAM_NULLABLE));
            if (!cJSON_IsNumber(node)) {
                log_err("Value of %s must be a number", ps->ps_name);
                return false;
            }
            *(double *)value = cJSON_GetNumberValue(node);
            break;
        case PARAM_TYPE_STRING:
            if (cJSON_IsNull(node)) {
                memset(value, 0, ps->ps_bounds.as_string.ps_max_len);
            } else {
                size_t n;
                const char *to_copy;

                if (!cJSON_IsString(node)) {
                    log_err("Value of %s must be a string", ps->ps_name);
                    return false;
                }

                to_copy = cJSON_GetStringValue(node);
                n = strlcpy(value, to_copy, ps->ps_bounds.as_string.ps_max_len);
                if (n >= ps->ps_bounds.as_string.ps_max_len) {
                    log_err(
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
            return cJSON_CreateNumber((double)(*(int64_t *)value));
        case PARAM_TYPE_U8:
            return cJSON_CreateNumber(*(uint8_t *)value);
        case PARAM_TYPE_U16:
            return cJSON_CreateNumber(*(uint16_t *)value);
        case PARAM_TYPE_U32:
            return cJSON_CreateNumber(*(uint32_t *)value);
        case PARAM_TYPE_U64:
            return cJSON_CreateNumber((double)(*(uint64_t *)value));
        case PARAM_TYPE_SIZE:
            return cJSON_CreateNumber((double)(*(size_t *)value));
        case PARAM_TYPE_INT:
        case PARAM_TYPE_ENUM:
            return cJSON_CreateNumber(*(int *)value);
        case PARAM_TYPE_DOUBLE:
            return cJSON_CreateNumber(*(double *)value);
        case PARAM_TYPE_STRING:
            return cJSON_CreateString(value);
        case PARAM_TYPE_ARRAY:
        case PARAM_TYPE_OBJECT:
            abort();
    }

    return NULL;
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
        case PARAM_TYPE_SIZE:
            n = snprintf(buf, buf_sz, "%zu", *(size_t *)value);
            break;
        case PARAM_TYPE_INT:
        case PARAM_TYPE_ENUM:
            n = snprintf(buf, buf_sz, "%d", *(int *)value);
            break;
        case PARAM_TYPE_DOUBLE:
            n = snprintf(buf, buf_sz, "%lf", *(double *)value);
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
        *needed_sz = (size_t)n;

    return 0;
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
            log_err(
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
            log_err(
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
            log_err(
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
            log_err(
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
            log_err(
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
            log_err(
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
            log_err(
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
            log_err(
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
            log_err(
                "Value of %s must be greater than or equal to %lu and less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_uscalar.ps_min,
                ps->ps_bounds.as_uscalar.ps_max);
            break;
        }
        case PARAM_TYPE_SIZE: {
            const size_t tmp = *(size_t *)value;
            if (tmp >= ps->ps_bounds.as_uscalar.ps_min && tmp <= ps->ps_bounds.as_uscalar.ps_max)
                return true;
            log_err(
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
            log_err(
                "Value of %s must be greater than or equal to %lu and less than or equal to %lu",
                ps->ps_name,
                ps->ps_bounds.as_uscalar.ps_min,
                ps->ps_bounds.as_uscalar.ps_max);
            break;
        }
        case PARAM_TYPE_DOUBLE: {
            const double tmp = *((double *)value);
            if (tmp >= ps->ps_bounds.as_double.ps_min && tmp <= ps->ps_bounds.as_double.ps_max)
                return true;
            log_err(
                "Value of %s must be greater than or equal to %f and less than or equal to %f",
                ps->ps_name,
                ps->ps_bounds.as_double.ps_min,
                ps->ps_bounds.as_double.ps_max);
            break;
        }
        case PARAM_TYPE_STRING: {
            if (strnlen(value, ps->ps_bounds.as_string.ps_max_len) <
                ps->ps_bounds.as_string.ps_max_len)
                return true;
            log_err(
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
                log_err(
                    "Value of %s must be greater than or equal to 0 and less than or equal to %u",
                    ps->ps_name,
                    UINT32_MAX);
                return false;
            }
            *(uint32_t *)value = (uint32_t)roundup_pow_of_two((unsigned long)to_conv);
            break;
        default:
            abort();
    }

    return true;
}

#define STORAGE_CONVERTER(_units)                                                                 \
    bool param_convert_to_bytes_from_##_units(                                                    \
        const struct param_spec *ps, const cJSON *node, void *value)                              \
    {                                                                                             \
        double tmp;                                                                               \
        int rc HSE_MAYBE_UNUSED;                                                                  \
                                                                                                  \
        assert(ps);                                                                               \
        assert(node);                                                                             \
        assert(value);                                                                            \
                                                                                                  \
        assert(!(ps->ps_flags & PARAM_NULLABLE));                                            \
        if (!cJSON_IsNumber(node)) {                                                              \
            log_err("Value of %s must be a number", ps->ps_name);                                 \
            return false;                                                                         \
        }                                                                                         \
                                                                                                  \
        rc = feclearexcept(FE_OVERFLOW | FE_UNDERFLOW);                                           \
        assert(rc == 0);                                                                          \
                                                                                                  \
        tmp = cJSON_GetNumberValue(node);                                                         \
        tmp = tmp * _units;                                                                       \
        if (fetestexcept(FE_OVERFLOW)) {                                                          \
            log_err("Value of %s is too large", ps->ps_name);                                     \
            feclearexcept(FE_OVERFLOW);                                                           \
            return false;                                                                         \
        } else if (fetestexcept(FE_UNDERFLOW)) {                                                  \
            log_err("Value of %s is too small", ps->ps_name);                                     \
            feclearexcept(FE_UNDERFLOW);                                                          \
            return false;                                                                         \
        }                                                                                         \
                                                                                                  \
        switch (ps->ps_type) {                                                                    \
            case PARAM_TYPE_INT:                                                                  \
                if (tmp < INT_MIN || tmp > INT_MAX) {                                             \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of a integer",            \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int *)value = (int)tmp;                                                         \
                break;                                                                            \
            case PARAM_TYPE_I8:                                                                   \
                if (tmp < INT8_MIN || tmp > INT8_MAX) {                                           \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of a signed 8-bit "       \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int8_t *)value = (int8_t)tmp;                                                   \
                break;                                                                            \
            case PARAM_TYPE_I16:                                                                  \
                if (tmp < INT16_MIN || tmp > INT16_MAX) {                                         \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of a signed 16-bit "      \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int16_t *)value = (int16_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_I32:                                                                  \
                if (tmp < INT32_MIN || tmp > INT32_MAX) {                                         \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of a signed 32-bit "      \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int32_t *)value = (int32_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_I64:                                                                  \
                if (tmp < INT64_MIN || tmp > (double)INT64_MAX) {                                 \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of a signed 64-bit "      \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(int64_t *)value = (int64_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_U8:                                                                   \
                if (tmp < 0 || tmp > (double)UINT8_MAX) {                                         \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of an unsigned 8-bit "    \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(uint8_t *)value = (uint8_t)tmp;                                                 \
                break;                                                                            \
            case PARAM_TYPE_U16:                                                                  \
                if (tmp < 0 || tmp > UINT16_MAX) {                                                \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of an unsigned 16-bit "   \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(uint16_t *)value = (uint16_t)tmp;                                               \
                break;                                                                            \
            case PARAM_TYPE_U32:                                                                  \
                if (tmp < 0 || tmp > UINT32_MAX) {                                                \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of an unsigned 8=32-bit " \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(uint32_t *)value = (uint32_t)tmp;                                               \
                break;                                                                            \
            case PARAM_TYPE_U64:                                                                  \
                if (tmp < 0 || tmp > (long double)UINT64_MAX) {                                   \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of an unsigned 64-bit "   \
                        "integer",                                                                \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(uint64_t *)value = (uint64_t)tmp;                                               \
                break;                                                                            \
            case PARAM_TYPE_SIZE:                                                                 \
                if (tmp < 0 || tmp > (long double)SIZE_MAX) {                                     \
                    log_err(                                                                      \
                        "Number of bytes of %s is not within the bounds of a size_t",             \
                        ps->ps_name);                                                             \
                    return false;                                                                 \
                }                                                                                 \
                *(size_t *)value = (size_t)tmp;                                                   \
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

#define STORAGE_JSONIFY(X)                                                                        \
    cJSON *param_jsonify_bytes_to_##X(const struct param_spec *const ps, const void *const value) \
    {                                                                                             \
        switch (ps->ps_type) {                                                                    \
            case PARAM_TYPE_INT:                                                                  \
                return cJSON_CreateNumber((double)(*(int *)value / (int64_t)X));                  \
            case PARAM_TYPE_I8:                                                                   \
                return cJSON_CreateNumber((double)(*(int8_t *)value / (int64_t)X));               \
            case PARAM_TYPE_I16:                                                                  \
                return cJSON_CreateNumber((double)(*(int16_t *)value / (int64_t)X));              \
            case PARAM_TYPE_I32:                                                                  \
                return cJSON_CreateNumber((double)(*(int32_t *)value / (int64_t)X));              \
            case PARAM_TYPE_I64:                                                                  \
                return cJSON_CreateNumber((double)(*(int64_t *)value / (int64_t)X));              \
            case PARAM_TYPE_U8:                                                                   \
                return cJSON_CreateNumber((double)(*(uint8_t *)value / X));                       \
            case PARAM_TYPE_U16:                                                                  \
                return cJSON_CreateNumber((double)(*(uint16_t *)value / X));                      \
            case PARAM_TYPE_U32:                                                                  \
                return cJSON_CreateNumber((double)(*(uint32_t *)value / X));                      \
            case PARAM_TYPE_U64:                                                                  \
                return cJSON_CreateNumber((double)(*(uint64_t *)value / X));                      \
            default:                                                                              \
                abort();                                                                          \
        }                                                                                         \
    }

STORAGE_JSONIFY(KB)
STORAGE_JSONIFY(MB)
STORAGE_JSONIFY(GB)
STORAGE_JSONIFY(TB)

#undef STORAGE_JSONIFY

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
            case PARAM_TYPE_SIZE:                                                   \
                n = snprintf(buf, buf_sz, "%zu", *(size_t *)value / (size_t)X);     \
                break;                                                              \
            default:                                                                \
                abort();                                                            \
        }                                                                           \
                                                                                    \
        if (n < 0)                                                                  \
            return merr(EBADMSG);                                                   \
        if (needed_sz)                                                              \
            *needed_sz = (size_t)n;                                                 \
                                                                                    \
        return 0;                                                                   \
    }

STORAGE_STRINGIFY(KB)
STORAGE_STRINGIFY(MB)
STORAGE_STRINGIFY(GB)
STORAGE_STRINGIFY(TB)

#undef STORAGE_STRINGIFY

merr_t
params_from_config(
    void *const params,
    const size_t pspecs_sz,
    const struct param_spec *const pspecs,
    const size_t ignore_keys_sz,
    const char *const *const ignore_keys,
    const size_t num_providers,
    ...)
{
    size_t j = 0;
    merr_t err = 0;
    va_list providers;

    INVARIANT(pspecs);
    INVARIANT(pspecs_sz > 0);

    va_start(providers, num_providers);

    /* Walk each provider to set params which will overwrite the previous provider */
    while (j < num_providers) {
        const cJSON *provider = va_arg(providers, const cJSON *);
        if (!provider || cJSON_IsNull(provider))
            continue;

        err = json_walk(provider, params, pspecs_sz, pspecs, ignore_keys_sz, ignore_keys, NULL,
            true);
        if (err)
            goto va_cleanup;

        j++;
    }

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec *ps = &pspecs[i];
        if (ps->ps_validate_relations && !ps->ps_validate_relations(ps, params)) {
            log_err("Failed to validate parameter relationships for %s", ps->ps_name);
            err = merr(EINVAL);
            goto va_cleanup;
        }
    }

va_cleanup:
    va_end(providers);

    return err;
}

void
params_from_defaults(
    void                    *const params,
    const size_t                   pspecs_sz,
    const struct param_spec *const pspecs)
{
    char *p;

    INVARIANT(pspecs);
    INVARIANT(pspecs_sz > 0);
    INVARIANT(params);

    p = params;

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec ps = pspecs[i];

        void *data = p + ps.ps_offset;
        assert(data);

        /* PARAM_TYPE_ARRAY and PARAM_TYPE_OBJECT must have PARAM_DEFAULT_BUILDER */
        if (ps.ps_flags & PARAM_DEFAULT_BUILDER) {
            ps.ps_default_value.as_builder(&ps, data);
            continue;
        }

        switch (ps.ps_type) {
            case PARAM_TYPE_BOOL:
                *(bool *)data = ps.ps_default_value.as_bool;
                break;
            case PARAM_TYPE_I8:
                *(int8_t *)data = (int8_t)ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_I16:
                *(int16_t *)data = (int16_t)ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_I32:
                *(int32_t *)data = (int32_t)ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_I64:
                *(int64_t *)data = ps.ps_default_value.as_scalar;
                break;
            case PARAM_TYPE_U8:
                *(uint8_t *)data = (uint8_t)ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_U16:
                *(uint16_t *)data = (uint16_t)ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_U32:
                *(uint32_t *)data = (uint32_t)ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_U64:
                *(uint64_t *)data = ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_SIZE:
                *(size_t *)data = ps.ps_default_value.as_uscalar;
                break;
            case PARAM_TYPE_INT:
            case PARAM_TYPE_ENUM:
                *(int *)data = ps.ps_default_value.as_enum;
                break;
            case PARAM_TYPE_DOUBLE:
                *(double *)data = ps.ps_default_value.as_double;
                break;
            case PARAM_TYPE_STRING:
                if (ps.ps_default_value.as_string) {
                    size_t n HSE_MAYBE_UNUSED;

                    strlcpy(data, ps.ps_default_value.as_string, ps.ps_bounds.as_string.ps_max_len);
                    n = strlcpy(
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

merr_t
params_from_paramv(
    void *const                    params,
    const size_t                   paramc,
    const char *const *const       paramv,
    const size_t                   pspecs_sz,
    const struct param_spec *const pspecs)
{
    merr_t err = 0;

    assert(pspecs);

    for (size_t i = 0; i < paramc; i++) {
        void *data;
        cJSON *node;
        const char *key;
        const char *value;
        const char *param;
        const struct param_spec *ps = NULL;

        param = paramv[i];
        if (!param || *param == '\0')
            continue;

        key = param;
        value = strstr(param, "=");
        if (!value || value[1] == '\0') {
            log_err("Parameter key/value pairs must be of the form <key=value>");
            err = merr(EINVAL);
            goto out;
        }

        for (size_t j = 0; j < pspecs_sz; j++) {
            if (!strncmp(pspecs[j].ps_name, key, (uintptr_t)value - (uintptr_t)key)) {
                ps = &pspecs[j];
                break;
            }
        }

        if (!ps) {
            log_err("Unknown parameter %s", key);
            err = merr(EINVAL);
            goto out;
        }

        /* Point value at one character past the '=' */
        value++;

        data = (char *)params + ps->ps_offset;

        node = cJSON_Parse(value);
        if (!node) {
            /* If we couldn't successfully parse the value plainly, then convert
             * it to a string by sticking the value in between two quote
             * characters. This happens when we have unquoted strings like
             * 'rest.socket_path=/tmp' or malformed JSON like dropping a
             * bracket in an array declaration. When this config string
             * eventually gets deserialized into params objects, we will find
             * the error if one exists after string conversion.
             */

            /* Copy pair into work buffer. Need 3 extra bytes: 1 for NULL
             * termination, and 2 for adding quotes when parsing value.
             */
            const size_t buf_sz = strlen(value) + 3;
            char *       buf = malloc(buf_sz);

            HSE_MAYBE_UNUSED const int n = snprintf(buf, buf_sz, "\"%s\"", value);
            assert(n < buf_sz);

            node = cJSON_Parse(buf);
            free(buf);

            if (!node) {
                if (cJSON_GetErrorPtr()) {
                    log_err("Failed to parse %s: %s", ps->ps_name, param);
                    err = merr(EINVAL);
                } else {
                    err = merr(ENOMEM);
                }
                goto out;
            }
        }

        log_debug("Applying %s from paramv", ps->ps_name);

        if (cJSON_IsNull(node) && !(ps->ps_flags & PARAM_NULLABLE)) {
            log_err("%s cannot be null", ps->ps_name);
            cJSON_Delete(node);
            err = merr(EINVAL);
            goto out;
        }

        assert(ps->ps_convert);
        if (!ps->ps_convert(ps, node, data)) {
            log_err("Failed to convert %s", key);
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
            log_err("Failed to validate %s", key);
            err = merr(EINVAL);
            goto out;
        }
    }

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec *ps = &pspecs[i];
        if (ps->ps_validate_relations && !ps->ps_validate_relations(ps, params)) {
            log_err("Failed to validate parameter relationships for %s", ps->ps_name);
            err = merr(EINVAL);
            goto out;
        }
    }

out:
    return err;
}

merr_t
params_get(
    const void *const              params,
    const size_t                   pspecs_sz,
    const struct param_spec *const pspecs,
    const char *const              param,
    char *const                    buf,
    const size_t                   buf_sz,
    size_t *const                  needed_sz)
{
    const struct param_spec *ps = NULL;

    if (!params || !pspecs || !param)
        return merr(EINVAL);

    for (size_t i = 0; i < pspecs_sz; i++)
        if (!strcmp(pspecs[i].ps_name, param))
            ps = &pspecs[i];

    if (!ps)
        return merr(ENOENT);

    assert(ps->ps_stringify);
    return ps->ps_stringify(ps, (char *)params + ps->ps_offset, buf, buf_sz, needed_sz);
}

merr_t
params_set(
    void *const                    params,
    const size_t                   params_sz,
    const size_t                   pspecs_sz,
    const struct param_spec *const pspecs,
    const char *const              param,
    const char *const              value)
{
    static DEFINE_MUTEX(lock);

    merr_t                   err = 0;
    cJSON *                  node;
    const struct param_spec *ps = NULL;
    void *                   new = NULL;
    void *                   data;

    INVARIANT(params);
    INVARIANT(params_sz > 0);
    INVARIANT(pspecs_sz > 0);
    INVARIANT(pspecs);
    INVARIANT(param);
    INVARIANT(value);

    node = cJSON_Parse(value);
    if (!node) {
        if (cJSON_GetErrorPtr()) {
            log_err("Failed to parse %s: %s", param, value);
            return merr(EINVAL);
        } else {
            return merr(ENOMEM);
        }
    }

    for (size_t i = 0; i < pspecs_sz; i++) {
        if (!strcmp(pspecs[i].ps_name, param)) {
            ps = &pspecs[i];
            break;
        }
    }

    if (!ps) {
        log_err("Unknown parameter %s", param);
        err = merr(ENOENT);
        goto out;
    }

    if (!(ps->ps_flags & PARAM_WRITABLE)) {
        log_err("%s is not writable", param);
        err = merr(EROFS);
        goto out;
    }

    new = malloc(params_sz);
    if (!new) {
        err = merr(ENOMEM);
        goto out;
    }

    memcpy(new, params, params_sz);

    data = (char *)new + ps->ps_offset;

    if (!ps->ps_convert(ps, node, data)) {
        log_err("Failed to convert %s", param);
        err = merr(EINVAL);
        goto out;
    }

    if (!ps->ps_validate(ps, data)) {
        log_err("Failed to validate %s", param);
        err = merr(EINVAL);
        goto out;
    }

    if (ps->ps_validate_relations && !ps->ps_validate_relations(ps, new)) {
        log_err("Failed to validate parameter relationships for %s", ps->ps_name);
        err = merr(EINVAL);
        goto out;
    }

    mutex_lock(&lock);

    /* [HSE_REVISIT]: This is a race condition. The way params are currently
     * designed doesn't allow for mutexes to be a part of the equation easily.
     * So when we do this memcpy(), there is a chance someone somewhere could be
     * reading the exact same value we are changing. I think one solution we
     * could follow-up with is a registration system, where components register
     * to be notified when values change.
     */

    assert(ps->ps_size > 0);
    memcpy((char *)params + ps->ps_offset, data, ps->ps_size);

    mutex_unlock(&lock);

out:
    free(new);
    cJSON_Delete(node);

    return err;
}


cJSON *
params_to_json(
    const void              *const params,
    const size_t                   pspecs_sz,
    const struct param_spec *const pspecs)
{
    cJSON *root;

    INVARIANT(params);
    INVARIANT(pspecs);
    INVARIANT(pspecs_sz > 0);

    root = cJSON_CreateObject();

    for (size_t i = 0; i < pspecs_sz; i++) {
        const struct param_spec *ps = &pspecs[i];
        const void *             data = (char *)params + ps->ps_offset;
        cJSON *                  item, *node = root;
        char *                   dup = strdup(ps->ps_name);
        char *                   key = dup;
        char *                   check = strchr(key, '.');
        bool                     res;

        if (!key)
            goto out;

        item = ps->ps_jsonify(ps, data);
        if (!item) {
            free(dup);
            goto out;
        }

        while (check) {
            cJSON *stash;
            const ptrdiff_t idx = check - key;

            key[idx] = '\0';
            stash = node;
            node = cJSON_GetObjectItemCaseSensitive(stash, key);
            if (!node)
                node = cJSON_AddObjectToObject(stash, key);
            if (!node) {
                free(dup);
                goto out;
            }
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
