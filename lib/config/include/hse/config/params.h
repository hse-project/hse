/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_PARAM_H
#define HSE_CONFIG_PARAM_H

#include <stdbool.h>
#include <stdint.h>

#include <cjson/cJSON.h>

#include <hse/error/merr.h>

/* PARAM_TYPE_ARRAY and PARAM_TYPE_OBJECT must have PARAM_DEFAULT_BUILDER */
#define PARAM_DEVELOPER_ONLY  (1 << 1)
#define PARAM_EXPERIMENTAL    (1 << 2)
#define PARAM_WRITABLE        (1 << 3)
#define PARAM_NULLABLE        (1 << 4)
#define PARAM_DEFAULT_BUILDER (1 << 5)

#define PARAM_SZ(_type, _field) sizeof(((_type *)NULL)->_field)

struct param_spec;

typedef bool param_converter_t(const struct param_spec *, const cJSON *, void *);
typedef bool param_validator_t(const struct param_spec *, const void *);
typedef bool param_relation_validator_t(const struct param_spec *, const void *);
typedef void param_default_builder_t(const struct param_spec *, void *);
typedef merr_t param_stringify_t(const struct param_spec *, const void *, char *, size_t, size_t *);
typedef cJSON *param_jsonify_t(const struct param_spec *, const void *);

enum param_type {
    PARAM_TYPE_BOOL,
    PARAM_TYPE_INT,
    PARAM_TYPE_I8,
    PARAM_TYPE_I16,
    PARAM_TYPE_I32,
    PARAM_TYPE_I64,
    PARAM_TYPE_U8,
    PARAM_TYPE_U16,
    PARAM_TYPE_U32,
    PARAM_TYPE_U64,
    PARAM_TYPE_SIZE,
    PARAM_TYPE_DOUBLE,
    PARAM_TYPE_ENUM,
    PARAM_TYPE_STRING,
    PARAM_TYPE_ARRAY,
    PARAM_TYPE_OBJECT,
};

struct param_spec {
    char *          ps_name;
    char *          ps_description;
    int             ps_flags;
    enum param_type ps_type;
    size_t          ps_offset;
    size_t          ps_size;
    param_converter_t *ps_convert /* Converts a JSON node into the expected data */;
    param_validator_t *ps_validate /* Validates data just after ps_convert() */;
    param_relation_validator_t *ps_validate_relations /* Validates relations after conversion, validation, and updating of all data */;
    param_stringify_t *ps_stringify /* Returns a JSON string representation of the value */;
    param_jsonify_t *ps_jsonify /* Returns a JSON representation of the parameter */;
    union {
        bool     as_bool;
        uint64_t as_uscalar;
        int64_t  as_scalar;
        uint64_t as_enum;
        double   as_double;
        char *   as_string;
        param_default_builder_t *as_builder /* Used for arrays and objects */;
    } ps_default_value;
    union {
        struct {
            int64_t ps_min;
            int64_t ps_max;
        } as_scalar;
        struct {
            uint64_t ps_min;
            uint64_t ps_max;
        } as_uscalar;
        struct {
            uint64_t ps_min;
            uint64_t ps_max;
        } as_enum;
        struct {
            double ps_min;
            double ps_max;
        } as_double;
        struct {
            size_t ps_max_len;
        } as_string;
        struct {
            size_t ps_max_len;
        } as_array;
    } ps_bounds;
};

bool
param_default_converter(const struct param_spec *ps, const cJSON *node, void *value);

merr_t
param_default_stringify(
    const struct param_spec *ps,
    const void *             value,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 needed_sz);

cJSON *
param_default_jsonify(const struct param_spec *ps, const void *value);

bool
param_default_validator(const struct param_spec *ps, const void *value);

bool
param_roundup_pow2(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_KB(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_MB(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_GB(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_TB(const struct param_spec *ps, const cJSON *node, void *value);

cJSON *
param_jsonify_bytes_to_KB(const struct param_spec *ps, const void *value);

cJSON *
param_jsonify_bytes_to_MB(const struct param_spec *ps, const void *value);

cJSON *
param_jsonify_bytes_to_GB(const struct param_spec *ps, const void *value);

cJSON *
param_jsonify_bytes_to_TB(const struct param_spec *ps, const void *value);

merr_t
param_stringify_bytes_to_KB(
    const struct param_spec *ps,
    const void *             value,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 needed_sz);

merr_t
param_stringify_bytes_to_MB(
    const struct param_spec *ps,
    const void *             value,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 needed_sz);

merr_t
param_stringify_bytes_to_GB(
    const struct param_spec *ps,
    const void *             value,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 needed_sz);

merr_t
param_stringify_bytes_to_TB(
    const struct param_spec *ps,
    const void *             value,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 needed_sz);

/**
 * Deserialize multiple configs into a params struct
 *
 * @param params Params object
 * @param pspecs Array of param_spec to search through
 * @param pspecs_sz Size of @p pspecs
 * @param ignore_keys Keys to ignore while recursing
 * @param ignore_keys_sz Size of @p ignore_keys
 * @param num_configs Number of configs for populating the @p params object
 *
 * @returns Error status
 * @retval Non-zero on error
 */
merr_t
params_from_config(
    void *params,
    size_t pspecs_sz,
    const struct param_spec* pspecs,
    size_t ignore_keys_sz,
    const char *const *ignore_keys,
    size_t num_configs,
    ...);

void
params_from_defaults(
    void                    *params,
    size_t                   pspecs_sz,
    const struct param_spec *pspecs);

merr_t
params_from_paramv(
    void *                   params,
    size_t                   paramc,
    const char *const *      paramv,
    size_t                   pspecs_sz,
    const struct param_spec *pspecs);

merr_t
params_get(
    const void              *params,
    size_t                   pspecs_sz,
    const struct param_spec *pspecs,
    const char *             param,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 needed_sz);

merr_t
params_set(
    void                    *params,
    size_t                   params_sz,
    size_t                   pspecs_sz,
    const struct param_spec *pspecs,
    const char *             param,
    const char *             value);

cJSON *
params_to_json(
    const void *params,
    size_t pspecs_sz,
    const struct param_spec *pspecs) HSE_WARN_UNUSED_RESULT;

#endif /* HSE_PARAM_H */
