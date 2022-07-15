/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_PARAM_H
#define HSE_CONFIG_PARAM_H

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cjson/cJSON.h>

#include <error/merr.h>

/* PARAM_TYPE_ARRAY and PARAM_TYPE_OBJECT must have PARAM_FLAG_DEFAULT_BUILDER */
#define PARAM_FLAG_DEVELOPER_ONLY  (1 << 1)
#define PARAM_FLAG_EXPERIMENTAL    (1 << 2)
#define PARAM_FLAG_WRITABLE        (1 << 3)
#define PARAM_FLAG_NULLABLE        (1 << 4)
#define PARAM_FLAG_DEFAULT_BUILDER (1 << 5)

#define PARAM_SZ(_type, _field) sizeof(((_type *)0)->_field)

struct hse_gparams;
struct kvdb_cparams;
struct kvdb_rparams;
struct kvs_cparams;
struct kvs_rparams;

struct params {
    enum {
        PARAMS_GEN,
        PARAMS_HSE_GP,
        PARAMS_KVDB_CP,
        PARAMS_KVDB_RP,
        PARAMS_KVS_CP,
        PARAMS_KVS_RP,
    } p_type;
    union {
        /* Do not assign to as_generic, for internal use only */
        const void *               as_generic;
        const struct kvdb_cparams *as_kvdb_cp;
        const struct kvdb_rparams *as_kvdb_rp;
        const struct kvs_cparams * as_kvs_cp;
        const struct kvs_rparams * as_kvs_rp;
        const struct hse_gparams * as_hse_gp;
    } p_params;
};

struct param_spec;

typedef bool (*param_converter_t)(const struct param_spec *, const cJSON *, void *);
typedef bool (*param_validator_t)(const struct param_spec *, const void *);
typedef bool (*param_relation_validator_t)(const struct param_spec *, const struct params *);
typedef void (*param_default_builder_t)(const struct param_spec *, void *);
typedef merr_t (
    *param_stringify_t)(const struct param_spec *, const void *, char *, size_t, size_t *);
typedef cJSON *(*param_jsonify_t)(const struct param_spec *, const void *);

enum param_type {
    PARAM_TYPE_BOOL,
    PARAM_TYPE_I8,
    PARAM_TYPE_I16,
    PARAM_TYPE_I32,
    PARAM_TYPE_I64,
    PARAM_TYPE_U8,
    PARAM_TYPE_U16,
    PARAM_TYPE_U32,
    PARAM_TYPE_U64,
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
    /* Converts a JSON node into the expected data */
    param_converter_t ps_convert;
    /* Validates data just after ps_convert() */
    param_validator_t ps_validate;
    /* Validates relations after conversion, validation, and updating of all data */
    param_relation_validator_t ps_validate_relations;
    /* Returns a JSON string representation of the value */
    param_stringify_t ps_stringify;
    /* Returns a JSON representation of the parameter */
    param_jsonify_t ps_jsonify;
    union {
        bool     as_bool;
        uint64_t as_uscalar;
        int64_t  as_scalar;
        uint64_t as_enum;
        char *   as_string;
        /* Used for arrays and objects */
        param_default_builder_t as_builder;
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
            size_t ps_max_len;
        } as_string;
        struct {
            size_t ps_max_len;
        } as_array;
    } ps_bounds;
};

cJSON *
param_to_json(const struct params *params, const struct param_spec *pspecs, size_t pspecs_sz);

void
param_default_populate(
    const struct param_spec *pspecs,
    const size_t             pspecs_sz,
    const struct params *    params);

bool
param_default_converter(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_default_validator(const struct param_spec *ps, const void *value);

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
param_roundup_pow2(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_KB(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_MB(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_GB(const struct param_spec *ps, const cJSON *node, void *value);

bool
param_convert_to_bytes_from_TB(const struct param_spec *ps, const cJSON *node, void *value);

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

cJSON *
param_jsonify_bytes_to_KB(const struct param_spec *ps, const void *value);

cJSON *
param_jsonify_bytes_to_MB(const struct param_spec *ps, const void *value);

cJSON *
param_jsonify_bytes_to_GB(const struct param_spec *ps, const void *value);

cJSON *
param_jsonify_bytes_to_TB(const struct param_spec *ps, const void *value);

merr_t
param_get(
    const struct params *    params,
    const struct param_spec *pspecs,
    size_t                   pspecs_sz,
    const char *             param,
    char *                   buf,
    size_t                   buf_sz,
    size_t *                 needed_sz);

merr_t
param_set(
    const struct params *    params,
    const struct param_spec *pspecs,
    size_t                   pspecs_sz,
    const char *             param,
    const char *             value);

#endif /* HSE_PARAM_H */
