/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_CONFIG_H
#define HSE_PLATFORM_CONFIG_H

#include <hse_util/data_tree.h>
#include <hse_util/atomic.h>
#include <hse_util/time.h>
#include <hse_util/param.h>

#define CONFIG_ROOT_PATH "/data/config"

typedef merr_t(validator_t)(
    const char *              instance,
    const char *              path,
    struct dt_set_parameters *dsp,
    void *                    dfault,
    void *                    rock,
    char *                    errbuf,
    size_t                    errbuf_sz);

struct hse_config {
    char               instance[DT_PATH_ELEMENT_LEN];
    char               path[DT_PATH_ELEMENT_LEN];
    void *             data;
    size_t             data_sz;
    void *             dfault;
    validator_t *      validator;
    void *             rock;
    atomic64_t         change_timestamp;
    dt_emit_handler_t *emit;
    dt_set_handler_t * set;
    param_show_t *     show;
    bool               writable;
};

size_t
bool_set(struct dt_element *dte, struct dt_set_parameters *dsp);

size_t
bool_emit(struct dt_element *dte, struct yaml_context *yc);

/* API Functions */
/**
 * config_init() - create data_tree framework for Config Variables
 *
 * config_init is called by the platform init code
 *
 * Return: void.
 */
void
config_init(void);

/**
 * hse_config() - Register a configuration variable
 */
struct hse_config *
hse_config(
    const char *      component,
    const char *      instance,
    const char *      path,
    void *            data,
    size_t            data_sz,
    void *            dfault,
    validator_t *     validator,
    void *            rock,
    dt_emit_handler_t emit,
    dt_set_handler_t  set,
    param_show_t      show,
    bool              writable);

#define CFG(path, instance, data, data_sz, dfault, validator, rock, emit, set, show, writable) \
    hse_config(                                                                                \
        COMPNAME,                                                                              \
        instance,                                                                              \
        path,                                                                                  \
        data,                                                                                  \
        data_sz,                                                                               \
        dfault,                                                                                \
        validator,                                                                             \
        rock,                                                                                  \
        emit,                                                                                  \
        set,                                                                                   \
        show,                                                                                  \
        writable)

/**
 * config_set_handler() - Programmatic API to setting config variables
 * @dte: pointer to struct dt_element (if known)
 * @dsp: structure with parameters to set the config config variable
 *
 * The standard mechanism for setting a config variable is through the
 * data_tree interfaces, but this is inconvenient when setting the variable
 * from inside the same address space.
 *
 * config_set_handler() provides a path by which an application can set
 * its own config variables internally.
 *
 * Returns 1 if the value is set.
 */
size_t
config_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp);

static inline struct hse_config *
config_u64(
    const char *component,
    const char *instance,
    const char *path,
    u64 *       data,
    u64 *       dfault,
    validator_t validator,
    void *      rock,
    bool        writable)
{
    return hse_config(
        component,
        instance,
        path,
        data,
        sizeof(u64),
        dfault,
        validator,
        rock,
        NULL,
        NULL,
        show_u64,
        writable);
}
#define CFG_U64(path, instance, data, dfault, validator, rock, writable) \
    config_u64(COMPNAME, instance, path, data, dfault, validator, rock, writable)

static inline struct hse_config *
config_u32(
    const char *component,
    const char *instance,
    const char *path,
    u32 *       data,
    u32 *       dfault,
    validator_t validator,
    void *      rock,
    bool        writable)
{
    return hse_config(
        component,
        instance,
        path,
        data,
        sizeof(u32),
        dfault,
        validator,
        rock,
        NULL,
        NULL,
        show_u32,
        writable);
}
#define CFG_U32(path, instance, data, dfault, validator, rock, writable) \
    config_u32(COMPNAME, instance, path, data, dfault, validator, rock, writable)

static inline struct hse_config *
config_bool(
    const char *component,
    const char *instance,
    const char *path,
    bool *      data,
    bool *      dfault,
    validator_t validator,
    void *      rock,
    bool        writable)
{
    return hse_config(
        component,
        instance,
        path,
        data,
        sizeof(bool),
        dfault,
        validator,
        rock,
        bool_emit,
        bool_set,
        show_bool,
        writable);
}
#define CFG_BOOL(path, instance, data, dfault, validator, rock, writable) \
    config_bool(COMPNAME, instance, path, data, dfault, validator, rock, writable)

size_t
string_set(struct dt_element *dte, struct dt_set_parameters *dsp);

size_t
string_emit(struct dt_element *dte, struct yaml_context *yc);

static inline struct hse_config *
config_string(
    const char *component,
    const char *instance,
    const char *path,
    char *      string,
    size_t      string_len,
    char *      dfault,
    validator_t validator,
    void *      rock,
    bool        writable)
{
    return hse_config(
        component,
        instance,
        path,
        string,
        string_len,
        dfault,
        validator,
        rock,
        string_emit,
        string_set,
        show_string,
        writable);
}
#define CFG_STRING(path, instance, string, string_len, dfault, validator, rock, writable) \
    config_string(COMPNAME, instance, path, string, string_len, dfault, validator, rock, writable)

#endif /* HSE_PLATFORM_CONFIG_H */
