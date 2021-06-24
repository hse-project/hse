/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_CONFIG_H
#define HSE_PLATFORM_CONFIG_H

#include <hse_util/data_tree.h>
#include <hse_util/atomic.h>
#include <hse_util/time.h>

#define CONFIG_ROOT_PATH "/data/config"

struct hse_config {
    char               instance[DT_PATH_ELEMENT_LEN];
    char               path[DT_PATH_ELEMENT_LEN];
    void *             data;
    size_t             data_sz;
    void *             dfault;
    void *             rock;
    atomic64_t         change_timestamp;
    dt_emit_handler_t *emit;
    dt_set_handler_t * set;
    bool               writable;
};

size_t
bool_set(struct dt_element *dte, struct dt_set_parameters *dsp);

size_t
bool_emit(struct dt_element *dte, struct yaml_context *yc);

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

size_t
string_set(struct dt_element *dte, struct dt_set_parameters *dsp);

size_t
string_emit(struct dt_element *dte, struct yaml_context *yc);

#endif /* HSE_PLATFORM_CONFIG_H */
