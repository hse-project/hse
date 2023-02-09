/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_REST_PARAMS_H
#define HSE_REST_PARAMS_H

#include <stdbool.h>
#include <stddef.h>

#include <hse/error/merr.h>

#define rest_params_get(_params, _param, _value, _def) \
    _Generic((_value), \
        bool * : rest_params_get_bool, \
        size_t * : rest_params_get_size, \
        const char ** : rest_params_get_string \
    )((_params), (_param), (_value), (_def))

struct rest_params;

merr_t
rest_params_get_bool(const struct rest_params *params, const char *key, bool *value, bool def);

merr_t
rest_params_get_size(const struct rest_params *params, const char *key, size_t *value, size_t def);

merr_t
rest_params_get_string(
    const struct rest_params *params,
    const char *key,
    const char **value,
    const char *def);

#endif
