/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CPARAMS_H
#define HSE_KVS_CPARAMS_H

#include <stddef.h>
#include <stdint.h>

#include <cjson/cJSON.h>

#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

struct kvs_cparams {
    uint32_t  fanout;
    uint32_t  pfx_len;
    uint32_t  sfx_len;
    uint32_t  kvs_ext01;
};

const struct param_spec *
kvs_cparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct kvs_cparams
kvs_cparams_defaults() HSE_CONST;

merr_t
kvs_cparams_get(
    const struct kvs_cparams *params,
    const char *              param,
    char *                    buf,
    size_t                    buf_sz,
    size_t *                  needed_sz);

cJSON *
kvs_cparams_to_json(const struct kvs_cparams *params);

#endif
