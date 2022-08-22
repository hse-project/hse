/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CPARAMS_H
#define HSE_KVDB_CPARAMS_H

#include <stddef.h>

#include <cjson/cJSON.h>

#include <hse_util/compiler.h>
#include <hse/error/merr.h>
#include <mpool/mpool_structs.h>

struct kvdb_cparams {
    struct mpool_cparams storage;
};

const struct param_spec *
kvdb_cparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct kvdb_cparams
kvdb_cparams_defaults() HSE_CONST;

merr_t
kvdb_cparams_resolve(struct kvdb_cparams *params, const char *home, bool pmem_only);

merr_t
kvdb_cparams_get(
    const struct kvdb_cparams *params,
    const char *               param,
    char *                     buf,
    size_t                     buf_sz,
    size_t *                   needed_sz);

cJSON *
kvdb_cparams_to_json(const struct kvdb_cparams *params);

#endif
