/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CPARAMS_H
#define HSE_KVDB_CPARAMS_H

#include <stddef.h>

#include <cjson/cJSON.h>

#include <hse/error/merr.h>
#include <hse/mpool/mpool_structs.h>
#include <hse/util/compiler.h>

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
    const char *param,
    char *buf,
    size_t buf_sz,
    size_t *needed_sz);

/**
 * Deserialize list of key=value parameters to KVDB cparams
 *
 * @param params Params struct
 * @param paramc Number of parameters
 * @param paramv List of key=value strings
 *
 * @returns Error status
 * @retval 0 success
 * @retval !0 failure
 */
merr_t
kvdb_cparams_from_paramv(struct kvdb_cparams *params, size_t paramc, const char * const *paramv);

cJSON *
kvdb_cparams_to_json(const struct kvdb_cparams *params);

#endif
