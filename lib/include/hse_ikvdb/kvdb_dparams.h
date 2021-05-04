/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_DPARAMS_H
#define HSE_KVDB_DPARAMS_H

#include <limits.h>
#include <stddef.h>

#include <mpool/mpool.h>
#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

struct kvdb_dparams {
    struct mpool_dparams storage;
};

const struct param_spec *
kvdb_dparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct kvdb_dparams
kvdb_dparams_defaults() HSE_CONST;

merr_t
kvdb_dparams_resolve(struct kvdb_dparams *params, const char *home);

#endif
