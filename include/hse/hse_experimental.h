/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_EXPERIMENTAL_API_H
#define HSE_KVDB_EXPERIMENTAL_API_H

/** ...
 *
 * \ingroup HSE
 */

#include <hse/hse.h>

#include <uuid/uuid.h>

/* MTF_MOCK_DECL(hse_experimental) */

/**
 * hse_kvdb_export_exp() - export a kvdb into files
 * @handle: kvdb handle
 * @params: configuration parameters
 * @path: export target path
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_export_exp(struct hse_kvdb *handle, struct hse_params *params, const char *path);

/**
 * hse_kvdb_import_exp() - import a kvdb from files
 * @mpool_name: name of mpool
 * @path: import target path
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_import_exp(const char *mpool_name, const char *path);

/**
 * hse_mpool_utype - unique uuid to identify hse mpools
 *
 * 0ccf8ce8-6f8f-11ea-adfc-248a07151670
 */
/* clang-format off */
static const uuid_t
hse_mpool_utype = {
    0x0c, 0xcf, 0x8c, 0xe8,
    0x6f, 0x8f,
    0x11, 0xea,
    0xad, 0xfc,
    0x24, 0x8a, 0x07, 0x15, 0x16, 0x70
};
/* clang-format on */

enum hse_kvs_pfx_probe_cnt {
    HSE_KVS_PFX_FOUND_ZERO = 0,
    HSE_KVS_PFX_FOUND_ONE,
    HSE_KVS_PFX_FOUND_MUL,
};

/**
 * hse_kvs_prefix_probe_exp() - probe for prefix. Outputs how many matches were
 *                              encountered - zero, one or multiple.
 * @kvs:       KVS handle
 * @opspec:    specification for delete operation
 * @pfx:       prefix to be probed
 * @pfx_len:   length of @pfx
 * @found:     (output) Zero, one or multiple matches seen
 * @keybuf:    buffer which will be populated with contents of first seen key
 * @keybuf_sz: size of @keybuf
 * @key_len:   (output) length of first seen key
 * @valbuf:    buffer which will be populated with value for @keybuf
 * @valbuf_sz: size of @valbuf
 * @val_len:   (output) length of the value seen
 */
hse_err_t
hse_kvs_prefix_probe_exp(
    struct hse_kvs *            kvs,
    struct hse_kvdb_opspec *    os,
    const void *                pfx,
    size_t                      pfx_len,
    enum hse_kvs_pfx_probe_cnt *found,
    void *                      keybuf,
    size_t                      keybuf_sz,
    size_t *                    key_len,
    void *                      valbuf,
    size_t                      valbuf_sz,
    size_t *                    val_len);

/**
 * hse_params_err_exp() - retrieve last error message
 * @params: configuration parameters
 * @buf:    output buffer
 * @buf_sz: size of buffer
 *
 * Returns a pointer to the provided buffer.
 */
char *
hse_params_err_exp(struct hse_params *params, char *buf, size_t buf_sz);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "hse_experimental_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
