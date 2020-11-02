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
 * Export a kvdb into files
 *
 * This function is not thread safe. Note that calling other functions that alter the
 * state of the KVDB while it is being exported is also not supported.
 *
 * @param handle: KVDB handle hse_kvdb_open()
 * @param params: Configuration parameters
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_export_exp(struct hse_kvdb *handle, struct hse_params *params, const char *path);

/**
 * Import a kvdb from files
 *
 * This function is not thread safe. Note that calling other functions that alter the
 * state of the mpool while it is being imported is also not supported.
 *
 * @param mpool_name: Mpool name
 * @param path:       Import target path
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_import_exp(const char *mpool_name, const char *path);

/**
 * Unique uuid to identify hse mpools
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
 * Probe for a prefix
 *
 * Outputs how many matches were encountered - zero, one or multiple. This function is
 * thread safe.
 *
 * @param kvs:       KVS handle from hse_kvdb_kvs_open()
 * @param opspec:    Specification for delete operation
 * @param pfx:       Prefix to be probed
 * @param pfx_len:   Length of @pfx
 * @param found:     [out] Zero, one or multiple matches seen
 * @param keybuf:    Buffer which will be populated with contents of first seen key
 * @param keybuf_sz: Size of @keybuf
 * @param key_len:   [out] Length of first seen key
 * @param valbuf:    Buffer which will be populated with value for @keybuf
 * @param valbuf_sz: Size of @valbuf
 * @param val_len:   [out] Length of the value seen
 * @return The function's error status
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
 * Retrieve the last error message
 *
 * This function is not thread safe.
 *
 * @param params: Configuration parameters
 * @param buf:    Output buffer
 * @param buf_sz: Size of buffer
 * @return A pointer to the provided buffer.
 */
char *
hse_params_err_exp(const struct hse_params *params, char *buf, size_t buf_sz);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "hse_experimental_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
