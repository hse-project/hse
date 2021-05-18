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

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

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

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif
