/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.
 */

#ifndef HSE_UTIL_COMPRESSION_H
#define HSE_UTIL_COMPRESSION_H

#include <sys/types.h>

#include <hse/error/merr.h>

typedef uint compress_op_estimate_t(
    const void *data,
    uint        len);

typedef merr_t compress_op_compress_t(
    const void *src,
    uint        src_len,
    void       *dst,
    uint        dst_capacity,
    uint       *dst_len);

typedef merr_t compress_op_decompress_t(
    const void *src,
    uint        src_len,
    void       *dst,
    uint        dst_capacity,
    uint       *dst_len);

struct compress_ops {
    compress_op_estimate_t   *cop_estimate;
    compress_op_compress_t   *cop_compress;
    compress_op_decompress_t *cop_decompress;
};

#endif
