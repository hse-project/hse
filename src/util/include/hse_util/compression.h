/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */
#ifndef HSE_UTIL_COMPRESSION_H
#define HSE_UTIL_COMPRESSION_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

typedef uint (*compress_op_estimate_fn)(
    const void *data,
    uint        len);

typedef merr_t (*compress_op_compress_fn)(
    const void *src,
    uint        src_len,
    void       *dst,
    uint        dst_capacity,
    uint       *dst_len);

typedef merr_t (*compress_op_decompress_fn)(
    const void *src,
    uint        src_len,
    void       *dst,
    uint        dst_capacity,
    uint       *dst_len);

struct compress_ops {
    compress_op_estimate_fn   cop_estimate;
    compress_op_compress_fn   cop_compress;
    compress_op_decompress_fn cop_decompress;
};

#endif
