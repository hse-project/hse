/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/vcomp_params.h>
#include <hse/util/compression_lz4.h>

const struct compress_ops *vcomp_compress_ops[VCOMP_ALGO_COUNT] = {
    &compress_lz4_ops,
};
