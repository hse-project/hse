/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.
 */

#include <hse/ikvdb/vcomp_params.h>
#include <hse/util/compression_lz4.h>

const struct compress_ops *vcomp_compress_ops[VCOMP_ALGO_COUNT] = {
    &compress_lz4_ops,
};
