/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stddef.h>
#include <string.h>

#include <hse_ikvdb/vcomp_params.h>
#include <hse_ikvdb/kvs_rparams.h>

#include <hse_util/compression_lz4.h>

static
bool
vcomp_param_match(
    const struct kvs_rparams   *rp,
    const char                 *check)
{
    size_t len = strlen(check);

    /* Use sizeof(rp->value_compression) to protect
     * against it not being null terminated.
     */
    return (len < sizeof(rp->value_compression))
        && (!strcmp(check, rp->value_compression));
}

struct compress_ops *
vcomp_compress_ops(const struct kvs_rparams *rp)
{
    if (vcomp_param_match(rp, VCOMP_PARAM_LZ4))
        return &compress_lz4_ops;
    return NULL;
}
