/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/vcomp_params.h>
#include <hse_ikvdb/kvs_rparams.h>

#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>
#include <hse_util/compression_lz4.h>

static bool
vcomp_param_match(const struct kvs_rparams *rp, const char *check)
{
    size_t len = strlen(check);

    /* Use sizeof(rp->value_compression) to protect
     * against it not being null terminated.
     */
    return (len < sizeof(rp->value_compression)) && (!strcmp(check, rp->value_compression));
}

bool
vcomp_param_valid(const struct kvs_rparams *rp)
{
    const char *check[] = {
        VCOMP_PARAM_NONE,
        VCOMP_PARAM_LZ4,
    };

    for (int i = 0; i < NELEM(check); i++)
        if (vcomp_param_match(rp, check[i]))
            return true;
    return false;
}

struct compress_ops *
vcomp_compress_ops(const struct kvs_rparams *rp)
{
    if (vcomp_param_match(rp, VCOMP_PARAM_LZ4))
        return &compress_lz4_ops;
    return NULL;
}
