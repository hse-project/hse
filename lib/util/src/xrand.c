/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/xrand.h>

#include <hse_util/compiler.h>
#include <hse_util/arch.h>

__thread struct xrand    xrand_tls;
__thread u64             xrand_tls_seed;


void
xrand_init(struct xrand *xr, u64 seed)
{
    xoroshiro128plus_init(xr->xr_state, seed);
}
