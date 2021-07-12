/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/arch.h>
#include <hse_util/xrand.h>

thread_local struct xrand xrand_tls;

void
xrand_init(struct xrand *xr, u64 seed)
{
    if (!seed) {
        while (1) {
            seed = (seed << 16) | ((get_cycles() >> 1) & 0xffffu);
            if (seed >> 48)
                break;

            usleep(seed % 127); /* leverage scheduling entropy */
        }
    }

    xoroshiro128plus_init(xr->xr_state, seed);
}

u64
xrand_range64(struct xrand *xr, u64 lo, u64 hi)
{
    /* compute rv: 0 <= rv < 1  */
    double rand_max = (double)((u64)-1);
    double rv = (double)xrand64(xr) / (rand_max + 1.0);

    /* scale rv to the desired range */
    return (u64)((double)lo + (double)(hi - lo) * rv);
}
