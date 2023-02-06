/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.
 */

#include <stdint.h>
#include <unistd.h>

#include <hse/util/arch.h>
#include <hse/util/xrand.h>

thread_local struct xrand xrand_tls;

void
xrand_init(struct xrand *xr, uint64_t seed)
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

uint64_t
xrand_range64(struct xrand *xr, uint64_t lo, uint64_t hi)
{
    /* compute rv: 0 <= rv < 1  */
    double rand_max = (double)((uint64_t)-1);
    double rv = (double)xrand64(xr) / (rand_max + 1.0);

    /* scale rv to the desired range */
    return (uint64_t)((double)lo + (double)(hi - lo) * rv);
}
