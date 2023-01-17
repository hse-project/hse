/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_XRAND_H
#define HSE_XRAND_H

#include <stdint.h>

#include <hse/util/compiler.h>

#include <xoroshiro.h>

struct xrand {
    uint64_t xr_state[2];
};

extern thread_local struct xrand    xrand_tls;

/* Functions xrand_init() and xrand64() implement a standard PRNG API where
 * the user manages the PRNG state and initializes it with a seed value.
 * They are not thread safe.
 */

void xrand_init(struct xrand *xr, uint64_t seed);

static HSE_ALWAYS_INLINE uint64_t
xrand64(struct xrand *xr)
{
    return xoroshiro128plus(xr->xr_state);
}

/* Function xrand64_tls() implements a PRNG that uses thread local state.
 * The PRNG is automatically initialized on the first call to xrand64_tls().
 * This function is thread safe.
 */
static HSE_ALWAYS_INLINE uint64_t
xrand64_tls(void)
{
    if (HSE_UNLIKELY(!xrand_tls.xr_state[0])) {
        xrand_init(&xrand_tls, 0);
    }

    return xrand64(&xrand_tls);
}

uint64_t
xrand_range64(struct xrand *xr, uint64_t lo, uint64_t hi);

#endif
