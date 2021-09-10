/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_XRAND_H
#define HSE_XRAND_H

#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>

#include <xoroshiro.h>

struct xrand {
    u64 xr_state[2];
};

extern thread_local struct xrand    xrand_tls;

/* Functions xrand_init() and xrand64() implement a standard PRNG API where
 * the user manages the PRNG state and initializes it with a seed value.
 * They are not thread safe.
 */

void xrand_init(struct xrand *xr, u64 seed);

static HSE_ALWAYS_INLINE
u64
xrand64(struct xrand *xr)
{
    return xoroshiro128plus(xr->xr_state);
}

/* Function xrand64_tls() implements a PRNG that uses thread local state.
 * The PRNG is automatically initialized on the first call to xrand64_tls().
 * This function is thread safe.
 */
static HSE_ALWAYS_INLINE
u64
xrand64_tls(void)
{
    if (HSE_UNLIKELY(!xrand_tls.xr_state[0])) {
        xrand_init(&xrand_tls, 0);
    }

    return xrand64(&xrand_tls);
}

u64
xrand_range64(struct xrand *xr, u64 lo, u64 hi);

#endif
