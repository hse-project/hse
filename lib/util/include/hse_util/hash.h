/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_HASH_H
#define HSE_PLATFORM_HASH_H

#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#include <xxhash.h>
#pragma GCC diagnostic pop

static HSE_ALWAYS_INLINE u64
hse_hash64(const void *data, size_t len)
{
    return XXH3_64bits(data, len);
}

static HSE_ALWAYS_INLINE u64
hse_hash64_seed(const void *data, size_t len, u64 seed)
{
    return XXH3_64bits_withSeed(data, len, seed);
}

static HSE_ALWAYS_INLINE u64
hse_hash64v(const void *data1, size_t len1, const void *data2, size_t len2)
{
    if (data1) {
        XXH3_state_t state;

        XXH3_64bits_reset(&state);
        XXH3_64bits_update(&state, data1, len1);
        XXH3_64bits_update(&state, data2, len2);

        return XXH3_64bits_digest(&state);
    }

    return XXH3_64bits(data2, len2);
}

#endif
