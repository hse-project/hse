/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_HASH_H
#define HSE_PLATFORM_HASH_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#include <xxhash.h>
#pragma GCC diagnostic pop

#define HSE_HASH_SEED32 0x9747b28cU
#define HSE_HASH_SEED64 0xc1355cc4855a3f87UL

static HSE_ALWAYS_INLINE u32
hse_hash32(const void *data, size_t len)
{
    return XXH32(data, len, HSE_HASH_SEED32);
}

static HSE_ALWAYS_INLINE u64
hse_hash64(const void *data, size_t len)
{
    return XXH64(data, len, HSE_HASH_SEED64);
}

static HSE_ALWAYS_INLINE u64
hse_hash64_seed(const void *data, size_t len, u64 seed)
{
    return XXH64(data, len, seed);
}

static HSE_ALWAYS_INLINE u64
hse_hash64v_seed(const void *data1, size_t len1, const void *data2, size_t len2, u64 seed)
{
    if (data1) {
        XXH64_state_t state;

        XXH64_reset(&state, seed);
        XXH64_update(&state, data1, len1);
        XXH64_update(&state, data2, len2);

        return XXH64_digest(&state);
    }

    return XXH64(data2, len2, seed);
}

static HSE_ALWAYS_INLINE u64
hse_hash64v(const void *data1, size_t len1, const void *data2, size_t len2)
{
    return hse_hash64v_seed(data1, len1, data2, len2, HSE_HASH_SEED64);
}

#endif
