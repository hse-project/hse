/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_KEY_HASH_H
#define HSE_IKVS_KEY_HASH_H

#include <stdint.h>

#include <hse/util/assert.h>
#include <hse/util/compiler.h>
#include <hse/util/hash.h>
#include <hse/util/key_util.h>

/*
 * This file defines the hash algorithm used for:
 *  - Spilling CN tree nodes to child nodes
 *  - KBLOCK Bloom filters
 */

static HSE_ALWAYS_INLINE uint64_t
key_hash64(const void *data, size_t len)
{
    assert(len < (1024 * 1024));

    return hse_hash64(data, len);
}

static HSE_ALWAYS_INLINE uint64_t
key_hash64_seed(const void *data, size_t len, uint64_t seed)
{
    return hse_hash64_seed(data, len, seed);
}

/* If key len > pfx_len and pfx_len > 0, then compute hash on first pfx_len
 * bytes. Otherwise, compute hash on entire key.
 */
static inline uint64_t
pfx_hash64(const void *data, int len, int pfx_len)
{
    assert(len >= 0 && pfx_len >= 0);
    return key_hash64(data, (pfx_len && len >= pfx_len) ? pfx_len : len);
}

static HSE_ALWAYS_INLINE uint64_t
key_obj_hash64(const struct key_obj *ko)
{
    assert(key_obj_len(ko) < (1024 * 1024));

    return hse_hash64v(ko->ko_pfx, ko->ko_pfx_len, ko->ko_sfx, ko->ko_sfx_len);
}

static inline uint64_t
pfx_obj_hash64(const struct key_obj *ko, int pfx_len)
{
    uint len = key_obj_len(ko);
    uint min_pfx_len;

    assert(pfx_len >= 0);
    if (HSE_UNLIKELY(len <= pfx_len))
        return key_obj_hash64(ko);

    /* Common case: pfx_len < len */
    min_pfx_len = min_t(uint, ko->ko_pfx_len, pfx_len);
    return hse_hash64v(ko->ko_pfx, min_pfx_len, ko->ko_sfx, pfx_len - min_pfx_len);
}

#endif
