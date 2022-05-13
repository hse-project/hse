/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_KEYCMP_H
#define HSE_PLATFORM_KEYCMP_H

#include <hse_util/base.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>

/*
 * Return value:
 *   0            : keys are equal
 *   negative int : key1 is "less than" key2
 *   positive int : key1 is "greater than" key2
 */
static inline int
keycmp(const void *key1, u32 len1, const void *key2, u32 len2)
{
    /*
     * If memcmp returns 0, then either (1) keys are equal or (2)
     * one key is a prefix of the other.  In either case returning
     * len1-len2 results in desired behavior:
     *
     *   len1 == len2 --> return 0 (keys are equal).
     *   len1 <  len2 --> return neg (key1 < ken2).
     *   len1 >  len2 --> return pos (key1 > key2).
     */
    size_t len = len1 < len2 ? len1 : len2;
    int    rc = memcmp(key1, key2, len);
    return rc == 0 ? len1 - len2 : rc;
}

/*
 * Return value:
 *   0            : pfx is a prefix of key.
 *   negative int : pfx is "less than" than key
 *   positive int : pfx is "greater than" key
 */
static HSE_ALWAYS_INLINE int
keycmp_prefix(const void *pfx, u32 pfxlen, const void *key, u32 keylen)
{
    if (keylen < pfxlen) {
        int rc = memcmp(pfx, key, keylen);

        return rc ? rc : 1;
    }

    return memcmp(pfx, key, pfxlen);
}

#endif
