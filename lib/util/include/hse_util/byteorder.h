/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_BYTEORDER_H
#define HSE_PLATFORM_BYTEORDER_H

#include <endian.h>
#include <stdint.h>

#include <hse_util/compiler.h>

static HSE_ALWAYS_INLINE uint16_t
cpu_to_le16(uint16_t x)
{
    return htole16(x);
}
static HSE_ALWAYS_INLINE uint32_t
cpu_to_le32(uint32_t x)
{
    return htole32(x);
}
static HSE_ALWAYS_INLINE uint64_t
cpu_to_le64(uint64_t x)
{
    return htole64(x);
}

static HSE_ALWAYS_INLINE uint16_t
le16_to_cpu(uint16_t x)
{
    return le16toh(x);
}
static HSE_ALWAYS_INLINE uint32_t
le32_to_cpu(uint32_t x)
{
    return le32toh(x);
}
static HSE_ALWAYS_INLINE uint64_t
le64_to_cpu(uint64_t x)
{
    return le64toh(x);
}

static HSE_ALWAYS_INLINE uint16_t
cpu_to_be16(uint16_t x)
{
    return htobe16(x);
}
static HSE_ALWAYS_INLINE uint32_t
cpu_to_be32(uint32_t x)
{
    return htobe32(x);
}
static HSE_ALWAYS_INLINE uint64_t
cpu_to_be64(uint64_t x)
{
    return htobe64(x);
}

static HSE_ALWAYS_INLINE uint16_t
be16_to_cpu(uint16_t x)
{
    return be16toh(x);
}
static HSE_ALWAYS_INLINE uint32_t
be32_to_cpu(uint32_t x)
{
    return be32toh(x);
}
static HSE_ALWAYS_INLINE uint64_t
be64_to_cpu(uint64_t x)
{
    return be64toh(x);
}

#endif
