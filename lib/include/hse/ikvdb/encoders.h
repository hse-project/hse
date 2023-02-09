/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_ENCODERS_H
#define HSE_KVDB_CN_ENCODERS_H

#include <stdint.h>
#include <string.h>

#include <linux/types.h>
#include <sys/types.h>

#include <hse/util/assert.h>
#include <hse/util/byteorder.h>
#include <hse/util/compiler.h>

/* HG16_32K encoding
 *
 *   Max Value    Encoding
 *   127          0xxxxxxx
 *   32K-1        1xxxxxxx xxxxxxxx
 */
#define HG16_32K_MAX 0x7fffu
static inline __attribute__((always_inline)) void
encode_hg16_32k(void *base, size_t *off, uint64_t val)
{
    uint8_t *p = base + *off;
    __be16 val16;

    assert(val <= HG16_32K_MAX);
    if (val < 0x80) {
        *off += 1;
        *p = (uint8_t)val;
    } else {
        *off += 2;
        val16 = cpu_to_be16(0x8000 | (uint16_t)val);
        memcpy(p, &val16, sizeof(val16));
    }
}

static HSE_ALWAYS_INLINE uint64_t
decode_hg16_32k(const void *base, size_t *off)
{
    const uint8_t *p = base + *off;
    __be16 val16;

    if (*p & 0x80) {
        *off += 2;
        memcpy(&val16, p, sizeof(val16));
        return 0x7fff & be16_to_cpu(val16);
    }
    *off += 1;
    return *p;
}

/* HG24_4M encoding:
 *   127      0xxxxxxx
 *   16K-1    10xxxxxx xxxxxxxx
 *   4M-1     11xxxxxx xxxxxxxx xxxxxxxx
 */
#define HG24_4M_MAX 0x3fffffu

static HSE_ALWAYS_INLINE void
encode_hg24_4m(void *base, size_t *off, uint64_t val)
{
    const unsigned m1 = 0x7f;
    const unsigned m2 = 0x3fff;
    uint8_t *p = base + *off;
    __be16 val16;

    assert(val <= HG24_4M_MAX);

    if (val <= m1) {
        *off += 1;
        *p = val;
    } else if (val <= m2) {
        *off += 2;
        val16 = cpu_to_be16(val | 0x8000);
        memcpy(p, &val16, sizeof(val16));
    } else {
        *off += 3;
        *p = (val >> 16) | 0xc0;
        val16 = cpu_to_be16(val);
        memcpy(p + 1, &val16, sizeof(val16));
    }
}

static HSE_ALWAYS_INLINE uint64_t
decode_hg24_4m(const void *base, size_t *off)
{
    const uint8_t *p = base + *off;
    __be16 val16;

    if (!(*p & 0x80)) {
        *off += 1;
        return p[0];
    }

    if (*p & 0x40) {
        *off += 3;
        memcpy(&val16, p + 1, sizeof(val16));
        return ((p[0] & 0x3f) << 16) | be16_to_cpu(val16);
    }

    *off += 2;
    memcpy(&val16, p, sizeof(val16));
    return 0x7fff & be16_to_cpu(val16);
}

/* HG32_1024M encoding:
 *   127      0xxxxxxx
 *   16K-1    10xxxxxx xxxxxxxx
 *   1024M-1  11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
 */
#define HG32_1024M_MAX (UINT32_MAX >> 2)

static HSE_ALWAYS_INLINE void
encode_hg32_1024m(void *base, size_t *off, uint64_t val)
{
    const unsigned m1 = UINT8_MAX >> 1;
    const unsigned m2 = UINT16_MAX >> 2;
    void *p = base + *off;
    __be32 val32;
    __be16 val16;

    assert(val <= HG32_1024M_MAX);

    if (val <= m1) {
        *off += 1;
        *(uint8_t *)p = val;
    } else if (val <= m2) {
        *off += 2;
        val16 = cpu_to_be16(val | 0x8000u);
        memcpy(p, &val16, sizeof(val16));
    } else {
        *off += 4;
        val32 = cpu_to_be32(val | 0xc0000000u);
        memcpy(p, &val32, sizeof(val32));
    }
}

static HSE_ALWAYS_INLINE uint64_t
decode_hg32_1024m(const void *base, size_t *off)
{
    const void *p = base + *off;
    uint code = *(const uint8_t *)p;
    __be32 val32;
    __be16 val16;

    if (!(code & 0x80)) {
        *off += 1;
        return *(const uint8_t *)p;
    }
    if (code & 0x40) {
        *off += 4;
        memcpy(&val32, p, sizeof(val32));
        return be32_to_cpu(val32) & HG32_1024M_MAX;
    }
    *off += 2;
    memcpy(&val16, p, sizeof(val16));
    return be16_to_cpu(val16) & (UINT16_MAX >> 2);
}

/* HG64 encoding:
 *
 *  Max Value         Encoding
 *  ---------         --------
 *  16K-1             00xxxxxx xxxxxxxx
 *  1024M-1           01xxxxxx xxxxxxxx +2 more bytes
 *  (1<<46)-1         10xxxxxx xxxxxxxx +4 more bytes
 *  (UINT64_MAX/4)-1  11xxxxxx xxxxxxxx +6 more bytes
 */
#define HG64_MAX (UINT64_MAX >> 2)

/* max value that can be stored in 2, 4 and 6 bytes */
#define HG64_MAX_2B ((uint64_t)UINT16_MAX >> 2)
#define HG64_MAX_4B ((uint64_t)UINT32_MAX >> 2)
#define HG64_MAX_6B (UINT64_MAX >> 18)

static inline __attribute__((always_inline)) void
encode_hg64(void *base, size_t *off, uint64_t val)
{
    /* codes to distinguish between 2, 4, 6 and 8-byte packings.
     * code4: 0100 in bits 31..28 of uint64_t
     * code6: 1000 in bits 47..44 of uint64_t
     * code8: 1100 in bits 63..60 of uint64_t
     */
    const uint32_t code4 = 0x4 << 28;
    const uint64_t code6 = 0x8LL << 44;
    const uint64_t code8 = 0xcULL << 60;
    void *p = base + *off;

    assert(val <= HG64_MAX);

    if (val <= HG64_MAX_2B) {
        __be16 val16 = cpu_to_be16(val);

        memcpy(p, &val16, sizeof(val16));
        *off += sizeof(val16);
    } else if (val <= HG64_MAX_4B) {
        __be32 val32 = cpu_to_be32(val | code4);

        memcpy(p, &val32, sizeof(val32));
        *off += sizeof(val32);
    } else if (val <= HG64_MAX_6B) {
        __be16 val16 = cpu_to_be16((val | code6) >> 32);
        __be32 val32 = cpu_to_be32(val);

        memcpy(p, &val16, sizeof(val16));
        memcpy(p + sizeof(val16), &val32, sizeof(val32));
        *off += sizeof(val16) + sizeof(val32);
    } else {
        __be64 val64 = cpu_to_be64(val | code8);

        memcpy(p, &val64, sizeof(val64));
        *off += sizeof(val64);
    }
}

static HSE_ALWAYS_INLINE uint64_t
decode_hg64(const void *base, size_t *off)
{
    const void *p = base + *off;
    unsigned code = *(const uint8_t *)p >> 6;
    uint64_t val;
    __be64 val64;
    __be32 val32;
    __be16 val16;

    switch (code) {
    case 0:
        *off += sizeof(val16);
        memcpy(&val16, p, sizeof(val16));
        val = be16_to_cpu(val16);
        break;
    case 1:
        *off += sizeof(val32);
        memcpy(&val32, p, sizeof(val32));
        val = be32_to_cpu(val32) & HG64_MAX_4B;
        break;
    case 2:
        *off += sizeof(val16) + sizeof(val32);
        memcpy(&val16, p, sizeof(val16));
        val = be16_to_cpu(val16);
        val <<= 32;
        memcpy(&val32, p + sizeof(val16), sizeof(val32));
        val |= be32_to_cpu(val32);
        val &= HG64_MAX_6B;
        break;
    case 3:
    default:
        *off += sizeof(val64);
        memcpy(&val64, p, sizeof(val64));
        val = be64_to_cpu(val64) & HG64_MAX;
        break;
    }

    return val;
}

/*
 * Google Protobuf Varint
 * - Doesn't perform as well as the homegrown encodings
 */
#define VARINT_MAX U64_MAX

static inline __attribute__((always_inline)) void
encode_varint(void *base, size_t *off, uint64_t val)
{
    uint8_t *p = base + *off;

    while (val >= 0x80) {
        *p++ = val | 0x80;
        val >>= 7;
    }
    *p++ = val;
    *off = p - (uint8_t *)base;
}

static HSE_ALWAYS_INLINE uint64_t
decode_varint(const void *base, size_t *off)
{
    const uint8_t *p = base + *off;
    uint8_t tmp, byte;
    uint64_t v;

    byte = 0;
    tmp = *p++;
    v = tmp & ~0x80;
    while (tmp & 0x80) {
        tmp = *p++;
        v |= ((uint64_t)(tmp & ~0x80) << (++byte * 7));
    }
    *off = p - (const uint8_t *)base;
    return v;
}

#endif
