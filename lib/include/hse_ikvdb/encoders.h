/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_ENCODERS_H
#define HSE_KVDB_CN_ENCODERS_H

#include <hse_util/inttypes.h>
#include <hse_util/byteorder.h>
#include <hse_util/assert.h>

/* HG16_32K encoding
 *
 *   Max Value    Encoding
 *   127          0xxxxxxx
 *   32K-1        1xxxxxxx xxxxxxxx
 */
#define HG16_32K_MAX 0x7fffu
static inline __attribute__((always_inline)) void
encode_hg16_32k(void *base, size_t *off, u64 val)
{
    u8     *p = base + *off;
    __be16  val16;

    assert(val <= HG16_32K_MAX);
    if (val < 0x80) {
        *off += 1;
        *p = (u8)val;
    } else {
        *off += 2;
        val16 = cpu_to_be16(0x8000 | (u16)val);
        memcpy(p, &val16, sizeof(val16));
    }
}

static HSE_ALWAYS_INLINE u64
decode_hg16_32k(const void *base, size_t *off)
{
    const u8 *p = base + *off;
    __be16    val16;

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

static inline __attribute__((always_inline)) void
encode_hg24_4m(void *base, size_t *off, u64 val)
{
    const unsigned m1 = 0x7f;
    const unsigned m2 = 0x3fff;
    u8 *           p = base + *off;
    __be16         val16;

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

static HSE_ALWAYS_INLINE u64
decode_hg24_4m(const void *base, size_t *off)
{
    const u8 *p = base + *off;
    __be16    val16;

    if (!(*p & 0x80)) {
        *off += 1;
        return p[0];
    }

    if (*p & 0x40) {
        *off += 3;
        return ((p[0] & 0x3f) << 16) | (p[1] << 8) | p[2];
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
#define HG32_1024M_MAX (U32_MAX >> 2)

static inline __attribute__((always_inline)) void
encode_hg32_1024m(void *base, size_t *off, u64 val)
{
    const unsigned m1 = U8_MAX >> 1;
    const unsigned m2 = U16_MAX >> 2;
    void *         p = base + *off;
    __be32         val32;
    __be16         val16;

    assert(val <= HG32_1024M_MAX);

    if (val <= m1) {
        *off += 1;
        *(u8 *)p = val;
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

static HSE_ALWAYS_INLINE u64
decode_hg32_1024m(const void *base, size_t *off)
{
    const void *p = base + *off;
    uint        code = *(const u8 *)p;
    __be32      val32;
    __be16      val16;

    if (!(code & 0x80)) {
        *off += 1;
        return *(const u8 *)p;
    }
    if (code & 0x40) {
        *off += 4;
        memcpy(&val32, p, sizeof(val32));
        return be32_to_cpu(val32) & HG32_1024M_MAX;
    }
    *off += 2;
    memcpy(&val16, p, sizeof(val16));
    return be16_to_cpu(val16) & (U16_MAX >> 2);
}

/* HG64 encoding:
 *
 *  Max Value      Encoding
 *  ---------      --------
 *  16K-1          00xxxxxx xxxxxxxx
 *  1024M-1        01xxxxxx xxxxxxxx +2 more bytes
 *  (1<<46)-1      10xxxxxx xxxxxxxx +4 more bytes
 *  (U64_MAX/4)-1  11xxxxxx xxxxxxxx +6 more bytes
 */
#define HG64_MAX (U64_MAX >> 2)

/* max value that can be stored in 2, 4 and 6 bytes */
#define HG64_MAX_2B ((u64)U16_MAX >> 2)
#define HG64_MAX_4B ((u64)U32_MAX >> 2)
#define HG64_MAX_6B (U64_MAX >> 18)

static inline __attribute__((always_inline)) void
encode_hg64(void *base, size_t *off, u64 val)
{
    /* codes to distinguish between 2, 4, 6 and 8-byte packings.
     * code4: 0100 in bits 31..28 of u64
     * code6: 1000 in bits 47..44 of u64
     * code8: 1100 in bits 63..60 of u64
     */
    const u32 code4 = 0x4 << 28;
    const u64 code6 = 0x8LL << 44;
    const u64 code8 = 0xcULL << 60;
    void *    p = base + *off;

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

static HSE_ALWAYS_INLINE u64
decode_hg64(const void *base, size_t *off)
{
    const void *p = base + *off;
    unsigned    code = *(const u8 *)p >> 6;
    u64         val;
    __be64      val64;
    __be32      val32;
    __be16      val16;

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
encode_varint(void *base, size_t *off, u64 val)
{
    u8 *p = base + *off;

    while (val >= 0x80) {
        *p++ = val | 0x80;
        val >>= 7;
    }
    *p++ = val;
    *off = p - (u8 *)base;
}

static HSE_ALWAYS_INLINE u64
decode_varint(const void *base, size_t *off)
{
    const u8 *p = base + *off;
    u8        tmp, byte;
    u64       v;

    byte = 0;
    tmp = *p++;
    v = tmp & ~0x80;
    while (tmp & 0x80) {
        tmp = *p++;
        v |= ((u64)(tmp & ~0x80) << (++byte * 7));
    }
    *off = p - (const u8 *)base;
    return v;
}

#endif
