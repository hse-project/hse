/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_OMF_KMD_H
#define HSE_KVDB_OMF_KMD_H

#include <hse/util/inttypes.h>

#include <hse/ikvdb/encoders.h>
#include <hse/ikvdb/omf_kmd_vtype.h>

/*
 * KMD Entry Members and their minimum, typical and maximum widths:
 *
 *   Member  Encoding    Min Typ Max  Notes
 *   ------  --------    --- --- ---  -----
 *   vtype   u8           1   1   1
 *   seqno   hg64         2   2   8   sequence number
 *   vboff   u32          4   4   4   not present for tombs
 *   vbidx   hg16_32k     1   1   2   not present for tombs
 *   vlen    hg32_1024m   1   1   4   not present for tombs
 *   clen    hg32_1024m   1   1   4   not present for tombs and
 *                                    non-compressed values
 *
 * Per-entry overhead:
 *
 *     Min  Typical  Max
 *      3      3      9     A key with 1 tombstone entry
 *      9      9     19     A key with a non-zero length value
 *     10     10     23     A compressed key
 *
 * KMD List:
 *
 *     count  hg32_1024m  1-4 bytes, indicates how many KMD entries follow
 *     kmd[0]
 *     kmd[1]
 *     ...
 *     kmd[count-1]
 *
 * Pack example:
 *
 *    count = 4;
 *    need = kmd_storage_max(count);
 *    if (off + need > mem_sz)
 *            return -1;
 *    kmd_set_count(mem, &off, count);
 *    kmd_add_tomb(mem, &off, seq);
 *    kmd_add_ptomb(mem, &off, seq);
 *    kmd_add_ival(mem, &off, seq, vbase, vlen);
 *    kmd_add_val(mem, &off, seq, vbidx, vboff, vlen);
 *    assert(off <= memsize);
 *
 * Unpack example:
 *
 *    count = kmd_count(mem, &off);
 *    for (i = 0; i < count; i++) {
 *            kmd_type_seq(mem, &off, &vtype, &seq);
 *            if (vtype == VTYPE_UCVAL) {
 *                    kmd_val(mem, &off, &vbidx, &vboff, &vlen);
 *            } else if (vtype == VTYPE_IVAL) {
 *                    kmd_ival(mem, &off, &vbase, &vlen);
 *            }
 *    }
 *
 * Notes:
 *   - Vblock offfsets are not encoded because the vast majority of offsets in
 *     a large vblock will exceed 16MB and thus require 4-bytes to encode
 *     anyhow.
 */

#define KMD_MAX_COUNT HG32_1024M_MAX

#define KMD_MAX_ENCODED_ENTRY_LEN 23
#define KMD_MAX_ENCODED_COUNT_LEN 4

static inline uint
kmd_storage_max(uint count)
{
    return KMD_MAX_ENCODED_COUNT_LEN + KMD_MAX_ENCODED_ENTRY_LEN * count;
}

static inline void
kmd_set_count(void *kmd, size_t *off, uint count)
{
    assert(count < HG32_1024M_MAX);
    encode_hg32_1024m(kmd, off, count);
}

static inline void
kmd_add_tomb(void *kmd, size_t *off, u64 seq)
{
    ((u8 *)kmd)[*off] = VTYPE_TOMB;
    *off += 1;
    encode_hg64(kmd, off, seq);
}

static inline void
kmd_add_ptomb(void *kmd, size_t *off, u64 seq)
{
    ((u8 *)kmd)[*off] = VTYPE_PTOMB;
    *off += 1;
    encode_hg64(kmd, off, seq);
}

static inline void
kmd_add_zval(void *kmd, size_t *off, u64 seq)
{
    ((u8 *)kmd)[*off] = VTYPE_ZVAL;
    *off += 1;
    encode_hg64(kmd, off, seq);
}

static inline void
kmd_add_ival(void *kmd, size_t *off, u64 seq, const void *vdata, u8 vlen)
{
    ((u8 *)kmd)[*off] = VTYPE_IVAL;
    *off += 1;
    encode_hg64(kmd, off, seq);
    ((u8 *)kmd)[*off] = vlen;
    *off += 1;
    memcpy(((u8 *)kmd) + *off, vdata, vlen);
    *off += vlen;
}

static inline void
kmd_add_val(void *kmd, size_t *off, u64 seq, uint vbidx, uint vboff, uint vlen)
{
    __be32 val32;

    ((u8 *)kmd)[*off] = VTYPE_UCVAL;
    *off += 1;
    encode_hg64(kmd, off, seq);
    encode_hg16_32k(kmd, off, vbidx);
    val32 = cpu_to_be32(vboff);
    memcpy(kmd + *off, &val32, sizeof(val32));
    *off += sizeof(val32);
    encode_hg32_1024m(kmd, off, vlen);
}

static inline void
kmd_add_cval(void *kmd, size_t *off, u64 seq, uint vbidx, uint vboff, uint vlen, uint complen)
{
    __be32 val32;

    ((u8 *)kmd)[*off] = VTYPE_CVAL;
    *off += 1;
    encode_hg64(kmd, off, seq);
    encode_hg16_32k(kmd, off, vbidx);
    val32 = cpu_to_be32(vboff);
    memcpy(kmd + *off, &val32, sizeof(val32));
    *off += sizeof(val32);
    encode_hg32_1024m(kmd, off, vlen);
    encode_hg32_1024m(kmd, off, complen);
}

static inline uint64_t
kmd_count(const void *kmd, size_t *off)
{
    return decode_hg32_1024m(kmd, off);
}

static inline void
kmd_type_seq(const void *kmd, size_t *off, enum kmd_vtype *vtype, u64 *seq)
{
    *vtype = ((const u8 *)kmd)[*off];
    *off += 1;
    *seq = decode_hg64(kmd, off);
}

static inline void
kmd_val(const void *kmd, size_t *off, uint *vbidx, uint *vboff, uint *vlen)
{
    __be32 val32;

    *vbidx = decode_hg16_32k(kmd, off);
    memcpy(&val32, kmd + *off, sizeof(val32));
    *vboff = be32_to_cpu(val32);
    *off += 4;
    *vlen = decode_hg32_1024m(kmd, off);
}

static inline void
kmd_cval(const void *kmd, size_t *off, uint *vbidx, uint *vboff, uint *vlen, uint *complen)
{
    __be32 val32;

    *vbidx = decode_hg16_32k(kmd, off);
    memcpy(&val32, kmd + *off, sizeof(val32));
    *vboff = be32_to_cpu(val32);
    *off += 4;
    *vlen = decode_hg32_1024m(kmd, off);
    *complen = decode_hg32_1024m(kmd, off);
}

static inline void
kmd_ival(const void *kmd, size_t *off, const void **vbase, uint *vlen)
{
    *vlen = ((const u8 *)kmd)[*off];
    *off += 1;
    *vbase = ((const u8 *)kmd) + *off;
    *off += *vlen;
}
#endif
