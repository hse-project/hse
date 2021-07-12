/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_TUPLE_H
#define HSE_CORE_TUPLE_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/key_util.h>
#include <hse_util/seqno.h>

#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/omf_kmd.h>

/* clang-format off */

/*-  Key/Value Tuple  -------------------------------------------------------*/

/* tombstone value */
#define HSE_CORE_TOMB_REG       ((void *)~0x1UL)
#define HSE_CORE_TOMB_PFX       ((void *)~0UL)

/* Note that HSE_CORE_IS_TOMB() will be true for both a reg tomb as well as a ptomb */
#define HSE_CORE_IS_TOMB(ptr)   (((uintptr_t)(ptr) & ~0x1UL) == ~0x1UL)
#define HSE_CORE_IS_PTOMB(ptr)  (((uintptr_t)(ptr) & ~0x0UL) == ~0x0UL)

enum key_lookup_res {
    NOT_FOUND = 1,
    FOUND_VAL = 2,
    FOUND_TMB = 3,
    FOUND_PTMB = 4,
    FOUND_MULTIPLE = 5,
};

/* clang-format on */

struct kvs_ktuple {
    u64         kt_hash;
    const void *kt_data;
    s32         kt_len;
    u32         kt_flags;
    u64         kt_seqno;
    u64         kt_dgen;
};

/**
 * struct kvs_vtuple - a container for carrying a value
 * @vt_data: ptr to the value in-core memory or a special tomb value
 * @vt_xlen: opaque encoded length
 *
 * Always use kvs_vtuple_vlen() to learn the in-core length of a value.
 * If it returns zero then @kt_data likely is not a valid pointer but
 * instead encodes a special value (e.g., a tomb).
 */
struct kvs_vtuple {
    void *vt_data;
    u64   vt_xlen;
};

struct kvs_buf {
    void *b_buf;
    u32   b_buf_sz;
    u32   b_len;
};

struct kvs_kvtuple {
    struct kvs_ktuple kvt_key;
    struct kvs_vtuple kvt_value;
};

struct kvs_vtuple_ref {
    enum kmd_vtype vr_type;
    union {
        struct {
            u16 vr_index;
            u32 vr_off;
            u32 vr_len;
            u32 vr_complen;
        } vb;
        struct {
            u16         vr_len;
            const void *vr_data;
        } vi;
    };
    u64 vr_seq;
};

static inline void
kvs_ktuple_init(struct kvs_ktuple *kt, const void *key, s32 key_len)
{
    kt->kt_data = key;
    kt->kt_len = key_len;
    kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);
    kt->kt_flags = 0;
}

static inline void
kvs_ktuple_init_nohash(struct kvs_ktuple *kt, const void *key, s32 key_len)
{
    kt->kt_data = key;
    kt->kt_len = key_len;
    kt->kt_hash = 0;
    kt->kt_flags = 0;
}

/**
 * kvs_vtuple_init() - initialize a value tuple
 * @vt:   the vtuple to initialize
 * @val:  pointer to the in-core value or other encoding (e.g. tomb)
 * @xlen: length of @val, opaque encoded @xlen, or zero for tomb
 *
 * kvs_vtuple_init() may be used to initialize a simple, uncompressed
 * value or tomb encoding.  It may also be used to initialize a vtuple
 * from the fields of an existing encoded vtuple.
 */
static inline void
kvs_vtuple_init(struct kvs_vtuple *vt, void *val, u64 xlen)
{
    vt->vt_data = val;
    vt->vt_xlen = xlen;
}

/**
 * kvs_vtuple_cinit() - initialize a compressed value tuple
 * @vt:   the vtuple to initialize
 * @val:  pointer to compressed in-core value
 * @vlen: the uncompressed value length
 * @clen: the compressed value length
 *
 * A compressed value length should always be greater than zero
 * and less than the uncompressed value length.  The val pointer
 * should always be a valid memory pointer, not a tomb encoding.
 */
static inline void
kvs_vtuple_cinit(struct kvs_vtuple *vt, void *val, uint vlen, uint clen)
{
    assert(!(HSE_CORE_IS_TOMB(val) && HSE_CORE_IS_PTOMB(val)));
    assert(clen > 0 && clen < vlen);

    vt->vt_data = val;
    vt->vt_xlen = ((u64)clen << 32) | vlen;
}

/**
 * kvs_vtuple_vlen() - return in-core value length
 * @vt: ptr to a vtuple
 *
 * kvs_vtuple_vlen() returns the in-core length (in bytes) of the
 * given vtuple, irrespective of whether or not it is compressed.
 */
static HSE_ALWAYS_INLINE uint
kvs_vtuple_vlen(const struct kvs_vtuple *vt)
{
    uint clen = vt->vt_xlen >> 32;
    uint vlen = vt->vt_xlen & 0xfffffffful;

    return clen ?: vlen;
}

static HSE_ALWAYS_INLINE uint
kvs_vtuple_clen(const struct kvs_vtuple *vt)
{
    return vt->vt_xlen >> 32;
}

static inline void
kvs_buf_init(struct kvs_buf *vbuf, void *buf, u32 buf_size)
{
    vbuf->b_buf = buf;
    vbuf->b_buf_sz = buf_size;
    vbuf->b_len = 0;
}
#endif
