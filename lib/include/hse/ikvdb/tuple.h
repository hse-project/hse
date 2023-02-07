/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_CORE_TUPLE_H
#define HSE_CORE_TUPLE_H

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/util/key_util.h>
#include <hse/util/seqno.h>

#include <hse/ikvdb/key_hash.h>
#include <hse/ikvdb/omf_kmd.h>

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
    uint64_t    kt_hash;
    const void *kt_data;
    int32_t     kt_len;
    uint32_t    kt_flags;
    uint64_t    kt_seqno;
    uint64_t    kt_dgen;
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
    void    *vt_data;
    uint64_t vt_xlen;
};

struct kvs_buf {
    void    *b_buf;
    uint32_t b_buf_sz;
    uint32_t b_len;
};

struct kvs_kvtuple {
    struct kvs_ktuple kvt_key;
    struct kvs_vtuple kvt_value;
};

struct kvs_vtuple_ref {
    enum kmd_vtype vr_type;
    union {
        struct {
            uint16_t vr_index;
            uint32_t vr_off;
            uint32_t vr_len;
            uint32_t vr_complen;
        } vb;
        struct {
            uint16_t    vr_len;
            const void *vr_data;
        } vi;
    };
    uint64_t vr_seq;
};

static inline void
kvs_ktuple_init(struct kvs_ktuple *kt, const void *key, int32_t key_len)
{
    kt->kt_data = key;
    kt->kt_len = key_len;
    kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);
    kt->kt_flags = kt->kt_seqno = kt->kt_dgen = 0;
}

static inline void
kvs_ktuple_init_nohash(struct kvs_ktuple *kt, const void *key, int32_t key_len)
{
    kt->kt_data = key;
    kt->kt_len = key_len;
    kt->kt_hash = 0;
    kt->kt_flags = kt->kt_seqno = kt->kt_dgen = 0;
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
kvs_vtuple_init(struct kvs_vtuple *vt, void *val, uint64_t xlen)
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
    vt->vt_xlen = ((uint64_t)clen << 32) | vlen;
}

/**
 * kvs_vtuple_vlen() - return in-core value length
 * @vt: ptr to a vtuple
 *
 * kvs_vtuple_vlen() returns the in-core length (in bytes) of the
 * given vtuple, irrespective of whether or not it is compressed.
 */
static HSE_ALWAYS_INLINE uint32_t
kvs_vtuple_vlen(const struct kvs_vtuple *vt)
{
    const uint32_t clen = vt->vt_xlen >> 32;
    const uint32_t vlen = vt->vt_xlen & 0xfffffffful;

    return clen ? clen : vlen;
}

static HSE_ALWAYS_INLINE uint32_t
kvs_vtuple_clen(const struct kvs_vtuple *vt)
{
    return vt->vt_xlen >> 32;
}

static inline void
kvs_buf_init(struct kvs_buf *vbuf, void *buf, uint32_t buf_size)
{
    vbuf->b_buf = buf;
    vbuf->b_buf_sz = buf_size;
    vbuf->b_len = 0;
}

#endif
