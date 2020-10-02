/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_TUPLE_H
#define HSE_CORE_TUPLE_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/key_util.h>
#include <hse_util/seqno.h>

#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/omf_kmd.h>

/*-  Key/Value Tuple  -------------------------------------------------------*/

/* tombstone value */
#define HSE_CORE_TOMB_REG ((void *)~0x1UL)
#define HSE_CORE_TOMB_PFX ((void *)~0UL)
#define HSE_CORE_IS_TOMB(ptr) (((uintptr_t)(ptr) & ~0x1UL) == ~0x1UL)

#define HSE_CORE_IS_PTOMB(ptr) (((uintptr_t)(ptr) & ~0x0UL) == ~0x0UL)

enum key_lookup_res {
    NOT_FOUND = 1,
    FOUND_VAL = 2,
    FOUND_TMB = 3,
    FOUND_PTMB = 4,
    FOUND_MULTIPLE = 5,
};

struct kvs_ktuple {
    u64         kt_hash;
    const void *kt_data;
    s32         kt_len;
};

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
}

static inline void
kvs_ktuple_init_nohash(struct kvs_ktuple *kt, const void *key, s32 key_len)
{
    kt->kt_data = key;
    kt->kt_len = key_len;
    kt->kt_hash = 0;
}

static inline void
kvs_vtuple_init(struct kvs_vtuple *vt, void *val, u64 xlen)
{
    vt->vt_data = val;
    vt->vt_xlen = xlen;
}

static __always_inline uint
kvs_vtuple_len(const struct kvs_vtuple *vt)
{
    uint clen = vt->vt_xlen >> 32;
    uint ulen = vt->vt_xlen & 0xfffffffful;

    return clen ?: ulen;
}

static inline void
kvs_buf_init(struct kvs_buf *vbuf, void *buf, u32 buf_size)
{
    vbuf->b_buf = buf;
    vbuf->b_buf_sz = buf_size;
    vbuf->b_len = 0;
}
#endif
