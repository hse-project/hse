/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_C0_KVSETM_H
#define HSE_CORE_C0_KVSETM_H

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0_kvset.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/slist.h>

#define C0KVMSM_ITER_FACTOR 2

struct bonsai_kv;
struct c0sk_mutation;
struct c0_kvmultiset;

/* struct c0_kvsetm - tracks mutations in a kvset.
 * @c0m_head:     head of the mutation list
 * @c0m_tail:     tail of the mutation list
 * @c0m_minseqno: min sequence number
 * @c0m_maxseqno: max sequence number
 * @c0m_ksize:    total key bytes in the mutation list
 * @c0m_vsize:    total value bytes in the mutation list
 * @c0m_kcnt:     number of keys mutated
 * @c0m_vcnt:     number of values mutated
 */
struct c0_kvsetm {
    struct s_list_head  c0m_head;
    struct s_list_head *c0m_tail;
    uintptr_t           c0m_minseqno;
    uintptr_t           c0m_maxseqno;
    u64                 c0m_ksize;
    u64                 c0m_vsize;
    u32                 c0m_kcnt;
    u32                 c0m_vcnt;
};

/**
 * struct c0kvsm_minfo - mutation info. for a c0kvset
 * @c0s_bkvs:     pointer to bonsai_kv elements mutated in one iter
 * @c0s_nbkv:     pointer to number of bonsai_kv mutated
 * @c0s_minseqno: min sequence number
 * @c0s_maxseqno: max sequence number
 * @c0s_tseqno:   transaction sequence number used in this mut. interval
 * @c0s_gen:      mutation gen. to be persisted
 * @c0s_kcnt:     number of bonsai_kv elements
 * @c0s_bkvidx:   current bonsai_kv index being processed
 * @c0s_cbkv:     current index processed in a c0kvset
 * @c0s_tbkv:     current index processed in an iter
 * @c0s_txn:      txn or non-txn mutation info.
 * @c0s_ptomb:    true, if it's a ptomb c0kvset.
 * @c0s_nkiter:   no. of c0kvsets in an iter
 * @c0s_mindex:   mutation index
 */
struct c0kvsm_info {
    struct bonsai_kv ***c0s_bkvs;
    u32 *               c0s_nbkv;
    u64                 c0s_minseqno;
    u64                 c0s_maxseqno;
    u64                 c0s_tseqno;
    u64                 c0s_gen;
    u32                 c0s_kcnt;
    u32                 c0s_bkvidx;
    u32                 c0s_cbkv;
    u32                 c0s_tbkv;
    bool                c0s_txn;
    bool                c0s_ptomb;
    u16                 c0s_nkiter;
    s8                  c0s_mindex;
};

/**
 * c0kvsm_reset - Resets the c0kvs mutation info.
 * @ckm:
 */
void
c0kvsm_reset(struct c0_kvsetm *ckm);

/**
 * c0kvsm_get_index - get mutation index
 * @handle: c0kvset handle
 */
u8
c0kvsm_get_mindex(struct c0_kvset *handle);

/**
 * c0kvsm_switch - switch mutation index in this c0kvset.
 * @handle: c0kvset handle
 */
void
c0kvsm_switch(struct c0_kvset *handle);

/**
 * c0kvsm_get - get the non-tx mutation list at the specified index.
 * @handle: c0kvset handle
 * @mindex: mutation index
 */
struct c0_kvsetm *
c0kvsm_get(struct c0_kvset *handle, u8 mindex);

/**
 * c0kvsm_get_tx - get the tx mutation list at the specified index.
 * @handle: c0kvset handle
 * @mindex: mutation index
 */
struct c0_kvsetm *
c0kvsm_get_tx(struct c0_kvset *handle, u8 mindex);

/**
 * c0kvsm_get_txpend - get the tx pending list at the specified index.
 * @handle: c0kvset handle
 */
struct c0_kvsetm *
c0kvsm_get_txpend(struct c0_kvset *handle);

/**
 * c0kvsm_add_txpend- add the bonsai_kv element to the pending mutation
 *                    list in the specified c0kvset.
 * @c0kvms: c0kvms handle
 * @c0skm: c0sk mutation handle
 * @bkv:    bonsai_kv element
 * @vlen:   value length
 * @skidx:
 * @c0kvs:  c0kvs handle (output parameter)
 */
void
c0kvsm_add_txpend(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct bonsai_kv *    bkv,
    u64                   vlen,
    u32                   skidx,
    struct c0_kvset **    c0kvs);

/**
 * c0kvsm_reset_mlist - Reset mutation lists in the specified c0kvset.
 * @c0kvs:   c0kvset handle
 * @mindex:  mutation index
 */
void
c0kvsm_reset_mlist(struct c0_kvset *c0kvs, u8 mindex);

/**
 * c0kvsm_copy_bkv - Copy bonsai_kv elements from the specified c0kvset.
 * @c0kvs:   c0kvset handle
 * @info:
 * @mindex:
 * @istxn:
 * @kidx:
 */
void
c0kvsm_copy_bkv(struct c0_kvset *c0kvs, struct c0kvsm_info *info, u8 mindex, bool istxn, u8 kidx);

/**
 * c0kvsm_has_kvmut - Check whether the specified c0kvset has mutations.
 * @c0kvs:   c0kvset handle
 * @mindex:  mutation index
 * @istxn:
 */
bool
c0kvsm_has_kvmut(struct c0_kvset *c0kvs, u8 mindex, bool istxn);

/**
 * c0kvsm_get_kcnt - Get the number of bonsai_kv elements in the mutation list
 * @c0kvs:   c0kvset handle
 * @mindex:  mutation index
 * @istxn:
 */
u32
c0kvsm_get_kcnt(struct c0_kvset *c0kvs, u8 mindex, bool istxn);

/**
 * c0kvsm_get_vcnt - Get the number of mutated values
 * @c0kvs:   c0kvset handle
 * @mindex:  mutation index
 * @istxn:
 */
u32
c0kvsm_get_vcnt(struct c0_kvset *c0kvs, u8 mindex, bool istxn);

/**
 * c0kvsm_get_kvsize - Get the mutation size
 * @c0kvs:   c0kvset handle
 * @mindex:  mutation index
 * @istxn:   transaction or not
 * @txpsz:   tx pending size
 */
u64
c0kvsm_get_kvsize(
    struct c0_kvset *c0kvs,
    u8               mindex,
    bool             istxn,
    u64 *            txpsz,
    u64 *            ksize,
    u64 *            vsize);

/**
 * c0kvsm_get_minseq - Get the min. sequence number
 * @c0kvs:   c0kvset handle
 * @mindex:  mutation index
 */
u64
c0kvsm_get_minseq(struct c0_kvset *c0kvs, u8 mindex);

/**
 * c0kvsm_get_maxseq - Get the max. sequence number
 * @c0kvs:   c0kvset handle
 * @mindex:  mutation index
 */
u64
c0kvsm_get_maxseq(struct c0_kvset *c0kvs, u8 mindex);

/**
 * c0kvsm_info_init - Initialize a mutation info instance
 * @info:
 * @gen:
 * @bkvs:
 * @nbkv:
 * @nkiter:
 * @istxn:
 */
void
c0kvsm_info_init(struct c0kvsm_info *info, u64 gen, void *bkvs, void *nbkv, u16 nkiter, bool istxn);

/**
 * c0kvsm_info_bkv_first - Returns the first bkv element from rbtree
 * @info:
 */
struct bonsai_kv *
c0kvsm_info_bkv_first(struct c0kvsm_info *info);

/**
 * c0kvsm_info_bkv_next - Returns the next bkv element from rbtree
 * @info:
 * @prev:
 */
struct bonsai_kv *
c0kvsm_info_bkv_next(struct c0kvsm_info *info, struct bonsai_kv *prev);

/**
 * c0kvsm_info_bkv_erase - Removes the bkv rbnode from rbtree
 * @info:
 * @bkv:
 */
void
c0kvsm_info_bkv_erase(struct c0kvsm_info *info, struct bonsai_kv *bkv);

/**
 * c0kvsm_info_set -
 * @info:
 * @minseq:
 * @maxseq:
 * @nbkv:
 * @idx:
 */
merr_t
c0kvsm_info_set(struct c0kvsm_info *info, u64 minseq, u64 maxseq, u32 nbkv, u8 idx);

/**
 * c0kvsm_ptinfo_set -
 * @info:
 * @tseqno:
 * @ptomb:
 */
void
c0kvsm_ptinfo_set(struct c0kvsm_info *info, u64 tseqno, bool ptomb);

#endif /* HSE_CORE_C0_KVSETM_H */
