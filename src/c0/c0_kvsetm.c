/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/perfc.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/seqno.h>

#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/cn.h>

#include "c0skm_internal.h"
#include "c0_kvsetm.h"

struct c0_kvmultiset;

void
c0kvsm_info_init(struct c0kvsm_info *info, u64 gen, u16 nkiter, bool istxn)
{
    info->c0s_minseqno = U64_MAX;
    info->c0s_gen = gen;
    info->c0s_txn = istxn;
    info->c0s_mindex = -1;
    info->c0s_nkiter = nkiter;
    info->c0s_nbkv = (void *)(info->c0s_bkvs + nkiter);
}

merr_t
c0kvsm_info_set(struct c0kvsm_info *info, u64 minseq, u64 maxseq, u32 nbkv, u8 idx)
{
    struct bonsai_kv **bkvs;

    bkvs = calloc(nbkv, sizeof(*bkvs));
    if (ev(!bkvs)) {
        info->c0s_bkvs[idx] = NULL;
        return merr(ENOMEM);
    }

    info->c0s_bkvs[idx] = bkvs;
    info->c0s_nbkv[idx] = nbkv;

    info->c0s_minseqno = min_t(u64, info->c0s_minseqno, minseq);
    info->c0s_maxseqno = max_t(u64, info->c0s_maxseqno, maxseq);

    return 0;
}

void
c0kvsm_ptinfo_set(struct c0kvsm_info *info, u64 tseqno, bool ptomb)
{
    info->c0s_tseqno = tseqno;
    info->c0s_ptomb = ptomb;
}

static void
c0kvsm_copy_txbkv(struct c0kvsm_info *info, struct c0_kvset *c0kvs, u8 mindex, u8 kidx)
{
    struct c0_kvsetm * ckm;
    struct bonsai_kv **bkvs;
    struct bonsai_kv * bkv;
    struct bonsai_kv * bkv_next;

    u64 nkv;

    bkvs = info->c0s_bkvs[kidx];
    nkv = 0;

    /* First, walk through the pending tx mutation list and add the
     * bonsai_kv element to the corresponding info instance.
     * If a bonsai_kv element is also part of the tx mutation list,
     * skip it.
     */
    ckm = c0kvsm_get_txpend(c0kvs);
    s_list_for_each_entry_safe(bkv, bkv_next, &ckm->c0m_head, bkv_txpend)
    {
        if (!s_list_empty(&bkv->bkv_txmnext[mindex])) {
            INIT_S_LIST_HEAD(&bkv->bkv_txpend);
            continue;
        }

        bkvs[nkv++] = bkv;
        INIT_S_LIST_HEAD(&bkv->bkv_txpend);
    }
    c0kvsm_reset(ckm);

    ckm = c0kvsm_get_tx(c0kvs, mindex);
    s_list_for_each_entry_safe(bkv, bkv_next, &ckm->c0m_head, bkv_txmnext[mindex])
    {
        bkvs[nkv++] = bkv;
        INIT_S_LIST_HEAD(&bkv->bkv_txmnext[mindex]);
    }
    c0kvsm_reset(ckm);

    /* Due to duplicates, nkv can be less than the aggregated value
     * obtained earlier for this kvset.
     */
    assert(nkv <= info->c0s_nbkv[kidx]);
    if (nkv < info->c0s_nbkv[kidx])
        info->c0s_nbkv[kidx] = nkv;

    info->c0s_kcnt += nkv;
}

void
c0kvsm_copy_bkv(struct c0_kvset *c0kvs, struct c0kvsm_info *info, u8 mindex, bool istxn, u8 kidx)
{
    struct c0_kvsetm * ckm;
    struct bonsai_kv **bkvs;
    struct bonsai_kv * bkv;
    struct bonsai_kv * bkv_next;

    u64 nkv;

    assert(info->c0s_mindex < 0 || (info->c0s_mindex == mindex));
    info->c0s_mindex = mindex;

    if (istxn)
        return c0kvsm_copy_txbkv(info, c0kvs, mindex, kidx);

    bkvs = info->c0s_bkvs[kidx];
    nkv = 0;

    /* Walk through the non-tx mutation list and add each bonsai_kv
     * element to the info instance.
     */
    ckm = c0kvsm_get(c0kvs, mindex);
    s_list_for_each_entry_safe(bkv, bkv_next, &ckm->c0m_head, bkv_mnext[mindex])
    {
        bkvs[nkv++] = bkv;
        INIT_S_LIST_HEAD(&bkv->bkv_mnext[mindex]);
    }
    c0kvsm_reset(ckm);

    /* Due to duplicates, nkv can be less than the aggregated value
     * obtained earlier for this kvset.
     */
    assert(nkv <= info->c0s_nbkv[kidx]);
    if (nkv < info->c0s_nbkv[kidx])
        info->c0s_nbkv[kidx] = nkv;

    info->c0s_kcnt += nkv;
}

/* Reset the non-tx, tx and pending list in error situations. */
void
c0kvsm_reset_mlist(struct c0_kvset *c0kvs, u8 mindex)
{
    struct c0_kvsetm *ckm;
    struct bonsai_kv *bkv;
    struct bonsai_kv *bkv_next;

    ckm = c0kvsm_get_txpend(c0kvs);
    s_list_for_each_entry_safe(bkv, bkv_next, &ckm->c0m_head, bkv_txpend)
        INIT_S_LIST_HEAD(&bkv->bkv_txpend);
    c0kvsm_reset(ckm);

    ckm = c0kvsm_get_tx(c0kvs, mindex);
    s_list_for_each_entry_safe(bkv, bkv_next, &ckm->c0m_head, bkv_txmnext[mindex])
        INIT_S_LIST_HEAD(&bkv->bkv_txmnext[mindex]);
    c0kvsm_reset(ckm);

    ckm = c0kvsm_get(c0kvs, mindex);
    s_list_for_each_entry_safe(bkv, bkv_next, &ckm->c0m_head, bkv_mnext[mindex])
        INIT_S_LIST_HEAD(&bkv->bkv_mnext[mindex]);
    c0kvsm_reset(ckm);
}

bool
c0kvsm_has_kvmut(struct c0_kvset *c0kvs, u8 mindex, enum c0kvsm_mut_type type)
{
    struct c0_kvsetm *ckm;
    bool              result = true;

    if (type == C0KVSM_TYPE_TX || type == C0KVSM_TYPE_BOTH) {
        struct c0_kvsetm *ckmp;

        ckmp = c0kvsm_get_txpend(c0kvs);
        ckm = c0kvsm_get_tx(c0kvs, mindex);

        result = (ckmp->c0m_kcnt != 0 || ckm->c0m_kcnt != 0);

        if (type == C0KVSM_TYPE_TX)
            return result;
    }

    ckm = c0kvsm_get(c0kvs, mindex);

    return result && (ckm->c0m_kcnt != 0);
}

u32
c0kvsm_get_kcnt(struct c0_kvset *c0kvs, u8 mindex, enum c0kvsm_mut_type type)
{
    struct c0_kvsetm *ckm;
    u32               kcnt = 0;

    if (type == C0KVSM_TYPE_TX || type == C0KVSM_TYPE_BOTH) {
        struct c0_kvsetm *ckmp;

        ckmp = c0kvsm_get_txpend(c0kvs);
        ckm = c0kvsm_get_tx(c0kvs, mindex);

        kcnt = ckmp->c0m_kcnt + ckm->c0m_kcnt;

        if (type == C0KVSM_TYPE_TX)
            return kcnt;
    }

    ckm = c0kvsm_get(c0kvs, mindex);

    return kcnt + ckm->c0m_kcnt;
}

u32
c0kvsm_get_vcnt(struct c0_kvset *c0kvs, u8 mindex, enum c0kvsm_mut_type type)
{
    struct c0_kvsetm *ckm;
    u32               vcnt = 0;

    if (type == C0KVSM_TYPE_TX || type == C0KVSM_TYPE_BOTH) {
        struct c0_kvsetm *ckmp;

        ckmp = c0kvsm_get_txpend(c0kvs);
        ckm = c0kvsm_get_tx(c0kvs, mindex);

        vcnt = ckmp->c0m_vcnt + ckm->c0m_vcnt;

        if (type == C0KVSM_TYPE_TX)
            return vcnt;
    }

    ckm = c0kvsm_get(c0kvs, mindex);

    return vcnt + ckm->c0m_vcnt;
}

u64
c0kvsm_get_ksize(struct c0_kvset *c0kvs, u8 mindex, enum c0kvsm_mut_type type)
{
    struct c0_kvsetm *ckm;
    u64               ksize = 0;

    if (type == C0KVSM_TYPE_TX || type == C0KVSM_TYPE_BOTH) {
        struct c0_kvsetm *ckmp;

        ckmp = c0kvsm_get_txpend(c0kvs);
        ckm = c0kvsm_get_tx(c0kvs, mindex);

        ksize = ckmp->c0m_ksize + ckm->c0m_ksize;

        if (type == C0KVSM_TYPE_TX)
            return ksize;
    }

    ckm = c0kvsm_get(c0kvs, mindex);

    return ksize + ckm->c0m_ksize;
}

u64
c0kvsm_get_vsize(struct c0_kvset *c0kvs, u8 mindex, enum c0kvsm_mut_type type)
{
    struct c0_kvsetm *ckm;
    u64               vsize = 0;

    if (type == C0KVSM_TYPE_TX || type == C0KVSM_TYPE_BOTH) {
        struct c0_kvsetm *ckmp;

        ckmp = c0kvsm_get_txpend(c0kvs);
        ckm = c0kvsm_get_tx(c0kvs, mindex);

        vsize = ckmp->c0m_vsize + ckm->c0m_vsize;

        if (type == C0KVSM_TYPE_TX)
            return vsize;
    }

    ckm = c0kvsm_get(c0kvs, mindex);

    return vsize + ckm->c0m_vsize;
}

u64
c0kvsm_get_kvsize(struct c0_kvset *c0kvs, u8 mindex, enum c0kvsm_mut_type type)
{
    return c0kvsm_get_ksize(c0kvs, mindex, type) + c0kvsm_get_vsize(c0kvs, mindex, type);
}

u64
c0kvsm_get_minseq(struct c0_kvset *c0kvs, u8 mindex)
{
    struct c0_kvsetm *ckm;

    ckm = c0kvsm_get(c0kvs, mindex);

    return ckm->c0m_minseqno;
}

u64
c0kvsm_get_maxseq(struct c0_kvset *c0kvs, u8 mindex)
{
    struct c0_kvsetm *ckm;

    ckm = c0kvsm_get(c0kvs, mindex);

    return ckm->c0m_maxseqno;
}

void
c0kvsm_add_txpend(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct bonsai_kv *    bkv,
    u64                   vlen,
    u32                   skidx,
    struct c0_kvset **    c0kvs)
{
    struct c0_kvsetm *ckmp;
    struct perfc_set *set;
    struct cn *       cn;

    u64    hash;
    u64    klen;
    size_t sfx_len;
    size_t hashlen;

    klen = key_imm_klen(&bkv->bkv_key_imm);
    set = c0skm_get_perfc_kv(c0skm);
    cn = c0sk_get_cn(c0skm->c0skm_c0skh, skidx);
    sfx_len = cn_get_sfx_len(cn);
    hashlen = klen - sfx_len;

    if (!(*c0kvs)) {
        hash = key_hash64(bkv->bkv_key, hashlen);
        *c0kvs = c0kvms_get_hashed_c0kvset(c0kvms, hash);
    }

    ckmp = c0kvsm_get_txpend(*c0kvs);

    /* If there is a duplicate for this bkv in the currently active
     * tx mutation list, it will be removed while copying the bkv ptrs.
     */
    if (s_list_empty(&bkv->bkv_txpend)) {
        s_list_add_tail(&bkv->bkv_txpend, &ckmp->c0m_tail);
        ++ckmp->c0m_kcnt;
        ckmp->c0m_ksize += key_imm_klen(&bkv->bkv_key_imm);
        perfc_inc(set, PERFC_BA_C0SKM_KVKPN);
    }

    ckmp->c0m_vsize += vlen;
    ++ckmp->c0m_vcnt;
    perfc_inc(set, PERFC_BA_C0SKM_KVVPN);
}
