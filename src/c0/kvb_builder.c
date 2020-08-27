/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/kvb_builder.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/c1.h>

#include "c0skm_internal.h"
#include "c0_kvmsm.h"
#include "kvb_builder_internal.h"

struct bonsai_kv;

merr_t
kvb_builder_iter_alloc(
    u64                       ingestid,
    u64                       gen,
    bool                      istxn,
    u16                       nkiter,
    struct perfc_set *        pc,
    struct kvb_builder_iter **iter)
{
    struct kvb_builder_iter *it;

    size_t sz;
    void * bkvs;
    void * nbkv;

    sz = sizeof(*it) + sizeof(*it->kvbi_info) + nkiter * sizeof(void *) + nkiter * sizeof(u32);

    it = calloc(1, sz);
    if (!it)
        return merr(ev(ENOMEM));

    it->kvbi_ingestid = ingestid;
    it->kvbi_info = (void *)(it + 1);
    bkvs = (void *)(it->kvbi_info + 1);
    nbkv = (void *)((void **)bkvs + nkiter);

    c0kvsm_info_init(it->kvbi_info, gen, bkvs, nbkv, nkiter, istxn);

    *iter = it;
    perfc_inc(pc, PERFC_RA_C0SKM_ITERC);

    return 0;
}

void
kvb_builder_iter_destroy(struct kvb_builder_iter *iter, struct perfc_set *pc)
{
    struct c1_kvcache *kvc;

    int i;

    if (ev(!iter))
        return;

    kvc = iter->kvbi_kvcache;
    if (kvc)
        c1_put_kvcache(kvc);

    if (iter->kvbi_c1h && iter->kvbi_bldrelm)
        c1_kvset_builder_release(iter->kvbi_c1h, iter->kvbi_bldrelm);

    for (i = 0; i < iter->kvbi_info->c0s_nkiter; i++)
        free(iter->kvbi_info->c0s_bkvs[i]);

    perfc_inc(pc, PERFC_RA_C0SKM_ITERD);

    free(iter);
}

void
kvb_builder_iter_init(
    struct kvb_builder_iter *iter,
    struct c0sk_mutation *   c0skm,
    struct c0_kvmultiset *   c0kvms,
    struct c1 *              c1h,
    int *                    ref,
    u64                      ksize,
    u64                      vsize,
    bool                     istxn)
{
    iter->kvbi_c0skm = c0skm;
    iter->kvbi_c0kvms = c0kvms;
    iter->kvbi_c1h = c1h;
    iter->kvbi_ref = ref;
    iter->kvbi_ksize = ksize;
    iter->kvbi_vsize = vsize;
    iter->get_next = kvb_builder_get_next;
    iter->put = kvb_builder_iter_put;

    c0kvms_mlock(c0kvms);
    ++(*ref);
    c0kvms_munlock(c0kvms);

    if (PERFC_ISON(c0skm_get_perfc_kv(c0skm)))
        iter->kvbi_kvbc = 0;
}

bool
kvb_builder_iter_istxn(struct kvb_builder_iter *iter)
{
    return iter->kvbi_info->c0s_txn;
}

void
kvb_builder_iter_put(struct kvb_builder_iter *iter)
{
    struct c0_kvmultiset *c0kvms;

    int *ref;

    if (ev(!iter))
        return;

    c0kvms = iter->kvbi_c0kvms;

    c0kvms_mlock(c0kvms);
    ref = iter->kvbi_ref;
    assert(*ref > 0);
    if (--(*ref) == 0)
        c0kvms_msignal(c0kvms);
    c0kvms_munlock(c0kvms);

    kvb_builder_iter_destroy(iter, c0skm_get_perfc_kv(iter->kvbi_c0skm));
}

merr_t
kvb_builder_get_next(struct kvb_builder_iter *iter, struct c1_kvbundle **ckvb)
{
    struct c1_kvbundle *  kvb;
    struct c1_kvcache *   kvc;
    struct s_list_head *  tail;
    struct c1 *           c1h;
    struct c0kvsm_info *  info;
    struct c0_kvmultiset *c0kvms;
    struct c0sk_mutation *c0skm;
    struct perfc_set *    set;

    merr_t err;
    u64    stripsz;
    u64    kvlen;
    u32    cbkv;
    u32    tbkv;
    u32    nbkv;
    u8     kidx;
    u64    kskip;

    c1h = iter->kvbi_c1h;
    info = iter->kvbi_info;
    c0skm = iter->kvbi_c0skm;
    tail = NULL;
    kskip = 0;
    *ckvb = NULL;

    kidx = info->c0s_bkvidx;
    cbkv = info->c0s_cbkv;
    tbkv = info->c0s_tbkv;
    nbkv = info->c0s_kcnt;
    set = c0skm_get_perfc_kv(c0skm);

    /* No more bundles to consume */
    if (tbkv >= nbkv) {
        perfc_rec_sample(set, PERFC_DI_C0SKM_KVBPI, iter->kvbi_kvbc);
        return 0;
    }

    /* If the KVMS is already ingested, then bail out. */
    c0kvms = iter->kvbi_c0kvms;
    if (c0kvms_is_ingested(c0kvms))
        return 0;

    /* Obtain a kv cache reference from c1 to be used by this iterator.
     * During this iterator's lifetime, the kv objects (kvbundle, kvtuple,
     * and vtuple) can be allocated by passing this kv cache reference.
     */
    kvc = iter->kvbi_kvcache;
    if (!kvc) {
        kvc = c1_get_kvcache(c1h);
        if (!kvc)
            return merr(ev(ENOENT));

        iter->kvbi_kvcache = kvc;
    }

    err = c1_kvbundle_alloc(kvc, &kvb);
    if (ev(err))
        return err;

    stripsz = c1_ingest_stripsize(c1h);
    kvlen = 0;
    tail = NULL;

    /* Fill a stripsz worth of data in this kvb */
    while (kvlen <= stripsz && tbkv < nbkv) {
        struct bonsai_kv **bkvs;
        struct bonsai_kv * bkv;
        struct c1_kvtuple *ckvt;

        u64 len;

        len = 0;
        ckvt = NULL;

        if (cbkv >= info->c0s_nbkv[kidx]) {
            ++kidx;
            cbkv = 0;
        }

        bkvs = info->c0s_bkvs[kidx];
        assert(bkvs);

        bkv = bkvs[cbkv++];
        assert(bkv);

        ++tbkv;
        /* Defensive check */
        if (ev(!bkv)) {
            tbkv += (info->c0s_nbkv[kidx] - cbkv);
            cbkv = info->c0s_nbkv[kidx];
            break;
        }

        /* Initialize and fill the key value tuple for this bkv */
        err = kvb_builder_kvtuple_add(iter, bkv, kvb, &len, &ckvt);
        if (ev(err))
            return err;

        /* If nothing is ready to be ingested in this bkv, continue. */
        if (len == 0) {
            if (PERFC_ISON(set))
                ++kskip;
            continue;
        }

        kvlen += len;
        c1_kvbundle_add_kvt(kvb, ckvt, &tail);
    }

    info->c0s_tbkv = tbkv;
    info->c0s_cbkv = cbkv;
    info->c0s_bkvidx = kidx;

    /* No more bkvs left to process and nothing to ingest. */
    if (kvlen == 0) {
        assert(tbkv >= nbkv);
        return 0;
    }

    c1_kvbundle_set_size(kvb, kvlen);

    if (PERFC_ISON(set)) {
        perfc_rec_sample(set, PERFC_DI_C0SKM_KVBSZ, kvlen);
        perfc_rec_sample(set, PERFC_DI_C0SKM_KVKPB, c1_kvbundle_get_ktc(kvb));
        perfc_rec_sample(set, PERFC_DI_C0SKM_KVVPB, c1_kvbundle_get_vtc(kvb));
        perfc_rec_sample(set, PERFC_DI_C0SKM_KVKSK, kskip);
        ++iter->kvbi_kvbc;
    }

    *ckvb = kvb;

    return 0;
}

merr_t
kvb_builder_kvtuple_add(
    struct kvb_builder_iter *iter,
    struct bonsai_kv *       bkv,
    struct c1_kvbundle *     kvb,
    u64 *                    kvlen,
    struct c1_kvtuple **     ckvt)
{
    struct c1_kvtuple *kvt;
    struct c1_kvcache *kvc;

    u64    minseqno, maxseqno;
    u64    klen, vlen, cnid;
    u32    skidx;
    merr_t err;

    *kvlen = 0;
    *ckvt = NULL;

    skidx = key_immediate_index(&bkv->bkv_key_imm);
    cnid = c0skm_get_cnid(iter->kvbi_c0skm, skidx);

    if (ev(cnid == 0)) { /* Invalid cnid */
        hse_log(HSE_ERR "%s: invalid cnid %lu for skidx %u", __func__, cnid, skidx);
        return merr(ENOENT);
    }

    kvc = iter->kvbi_kvcache;

    /* Allocate kv tuple */
    err = c1_kvtuple_alloc(kvc, &kvt);
    if (ev(err))
        return err;

    vlen = 0;
    err = kvb_builder_vtuple_add(iter, bkv, kvt, &vlen, &minseqno, &maxseqno);
    if (err) {
        /* This indicates that no values from this bkv was chosen for
         * c1 ingest.
         */
        if (merr_errno(err) == ENOENT) {
            assert(vlen == 0);
            return 0;
        }

        return ev(err);
    }

    klen = key_imm_klen(&bkv->bkv_key_imm);

    c1_kvtuple_init(kvt, klen, bkv->bkv_key, cnid, skidx, bkv);

    c1_kvbundle_set_seqno(kvb, minseqno, maxseqno);

    *kvlen = klen + vlen;

    *ckvt = kvt;

    return 0;
}

merr_t
kvb_builder_vtuple_add(
    struct kvb_builder_iter *iter,
    struct bonsai_kv *       bkv,
    struct c1_kvtuple *      ckvt,
    u64 *                    vlen,
    u64 *                    minseqno,
    u64 *                    maxseqno)
{
    struct bonsai_val *   val;
    struct c0_kvmultiset *c0kvms;
    struct c0_kvset *     c0kvs;
    struct c0kvsm_info *  info;
    struct c1_kvcache *   kvc;
    struct s_list_head *  tail;

    bool istxn;
    u64  tlen = 0;
    u64  seqno_prev;
    u32  skidx;
    bool found = false;

    s8 mindex __maybe_unused;

    seqno_prev = U64_MAX;
    *minseqno = U64_MAX;
    *maxseqno = 0;

    c0kvms = iter->kvbi_c0kvms;
    c0kvs = NULL;
    info = iter->kvbi_info;
    istxn = kvb_builder_iter_istxn(iter);
    kvc = iter->kvbi_kvcache;
    tail = NULL;
    skidx = key_immediate_index(&bkv->bkv_key_imm);
    mindex = info->c0s_mindex;

    assert(bkv);
    assert(mindex == 0 || mindex == 1);

    /* If ptomb, set c0kvs to ptomb kvset. */
    if (istxn && info->c0s_ptomb)
        c0kvs = c0kvms_ptomb_c0kvset_get(c0kvms);

    for (val = bkv->bkv_values; val; val = val->bv_next) {
        enum hse_seqno_state     state;
        struct c1_vtuple *       cvt;
        struct c1_bonsai_vbldr **vbldr;

        merr_t err;
        void * data;
        u64    len;
        u64    seqno;
        bool   tomb;

        /* Skip the val if it was ingested in a prior mutation
         * generation.
         */
        if (bv_priv_get(val) != 0)
            continue;

        /* If processing a transaction mutation list skip the non-tx
         * values and vice-versa.
         */
        if ((istxn && !bv_is_txn(val)) || (!istxn && bv_is_txn(val)))
            continue;

        /* If the seqno state is INVAL/UNDEF, it corresponds to a txn
         * in the merge phase. If we are processing a transaction
         * mutation list add this bkv to the pending list in this
         * kvset. This is done to not lose track of this txn mutation.
         * The pending list will be processed in the next interval.
         */
        seqno = 0;
        state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);
        if (state != HSE_SQNREF_STATE_DEFINED) {
            if (istxn && (state == HSE_SQNREF_STATE_INVALID || state == HSE_SQNREF_STATE_UNDEFINED))
                c0kvsm_add_txpend(c0kvms, iter->kvbi_c0skm, bkv, val->bv_vlen, skidx, &c0kvs);
            continue;
        }

        /*
         * For a non-tx mutation:
         * If seqno > max seqno, skip it as it will be processed in
         * the next interval. This bkv must be part of the current
         * active mutation list.
         *
         * If seqno < min seqno, there's no need to look at further
         * values, as the bonsai_val list is ordered by seqno.
         */
        if (!istxn) {
            if (seqno > info->c0s_maxseqno)
                continue;

            if (seqno < info->c0s_minseqno)
                break;
        }

        /*
         * For a tx mutation:
         * If seqno > tx seqno, add it to the pending list as we
         * cannot process a tx mutation partially.
         */
        if (istxn && seqno > info->c0s_tseqno) {
            c0kvsm_add_txpend(c0kvms, iter->kvbi_c0skm, bkv, val->bv_vlen, skidx, &c0kvs);
            continue;
        }

        /* Skip this value if the same seqno was seen already. */
        if (seqno == seqno_prev)
            continue;

        seqno_prev = seqno;
        found = true;

        err = c1_vtuple_alloc(kvc, &cvt);
        if (ev(err))
            return err;

        /* Set the mutation gen number in this bonsai val instance. */
        bv_priv_set(val, info->c0s_gen);

        data = NULL;
        len = 0;
        tomb = false;

        /* For a tombstone, store the unique pointer on media. */
        if (val->bv_vlen != 0) {
            len = val->bv_vlen;
            data = val->bv_value;
        } else if (val->bv_valuep == HSE_CORE_TOMB_REG || val->bv_valuep == HSE_CORE_TOMB_PFX) {
            len = sizeof(val->bv_valuep);
            data = &val->bv_valuep;
            tomb = true;
        }

        vbldr = (struct c1_bonsai_vbldr **)&val->bv_rock;

        if (*minseqno > seqno)
            *minseqno = seqno;
        if (*maxseqno < seqno)
            *maxseqno = seqno;

        c1_vtuple_init(cvt, len, seqno, data, tomb, vbldr);

        c1_kvtuple_addval(ckvt, cvt, &tail);

        tlen += len;
    }

    *vlen = tlen;

    if (!found)
        return merr_once(ENOENT);

    return 0;
}
