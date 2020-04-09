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

#include "c0_kvmsm.h"
#include "c0_kvmsm_internal.h"
#include "c0skm_internal.h"

#define C0KVMSM_ITER_FACTOR 2

merr_t
c0kvmsm_ingest(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    u64                   txnseq,
    u8                    itype,
    bool                  final,
    struct c0kvmsm_info * info,
    struct c0kvmsm_info * txinfo)
{
    struct perfc_set *set;

    merr_t err;
    u64    go;

    set = c0skm_get_perfc_kv(c0skm);

    go = perfc_lat_start(set);

    /* Ingest mutations from this kvms. */
    err = c0kvmsm_ingest_internal(c0kvms, c0skm, c1h, gen, txnseq, info, txinfo);
    if (ev(err))
        goto exit;

    if (PERFC_ISON(set)) {
        perfc_rec_lat(set, PERFC_LT_C0SKM_C1ING, go);
        perfc_inc(set, PERFC_RA_C0SKM_C1ING);
    }

    /* Issue a c1_flush or c1_sync based on the request type. */
    if (itype == C1_INGEST_FLUSH) {
        err = c1_flush(c1h);
        if (ev(err))
            hse_log(HSE_ERR "%s: c1 flush failed", __func__);
    } else if (itype == C1_INGEST_SYNC) {
        err = c1_sync(c1h);
        if (ev(err))
            hse_log(HSE_ERR "%s: c1 sync failed", __func__);
    }

exit:
    /* If a KVMS was in INGESTING state before arriving here, we have
     * processed the final set of mutations. So, unset the mutating
     * flag for this KVMS. In the next interval, we will skip this
     * KVMS if it still stays as INGESTING.
     */
    if (!err && final)
        c0kvms_unset_mutating(c0kvms);

    /* Release the final reference on this KVMS. The c0 bonsai cursor
     * heaps can be destroyed post this point.
     */
    c0kvms_putref(c0kvms);

    return err;
}

merr_t
c0kvmsm_ingest_internal(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    u64                   txnseq,
    struct c0kvmsm_info * info_out,
    struct c0kvmsm_info * txinfo_out)
{
    struct c0kvmsm_info info;
    struct c0kvmsm_info txinfo;

    int    ref;
    bool   tx;
    bool   nontx;
    merr_t err = 0;

    /* Two kvb iterators are created per-c0kvset, one for tx mutations
     * and the other for non-tx mutations, if there are any. Both the
     * iterator types obtain a shared reference. When all c0kvsets in a
     * c0kvms have been processed, all its iterators would have got
     * released bringing the reference down to zero.
     */
    ref = 1;

    /* First, determine the number of kvsets that contain mutations.
     * Also, determine the overall mutation size (key + value size)
     * that will be ingested from this kvms into c1.
     */
    c0kvmsm_get_info(c0kvms, &info, &txinfo, false);

    tx = (txinfo.c0ms_kvscnt != 0);
    nontx = (info.c0ms_kvscnt != 0);

    /* If there are no mutations, bail out */
    if (!tx && !nontx)
        return 0;

    /* Ingest tx mutations from all c0 kvsets belonging to this kvms. */
    if (tx) {
        err = c0kvmsm_ingest_tx(c0kvms, c0skm, c1h, gen, txnseq, txinfo.c0ms_kvbytes, &ref);
        if (ev(err))
            goto err_exit;
    }

    /* Ingest non-tx mutations. */
    if (nontx)
        err = c0kvmsm_ingest_nontx(c0kvms, c0skm, c1h, gen, &ref);

    if (!err) {
        if (info_out) {
            info_out->c0ms_kvbytes += info.c0ms_kvbytes;
            info_out->c0ms_kvpbytes += info.c0ms_kvpbytes;
            info_out->c0ms_kvscnt += info.c0ms_kvscnt;
        }
        if (txinfo_out) {
            txinfo_out->c0ms_kvbytes += txinfo.c0ms_kvbytes;
            txinfo_out->c0ms_kvpbytes += txinfo.c0ms_kvpbytes;
            txinfo_out->c0ms_kvscnt += txinfo.c0ms_kvscnt;
        }
    }
err_exit:
    /* Wait for mutations to ingest into c1. For transaction mutations,
     * this ensures that that the pending list is built completely and
     * is ready to be consumed in the next interval.
     */
    c0kvmsm_wait(c0kvms, &ref);
    assert(ref == 0);

    return err;
}

merr_t
c0kvmsm_ingest_nontx(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    int *                 ref)
{
    merr_t err;

    err = c0kvmsm_ingest_common(c0kvms, c0skm, c1h, gen, ref, 0, false);
    if (err) {
        if (merr_errno(err) == EEXIST)
            return 0;

        return ev(err);
    }

    return 0;
}

merr_t
c0kvmsm_ingest_tx(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    u64                   txnseq,
    u64                   txnsz,
    int *                 txnref)
{
    u64    txnid;
    merr_t err;

    /* Get the c1 transaction ID. */
    txnid = c1_get_txnid(c1h);

    /* Start a c1 async. transaction. */
    err = c1_txn_begin(c1h, txnid, txnsz, C1_TXN_ASYNC);
    if (ev(err)) {
        c0kvmsm_reset_mlist(c0kvms, 0);
        return err;
    }

    /* Ingest all transaction mutations. */
    err = c0kvmsm_ingest_common(c0kvms, c0skm, c1h, gen, txnref, txnseq, true);
    if (ev(err)) {
        (void)c1_txn_abort(c1h, txnid);
        if (merr_errno(err) == EEXIST)
            return 0;

        return err;
    }

    /* Commit this c1 transaction. */
    err = c1_txn_commit(c1h, txnid, txnseq, C1_TXN_ASYNC);
    if (ev(err)) {
        (void)c1_txn_abort(c1h, txnid);
        return err;
    }

    return 0;
}

merr_t
c0kvmsm_ingest_common(
    struct c0_kvmultiset *c0kvms,
    struct c0sk_mutation *c0skm,
    struct c1 *           c1h,
    u64                   gen,
    int *                 ref,
    u64                   txnseq,
    bool                  istxn)
{
    struct kvb_builder_iter **iterv;
    struct perfc_set *        set;

    merr_t err = 0;
    u64    go = 0;
    u64    tksz = 0;
    u64    tvsz = 0;
    u32    iterc;
    u32    kvsetc;
    bool   ingest = false;
    bool   found = false;
    u16    nkiter;
    u16    kidx = 0;
    int    i;
    int    slot = 0;
    int    lslot = -1;

    set = c0skm_get_perfc_kv(c0skm);

    /* 'nkiter' determines the number of c0kvsets processed by
     * a single iterator.
     */
    kvsetc = c0kvms_width(c0kvms);
    /* +1 for ptomb kvset and +1 for rounding up. */
    iterc = (kvsetc / C0KVMSM_ITER_FACTOR) + 2;
    nkiter = (kvsetc + iterc - 1) / iterc;

    err = c0kvmsm_iterv_alloc(c0kvms, gen, istxn, iterc, nkiter, set, &iterv);
    if (ev(err)) {
        c0kvmsm_reset_mlist(c0kvms, 0);

        return err;
    }

    for (i = 0; i < kvsetc; ++i) {
        struct c0_kvset *   c0kvs;
        struct c0kvsm_info *info;

        u64 minseq;
        u64 maxseq;
        u64 ksz = 0;
        u64 vsz = 0;
        u32 nbkv;
        u8  mindex;

        c0kvs = c0kvms_get_c0kvset(c0kvms, i);
        mindex = c0kvsm_get_mindex(c0kvs) ^ 1;
        info = iterv[slot]->kvbi_info;

        /* If this kvms is already ingested, bail out. */
        if (c0kvms_is_ingested(c0kvms)) {
            /* No need to reset the mutation list here. It will
             * be reset when the c0kvsets from this c0kvms gets
             * reused for a future c0kvms instance.
             */
            err = merr(EEXIST);
            goto exit;
        }

        /* Process this c0kvset if it has mutations. */
        if (c0kvsm_has_kvmut(c0kvs, mindex, istxn)) {
            found = true;

            minseq = c0kvsm_get_minseq(c0kvs, mindex);
            maxseq = c0kvsm_get_maxseq(c0kvs, mindex);
            nbkv = c0kvsm_get_kcnt(c0kvs, mindex, istxn);

            err = c0kvsm_info_set(info, minseq, maxseq, nbkv, kidx);
            if (ev(err)) {
                lslot = slot;
                c0kvmsm_reset_mlist(c0kvms, slot * nkiter);
                kvb_builder_iter_put(iterv[slot]);

                goto exit;
            }

            /* Get the total key & value size for this c0kvset.*/
            (void)c0kvsm_get_kvsize(c0kvs, mindex, istxn, NULL, &ksz, &vsz);
            tksz += ksz;
            tvsz += vsz;

            go = perfc_lat_startu(set, PERFC_LT_C0SKM_COPY);
            c0kvsm_copy_bkv(c0kvs, info, mindex, istxn, kidx);
            perfc_rec_lat(set, PERFC_LT_C0SKM_COPY, go);

            /* Do not combine ptomb kvset (index 0) with another.
             * After aggregating 'nkiter' c0kvsets, queue this
             * iterator for c1 ingest.
             */
            ingest = ((i == 0) || (++kidx == nkiter));
            if (ingest)
                kidx = 0;

            /* If more c0kvsets can be aggregated for this
             * iterator, continue.
             */
            if (!ingest && (i < kvsetc - 1))
                continue;
        } else {
            /* If this is the last c0kvset and an iterator is
             * is outstanding, queue it.
             */
            if (i < kvsetc - 1 || !found)
                continue;
        }

        if (istxn)
            c0kvsm_ptinfo_set(info, txnseq, (i == 0));

        kvb_builder_iter_init(iterv[slot], c0skm, c0kvms, c1h, ref, tksz, tvsz, istxn);
        assert(iterv[slot]->kvbi_bldrelm == NULL);

        lslot = slot;
        /* Queue this iterator for c1 ingest. */
        err = c1_ingest(c1h, iterv[slot], tksz + tvsz, C1_INGEST_ASYNC);
        if (ev(err)) {
            c0kvmsm_reset_mlist(c0kvms, slot * nkiter);
            kvb_builder_iter_put(iterv[slot]);

            goto exit;
        }

        /* After queueing an iter, advance the slot */
        if (i < kvsetc - 1)
            ++slot;

        found = false;
        tksz = 0;
        tvsz = 0;
    }

exit:
    /* If any iterators are unsed from the loop above, destroy them. */
    while (++lslot < iterc) {
        assert(!iterv[lslot]->kvbi_c0skm);
        kvb_builder_iter_destroy(iterv[lslot], set);
    }

    free(iterv);

    return err;
}

void
c0kvmsm_switch(struct c0_kvmultiset *c0kvms)
{
    struct c0_kvset *c0kvs;

    int i;
    u32 kvsetc;

    kvsetc = c0kvms_width(c0kvms);

    /* Switch the mutation index in all c0kvsets. */
    for (i = 0; i < kvsetc; ++i) {
        c0kvs = c0kvms_get_c0kvset(c0kvms, i);
        c0kvsm_switch(c0kvs);
    }
}

void
c0kvmsm_reset_mlist(struct c0_kvmultiset *c0kvms, int index)
{
    u32 kvsetc;
    int i;

    kvsetc = c0kvms_width(c0kvms);

    for (i = index; i < kvsetc; ++i) {
        struct c0_kvset *c0kvs;

        u8 mindex;

        c0kvs = c0kvms_get_c0kvset(c0kvms, i);
        mindex = c0kvsm_get_mindex(c0kvs) ^ 1;

        c0kvsm_reset_mlist(c0kvs, mindex);
    }
}

void
c0kvmsm_get_info(
    struct c0_kvmultiset *c0kvms,
    struct c0kvmsm_info * info,
    struct c0kvmsm_info * txinfo,
    bool                  active)
{
    int i;
    u32 kvsetc;

    if (info)
        memset(info, 0, sizeof(*info));

    if (txinfo)
        memset(txinfo, 0, sizeof(*txinfo));

    kvsetc = c0kvms_width(c0kvms);

    for (i = 0; i < kvsetc; ++i) {
        struct c0_kvset *c0kvs;

        u8 mindex;

        c0kvs = c0kvms_get_c0kvset(c0kvms, i);
        mindex = c0kvsm_get_mindex(c0kvs);
        if (!active)
            mindex ^= 1;

        if (info) {
            info->c0ms_kvbytes += c0kvsm_get_kvsize(c0kvs, mindex, false, NULL, NULL, NULL);
            if (c0kvsm_get_kcnt(c0kvs, mindex, false) > 0)
                ++info->c0ms_kvscnt;
        }

        if (txinfo) {
            u64 txpsz;

            txpsz = 0;

            txinfo->c0ms_kvbytes += c0kvsm_get_kvsize(c0kvs, mindex, true, &txpsz, NULL, NULL);
            txinfo->c0ms_kvpbytes += txpsz;

            if (c0kvsm_get_kcnt(c0kvs, mindex, true) > 0)
                ++txinfo->c0ms_kvscnt;
        }
    }
}

bool
c0kvmsm_has_txpend(struct c0_kvmultiset *c0kvms)
{
    struct c0kvmsm_info txinfo = { 0 };

    c0kvmsm_get_info(c0kvms, NULL, &txinfo, true);

    return txinfo.c0ms_kvscnt != 0;
}

void
c0kvmsm_wait(struct c0_kvmultiset *c0kvms, int *ref)
{
    c0kvms_mlock(c0kvms);
    assert(*ref > 0);

    --(*ref);

    /* Wait here for the reference to drop to zero. */
    while (*ref != 0)
        c0kvms_mwait(c0kvms);
    c0kvms_munlock(c0kvms);
}

merr_t
c0kvmsm_iterv_alloc(
    struct c0_kvmultiset *     c0kvms,
    u64                        gen,
    bool                       istxn,
    u32                        iterc,
    u16                        nkiter,
    struct perfc_set *         pc,
    struct kvb_builder_iter ***iterv)
{
    struct kvb_builder_iter **itv;

    u64 ingestid;
    int i;

    ingestid = c0kvms_rsvd_sn_get(c0kvms);

    itv = calloc(iterc, sizeof(*itv));
    if (ev(!itv))
        return merr(ENOMEM);

    for (i = 0; i < iterc; i++) {
        merr_t err;

        err = kvb_builder_iter_alloc(ingestid, gen, istxn, nkiter, pc, &itv[i]);
        if (ev(err)) {
            while (--i >= 0)
                kvb_builder_iter_destroy(itv[i], pc);
            free(itv);

            return err;
        }
    }

    *iterv = itv;

    return 0;
}
