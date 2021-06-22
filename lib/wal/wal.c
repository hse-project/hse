/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_wal

#include <hse_util/hse_err.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include <mpool/mpool.h>

#include "wal.h"
#include "wal_buffer.h"
#include "wal_file.h"
#include "wal_omf.h"
#include "wal_mdc.h"

/* clang-format off */

struct wal {
    struct mpool       *mp HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct wal_bufset  *wbs;
    struct wal_fileset *wfset;
    struct wal_mdc     *mdc;

    atomic64_t ingestseq;
    atomic64_t ingestgen;
    atomic64_t txhorizon;

    atomic64_t rid HSE_ALIGNED(SMP_CACHE_BYTES);

    atomic_t   closing HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t error;
    bool       timer_tid_valid;
    pthread_t  timer_tid;
    uint32_t   dur_ms;
    uint32_t   dur_bytes;
    uint32_t   version;
    uint64_t   rgen;
};

/* clang-format on */

static void *
wal_timer(void *rock)
{
    struct wal *wal = rock;
    struct timespec req = {0};
    u64 rid_last = 0;
    long dur_ns;

    pthread_setname_np(pthread_self(), "wal_timer");

    /* dur_ns must not fall outside the range defined by nanosleep(3).
     */
    dur_ns = MSEC_TO_NSEC(wal->dur_ms);
    dur_ns = clamp_t(long, dur_ns - (long)timer_slack, 1, 999999999);

    while (true) {
        u64 tstart, rid, lag;
        merr_t err;

        if (atomic_read(&wal->closing) != 0 || atomic64_read(&wal->error) != 0)
            break;

        tstart = get_time_ns();
        req.tv_nsec = dur_ns;

        rid = atomic64_read(&wal->rid);
        if (rid != rid_last) {
            rid_last = rid;

            err = wal_bufset_flush(wal->wbs);
            if (err) {
                atomic64_set(&wal->error, err);
                break;
            }

            lag = get_time_ns() - tstart;
            if (lag >= req.tv_nsec)
                continue;

            req.tv_nsec -= lag;
        }

        nanosleep(&req, 0);
    }

    pthread_exit(NULL);
}

/*
 * WAL data plane
 */

merr_t
wal_put(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    struct wal_record *recout)
{
    const size_t kvalign = alignof(uint64_t);
    struct wal_rec_omf *rec;
    uint64_t rid, txid = 0, offset;
    size_t klen, vlen, rlen, kvlen, len;
    char *kvdata;
    uint rtype = WAL_RT_NONTX;

    klen = kt->kt_len;
    vlen = kvs_vtuple_vlen(vt);
    rlen = wal_rec_len();
    kvlen = ALIGN(klen, kvalign) + ALIGN(vlen, kvalign);
    len = rlen + kvlen;

    rec = wal_bufset_alloc(wal->wbs, len, &offset);
    if (!rec)
        return merr(ENOMEM);

    rid = atomic64_inc_return(&wal->rid);

    rtype = kvdb_kop_is_txn(os) ? WAL_RT_TX : WAL_RT_NONTX;
    if (rtype == WAL_RT_TX) {
        merr_t err;

        err = kvdb_ctxn_get_view_seqno(kvdb_ctxn_h2h(os->kop_txn), &txid);
        if (err)
            return err;
    }

    wal_rechdr_pack(rtype, rid, kvlen, rec);
    wal_rec_pack(WAL_OP_PUT, kvs->ikv_cnid, txid, klen, vt->vt_xlen, rec);

    kvdata = (char *)rec + rlen;
    memcpy(kvdata, kt->kt_data, klen);
    kt->kt_data = kvdata;
    kt->kt_flags = HSE_BTF_MANAGED;

    if (vlen > 0) {
        kvdata = PTR_ALIGN(kvdata + klen, kvalign);
        memcpy(kvdata, vt->vt_data, vlen);
        vt->vt_data = kvdata;
    }

    recout->recbuf = rec;
    recout->len = len;
    recout->offset = offset;

    return 0;
}

static merr_t
wal_del_impl(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    bool prefix,
    struct wal_record *recout)
{
    const size_t kalign = alignof(uint64_t);
    struct wal_rec_omf *rec;
    uint64_t rid, txid = 0, offset;
    size_t klen, rlen, kalen, len;
    char *kdata;
    uint rtype;

    rlen = wal_rec_len();
    klen = kt->kt_len;
    kalen = ALIGN(klen, kalign);
    len = rlen + kalen;

    rec = wal_bufset_alloc(wal->wbs, len, &offset);
    if (!rec)
        return merr(ENOMEM);

    rid = atomic64_inc_return(&wal->rid);

    rtype = kvdb_kop_is_txn(os) ? WAL_RT_TX : WAL_RT_NONTX;
    if (rtype == WAL_RT_TX) {
        merr_t err;

        err = kvdb_ctxn_get_view_seqno(kvdb_ctxn_h2h(os->kop_txn), &txid);
        if (err)
            return err;
    }

    wal_rechdr_pack(rtype, rid, kalen, rec);
    wal_rec_pack(prefix ? WAL_OP_PDEL : WAL_OP_DEL, kvs->ikv_cnid, txid, klen, 0, rec);

    kdata = (char *)rec + rlen;
    memcpy(kdata, kt->kt_data, klen);
    kt->kt_data = kdata;
    kt->kt_flags = HSE_BTF_MANAGED;

    recout->recbuf = rec;
    recout->len = len;
    recout->offset = offset;

    return 0;
}

merr_t
wal_del(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct wal_record *recout)
{
    return wal_del_impl(wal, kvs, os, kt, false, recout);
}

merr_t
wal_del_pfx(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct wal_record *recout)
{
    return wal_del_impl(wal, kvs, os, kt, true, recout);
}

static merr_t
wal_txn(struct wal *wal, uint rtype, uint64_t txid, uint64_t seqno)
{
    struct wal_txnrec_omf *rec;
    uint64_t rid, offset;
    size_t rlen;

    rlen = wal_txn_rec_len();
    rec = wal_bufset_alloc(wal->wbs, rlen, &offset);
    if (!rec)
        return merr(ENOMEM);

    rid = atomic64_inc_return(&wal->rid);

    wal_txn_rechdr_pack(rtype, rid, rec);
    wal_txn_rec_pack(txid, seqno, rec);
    wal_txn_rechdr_finish(rec, rlen, offset);

    return 0;
}

merr_t
wal_txn_begin(struct wal *wal, uint64_t txid)
{
    return wal_txn(wal, WAL_RT_TXBEGIN, txid, 0);
}

merr_t
wal_txn_abort(struct wal *wal, uint64_t txid)
{
    return wal_txn(wal, WAL_RT_TXABORT, txid, 0);
}

merr_t
wal_txn_commit(struct wal *wal, uint64_t txid, uint64_t seqno)
{
    return wal_txn(wal, WAL_RT_TXCOMMIT, txid, seqno);
}

void
wal_op_finish(struct wal *wal, struct wal_record *rec, uint64_t seqno, uint64_t gen, int rc)
{
    if (rc) {
        if (rc == EAGAIN || rc == ECANCELED)
            rec->offset = U64_MAX - 1; /* recoverable error */
        else
            rec->offset = U64_MAX; /* non-recoverable error */
    }

    wal_rec_finish(rec, seqno, gen);
}

/*
 * WAL control plane
 */

merr_t
wal_create(struct mpool *mp, struct kvdb_cparams *cp, uint64_t *mdcid1, uint64_t *mdcid2)
{
    struct wal_mdc *mdc;
    merr_t err;
    u32 dur_ms, dur_bytes;

    err = wal_mdc_create(mp, MP_MED_CAPACITY, WAL_MDC_CAPACITY, mdcid1, mdcid2);
    if (err)
        return err;

    err = wal_mdc_open(mp, *mdcid1, *mdcid2, &mdc);
    if (err) {
        wal_mdc_destroy(mp, *mdcid1, *mdcid2);
        return err;
    }

    dur_ms = cp->dur_lag_ms;
    dur_ms = clamp_t(long, dur_ms, WAL_DUR_MS_MIN, WAL_DUR_MS_MAX);

    dur_bytes = cp->dur_buf_sz;
    dur_bytes = clamp_t(long, dur_bytes, WAL_DUR_BYTES_MIN, WAL_DUR_BYTES_MAX);

    err = wal_mdc_format(mdc, WAL_VERSION, dur_ms, dur_bytes);

    wal_mdc_close(mdc);

    if (err)
        wal_mdc_destroy(mp, *mdcid1, *mdcid2);

    return err;
}

void
wal_destroy(struct mpool *mp, uint64_t oid1, uint64_t oid2)
{
    wal_mdc_destroy(mp, oid1, oid2);
}

merr_t
wal_open(
    struct mpool        *mp,
    struct kvdb_rparams *rp,
    uint64_t             mdcid1,
    uint64_t             mdcid2,
    struct wal         **wal_out)
{
    struct wal         *wal;
    struct wal_bufset  *wbs;
    struct wal_fileset *wfset;
    struct wal_mdc     *mdc;
    merr_t err;
    int rc;

    if (!mp || !rp || !wal_out)
        return merr(EINVAL);

    if (!rp->dur_enable)
        return 0;

    wal = aligned_alloc(alignof(*wal), sizeof(*wal));
    if (!wal)
        return merr(ENOMEM);

    err = wal_mdc_open(mp, mdcid1, mdcid2, &mdc);
    if (err)
        goto errout;

    wal->rgen = 0;
    wal->version = WAL_VERSION;
    atomic64_set(&wal->rid, 0);
    atomic64_set(&wal->error, 0);
    atomic64_set(&wal->ingestgen, 0);
    atomic_set(&wal->closing, 0);

    wal->mp = mp;
    wal->mdc = mdc;

    err = wal_mdc_replay(mdc, wal);
    if (err)
        goto errout;

    /* Override persisted params if changed at run-time */
    if (rp->dur_lag_ms != 0) {
        wal->dur_ms = rp->dur_lag_ms;
        wal->dur_ms = clamp_t(long, wal->dur_ms, WAL_DUR_MS_MIN, WAL_DUR_MS_MAX);
    }

    if (rp->dur_buf_sz != 0) {
        wal->dur_bytes = rp->dur_buf_sz;
        wal->dur_bytes = clamp_t(long, wal->dur_bytes, WAL_DUR_BYTES_MIN, WAL_DUR_BYTES_MAX);
    }

    wfset = wal_fileset_open(mp, MP_MED_CAPACITY, WAL_FILE_SIZE, WAL_MAGIC, WAL_VERSION);
    if (!wfset) {
        err = merr(ENOMEM);
        goto errout;
    }
    wal->wfset = wfset;

    wbs = wal_bufset_open(wfset, &wal->ingestgen);
    if (!wbs) {
        err = merr(ENOMEM);
        goto errout;
    }
    wal->wbs = wbs;

    rc = pthread_create(&wal->timer_tid, NULL, wal_timer, wal);
    if (rc) {
        err = merr(rc);
        goto errout;
    }

    wal->timer_tid_valid = true;
    *wal_out = wal;

    return 0;

errout:
    wal_close(wal);

    return err;
}

void
wal_close(struct wal *wal)
{
    if (!wal)
        return;

    atomic_inc(&wal->closing);

    if (wal->timer_tid_valid)
        pthread_join(wal->timer_tid, 0);

    wal_bufset_close(wal->wbs);
    wal_fileset_close(wal->wfset, atomic64_read(&wal->ingestseq),
                      atomic64_read(&wal->ingestgen), atomic64_read(&wal->txhorizon));
    wal_mdc_close(wal->mdc);

    free(wal);
}

void
wal_cningest_cb(struct wal *wal, u64 seqno, u64 gen, u64 txhorizon)
{
    atomic64_set(&wal->ingestseq, seqno);
    atomic64_set(&wal->ingestgen, gen);
    atomic64_set(&wal->txhorizon, txhorizon);
    wal_fileset_reclaim(wal->wfset, seqno, gen, txhorizon, false);
}

/*
 * get/set interfaces for struct wal fields
 */
void
wal_dur_params_get(struct wal *wal, uint32_t *dur_ms, uint32_t *dur_bytes)
{
    *dur_ms = wal->dur_ms;
    *dur_bytes = wal->dur_bytes;
}

void
wal_dur_params_set(struct wal *wal, uint32_t dur_ms, uint32_t dur_bytes)
{
    wal->dur_ms = dur_ms;
    wal->dur_bytes = dur_bytes;
}

uint64_t
wal_reclaim_gen_get(struct wal *wal)
{
    return wal->rgen;
}

void
wal_reclaim_gen_set(struct wal *wal, uint64_t rgen)
{
    wal->rgen = rgen;
}

uint32_t
wal_version_get(struct wal *wal)
{
    return wal->version;
}

void
wal_version_set(struct wal *wal, uint32_t version)
{
    wal->version = version;
}

#if HSE_MOCKING
#include "wal_ut_impl.i"
#endif /* HSE_MOCKING */
