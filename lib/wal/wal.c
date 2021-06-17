/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_wal

#include <hse_util/hse_err.h>
#include <hse_util/platform.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/kvdb_ctxn.h>

#include <mpool/mpool.h>

#include "wal.h"
#include "wal_buffer.h"
#include "wal_file.h"
#include "wal_omf.h"
#include "wal_mdc.h"

struct wal {
    struct mpool       *mp;
    struct wal_bufset  *wbs;
    struct wal_fileset *wfset;
    struct wal_mdc     *mdc;

    pthread_t timer_tid;
    uint64_t rgen;
    uint32_t version;
    uint32_t dintvl_ms;
    uint32_t dsize_bytes;

    atomic64_t error;
    atomic64_t ingestseq;
    atomic64_t ingestgen;
    atomic64_t txhorizon;
    atomic_t closing;

    atomic64_t rid HSE_ALIGNED(SMP_CACHE_BYTES);

    volatile u64 reqtime HSE_ALIGNED(SMP_CACHE_BYTES);
};


static inline void
wal_reqtime_set(struct wal *wal)
{
    if (wal->reqtime == 0)
        wal->reqtime = jclock_ns;
}

static inline void
wal_reqtime_reset(struct wal *wal)
{
    wal->reqtime = 0;
}

static inline u64
wal_reqtime_get(struct wal *wal)
{
    return wal->reqtime;
}

static void *
wal_timer(void *rock)
{
    struct wal *wal = rock;
    struct timespec req = {0};
    long dintvl_ns;

    pthread_setname_np(pthread_self(), "wal_timer");

    /* tv_nsec must not fall outside the range [0,999999999].
     */
    dintvl_ns = clamp_t(long, MSEC_TO_NSEC(wal->dintvl_ms),
                        MSEC_TO_NSEC(10), MSEC_TO_NSEC(1000) - 1);
    dintvl_ns = max_t(long, dintvl_ns - (long)timer_slack, 1);

    while (true) {
        u64 reqtime, lag;

        if (atomic_read(&wal->closing) != 0 || atomic64_read(&wal->error) != 0)
            break;

        reqtime = wal_reqtime_get(wal);
        req.tv_nsec = dintvl_ns;

        if (reqtime > 0) { /* Call flush if there might be mutations */
            merr_t err;

            wal_reqtime_reset(wal);

            err = wal_bufset_flush(wal->wbs);
            if (err) {
                atomic64_set(&wal->error, err);
                break;
            }

            lag = get_time_ns() - reqtime;
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
    uint rtype = WAL_RT_NONTX, op = WAL_OP_PUT;

    klen = kt->kt_len;
    vlen = kvs_vtuple_vlen(vt);
    rlen = wal_rec_len();
    kvlen = ALIGN(klen, kvalign) + ALIGN(vlen, kvalign);
    len = rlen + kvlen;

    wal_reqtime_set(wal);

    rec = wal_bufset_alloc(wal->wbs, len, &offset);
    rid = atomic64_inc_return(&wal->rid);
    if (kvdb_kop_is_txn(os)) {
        merr_t err;

        err = kvdb_ctxn_get_view_seqno(kvdb_ctxn_h2h(os->kop_txn), &txid);
        if (err)
            return err;
        rtype = WAL_RT_TX;
    }

    wal_rechdr_pack(rtype, rid, kvlen, rec);
    wal_rec_pack(op, kvs->ikv_cnid, txid, klen, vt->vt_xlen, rec);

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
    uint rtype = WAL_RT_NONTX, op = prefix ? WAL_OP_PDEL : WAL_OP_DEL;

    wal_reqtime_set(wal);

    rlen = wal_rec_len();
    klen = kt->kt_len;
    kalen = ALIGN(klen, kalign);
    len = rlen + kalen;

    rec = wal_bufset_alloc(wal->wbs, len, &offset);
    rid = atomic64_inc_return(&wal->rid);
    if (kvdb_kop_is_txn(os)) {
        merr_t err;

        err = kvdb_ctxn_get_view_seqno(kvdb_ctxn_h2h(os->kop_txn), &txid);
        if (err)
            return err;
        rtype = WAL_RT_TX;
    }

    wal_rechdr_pack(rtype, rid, kalen, rec);
    wal_rec_pack(op, kvs->ikv_cnid, txid, klen, 0, rec);

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
wal_op_finish(struct wal *wal, struct wal_record *rec, uint64_t seqno, uint64_t gen)
{
    wal_rec_finish(rec, seqno, gen);
}

/*
 * WAL control plane
 */

merr_t
wal_create(struct mpool *mp, uint64_t *mdcid1, uint64_t *mdcid2)
{
    struct wal_mdc *mdc;
    merr_t err;

    err = wal_mdc_create(mp, MP_MED_CAPACITY, WAL_MDC_CAPACITY, mdcid1, mdcid2);
    if (err)
        return err;

    err = wal_mdc_open(mp, *mdcid1, *mdcid2, &mdc);
    if (err) {
        wal_mdc_destroy(mp, *mdcid1, *mdcid2);
        return err;
    }

    err = wal_mdc_format(mdc, WAL_VERSION, WAL_DUR_INTVL_MS, WAL_DUR_SZ_BYTES);

    wal_mdc_close(mdc);

    if (err)
        wal_mdc_destroy(mp, *mdcid1, *mdcid2);

    return err;
}

merr_t
wal_destroy(struct mpool *mp, uint64_t oid1, uint64_t oid2)
{
    return wal_mdc_destroy(mp, oid1, oid2);
}

merr_t
wal_open(struct mpool *mp, bool rdonly, uint64_t mdcid1, uint64_t mdcid2, struct wal **wal_out)
{
    struct wal         *wal;
    struct wal_bufset  *wbs;
    struct wal_fileset *wfset;
    struct wal_mdc     *mdc;
    merr_t err;
    int rc;

    if (!mp || !wal_out)
        return merr(EINVAL);

    wal = aligned_alloc(alignof(*wal) * 2, sizeof(*wal));
    if (!wal)
        return merr(ENOMEM);

    err = wal_mdc_open(mp, mdcid1, mdcid2, &mdc);
    if (err)
        goto errout;

    wal->rgen = 0;
    wal->version = WAL_VERSION;
    wal->dintvl_ms = WAL_DUR_INTVL_MS;
    wal->dsize_bytes = WAL_DUR_SZ_BYTES;
    atomic64_set(&wal->rid, 0);
    atomic64_set(&wal->error, 0);
    atomic64_set(&wal->ingestgen, 0);
    atomic_set(&wal->closing, 0);

    wal->mp = mp;
    wal->mdc = mdc;

    err = wal_mdc_replay(mdc, wal);
    if (err)
        goto errout;

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
    if (rc)
        goto errout;

    *wal_out = wal;

    return 0;

errout:
    wal_close(wal);

    return err;
}

merr_t
wal_close(struct wal *wal)
{
    if (!wal)
        return 0;

    atomic_set(&wal->closing, 1);
    pthread_join(wal->timer_tid, 0);

    wal_bufset_close(wal->wbs);
    wal_fileset_close(wal->wfset, atomic64_read(&wal->ingestseq),
                      atomic64_read(&wal->ingestgen), atomic64_read(&wal->txhorizon));
    wal_mdc_close(wal->mdc);

    free(wal);

    return 0;
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
wal_dur_params_get(struct wal *wal, uint32_t *dintvl_ms, uint32_t *dsize_bytes)
{
    *dintvl_ms = wal->dintvl_ms;
    *dsize_bytes = wal->dsize_bytes;
}

void
wal_dur_params_set(struct wal *wal, uint32_t dintvl_ms, uint32_t dsize_bytes)
{
    wal->dintvl_ms = dintvl_ms;
    wal->dsize_bytes = dsize_bytes;
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
