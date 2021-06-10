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
#include "wal_omf.h"
#include "wal_mdc.h"

struct wal {
    struct mpool      *mp;
    struct wal_bufset *wbs;
    struct wal_mdc    *mdc;

    pthread_t timer_tid;
    uint64_t rdgen;
    uint32_t version;
    uint32_t dintvl_ms;
    uint32_t dsize_bytes;

    atomic64_t error;
    atomic_t closing;

    atomic64_t rid HSE_ALIGNED(SMP_CACHE_BYTES);

    volatile u64 reqtime HSE_ALIGNED(SMP_CACHE_BYTES);
};


static inline void
wal_reqtime_set(struct wal *wal)
{
    if (wal && wal->reqtime == 0)
        wal->reqtime = jclock_ns;
}

static inline void
wal_reqtime_reset(struct wal *wal)
{
    if (wal)
        wal->reqtime = 0;
}

static inline u64
wal_reqtime_get(struct wal *wal)
{
     return wal ? wal->reqtime : 0;
}

static void*
wal_timer(void *rock)
{
    struct wal *wal = rock;
    struct timespec req = {0};
    u64 dintvl_ns = MSEC_TO_NSEC(wal->dintvl_ms);

    pthread_setname_np(pthread_self(), "wal_timer");

    while (true) {
        u64 start, now, lag, reqtime, one_ms = MSEC_TO_NSEC(1);

        if (atomic_read(&wal->closing) != 0 || atomic64_read(&wal->error) != 0)
            break;

        req.tv_nsec = one_ms;

        reqtime = wal_reqtime_get(wal);
        start = reqtime ?: get_time_ns();

        if (reqtime != 0) { /* Call flush only if there are mutations */
            merr_t err;

            wal_reqtime_reset(wal);
            err = wal_bufset_flush(wal->wbs);
            if (err) {
                atomic64_set(&wal->error, err);
                break;
            }
        }

        now = get_time_ns();
        lag = now - start;
        if (lag < dintvl_ns) {
            u64 sleep_ns = dintvl_ns - lag;

            sleep_ns = max_t(u64, sleep_ns, one_ms);
            req.tv_nsec = sleep_ns;
            nanosleep(&req, 0);
            continue;
        }

        nanosleep(&req, 0);
    }

    return 0;
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
    uint64_t rid, txid = 0;
    size_t klen, vlen, rlen, kvlen, len;
    char *kvdata;
    uint rtype = WAL_RT_NONTX, op = WAL_OP_PUT;

    klen = kt->kt_len;
    vlen = kvs_vtuple_vlen(vt);
    rlen = wal_rec_len();
    kvlen = ALIGN(klen, kvalign) + ALIGN(vlen, kvalign);
    len = rlen + kvlen;

    wal_reqtime_set(wal);

    rec = wal_bufset_alloc(wal->wbs, len);
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
    uint64_t rid, txid = 0;
    size_t klen, rlen, kalen, len;
    char *kdata;
    uint rtype = WAL_RT_NONTX, op = prefix ? WAL_OP_PDEL : WAL_OP_DEL;

    wal_reqtime_set(wal);

    rlen = wal_rec_len();
    klen = kt->kt_len;
    kalen = ALIGN(klen, kalign);
    len = rlen + kalen;

    rec = wal_bufset_alloc(wal->wbs, len);
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
    uint64_t rid;
    size_t rlen;

    rlen = wal_txn_rec_len();
    rec = wal_bufset_alloc(wal->wbs, rlen);
    rid = atomic64_inc_return(&wal->rid);

    wal_txn_rechdr_pack(rtype, rid, rec);
    wal_txn_rec_pack(txid, seqno, rec);
    wal_txn_rechdr_crc_pack(rec, rlen);

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
wal_op_finish(struct wal *wal, struct wal_record *rec, uint64_t seqno, uint64_t dgen)
{
    wal_rec_finish(rec, seqno, dgen);
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
    struct wal *wal;
    struct wal_bufset *wbs;
    struct wal_mdc *mdc;
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

    wal->rdgen = 0;
    wal->version = WAL_VERSION;
    wal->dintvl_ms = WAL_DUR_INTVL_MS;
    wal->dsize_bytes = WAL_DUR_SZ_BYTES;
    atomic64_set(&wal->rid, 0);
    atomic64_set(&wal->error, 0);
    atomic_set(&wal->closing, 0);

    wal->mp = mp;
    wal->mdc = mdc;

    err = wal_mdc_replay(mdc, wal);
    if (err) {
        wal_mdc_close(mdc);
        goto errout;
    }

    wbs = wal_bufset_open(wal);
    if (!wbs) {
        free(wal);
        return merr(ENOMEM);
    }
    wal->wbs = wbs;

    rc = pthread_create(&wal->timer_tid, NULL, wal_timer, wal);
    if (rc)
        goto errout;

    *wal_out = wal;

    return 0;

errout:
    free(wal);

    return err;
}

merr_t
wal_close(struct wal *wal)
{
    merr_t err;

    if (!wal)
        return 0;

    err = wal_mdc_close(wal->mdc);
    ev(err);

    atomic_set(&wal->closing, 1);
    pthread_join(wal->timer_tid, 0);

    wal_bufset_close(wal->wbs);

    free(wal);

    return err;
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
wal_reclaim_dgen_get(struct wal *wal)
{
    return wal->rdgen;
}

void
wal_reclaim_dgen_set(struct wal *wal, uint64_t rdgen)
{
    wal->rdgen = rdgen;
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

struct mpool *
wal_mpool_get(struct wal *wal)
{
    return wal->mp;
}

#if HSE_MOCKING
#include "wal_ut_impl.i"
#endif /* HSE_MOCKING */
