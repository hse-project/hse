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
#include <hse_ikvdb/c0sk.h>

#include <mpool/mpool.h>

#include "wal.h"
#include "wal_buffer.h"
#include "wal_file.h"
#include "wal_omf.h"
#include "wal_mdc.h"

/* clang-format off */

struct wal {
    struct mpool           *mp HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct wal_bufset      *wbs;
    struct wal_fileset     *wfset;
    struct wal_mdc         *mdc;
    struct throttle_sensor *wal_thr_sensor;
    uint                    wal_thr_hwm;
    uint                    wal_thr_lwm;

    atomic64_t              wal_rid HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t              wal_ingestseq;
    atomic64_t              wal_ingestgen;
    atomic64_t              wal_txhorizon;

    struct mutex     sync_mutex HSE_ALIGNED(SMP_CACHE_BYTES);
    struct list_head sync_waiters;
    struct cv        sync_cv;

    struct mutex timer_mutex HSE_ALIGNED(SMP_CACHE_BYTES);
    bool         sync_pending;
    struct cv    timer_cv;

    atomic64_t error HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic_t   closing;
    bool       timer_tid_valid;
    bool       sync_notify_tid_valid;
    pthread_t  timer_tid;
    pthread_t  sync_notify_tid;
    uint32_t   dur_ms;
    uint32_t   dur_bytes;
    uint32_t   version;
    enum mpool_mclass mclass;
    struct kvdb_health *health;
    struct wal_iocb wiocb;
};

struct wal_sync_waiter {
    struct list_head ws_link;
    merr_t           ws_err;
    int              ws_bufcnt;
    uint64_t         ws_offv[WAL_BUF_MAX];
    struct cv        ws_cv;
};


#define recoverable_error(rc)  (rc == EAGAIN || rc == ECANCELED || rc == EPROTO)

/* clang-format on */

/* Forward decls */
void
wal_ionotify_cb(void *cbarg, merr_t err);

static void *
wal_timer(void *rock)
{
    struct wal *wal = rock;
    uint64_t rid_last = 0;
    long dur_ns;
    bool closing = false;
    merr_t err;

    pthread_setname_np(pthread_self(), "wal_timer");

    dur_ns = MSEC_TO_NSEC(wal->dur_ms) - (long)timer_slack;

    while (!closing && !atomic64_read(&wal->error)) {
        uint64_t tstart, rid, lag, sleep_ns, flushb, bufsz, buflen;

        closing = !!atomic_read(&wal->closing);

        tstart = get_time_ns();
        sleep_ns = dur_ns;

        rid = atomic64_read(&wal->wal_rid);
        if (rid != rid_last || closing) {
            rid_last = rid;

            err = wal_bufset_flush(wal->wbs, &flushb, &bufsz, &buflen);
            if (err) {
                atomic64_set(&wal->error, err);
                wal_ionotify_cb(wal, err); /* Notify sync waiters on flush error */
                continue;
            }

            /* No dirty data, notify any sync waiters */
            if (flushb == 0)
                wal_ionotify_cb(wal, 0);

            if (wal->wal_thr_sensor) {
                const uint64_t hwm = (bufsz * wal->wal_thr_hwm) / 100;
                const uint64_t lwm = (bufsz * wal->wal_thr_lwm) / 100;
                uint new;

                assert(buflen < bufsz);

                new = (buflen > lwm) ? (THROTTLE_SENSOR_SCALE * buflen) / hwm : 0;

                throttle_sensor_set(wal->wal_thr_sensor, new);
            }

            lag = get_time_ns() - tstart;
            sleep_ns = (lag >= sleep_ns || closing) ? 0 : sleep_ns - lag;
        } else {
            /* No mutations, notify any sync waiters */
            wal_ionotify_cb(wal, 0);
        }

        mutex_lock(&wal->timer_mutex);
        if (wal->sync_pending)
            closing = false;
        else if (!closing && sleep_ns > 0)
            cv_timedwait(&wal->timer_cv, &wal->timer_mutex, NSEC_TO_MSEC(sleep_ns));
        wal->sync_pending = false;
        mutex_unlock(&wal->timer_mutex);
    }

    err = atomic64_read(&wal->error);
    if (err)
        kvdb_health_error(wal->health, err);

    pthread_exit(NULL);
}

static void *
wal_sync_notifier(void *rock)
{
    struct wal *wal = rock;
    bool closing = false;
    merr_t err;

    pthread_setname_np(pthread_self(), "wal_sync_notifier");

    while (!closing) {
        struct wal_sync_waiter *swait;

        mutex_lock(&wal->sync_mutex);
        err = atomic64_read(&wal->error);
        closing = !!atomic_read(&wal->closing);

        list_for_each_entry(swait, &wal->sync_waiters, ws_link) {
            if (err ||
                swait->ws_bufcnt <= wal_bufset_durcnt(wal->wbs, swait->ws_bufcnt, swait->ws_offv)) {
                swait->ws_err = err;
                cv_signal(&swait->ws_cv);
            }
        }

        closing = (closing || err) && list_empty(&wal->sync_waiters);
        if (!closing)
            cv_timedwait(&wal->sync_cv, &wal->sync_mutex, wal->dur_ms);
        mutex_unlock(&wal->sync_mutex);
    }

    err = atomic64_read(&wal->error);
    if (err)
        kvdb_health_error(wal->health, err);

    pthread_exit(NULL);
}

void
wal_ionotify_cb(void *cbarg, merr_t err)
{
    struct wal *wal = cbarg;

    if (err)
        atomic64_set(&wal->error, err);

    mutex_lock(&wal->sync_mutex);
    cv_signal(&wal->sync_cv);
    mutex_unlock(&wal->sync_mutex);
}

static merr_t
wal_sync_impl(struct wal *wal, struct wal_sync_waiter *swait)
{
    mutex_lock(&wal->sync_mutex);
    list_add_tail(&swait->ws_link, &wal->sync_waiters);

    /* Notify the timer worker */
    mutex_lock(&wal->timer_mutex);
    wal->sync_pending = true;
    cv_signal(&wal->timer_cv);
    mutex_unlock(&wal->timer_mutex);

    while (swait->ws_bufcnt > wal_bufset_durcnt(wal->wbs, swait->ws_bufcnt, swait->ws_offv) &&
           !swait->ws_err)
        cv_timedwait(&swait->ws_cv, &wal->sync_mutex, wal->dur_ms);

    list_del(&swait->ws_link);
    mutex_unlock(&wal->sync_mutex);

    cv_destroy(&swait->ws_cv);

    return swait->ws_err;
}

merr_t
wal_sync(struct wal *wal)
{
    struct wal_sync_waiter swait = {0};

    if (!wal)
        return merr(EINVAL);

    cv_init(&swait.ws_cv, "wal_sync_waiter");
    INIT_LIST_HEAD(&swait.ws_link);

    swait.ws_bufcnt = wal_bufset_curoff(wal->wbs, WAL_BUF_MAX, swait.ws_offv);
    if (swait.ws_bufcnt < 0)
        return merr(EBUG);

    return wal_sync_impl(wal, &swait);
}

static merr_t
wal_cond_sync(struct wal *wal, u64 gen)
{
    struct wal_sync_waiter swait = {0};
    u64 start, end;
    uint dur;
    merr_t err;

    assert(wal);

    cv_init(&swait.ws_cv, "wal_cond_sync_waiter");
    INIT_LIST_HEAD(&swait.ws_link);

    swait.ws_bufcnt = wal_bufset_genoff(wal->wbs, gen, WAL_BUF_MAX, swait.ws_offv);
    if (swait.ws_bufcnt < 0)
        return merr(EBUG);

    start = get_time_ns();
    err = wal_sync_impl(wal, &swait);
    end = get_time_ns();

    if (!err && (dur = NSEC_TO_MSEC(end - start)) > 20)
        hse_log(HSE_NOTICE "%s: WAL ingest sync for dgen %lu took %u msec", __func__, gen, dur);

    return err;
}


/*
 * WAL data plane
 */

merr_t
wal_put(
    struct wal *wal,
    struct ikvs *kvs,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    uint64_t txid,
    struct wal_record *recout)
{
    const size_t kvalign = alignof(uint64_t);
    struct wal_rec_omf *rec;
    uint64_t rid;
    size_t klen, vlen, rlen, kvlen, len;
    char *kvdata;
    uint rtype = WAL_RT_NONTX;
    merr_t err;

    if (!wal)
        return 0;

    klen = kt->kt_len;
    vlen = kvs_vtuple_vlen(vt);
    rlen = wal_rec_len();
    kvlen = ALIGN(klen, kvalign) + ALIGN(vlen, kvalign);
    len = rlen + kvlen;

    rec = wal_bufset_alloc(wal->wbs, len, &recout->offset, &recout->wbidx);
    if (!rec) {
        err = merr(ENOMEM); /* unrecoverable error */
        kvdb_health_error(wal->health, err);
        return err;
    }

    recout->recbuf = rec;
    recout->len = len;

    rid = atomic64_inc_return(&wal->wal_rid);
    rtype = (txid > 0) ? WAL_RT_TX : WAL_RT_NONTX;
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

    return 0;
}

static merr_t
wal_del_impl(
    struct wal *wal,
    struct ikvs *kvs,
    struct kvs_ktuple *kt,
    uint64_t txid,
    struct wal_record *recout,
    bool prefix)
{
    const size_t kalign = alignof(uint64_t);
    struct wal_rec_omf *rec;
    uint64_t rid;
    size_t klen, rlen, kalen, len;
    char *kdata;
    uint rtype;
    merr_t err;

    if (!wal)
        return 0;

    rlen = wal_rec_len();
    klen = kt->kt_len;
    kalen = ALIGN(klen, kalign);
    len = rlen + kalen;

    rec = wal_bufset_alloc(wal->wbs, len, &recout->offset, &recout->wbidx);
    if (!rec) {
        err = merr(ENOMEM); /* unrecoverable error */
        kvdb_health_error(wal->health, err);
        return err;
    }

    recout->recbuf = rec;
    recout->len = len;

    rid = atomic64_inc_return(&wal->wal_rid);
    rtype = (txid > 0) ? WAL_RT_TX : WAL_RT_NONTX;
    wal_rechdr_pack(rtype, rid, kalen, rec);

    wal_rec_pack(prefix ? WAL_OP_PDEL : WAL_OP_DEL, kvs->ikv_cnid, txid, klen, 0, rec);

    kdata = (char *)rec + rlen;
    memcpy(kdata, kt->kt_data, klen);
    kt->kt_data = kdata;
    kt->kt_flags = HSE_BTF_MANAGED;

    return 0;
}

merr_t
wal_del(
    struct wal *wal,
    struct ikvs *kvs,
    struct kvs_ktuple *kt,
    uint64_t txid,
    struct wal_record *recout)
{
    return wal_del_impl(wal, kvs, kt, txid, recout, false);
}

merr_t
wal_del_pfx(
    struct wal *wal,
    struct ikvs *kvs,
    struct kvs_ktuple *kt,
    uint64_t txid,
    struct wal_record *recout)
{
    return wal_del_impl(wal, kvs, kt, txid, recout, true);
}

static merr_t
wal_txn(struct wal *wal, uint rtype, uint64_t txid, uint64_t seqno)
{
    struct wal_txnrec_omf *rec;
    uint64_t rid, offset, gen;
    size_t rlen;
    uint wbidx;

    if (!wal)
        return 0;

    rlen = wal_txn_rec_len();
    rec = wal_bufset_alloc(wal->wbs, rlen, &offset, &wbidx);
    if (!rec) {
        merr_t err = merr(ENOMEM); /* unrecoverable error */

        kvdb_health_error(wal->health, err);
        return err;
    }

    rid = atomic64_inc_return(&wal->wal_rid);
    gen = c0sk_gen_current();

    wal_txn_rechdr_pack(rtype, rid, gen, rec);
    wal_txn_rec_pack(txid, seqno, rec);

    wal_bufset_finish(wal->wbs, wbidx, rlen, gen, offset + rlen);
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
    if (wal) {
        if (rc) {
            if (recoverable_error(rc))
                rec->offset = U64_MAX - 1;
            else
                rec->offset = U64_MAX;
        }

        wal_bufset_finish(wal->wbs, rec->wbidx, rec->len, gen, rec->offset + rec->len);
        wal_rec_finish(rec, seqno, gen);
    }
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
    enum mpool_mclass mclass;

    mclass = cp->dur_mclass;
    assert(mclass >= MP_MED_BASE && mclass < MP_MED_COUNT);

    err = wal_mdc_create(mp, mclass, WAL_MDC_CAPACITY, mdcid1, mdcid2);
    if (err)
        return err;

    err = wal_mdc_open(mp, *mdcid1, *mdcid2, &mdc);
    if (err) {
        wal_mdc_destroy(mp, *mdcid1, *mdcid2);
        return err;
    }

    dur_ms = cp->dur_intvl_ms;
    dur_ms = clamp_t(long, dur_ms, WAL_DUR_MS_MIN, WAL_DUR_MS_MAX);

    dur_bytes = cp->dur_buf_sz;
    dur_bytes = clamp_t(long, dur_bytes, WAL_DUR_BYTES_MIN, WAL_DUR_BYTES_MAX);

    err = wal_mdc_format(mdc, WAL_VERSION, dur_ms, dur_bytes, mclass);

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
    struct kvdb_health  *health,
    struct wal         **wal_out)
{
    struct wal *wal;
    merr_t err;
    int rc;

    if (!mp || !rp || !wal_out)
        return merr(EINVAL);

    if (!rp->dur_enable)
        return 0;

    wal = aligned_alloc(alignof(*wal), sizeof(*wal));
    if (!wal)
        return merr(ENOMEM);

    memset(wal, 0, sizeof(*wal));
    wal->version = WAL_VERSION;
    wal->mp = mp;
    wal->health = health;

    wal->wal_thr_hwm = rp->dur_throttle_hi_th;
    wal->wal_thr_lwm = rp->dur_throttle_lo_th;
    if (wal->wal_thr_lwm > wal->wal_thr_hwm / 2)
        wal->wal_thr_lwm = wal->wal_thr_hwm / 2;

    err = wal_mdc_open(mp, mdcid1, mdcid2, &wal->mdc);
    if (err)
        goto errout;

    err = wal_mdc_replay(wal->mdc, wal);
    if (err)
        goto errout;

    /* Override persisted params if changed at run-time */
    if (rp->dur_intvl_ms != 0) {
        wal->dur_ms = rp->dur_intvl_ms;
        wal->dur_ms = clamp_t(long, wal->dur_ms, WAL_DUR_MS_MIN, WAL_DUR_MS_MAX);
    }

    if (rp->dur_buf_sz != 0) {
        wal->dur_bytes = rp->dur_buf_sz;
        wal->dur_bytes = clamp_t(long, wal->dur_bytes, WAL_DUR_BYTES_MIN, WAL_DUR_BYTES_MAX);
    }

    if (rp->read_only) {
        *wal_out = wal;
        return 0;
    }

    err = wal_mdc_compact(wal->mdc, wal);
    if (err)
        goto errout;

    wal->wfset= wal_fileset_open(mp, wal->mclass, WAL_FILE_SIZE_BYTES, WAL_MAGIC, WAL_VERSION);
    if (!wal->wfset) {
        err = merr(ENOMEM);
        goto errout;
    }

    wal->wiocb.iocb = wal_ionotify_cb;
    wal->wiocb.cbarg = wal;
    wal->wbs = wal_bufset_open(wal->wfset, &wal->wal_ingestgen, &wal->wiocb);
    if (!wal->wbs) {
        err = merr(ENOMEM);
        goto errout;
    }

    cv_init(&wal->timer_cv, "wal_timer_cv");
    mutex_init(&wal->timer_mutex);
    rc = pthread_create(&wal->timer_tid, NULL, wal_timer, wal);
    if (rc) {
        err = merr(rc);
        goto errout;
    }
    wal->timer_tid_valid = true;

    INIT_LIST_HEAD(&wal->sync_waiters);
    cv_init(&wal->sync_cv, "wal_sync_cv");
    mutex_init(&wal->sync_mutex);
    wal->sync_pending = false;
    rc = pthread_create(&wal->sync_notify_tid, NULL, wal_sync_notifier, wal);
    if (rc) {
        err = merr(rc);
        goto errout;
    }
    wal->sync_notify_tid_valid = true;

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

    if (wal->timer_tid_valid) {
        mutex_lock(&wal->timer_mutex);
        cv_signal(&wal->timer_cv);
        mutex_unlock(&wal->timer_mutex);

        pthread_join(wal->timer_tid, 0);
        cv_destroy(&wal->timer_cv);
        mutex_destroy(&wal->timer_mutex);
    }

    wal_bufset_close(wal->wbs);
    wal_fileset_close(wal->wfset, atomic64_read(&wal->wal_ingestseq),
                      atomic64_read(&wal->wal_ingestgen), atomic64_read(&wal->wal_txhorizon));
    wal_mdc_close(wal->mdc);

    /* Ensure that the notify thread exits after all pending IOs are drained */
    if (wal->sync_notify_tid_valid) {
        mutex_lock(&wal->sync_mutex);
        cv_signal(&wal->sync_cv);
        mutex_unlock(&wal->sync_mutex);

        pthread_join(wal->sync_notify_tid, 0);
        cv_destroy(&wal->sync_cv);
        mutex_destroy(&wal->sync_mutex);
    }

    free(wal);
}


static void
wal_reclaim(struct wal *wal, u64 seqno, u64 gen, u64 txhorizon)
{
    atomic64_set(&wal->wal_ingestseq, seqno);
    atomic64_set(&wal->wal_ingestgen, gen);
    atomic64_set(&wal->wal_txhorizon, txhorizon);

    wal_bufset_reclaim(wal->wbs, gen);
    wal_fileset_reclaim(wal->wfset, seqno, gen, txhorizon, false);
}

void
wal_cningest_cb(struct wal *wal, u64 seqno, u64 gen, u64 txhorizon, bool post_ingest)
{
    if (post_ingest)
        wal_reclaim(wal, seqno, gen, txhorizon);
    else
        wal_cond_sync(wal, gen);
}

void
wal_throttle_sensor(struct wal *wal, struct throttle_sensor *sensor)
{
    if (wal)
        wal->wal_thr_sensor = sensor;
}

/*
 * get/set interfaces for struct wal fields
 */
void
wal_dur_params_get(
    struct wal        *wal,
    uint32_t          *dur_ms,
    uint32_t          *dur_bytes,
    enum mpool_mclass *mclass)
{
    *dur_ms = wal->dur_ms;
    *dur_bytes = wal->dur_bytes;
    *mclass = wal->mclass;
}

void
wal_dur_params_set(struct wal *wal, uint32_t dur_ms, uint32_t dur_bytes, enum mpool_mclass mclass)
{
    wal->dur_ms = dur_ms;
    wal->dur_bytes = dur_bytes;
    wal->mclass = mclass;
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
