/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_wal

#include <hse_util/hse_err.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/event_counter.h>
#include <hse_util/log2.h>

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
#include "wal_replay.h"

/* clang-format off */

struct wal {
    struct mpool           *mp HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct wal_bufset      *wbs;
    struct wal_fileset     *wfset;
    struct wal_mdc         *mdc;
    struct throttle_sensor *wal_thr_sensor;
    uint32_t                wal_thr_hwm;
    uint32_t                wal_thr_lwm;

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
    bool       clean;
    bool       rdonly;
    bool       timer_tid_valid;
    bool       sync_notify_tid_valid;
    pthread_t  timer_tid;
    pthread_t  sync_notify_tid;
    uint32_t   dur_ms;
    size_t     dur_bufsz;
    enum mpool_mclass dur_mclass;
    uint32_t   version;
    bool       buf_managed;
    uint32_t   buf_flags;
    struct kvdb_health *health;
    struct ikvdb *ikvdb;
    struct wal_iocb wiocb;
};

struct wal_sync_waiter {
    struct list_head ws_link;
    merr_t           ws_err;
    int              ws_bufcnt;
    uint64_t         ws_offv[WAL_BUF_MAX];
    struct cv        ws_cv;
};


#define recoverable_error(rc)  (rc == EAGAIN || rc == ECANCELED)

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
                uint32_t new;

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
wal_cond_sync(struct wal *wal, uint64_t gen)
{
    struct wal_sync_waiter swait = {0};
    uint64_t start, end;
    uint32_t dur;
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
    uint32_t rtype = WAL_RT_NONTX;
    merr_t err;

    if (!wal)
        return 0;

    klen = kt->kt_len;
    vlen = kvs_vtuple_vlen(vt);
    rlen = wal_reclen();
    kvlen = ALIGN(klen, kvalign) + ALIGN(vlen, kvalign);
    len = rlen + kvlen;

    rec = wal_bufset_alloc(wal->wbs, len, &recout->offset, &recout->wbidx, &recout->cookie);
    if (!rec) {
        err = merr(ENOMEM); /* unrecoverable error */
        kvdb_health_error(wal->health, err);
        return err;
    }

    recout->recbuf = rec;
    recout->len = len;

    rid = atomic64_inc_return(&wal->wal_rid);
    rtype = (txid > 0) ? WAL_RT_TX : WAL_RT_NONTX;
    wal_rechdr_pack(rtype, rid, len, 0, rec);

    wal_rec_pack(WAL_OP_PUT, kvs->ikv_cnid, txid, klen, vt->vt_xlen, rec);

    kvdata = (char *)rec + rlen;
    memcpy(kvdata, kt->kt_data, klen);
    kt->kt_data = kvdata;
    kt->kt_flags = wal->buf_flags;

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
    uint32_t rtype;
    merr_t err;

    if (!wal)
        return 0;

    rlen = wal_reclen();
    klen = kt->kt_len;
    kalen = ALIGN(klen, kalign);
    len = rlen + kalen;

    rec = wal_bufset_alloc(wal->wbs, len, &recout->offset, &recout->wbidx, &recout->cookie);
    if (!rec) {
        err = merr(ENOMEM); /* unrecoverable error */
        kvdb_health_error(wal->health, err);
        return err;
    }

    recout->recbuf = rec;
    recout->len = len;

    rid = atomic64_inc_return(&wal->wal_rid);
    rtype = (txid > 0) ? WAL_RT_TX : WAL_RT_NONTX;
    wal_rechdr_pack(rtype, rid, len, 0, rec);

    wal_rec_pack(prefix ? WAL_OP_PDEL : WAL_OP_DEL, kvs->ikv_cnid, txid, klen, 0, rec);

    kdata = (char *)rec + rlen;
    memcpy(kdata, kt->kt_data, klen);
    kt->kt_data = kdata;
    kt->kt_flags = wal->buf_flags;

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
wal_txn(
    struct wal *wal,
    uint32_t    rtype,
    uint64_t    txid,
    uint64_t    seqno,
    uint64_t    cid,
    int64_t    *cookie)
{
    struct wal_txnrec_omf *rec;
    uint64_t rid, offset, gen;
    size_t rlen;
    uint32_t wbidx;

    if (!wal)
        return 0;

    rlen = wal_txn_reclen();
    rec = wal_bufset_alloc(wal->wbs, rlen, &offset, &wbidx, cookie);
    if (!rec) {
        merr_t err = merr(ENOMEM); /* unrecoverable error */

        kvdb_health_error(wal->health, err);
        return err;
    }

    rid = atomic64_inc_return(&wal->wal_rid);
    gen = c0sk_gen_current();
    wal_rechdr_pack(rtype, rid, rlen, gen, rec);

    wal_txn_rec_pack(txid, seqno, cid, rec);

    wal_bufset_finish(wal->wbs, wbidx, rlen, gen, offset + rlen);
    wal_txn_rechdr_finish(rec, rlen, offset);

    return 0;
}

merr_t
wal_txn_begin(struct wal *wal, uint64_t txid, int64_t *cookie)
{
    *cookie = -1;

    return wal_txn(wal, WAL_RT_TXBEGIN, txid, 0, 0, cookie);
}

merr_t
wal_txn_abort(struct wal *wal, uint64_t txid, int64_t cookie)
{
    assert(!wal || cookie >= 0);

    return wal_txn(wal, WAL_RT_TXABORT, txid, 0, 0, &cookie);
}

merr_t
wal_txn_commit(struct wal *wal, uint64_t txid, uint64_t seqno, uint64_t cid, int64_t cookie)
{
    assert(!wal || cookie >= 0);

    return wal_txn(wal, WAL_RT_TXCOMMIT, txid, seqno, cid, &cookie);
}

void
wal_op_finish(struct wal *wal, struct wal_record *rec, uint64_t seqno, uint64_t gen, int rc)
{
    if (wal) {
        if (rc) {
            if (recoverable_error(rc))
                rec->offset = WAL_ROFF_RECOV_ERR;
            else
                rec->offset = WAL_ROFF_UNRECOV_ERR;

            gen = gen ? : c0sk_gen_current();
        }

        assert(gen);
        wal_bufset_finish(wal->wbs, rec->wbidx, rec->len, gen, rec->offset + rec->len);
        wal_rec_finish(rec, seqno, gen);
    }
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

    err = wal_mdc_format(mdc, WAL_VERSION);

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
    struct mpool           *mp,
    struct kvdb_rparams    *rp,
    struct wal_replay_info *rinfo,
    struct ikvdb           *ikdb,
    struct kvdb_health     *health,
    struct wal            **wal_out)
{
    struct wal *wal;
    enum mpool_mclass mclass;
    merr_t err;
    int rc;

    if (!mp || !rp || !rinfo || !wal_out)
        return merr(EINVAL);

    *wal_out = NULL;

    wal = aligned_alloc(alignof(*wal), sizeof(*wal));
    if (!wal)
        return merr(ENOMEM);

    memset(wal, 0, sizeof(*wal));
    wal->version = WAL_VERSION;
    wal->mp = mp;
    wal->health = health;
    wal->rdonly = rp->read_only;
    wal->ikvdb = ikdb;
    wal->buf_managed = rp->dur_buf_managed;
    wal->buf_flags = wal->buf_managed ? HSE_BTF_MANAGED : 0;

    wal->dur_ms = HSE_WAL_DUR_MS_DFLT;
    wal->dur_bufsz = HSE_WAL_DUR_BUFSZ_MB_DFLT << 20;
    wal->dur_mclass = MP_MED_CAPACITY;

    err = wal_mdc_open(mp, rinfo->mdcid1, rinfo->mdcid2, &wal->mdc);
    if (err)
        goto errout;

    err = wal_mdc_replay(wal->mdc, wal);
    if (err)
        goto errout;

    wal->wfset = wal_fileset_open(mp, wal->dur_mclass, WAL_FILE_SIZE_BYTES, WAL_MAGIC, WAL_VERSION);
    if (!wal->wfset) {
        err = merr(ENOMEM);
        goto errout;
    }

    err = wal_replay(wal, rinfo);
    if (err)
        goto errout;

    if (!rp->dur_enable) {
        wal_close(wal);
        return 0;
    }

    if (wal->rdonly) {
        *wal_out = wal;
        return 0;
    }

    if (rp->dur_intvl_ms != HSE_WAL_DUR_MS_DFLT)
        wal->dur_ms = clamp_t(long, rp->dur_intvl_ms, HSE_WAL_DUR_MS_MIN, HSE_WAL_DUR_MS_MAX);

    if (rp->dur_bufsz_mb != HSE_WAL_DUR_BUFSZ_MB_DFLT) {
        wal->dur_bufsz = clamp_t(size_t, rp->dur_bufsz_mb << 20, HSE_WAL_DUR_BUFSZ_MB_MIN << 20,
                                 HSE_WAL_DUR_BUFSZ_MB_MAX << 20);
        wal->dur_bufsz = roundup_pow_of_two(wal->dur_bufsz);
    }

    mclass = rp->dur_mclass;
    if (mclass != wal->dur_mclass) {
        assert(mclass < MP_MED_COUNT);
        wal->dur_mclass = mclass;
        wal_fileset_mclass_update(wal->wfset, wal->dur_mclass);
    }

    err = wal_mdc_compact(wal->mdc, wal);
    if (err)
        goto errout;

    wal->wal_thr_hwm = rp->dur_throttle_hi_th;
    wal->wal_thr_lwm = rp->dur_throttle_lo_th;
    if (wal->wal_thr_lwm > wal->wal_thr_hwm / 2)
        wal->wal_thr_lwm = wal->wal_thr_hwm / 2;

    wal->wiocb.iocb = wal_ionotify_cb;
    wal->wiocb.cbarg = wal;
    wal->wbs = wal_bufset_open(wal->wfset, wal->dur_bufsz, &wal->wal_ingestgen, &wal->wiocb);
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

    /* Ensure that the notify thread exits after all pending IOs are drained */
    if (wal->sync_notify_tid_valid) {
        mutex_lock(&wal->sync_mutex);
        cv_signal(&wal->sync_cv);
        mutex_unlock(&wal->sync_mutex);

        pthread_join(wal->sync_notify_tid, 0);
        cv_destroy(&wal->sync_cv);
        mutex_destroy(&wal->sync_mutex);
    }

    /* Write a close record to indicate graceful shutdown */
    wal_mdc_close_write(wal->mdc);
    wal_mdc_close(wal->mdc);

    free(wal);
}


static void
wal_reclaim(struct wal *wal, uint64_t seqno, uint64_t gen, uint64_t txhorizon)
{
    atomic64_set(&wal->wal_ingestseq, seqno);
    atomic64_set(&wal->wal_ingestgen, gen);
    atomic64_set(&wal->wal_txhorizon, txhorizon);

    if (!wal->buf_managed)
        wal_bufset_reclaim(wal->wbs, gen);
    wal_fileset_reclaim(wal->wfset, seqno, gen, txhorizon, false);
}

void
wal_cningest_cb(struct wal *wal, uint64_t seqno, uint64_t gen, uint64_t txhorizon, bool post_ingest)
{
    if (post_ingest)
        wal_reclaim(wal, seqno, gen, txhorizon);
    else
        wal_cond_sync(wal, gen);
}

void
wal_bufrel_cb(struct wal *wal, uint64_t gen)
{
    if (wal->buf_managed)
        wal_bufset_reclaim(wal->wbs, gen);
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
enum mpool_mclass
wal_dur_mclass_get(struct wal *wal)
{
    return wal->dur_mclass;
}

void
wal_dur_mclass_set(struct wal *wal, enum mpool_mclass mclass)
{
    wal->dur_mclass = mclass;
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

void
wal_clean_set(struct wal *wal)
{
    wal->clean = true;
}

bool
wal_is_rdonly(struct wal *wal)
{
    return wal->rdonly;
}

bool
wal_is_clean(struct wal *wal)
{
    return wal->clean;
}

struct ikvdb *
wal_ikvdb(struct wal *wal)
{
    return wal->ikvdb;
}

struct wal_fileset *
wal_fset(struct wal *wal)
{
    return wal->wfset;
}

struct wal_mdc *
wal_mdc(struct wal *wal)
{
    return wal->mdc;
}

#if HSE_MOCKING
#include "wal_ut_impl.i"
#endif /* HSE_MOCKING */
