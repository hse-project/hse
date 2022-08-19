/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_wal

#include <hse/error/merr.h>
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
#include <hse_ikvdb/omf_version.h>

#include <hse/hse.h>
#include <mpool/mpool.h>

#include "wal.h"
#include "wal_buffer.h"
#include "wal_file.h"
#include "wal_omf.h"
#include "wal_mdc.h"
#include "wal_replay.h"

/* clang-format off */

struct wal {
    struct mpool           *mp HSE_ACP_ALIGNED;
    struct wal_bufset      *wbs;
    struct wal_fileset     *wfset;
    struct wal_mdc         *mdc;
    struct throttle_sensor *wal_thr_sensor;
    uint8_t                 wal_thr_hwm;
    uint8_t                 wal_thr_lwm;

    atomic_ulong            wal_rid HSE_L1D_ALIGNED;
    atomic_ulong            wal_ingestseq;
    atomic_ulong            wal_ingestgen;
    atomic_ulong            wal_txhorizon;

    struct mutex     sync_mutex HSE_L1D_ALIGNED;
    struct list_head sync_waiters;
    struct cv        sync_cv;

    struct mutex timer_mutex HSE_L1D_ALIGNED;
    bool         sync_pending;
    struct cv    timer_cv;

    atomic_long error HSE_L1D_ALIGNED;
    atomic_int closing;
    bool       clean;
    bool       read_only;
    bool       timer_running;
    bool       sync_notifier_running;
    struct work_struct timer_work;
    struct work_struct sync_notifier_work;
    struct workqueue_struct *wq;
    uint32_t   dur_ms;
    uint32_t   dur_bytes;
    size_t     dur_bufsz;
    enum hse_mclass dur_mclass;
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
    uint32_t         ws_bufcnt;
    uint64_t         ws_offv[WAL_BUF_MAX];
    struct cv        ws_cv;
};


#define recoverable_error(rc)  (rc == EAGAIN || rc == ECANCELED)

/* clang-format on */

/* Forward decls */
void
wal_ionotify_cb(void *cbarg, merr_t err);

static HSE_ALWAYS_INLINE void
wal_throttle_sensor_set(struct wal *wal, uint64_t bufsz, uint64_t buflen)
{
    const uint64_t hwm = (bufsz * wal->wal_thr_hwm) / 100;
    const uint64_t lwm = (bufsz * wal->wal_thr_lwm) / 100;
    uint32_t new;

    if (ev(!wal->wal_thr_sensor))
        return;

    ev(buflen >= bufsz);

    new = (buflen > lwm) ? (THROTTLE_SENSOR_SCALE * buflen) / hwm : 0;

    throttle_sensor_set(wal->wal_thr_sensor, new);
}

/*
 * Wait for at least 'pct' of flushed data to become durable.
 * This avoids overloading the WAL IO layer with numerous flushes when IOs are
 * backed up due to a slow IO backend.
 */
static HSE_ALWAYS_INLINE void
wal_flush_wait(struct wal *wal, struct wal_flush_stats *stats, uint8_t pct)
{
    INVARIANT(wal && stats);

    uint64_t flushv[WAL_BUF_MAX];
    const uint32_t flushc = stats->bufcnt;
    assert(flushc <= WAL_BUF_MAX);

    pct = clamp_t(uint8_t, pct, 0, 100);

    for (int i = 0; i < flushc; i++)
        flushv[i] = stats->flush_soff[i] + ((stats->flush_len[i] * pct) / 100);

    while (wal_bufset_durcnt(wal->wbs, WAL_BUF_MAX, flushv) < flushc) {
        if (HSE_UNLIKELY(atomic_read(&wal->error)))
            break;
        usleep(50);
    }
}

static HSE_ALWAYS_INLINE bool
wal_dirty_exceeds_threshold(struct wal *wal, const uint32_t flushc, uint64_t *flushv)
{
    INVARIANT(wal && flushc <= WAL_BUF_MAX);

    uint64_t curv[WAL_BUF_MAX], tot_bytes = 0;
    uint32_t buf_thresh = wal->dur_bytes / flushc;
    uint32_t buf_cnt;

    buf_cnt = wal_bufset_curoff(wal->wbs, WAL_BUF_MAX, curv);
    assert(buf_cnt == flushc);
    if (ev(buf_cnt != flushc))
        return false;

    buf_cnt = 0;
    for (int i = 0; i < flushc; i++) {
        const uint64_t bytes = (curv[i] - flushv[i]);

        if (bytes > 0) {
            tot_bytes += bytes;
            buf_cnt++;
        }
    }

    return (tot_bytes > 0 && tot_bytes >= (buf_cnt * buf_thresh));
}

static void
wal_timer(struct work_struct *work)
{
    struct wal *wal = container_of(work, struct wal, timer_work);
    uint64_t rid_last = 0;
    long dur_ns;
    bool closing = false;
    merr_t err;

    pthread_setname_np(pthread_self(), "hse_wal_timer");

    dur_ns = MSEC_TO_NSEC(wal->dur_ms) - (long)timer_slack;

    while (!closing && !atomic_read(&wal->error)) {
        uint64_t tstart, rid, lag, sleep_ns;

        closing = !!atomic_read(&wal->closing);

        tstart = get_time_ns();
        sleep_ns = dur_ns;

        rid = atomic_read(&wal->wal_rid);
        if (rid != rid_last || closing) {
            struct wal_flush_stats stats;
            rid_last = rid;

            err = wal_bufset_flush(wal->wbs, &stats);
            if (err) {
                atomic_set(&wal->error, err);
                wal_ionotify_cb(wal, err); /* Notify sync waiters on flush error */
                continue;
            }

            if (stats.flush_tlen == 0)
                wal_ionotify_cb(wal, 0); /* No dirty data, notify any sync waiters */

            wal_throttle_sensor_set(wal, stats.bufsz, stats.max_buflen);

            wal_flush_wait(wal, &stats, WAL_FLUSH_WAIT_PCT);

            lag = get_time_ns() - tstart;
            sleep_ns = (lag >= sleep_ns || closing) ? 0 : sleep_ns - lag;
        } else {
            wal_ionotify_cb(wal, 0); /* No mutations, notify any sync waiters */
        }

        mutex_lock(&wal->timer_mutex);
        end_stats_work();

        if (wal->sync_pending) {
            closing = false;
        } else if (!closing && sleep_ns > 0) {
            uint64_t flushv[WAL_BUF_MAX], intvl, tstart = get_time_ns();
            uint32_t flushc;

            intvl = max_t(uint64_t, sleep_ns / 10, MSEC_TO_NSEC(1));
            flushc = wal_bufset_flushoff(wal->wbs, WAL_BUF_MAX, flushv);

            while (!atomic_read(&wal->closing) && !atomic_read(&wal->error)) {
                int rc = cv_timedwait(&wal->timer_cv, &wal->timer_mutex,
                                      NSEC_TO_MSEC(intvl), "waltmslp");
                if (rc != ETIMEDOUT)
                    break;

                if (wal->sync_pending || (get_time_ns() - tstart >= sleep_ns))
                    break;

                if (wal_dirty_exceeds_threshold(wal, flushc, flushv))
                    break;
            }
        }

        wal->sync_pending = false;

        begin_stats_work();
        mutex_unlock(&wal->timer_mutex);
    }

    err = atomic_read(&wal->error);
    if (err)
        kvdb_health_error(wal->health, err);

    wal->timer_running = false;
}

static void
wal_sync_notifier(struct work_struct *work)
{
    struct wal *wal = container_of(work, struct wal, sync_notifier_work);
    bool closing = false;
    merr_t err;

    pthread_setname_np(pthread_self(), "hse_wal_sync");

    while (!closing) {
        struct wal_sync_waiter *swait;

        mutex_lock(&wal->sync_mutex);
        err = atomic_read(&wal->error);
        if (!err)
            err = kvdb_health_check(wal->health, KVDB_HEALTH_FLAG_ALL);
        closing = !!atomic_read(&wal->closing);

        list_for_each_entry(swait, &wal->sync_waiters, ws_link) {
            if (err ||
                swait->ws_bufcnt <= wal_bufset_durcnt(wal->wbs, WAL_BUF_MAX, swait->ws_offv)) {
                swait->ws_err = err;
                cv_signal(&swait->ws_cv);
            }
        }

        closing = (closing || err) && list_empty(&wal->sync_waiters);
        if (!closing) {
            end_stats_work();
            cv_timedwait(&wal->sync_cv, &wal->sync_mutex, wal->dur_ms, "walsnslp");
            begin_stats_work();
        }
        mutex_unlock(&wal->sync_mutex);
    }

    err = atomic_read(&wal->error);
    if (err)
        kvdb_health_error(wal->health, err);

    wal->sync_notifier_running = false;
}

void
wal_ionotify_cb(void *cbarg, merr_t err)
{
    struct wal *wal = cbarg;

    if (err)
        atomic_set(&wal->error, err);

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

    while (swait->ws_bufcnt > wal_bufset_durcnt(wal->wbs, WAL_BUF_MAX, swait->ws_offv) &&
           !swait->ws_err)
        cv_timedwait(&swait->ws_cv, &wal->sync_mutex, wal->dur_ms, "walsync");

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

    cv_init(&swait.ws_cv);
    INIT_LIST_HEAD(&swait.ws_link);

    swait.ws_bufcnt = wal_bufset_curoff(wal->wbs, WAL_BUF_MAX, swait.ws_offv);

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

    cv_init(&swait.ws_cv);
    INIT_LIST_HEAD(&swait.ws_link);

    swait.ws_bufcnt = wal_bufset_genoff(wal->wbs, gen, WAL_BUF_MAX, swait.ws_offv);

    start = get_time_ns();
    err = wal_sync_impl(wal, &swait);
    end = get_time_ns();

    if (!err && (dur = NSEC_TO_MSEC(end - start)) > 20)
        log_info("WAL ingest sync for dgen %lu took %u msec", gen, dur);

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
    const size_t kvalign = sizeof(uint64_t);
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
    rlen = wal_reclen(wal->version);
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

    rid = atomic_inc_return(&wal->wal_rid);
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
    const size_t kalign = sizeof(uint64_t);
    struct wal_rec_omf *rec;
    uint64_t rid;
    size_t klen, rlen, kalen, len;
    char *kdata;
    uint32_t rtype;
    merr_t err;

    if (!wal)
        return 0;

    rlen = wal_reclen(wal->version);
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

    rid = atomic_inc_return(&wal->wal_rid);
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

    rlen = wal_txn_reclen(wal->version);
    rec = wal_bufset_alloc(wal->wbs, rlen, &offset, &wbidx, cookie);
    if (!rec) {
        merr_t err = merr(ENOMEM); /* unrecoverable error */

        kvdb_health_error(wal->health, err);
        return err;
    }

    rid = atomic_inc_return(&wal->wal_rid);
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
    struct wal_mdc *          mdc;
    merr_t                    err;
    int                       i;

    for (i = HSE_MCLASS_COUNT - 1; i >= HSE_MCLASS_BASE; i--) {
        if (mpool_mclass_is_configured(mp, i))
            break;
    }
    assert(i >= HSE_MCLASS_BASE);

    if (i < HSE_MCLASS_BASE)
        return merr(ENOENT);

    err = wal_mdc_create(mp, i, WAL_MDC_CAPACITY, mdcid1, mdcid2);
    if (err)
        return err;

    err = wal_mdc_open(mp, *mdcid1, *mdcid2, false, &mdc);
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
    uint8_t mclass;
    merr_t err;

    if (!mp || !rp || !rinfo || !wal_out)
        return merr(EINVAL);

    *wal_out = NULL;

    wal = aligned_alloc(__alignof__(*wal), sizeof(*wal));
    if (!wal)
        return merr(ENOMEM);

    memset(wal, 0, sizeof(*wal));
    wal->version = WAL_VERSION;
    wal->mp = mp;
    wal->health = health;
    wal->read_only = rp->read_only;
    wal->ikvdb = ikdb;
    wal->buf_managed = rp->dur_buf_managed;
    wal->buf_flags = wal->buf_managed ? HSE_BTF_MANAGED : 0;

    wal->dur_ms = HSE_WAL_DUR_MS_DFLT;
    wal->dur_bytes = HSE_WAL_DUR_SIZE_BYTES_DFLT;
    wal->dur_bufsz = HSE_WAL_DUR_BUFSZ_MB_DFLT << MB_SHIFT;

    mutex_init(&wal->timer_mutex);
    cv_init(&wal->timer_cv);

    mutex_init(&wal->sync_mutex);
    cv_init(&wal->sync_cv);
    INIT_LIST_HEAD(&wal->sync_waiters);
    wal->sync_pending = false;

    err = wal_mdc_open(mp, rinfo->mdcid1, rinfo->mdcid2, wal->read_only, &wal->mdc);
    if (err)
        goto errout;

    err = wal_mdc_replay(wal->mdc, wal);
    if (err)
        goto errout;

    wal->wfset = wal_fileset_open(mp, wal->dur_mclass, WAL_FILE_SIZE_BYTES,
                                  WAL_MAGIC, wal->version);
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

    if (wal->read_only) {
        *wal_out = wal;
        return 0;
    }

    wal->version = WAL_VERSION;
    wal_fileset_version_set(wal->wfset, wal->version);

    if (rp->dur_intvl_ms != HSE_WAL_DUR_MS_DFLT)
        wal->dur_ms = clamp_t(uint32_t, rp->dur_intvl_ms, HSE_WAL_DUR_MS_MIN, HSE_WAL_DUR_MS_MAX);

    if (rp->dur_size_bytes != HSE_WAL_DUR_SIZE_BYTES_DFLT)
        wal->dur_bytes = clamp_t(uint32_t, rp->dur_size_bytes,
                                 HSE_WAL_DUR_SIZE_BYTES_MIN, HSE_WAL_DUR_SIZE_BYTES_MAX);

    if (rp->dur_bufsz_mb != HSE_WAL_DUR_BUFSZ_MB_DFLT)
        wal->dur_bufsz = (size_t)rp->dur_bufsz_mb << MB_SHIFT;

    mclass = rp->dur_mclass;
    if (mclass == HSE_MCLASS_AUTO) {
        int i;

        for (i = HSE_MCLASS_COUNT - 1; i >= HSE_MCLASS_BASE; i--) {
            if (mpool_mclass_is_configured(mp, i))
                break;
        }
        assert(i >= HSE_MCLASS_BASE);

        if (i < HSE_MCLASS_BASE) {
            err = merr(ENOENT);
            goto errout;
        }
        mclass = i;
        assert(mclass < HSE_MCLASS_COUNT);
        log_info("setting durability.mclass policy to \"%s\"", hse_mclass_name_get(mclass));
    }

    if (mclass != wal->dur_mclass) {
        const char *name = hse_mclass_name_get(mclass);

        if (!mpool_mclass_is_configured(mp, mclass)) {
            log_err("%s media not configured, cannot set durability.mclass to \"%s\"",
                    name, name);
            err = merr(ENOENT);
            goto errout;
        }

        wal->dur_mclass = mclass;
        wal_fileset_mclass_set(wal->wfset, wal->dur_mclass);
    }

    wal_fileset_flags_set(wal->wfset, rp->dio_enable[wal->dur_mclass] ? O_DIRECT : 0);

    err = wal_mdc_compact(wal->mdc, wal);
    if (err)
        goto errout;

    wal->wal_thr_hwm = rp->dur_throttle_hi_th;
    wal->wal_thr_lwm = rp->dur_throttle_lo_th;
    if (wal->wal_thr_lwm > wal->wal_thr_hwm / 2)
        wal->wal_thr_lwm = wal->wal_thr_hwm / 2;

    wal->wiocb.iocb = wal_ionotify_cb;
    wal->wiocb.cbarg = wal;
    wal->wbs = wal_bufset_open(wal->wfset, wal->dur_bufsz, wal->dur_bytes,
                               &wal->wal_ingestgen, &wal->wiocb);
    if (!wal->wbs) {
        err = merr(ENOMEM);
        goto errout;
    }

    wal->wq = alloc_workqueue("hse_wal", 0, 2, 2);
    if (!wal->wq) {
        err = merr(ENOMEM);
        goto errout;
    }

    wal->timer_running = true;
    INIT_WORK(&wal->timer_work, wal_timer);
    queue_work(wal->wq, &wal->timer_work);

    wal->sync_notifier_running = true;
    INIT_WORK(&wal->sync_notifier_work, wal_sync_notifier);
    queue_work(wal->wq, &wal->sync_notifier_work);

    *wal_out = wal;

    return 0;

errout:
    wal_close(wal);

    return err;
}

void
wal_close(struct wal *wal)
{
    merr_t err;

    if (!wal)
        return;

    atomic_inc(&wal->closing);

    while (wal->timer_running) {
        mutex_lock(&wal->timer_mutex);
        cv_signal(&wal->timer_cv);
        mutex_unlock(&wal->timer_mutex);

        usleep(333);
    }

    wal_bufset_close(wal->wbs);
    wal_fileset_close(wal->wfset, atomic_read(&wal->wal_ingestseq),
                      atomic_read(&wal->wal_ingestgen), atomic_read(&wal->wal_txhorizon));

    /* Ensure that the notify thread exits after all pending IOs are drained */
    if (wal->sync_notifier_running) {
        mutex_lock(&wal->sync_mutex);
        cv_signal(&wal->sync_cv);
        mutex_unlock(&wal->sync_mutex);
    }

    destroy_workqueue(wal->wq);

    /* Write a close record to indicate graceful shutdown if there's no health error */
    err = kvdb_health_check(wal->health, KVDB_HEALTH_FLAG_ALL);
    if (!err && !wal->read_only)
        wal_mdc_close_write(wal->mdc);
    wal_mdc_close(wal->mdc);

    mutex_destroy(&wal->sync_mutex);
    cv_destroy(&wal->sync_cv);

    mutex_destroy(&wal->timer_mutex);
    cv_destroy(&wal->timer_cv);

    free(wal);
}


static void
wal_reclaim(struct wal *wal, uint64_t seqno, uint64_t gen, uint64_t txhorizon)
{
    atomic_set(&wal->wal_ingestseq, seqno);
    atomic_set(&wal->wal_ingestgen, gen);
    atomic_set(&wal->wal_txhorizon, txhorizon);

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
enum hse_mclass
wal_dur_mclass_get(struct wal *wal)
{
    return wal->dur_mclass;
}

void
wal_dur_mclass_set(struct wal *wal, enum hse_mclass mclass)
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
wal_is_read_only(struct wal *wal)
{
    return wal->read_only;
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

struct kvdb_health *
wal_health(struct wal *wal)
{
    return wal->health;
}

#if HSE_MOCKING
#include "wal_ut_impl.i"
#endif /* HSE_MOCKING */
