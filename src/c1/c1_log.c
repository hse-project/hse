/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mpool/mpool.h>

#include "c1_private.h"
#include "../cn/cn_metrics.h"

merr_t
c1_log_create(struct mpool *mp, u64 capacity, int *mclass, struct c1_log_desc *desc)
{
    struct mlog_capacity mlcap;
    merr_t               err;
    struct mlog_props    props;
    u64                  staging_absent;
    u64                  objid;

    enum mp_media_classp mclassp = MP_MED_STAGING;

    memset(&mlcap, 0, sizeof(mlcap));
    mlcap.lcp_captgt = capacity;
    mlcap.lcp_spare = false;

    staging_absent = mpool_mclass_get(mp, MP_MED_STAGING, NULL);
    if (staging_absent)
        mclassp = MP_MED_CAPACITY;

    err = mpool_mlog_alloc(mp, mclassp, &mlcap, &objid, &props);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: mpool_mlog_alloc mclass:%d failed: @@e", err, __func__, mclassp);
        return err;
    }

    desc->c1_oid = objid;

    *mclass = props.lpr_mclassp;

    return 0;
}

merr_t
c1_log_abort(struct mpool *mp, struct c1_log_desc *desc)
{
    merr_t err;

    err = mpool_mlog_abort(mp, desc->c1_oid);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: mpool_mlog_abort failed: @@e", err, __func__);
        return err;
    }

    return 0;
}

merr_t
c1_log_destroy(struct mpool *mp, struct c1_log_desc *desc)
{
    merr_t err;

    err = mpool_mlog_delete(mp, desc->c1_oid);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: mpool_mlog_delete failed: @@e", err, __func__);
        return err;
    }

    return 0;
}

static merr_t
c1_log_alloc(
    struct mpool *  mp,
    u64             seqno,
    u32             gen,
    u64             mdcoid1,
    u64             mdcoid2,
    u64             oid,
    u64             capacity,
    struct c1_log **out)

{
    struct c1_log *log;
    struct cheap * cheap[HSE_C1_DEFAULT_STRIPE_WIDTH];
    int i;

    log = calloc(1, sizeof(*log));
    if (!log)
        return merr(ev(ENOMEM));

    log->c1l_mdcoid1 = mdcoid1;
    log->c1l_mdcoid2 = mdcoid2;
    log->c1l_oid = oid;
    log->c1l_seqno = seqno;
    log->c1l_gen = gen;
    log->c1l_empty = false;
    log->c1l_space = capacity;
    log->c1l_mp = mp;
    log->c1l_mlh = NULL;
    log->c1l_maxkv_seqno = C1_INVALID_SEQNO;
    log->c1l_repbuf = 0;
    log->c1l_repbuflen = 0;
    log->c1l_reptype = C1_REPLAY_INVALID;
    log->c1l_repseek = 0;
    log->c1l_repoffset = 0;
    atomic_set(&log->c1l_mb_lowutil, 0);
    atomic64_set(&log->c1l_rsvdspace, 0);
    atomic64_set(&log->c1l_ckcount, 0);
    atomic64_set(&log->c1l_kcount, 0);
    atomic64_set(&log->c1l_cvcount, 0);
    mutex_init(&log->c1l_ingest_mtx);
    INIT_LIST_HEAD(&log->c1l_kvb_list);
    INIT_LIST_HEAD(&log->c1l_txn_list);

    for (i = 0; i < HSE_C1_DEFAULT_STRIPE_WIDTH; i++) {
        cheap[i] =
            cheap_create(sizeof(cheap), HSE_C1_LOG_VBLDR_HEAPSZ / HSE_C1_DEFAULT_STRIPE_WIDTH);
        if (!cheap[i]) {
            while (--i >= 0)
                cheap_destroy(cheap[i]);
            free(log->c1l_ibuf);
            free(log);
            return merr(ev(ENOMEM));
        }
        log->c1l_cheap[i] = cheap[i];
    }

    *out = log;

    return 0;
}

static void
c1_log_free(struct c1_log *log)
{
    int i;

    for (i = 0; i < HSE_C1_DEFAULT_STRIPE_WIDTH; i++)
        cheap_destroy(log->c1l_cheap[i]);

    free(log->c1l_ibuf);
    free(log);
}

merr_t
c1_log_format(struct c1_log *log)
{
    struct c1_kvlog_omf kv;
    merr_t              err;
    struct iovec        iov;

    c1_set_hdr(&kv.hdr, C1_TYPE_KVLOG, sizeof(kv));
    omf_set_c1kvlog_mdcoid1(&kv, log->c1l_mdcoid1);
    omf_set_c1kvlog_mdcoid2(&kv, log->c1l_mdcoid2);
    omf_set_c1kvlog_oid(&kv, log->c1l_oid);
    omf_set_c1kvlog_gen(&kv, log->c1l_gen);
    omf_set_c1kvlog_size(&kv, log->c1l_space);
    omf_set_c1kvlog_seqno(&kv, log->c1l_seqno);

    iov.iov_base = &kv;
    iov.iov_len = sizeof(kv);

    err = mpool_mlog_append(log->c1l_mlh, &iov, iov.iov_len, true);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mlog_append failed: @@e", err, __func__);

    return err;
}

merr_t
c1_log_make(
    struct mpool *      mp,
    u64                 seqno,
    u32                 gen,
    u64                 mdcoid1,
    u64                 mdcoid2,
    struct c1_log_desc *desc,
    u64                 capacity)
{
    merr_t         err;
    struct c1_log *log = NULL;

    err = mpool_mlog_commit(mp, desc->c1_oid);
    if (ev(err)) {
        mpool_mlog_abort(mp, desc->c1_oid);
        hse_elog(HSE_ERR "%s: mpool_mlog_commit failed: @@e", err, __func__);
        return err;
    }

    err = c1_log_open(mp, seqno, gen, mdcoid1, mdcoid2, desc, capacity, &log);
    if (ev(err))
        return err;

    err = c1_log_format(log);

    c1_log_close(log);

    return err;
}

merr_t
c1_log_open(
    struct mpool *      mp,
    u64                 seqno,
    u32                 gen,
    u64                 mdcoid1,
    u64                 mdcoid2,
    struct c1_log_desc *desc,
    u64                 capacity,
    struct c1_log **    out)
{
    merr_t             err;
    struct c1_log *    log = NULL;
    struct mpool_mlog *mlh;
    u64                mlog_gen;

    err = c1_log_alloc(mp, seqno, gen, mdcoid1, mdcoid2, desc->c1_oid, capacity, &log);
    if (ev(err))
        return err;
    assert(log != NULL);

    err = mpool_mlog_open(log->c1l_mp, log->c1l_oid, 0, &mlog_gen, &mlh);
    if (ev(err)) {
        c1_log_free(log);
        hse_elog(HSE_ERR "%s: mpool_mlog_open failed: @@e", err, __func__);
        return err;
    }

    log->c1l_mlh = mlh;

    *out = log;

    return 0;
}

merr_t
c1_log_close(struct c1_log *log)
{
    merr_t err;

    /* With no preallocation of mlogs being done, mlog handle
     * can be NULL.
     */
    if (log->c1l_mlh == NULL)
        return 0;

    err = mpool_mlog_close(log->c1l_mlh);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mlog_close failed: @@e", err, __func__);

    c1_log_free(log);

    return err;
}

BullseyeCoverageSaveOff
merr_t
c1_log_reset(struct c1_log *log, u64 newseqno, u64 newgen)
{
    merr_t err;
    int    i;

    err = mpool_mlog_erase(log->c1l_mlh, 0);
    if (ev(err))
        return err;

    log->c1l_seqno = newseqno;
    log->c1l_gen = newgen;

    atomic64_set(&log->c1l_rsvdspace, 0);
    atomic64_set(&log->c1l_kcount, 0);
    atomic64_set(&log->c1l_ckcount, 0);
    atomic64_set(&log->c1l_cvcount, 0);

    for (i = 0; i < HSE_C1_DEFAULT_STRIPE_WIDTH; i++)
        cheap_reset(log->c1l_cheap[i], 0);

    return c1_log_format(log);
}
BullseyeCoverageRestore

    merr_t
    c1_log_flush(struct c1_log *log)
{
    merr_t err;

    err = mpool_mlog_sync(log->c1l_mlh);
    if (ev(err))
        return err;

    atomic_set(&log->c1l_mb_lowutil, 0);

    return 0;
}

u64
c1_log_get_capacity(struct c1_log *log)
{
    if (!log)
        return 0;

    return log->c1l_space;
}

void
c1_log_set_capacity(struct c1_log *log, u64 size)
{
    log->c1l_space = size;
}

merr_t
c1_log_reserve_space(struct c1_log *log, u64 rsvsz, u64 peeksz)
{
    merr_t err;
    u64    available;
    u64    reserved;
    size_t len;

    /*
     * Accomodating the metadata overheads of mlog appends. To support
     * all-or-nothing transactional behavior, c1 cannot affort to see
     * mlog append failures, until it has retry logic when the current
     * gets exhausted and mlog appends start failing.
     */
    err = mpool_mlog_len(log->c1l_mlh, &len);
    if (ev(err))
        return err;

    available = HSE_C1_LOG_USEABLE_CAPACITY(log->c1l_space);
    if (rsvsz >= available) {
        hse_log(
            HSE_ERR "c1_log ingest rsvsz 0x%lx exceeded capacity 0x%lx",
            (unsigned long)rsvsz,
            (unsigned long)available);
        return merr(ENOSPC);
    }
    reserved = atomic64_add_return(rsvsz, &log->c1l_rsvdspace);

    if ((len >= available) || (reserved + peeksz >= available))
        return merr(ENOMEM);

    return 0;
}

u64
c1_log_refresh_space(struct c1_log *log)
{
    size_t len;
    merr_t err;

    err = mpool_mlog_len(log->c1l_mlh, &len);
    if (err)
        return atomic64_read(&log->c1l_rsvdspace);

    atomic64_set(&log->c1l_rsvdspace, len);

    return len;
}

static void
c1_log_add_val_mlog(struct c1_vtuple *vt, struct iovec *iov, size_t *size, int *logtype)
{
    *size += vt->c1vt_vlen;
    iov->iov_base = vt->c1vt_data;
    iov->iov_len = vt->c1vt_vlen;
    *logtype = C1_LOG_MLOG;
}

static inline bool
c1_log_use_mblock(struct c1_kvset_builder_elem *vbldr, struct c1_vtuple *vt, u64 kvbsize, u64 vsize)
{
    if (!vbldr || (vt->c1vt_data == HSE_CORE_TOMB_REG) || (vt->c1vt_data == HSE_CORE_TOMB_PFX) ||
        (vt->c1vt_vlen <= HSE_C1_SMALL_VALUE_THRESHOLD))
        return false;

    return true;
}

static merr_t
c1_log_add_val(
    struct c1_log *               log,
    struct c1_kvset_builder_elem *vbldr,
    u32                           skidx,
    u64                           cnid,
    struct c1_vtuple *            vt,
    struct iovec *                iov,
    size_t *                      size,
    int *                         logtype,
    u8                            tidx,
    u64                           kvbsize,
    u64                           vsize)
{
    struct c1_mblk_omf *    omf;
    struct c1_bonsai_vbldr *vbb;
    merr_t                  err;
    atomic64_t *            vbbptr;

    /*
     * [HSE_REVISIT] Need a more comprehensive criteria for
     * making the decision (mlog or mblock) here which includes
     * media class.
     */
    if (!c1_log_use_mblock(vbldr, vt, kvbsize, vsize)) {
        c1_log_add_val_mlog(vt, iov, size, logtype);
        return 0;
    }

    if (atomic_read(&log->c1l_mb_lowutil) > 0) {
        c1_log_add_val_mlog(vt, iov, size, logtype);
        return 0;
    }

    *logtype = C1_LOG_MBLOCK;

    mutex_lock(&log->c1l_ingest_mtx);
    vbb = cheap_malloc(log->c1l_cheap[tidx], sizeof(*vbb));
    omf = cheap_malloc(log->c1l_cheap[tidx], sizeof(*omf));

    if (!vbb || !omf || (atomic_read(&log->c1l_mb_lowutil) > 0)) {
        mutex_unlock(&log->c1l_ingest_mtx);
        c1_log_add_val_mlog(vt, iov, size, logtype);
        return 0;
    }

    memset(vbb, 0, sizeof(*vbb));
    memset(omf, 0, sizeof(*omf));

    vbbptr = (atomic64_t *)vt->c1vt_vbuilder;
    atomic64_set(vbbptr, 0);

    err = c1_kvset_builder_add_val(
        vbldr,
        skidx,
        cnid,
        vt->c1vt_seqno,
        vt->c1vt_data,
        vt->c1vt_vlen,
        tidx,
        &vbb->cbv_gen,
        &vbb->cbv_blkid,
        &vbb->cbv_blkidx,
        &vbb->cbv_blkoff,
        &vbb->cbv_bldr);

    if (err && merr_errno(err) == ENOSPC)
        atomic_set(&log->c1l_mb_lowutil, 1);

    mutex_unlock(&log->c1l_ingest_mtx);
    if (err) {
        c1_log_add_val_mlog(vt, iov, size, logtype);

        return 0;
    }

    omf_set_c1mblk_id(omf, vbb->cbv_blkid);
    omf_set_c1mblk_off(omf, vbb->cbv_blkoff);

    vbb->cbv_blkvlen = vt->c1vt_vlen;
    vbb->cbv_blkval = (u64)vt->c1vt_data;

    /*
     * c0sk_ingest_worker reads the above fields to validate
     * contents.
     */
    smp_mb();
    atomic64_set(vbbptr, (unsigned long)vbb);

    *size += sizeof(*omf);
    iov->iov_base = omf;
    iov->iov_len = sizeof(*omf);

    return 0;
}

merr_t
c1_log_issue_kvb(
    struct c1_log *               log,
    struct c1_kvset_builder_elem *vbldr,
    u64                           ingestid,
    u64                           vsize,
    struct c1_kvbundle *          kvb,
    u64                           seqno,
    u64                           txnid,
    u32                           gen,
    u64                           mutation,
    int                           sync,
    u8                            tidx,
    struct c1_log_stats *         statsp)
{
    size_t                 vtsz, iovsz, kvtomfsz;
    struct c1_kvbundle_omf omf;
    merr_t                 err;
    struct c1_ktuple *     skt;
    struct c1_vtuple_omf * vt;
    struct iovec *         iov;
    u64                    numiov;
    int                    i, j;
    int                    nextkvt;
    size_t                 size = 0;
    struct c1_kvtuple *    next;
    struct c1_vtuple *     nextvt;
    struct c1_kvtuple_omf *kvtomf;
    u64                    vtacount;
    u64                    vtalen;
    int                    logtype;
    u64                    latency = 0;
    struct iovec           siov;

    atomic64_add(kvb->c1kvb_ktcount, &log->c1l_ckcount);
    atomic64_add(kvb->c1kvb_vtcount, &log->c1l_cvcount);

    numiov = (kvb->c1kvb_ktcount * HSE_C1_KEY_IOVS) + (kvb->c1kvb_vtcount * HSE_C1_VAL_IOVS);

    vtsz = roundup(kvb->c1kvb_vtcount * sizeof(*vt), 16);
    iovsz = roundup(numiov * sizeof(*iov), 16);
    kvtomfsz = roundup(kvb->c1kvb_ktcount * sizeof(*kvtomf), 16);

    if (vtsz + iovsz + kvtomfsz > log->c1l_ibufsz) {
        log->c1l_ibufsz = roundup(vtsz + iovsz + kvtomfsz, 128 * 1024);
        free(log->c1l_ibuf);

        log->c1l_ibuf = malloc(log->c1l_ibufsz);

        if (ev(!log->c1l_ibuf)) {
            log->c1l_ibufsz = 0;
            return merr(ENOMEM);
        }
    }

    vt = (void *)log->c1l_ibuf;
    iov = (void *)(log->c1l_ibuf + vtsz);
    kvtomf = (void *)(log->c1l_ibuf + vtsz + iovsz);

    nextkvt = i = j = 0;

    s_list_for_each_entry(next, &kvb->c1kvb_kvth, c1kvt_next)
    {
        skt = &next->c1kvt_kt;

        if (ev(i > (numiov - HSE_C1_KEY_IOVS))) {
            hse_log(HSE_ERR "%s: c1 ingest kv overflow: %d %lu",
                    __func__, i, (u_long)numiov);
            assert(i <= (numiov - HSE_C1_KEY_IOVS));
            return merr(EINVAL);
        }

        /*
         * Placing key - struct c1_kvtuple
         */
        assert(nextkvt < kvb->c1kvb_ktcount);
        omf_set_c1kvt_sign(&kvtomf[nextkvt], C1_KEY_MAGIC);
        omf_set_c1kvt_klen(&kvtomf[nextkvt], skt->c1kt_klen);
        omf_set_c1kvt_cnid(&kvtomf[nextkvt], next->c1kvt_cnid);
        omf_set_c1kvt_vlen(&kvtomf[nextkvt], next->c1kvt_vt.c1vt_vlen);
        omf_set_c1kvt_vcount(&kvtomf[nextkvt], next->c1kvt_vt.c1vt_vcount);

        iov[i].iov_base = &kvtomf[nextkvt];
        iov[i].iov_len = sizeof(kvtomf[nextkvt]);
        iov[i + 1].iov_base = skt->c1kt_data;
        iov[i + 1].iov_len = skt->c1kt_klen;

        __builtin_prefetch(skt->c1kt_data, 0);

        /*
         * Placing struct c1_vtuple_array
         */
        vtacount = next->c1kvt_vt.c1vt_vcount;
        vtalen = next->c1kvt_vt.c1vt_vlen;

        size += iov[i].iov_len + iov[i + 1].iov_len;
        i += HSE_C1_KEY_IOVS;

        /*
         * Filling individual struct c1_vtuple into OMF
         */
        s_list_for_each_entry(nextvt, &next->c1kvt_vt.c1vt_vth, c1vt_next)
        {
            if (ev(j >= kvb->c1kvb_vtcount || i >= numiov)) {
                hse_log(HSE_ERR "%s: c1 ingest kv overflow: %d %lu, %d %u",
                        __func__, i, (u_long)numiov, j, kvb->c1kvb_vtcount);
                assert(j < kvb->c1kvb_vtcount);
                assert(i < numiov);
                return merr(EINVAL);
            }

            assert(nextvt->c1vt_seqno >= kvb->c1kvb_minseqno);
            assert(nextvt->c1vt_seqno <= kvb->c1kvb_maxseqno);

            __builtin_prefetch(nextvt->c1vt_data, 0);

            omf_set_c1vt_sign(&vt[j], C1_VAL_MAGIC);
            omf_set_c1vt_seqno(&vt[j], nextvt->c1vt_seqno);
            omf_set_c1vt_vlen(&vt[j], nextvt->c1vt_vlen);
            omf_set_c1vt_tomb(&vt[j], nextvt->c1vt_tomb ? 1 : 0);

            assert(i < numiov);

            size += sizeof(vt[j]);
            iov[i].iov_base = &vt[j];
            iov[i].iov_len = sizeof(vt[j]);

            ++i;
            assert(i < numiov);

            if (statsp)
                latency = get_time_ns();

            err = c1_log_add_val(
                log,
                vbldr,
                next->c1kvt_skidx,
                next->c1kvt_cnid,
                nextvt,
                &iov[i],
                &size,
                &logtype,
                tidx,
                kvb->c1kvb_size,
                vsize);
            if (ev(err))
                return err;

            if (statsp && (logtype == C1_LOG_MBLOCK)) {
                statsp->c1log_mbwrites++;
                latency = get_time_ns() - latency;
                if (latency > 0) {
                    statsp->c1log_mblatency += latency;
                    statsp->c1log_mblatency >>= 1;
                }
            } else if (statsp) {
                statsp->c1log_mlwrites++;
                latency = get_time_ns() - latency;
                if (latency > 0) {
                    statsp->c1log_mllatency += latency;
                    statsp->c1log_mllatency >>= 1;
                }
            }

            omf_set_c1vt_logtype(&vt[j], logtype);

            i++;
            j++;

            vtacount--;
            vtalen -= nextvt->c1vt_vlen;
        }

        if (ev(vtalen || vtacount)) {
            hse_log(HSE_ERR "%s: c1 ingest failed: vtalen %lu, vtacount %lu",
                    __func__, (u_long)vtalen, (u_long)vtacount);
            assert(!vtalen);
            assert(!vtacount);
            return merr(EIO);
        }

        nextkvt++;
    }

    assert(i <= numiov);

    c1_set_hdr(&omf.hdr, C1_TYPE_KVB, sizeof(omf));

    omf_set_c1kvb_seqno(&omf, seqno);
    omf_set_c1kvb_txnid(&omf, txnid);
    omf_set_c1kvb_gen(&omf, gen);
    omf_set_c1kvb_mutation(&omf, mutation);
    omf_set_c1kvb_keycount(&omf, kvb->c1kvb_ktcount);
    omf_set_c1kvb_ckeycount(&omf, atomic64_read(&log->c1l_ckcount));
    omf_set_c1kvb_size(&omf, size);
    omf_set_c1kvb_minseqno(&omf, kvb->c1kvb_minseqno);
    omf_set_c1kvb_maxseqno(&omf, kvb->c1kvb_maxseqno);
    omf_set_c1kvb_minkey(&omf, kvb->c1kvb_minkey);
    omf_set_c1kvb_maxkey(&omf, kvb->c1kvb_maxkey);
    omf_set_c1kvb_ingestid(&omf, ingestid);

    mutex_lock(&log->c1l_ingest_mtx);
    if (statsp)
        latency = get_time_ns();

    /* Send header to mlog first, followed by the key-value bundle...
     */
    siov.iov_base = &omf;
    siov.iov_len = sizeof(omf);

    err = mpool_mlog_append(log->c1l_mlh, &siov, siov.iov_len, false);
    if (!err)
        err = mpool_mlog_append(log->c1l_mlh, iov, size, sync);

    if (ev(err)) {
        size_t len;

        mpool_mlog_len(log->c1l_mlh, &len);

        hse_elog(
            HSE_ERR "%s: mpool_mlog_append failed: mlog len %zu, reserved space %ld: @@e",
            err, __func__, len, atomic64_read(&log->c1l_rsvdspace));
    }
    else {
        log->c1l_maxkv_seqno = max_t(u64, log->c1l_maxkv_seqno, kvb->c1kvb_maxseqno);

        if (statsp) {
            latency = get_time_ns() - latency;
            statsp->c1log_mllatency += latency;
            statsp->c1log_vsize = vsize;
        }
    }
    mutex_unlock(&log->c1l_ingest_mtx);

    /* It's unusual for ibuf to be larger than 256K...
     */
    if (ev(log->c1l_ibufsz > 256 * 1024)) {
        free(log->c1l_ibuf);
        log->c1l_ibuf = NULL;
        log->c1l_ibufsz = 0;
    }

    return err;
}

merr_t
c1_log_issue_txn(
    struct c1_log * log,
    struct c1_ttxn *txn,
    u64             seqno,
    u32             gen,
    u64             mutation,
    int             sync)

{
    struct iovec          iov;
    struct c1_treetxn_omf omf;
    merr_t                err;

    c1_set_hdr(&omf.hdr, C1_TYPE_TXN, sizeof(omf));

    omf_set_c1ttxn_seqno(&omf, txn->c1t_segno);
    omf_set_c1ttxn_gen(&omf, txn->c1t_gen);
    omf_set_c1ttxn_id(&omf, txn->c1t_txnid);
    omf_set_c1ttxn_kvseqno(&omf, txn->c1t_kvseqno);
    omf_set_c1ttxn_mutation(&omf, mutation);
    omf_set_c1ttxn_cmd(&omf, txn->c1t_cmd);
    omf_set_c1ttxn_flag(&omf, txn->c1t_flag);

    iov.iov_base = &omf;
    iov.iov_len = sizeof(omf);

    mutex_lock(&log->c1l_ingest_mtx);
    err = mpool_mlog_append(log->c1l_mlh, &iov, iov.iov_len, sync);
    mutex_unlock(&log->c1l_ingest_mtx);

    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mlog_append failed: @@e", err, __func__);

    return err;
}
