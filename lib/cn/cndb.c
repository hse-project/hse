/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/minmax.h>
#include <hse_util/string.h>
#include <hse_util/log2.h>
#include <hse_util/atomic.h>

#define MTF_MOCK_IMPL_cndb
#define MTF_MOCK_IMPL_cndb_internal

#include <hse/hse.h>

#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cndb.h>

#include "blk_list.h"
#include "cndb_omf.h"
#include "cndb_internal.h"
#include "kvset.h"

#include <stdlib.h>

/* PRIVATE */
void
cndb_validate_vector_failed(int i)
{
    hse_alog(HSE_CRIT "%s: element %d is corrupt", __func__, i);
    abort();
}

/* PRIVATE */
void
cndb_validate_vector(void **v, size_t c)
{
    union cndb_mtu *mtu;
    int             i;

    for (i = 0; i < c; i++) {
        mtu = (void *)v[i];

        if (!mtu)
            continue;

        if (mtu->h.mth_type == 0 || mtu->h.mth_type > CNDB_TYPE_META)
            cndb_validate_vector_failed(i);
    }
}

struct nfault_probe cndb_no_probes[CNDB_NUM_PROBES] = {};

struct nfault_probe cndb_ack_probes[CNDB_NUM_PROBES] = {
    {},                                /* CNDB_PROBE_DROP_TX */
    { 0, { NFAULT_TRIG_ONESHOT, 3 } }, /* CNDB_PROBE_DROP_ACKC */
    { 0, { NFAULT_TRIG_PERIOD, 3 } },  /* CNDB_PROBE_DROP_ACKD */
    {},                                /* CNDB_PROBE_DROP_NAK */
    {},                                /* CNDB_PROBE_DROP_TXC */
    {},                                /* CNDB_PROBE_DROP_TXM */
    {},                                /* CNDB_PROBE_DROP_TXD */
};

static struct nfault_probe *cndb_probes = cndb_no_probes;

/* PRIVATE */
int
nfault_probe(struct nfault_probe *probes, int id)
{
    int trig;
    u64 od;
    u64 val;

    od = ++probes[id].probe_odometer;
    trig = probes[id].probe_trigger.trig_type;
    val = probes[id].probe_trigger.trig_value;

    if (trig == NFAULT_TRIG_ONESHOT && od == val) {
        hse_alog(HSE_NOTICE "%s: trigger %d %lu %lu", __func__, trig, (ulong)od, (ulong)val);
        return NFAULT_TRIG_ONESHOT;
    }

    if (trig == NFAULT_TRIG_PERIOD && (od % val) == 0) {
        hse_alog(HSE_NOTICE "%s: trigger %d %lu %lu", __func__, trig, (ulong)od, (ulong)val);
        return NFAULT_TRIG_PERIOD;
    }

    if (trig == NFAULT_TRIG_LEVEL && od >= val) {
        hse_alog(HSE_NOTICE "%s: trigger %d %lu %lu", __func__, trig, (ulong)od, (ulong)val);
        return NFAULT_TRIG_LEVEL;
    }

    return NFAULT_TRIG_NONE;
}

void
cndb_set_hdr(struct cndb_hdr_omf *hdr, int type, int len)
{
    assert(len >= sizeof(*hdr));

    omf_set_cnhdr_type(hdr, type);
    omf_set_cnhdr_len(hdr, len - sizeof(*hdr));
}

/**
 * cndb_info2omf() - serialize cn descriptor to OMF
 * @hdr_type:     must be CNDB_TYPE_INFO or CNDB_TYPE_INFOD
 * @cn:           the cn to serialize
 * @inf:          (output) OMF buffer
 *
 * Note:  The caller must format the cninfo_meta field in inf
 */
static void
cndb_info2omf(int hdr_type, const struct cndb_cn *cn, struct cndb_info_omf *inf)
{
    size_t sz = sizeof(*inf);

    if (hdr_type != CNDB_TYPE_INFOD)
        sz = cn->cn_cbufsz;

    memset(inf, 0, sizeof(*inf));

    cndb_set_hdr(&inf->hdr, hdr_type, sz);
    omf_set_cninfo_fanout_bits(inf, ilog2(cn->cn_cp.cp_fanout));
    omf_set_cninfo_prefix_len(inf, cn->cn_cp.cp_pfx_len);
    omf_set_cninfo_sfx_len(inf, cn->cn_cp.cp_sfx_len);
    omf_set_cninfo_prefix_pivot(inf, cn->cn_cp.cp_pfx_pivot);

    omf_set_cninfo_flags(inf, cn->cn_flags);
    omf_set_cninfo_metasz(inf, sz - sizeof(*inf));
    omf_set_cninfo_cnid(inf, cn->cn_cnid);

    omf_set_cninfo_name(inf, (unsigned char *)cn->cn_name, strlen(cn->cn_name));
}

merr_t
cndb_alloc(struct mpool *ds, u64 *captgt, u64 *oid1_out, u64 *oid2_out)
{
    merr_t               err;
    struct mdc_capacity  mdcap;
    struct mdc_props     props = { 0 };
    enum mp_media_classp mclassp = MP_MED_STAGING;
    u64                  staging_absent;

    if (captgt && *captgt)
        mdcap.mdt_captgt = *captgt;
    else
        mdcap.mdt_captgt = CNDB_CAPTGT_DEFAULT;

    mdcap.mdt_spare = false;

    staging_absent = mpool_mclass_get(ds, MP_MED_STAGING, NULL);
    if (staging_absent)
        mclassp = MP_MED_CAPACITY;

    err = mpool_mdc_alloc(ds, oid1_out, oid2_out, mclassp, &mdcap, &props);
    if (ev(err)) {
        hse_elog(
            HSE_ERR "%s: cannot allocate cNDB MDC (%lld): @@e",
            err,
            __func__,
            (long long int)mdcap.mdt_captgt);
        return err;
    }

    if (captgt)
        *captgt = props.mdc_alloc_cap;

    return 0;
}

merr_t
cndb_make(struct mpool *ds, u64 captgt, u64 oid1, u64 oid2)
{
    merr_t err, err2;

    struct mpool_mdc *   mdc;
    struct cndb_ver_omf  ver = {};
    struct cndb_meta_omf meta = {};

    captgt = captgt ?: CNDB_CAPTGT_DEFAULT;

    err = mpool_mdc_commit(ds, oid1, oid2);
    if (err) {
        hse_elog(
            HSE_ERR "%s: cannot commit cNDB MDC (%lld): @@e", err, __func__, (long long int)captgt);
        return err;
    }

    err = mpool_mdc_open(ds, oid1, oid2, 0, &mdc);
    if (err) {
        hse_elog(HSE_ERR "%s: cannot open cNDB MDC: @@e", err, __func__);
        return err;
    }

    cndb_set_hdr(&ver.hdr, CNDB_TYPE_VERSION, sizeof(ver));
    omf_set_cnver_magic(&ver, CNDB_MAGIC);
    omf_set_cnver_version(&ver, CNDB_VERSION);
    omf_set_cnver_captgt(&ver, captgt);

    err = mpool_mdc_append(mdc, &ver, sizeof(ver), true);
    if (ev(err))
        goto errout;

    cndb_set_hdr(&meta.hdr, CNDB_TYPE_META, sizeof(meta));
    omf_set_cnmeta_seqno_max(&meta, 0);

    err = mpool_mdc_append(mdc, &meta, sizeof(meta), true);
    if (ev(err))
        goto errout;

    err2 = mpool_mdc_close(mdc);
    if (err2) {
        hse_elog(HSE_ERR "%s: MDC close failed: @@e", err, __func__);
        if (!err)
            return err2;
    }

    return err;

errout:
    hse_elog(
        HSE_ERR "%s: MDC append (%lx, %lx) failed: @@e", err, __func__, (ulong)oid1, (ulong)oid2);
    err2 = mpool_mdc_delete(ds, oid1, oid2);
    if (err2)
        hse_elog(
            HSE_ERR "%s: destroy (%lx,%lx) failed: @@e", err2, __func__, (ulong)oid1, (ulong)oid2);
    return err;
}

merr_t
cndb_drop(struct mpool *ds, u64 oid1, u64 oid2)
{
    return 0;
}

/* PRIVATE */
merr_t
cndb_init(
    struct cndb *       cndb,
    struct mpool *      ds,
    bool                rdonly,
    atomic64_t *        ikvdb_seqno,
    size_t              cndb_entries,
    u64                 oid1,
    u64                 oid2,
    struct kvdb_health *health)
{
    size_t sz;
    size_t entries = cndb_entries ?: CNDB_ENTRIES;
    merr_t err = 0;

    memset(cndb, 0, sizeof(*cndb));
    cndb->cndb_oid1 = oid1;
    cndb->cndb_oid2 = oid2;
    cndb->cndb_ikvdb_seqno = ikvdb_seqno;

    sz = entries * sizeof(void *);

    cndb->cndb_workv = calloc(1, sz);
    if (!cndb->cndb_workv) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "%s: workv allocation: @@e", err, __func__);
        return err;
    }

    cndb->cndb_keepv = calloc(1, sz);
    if (!cndb->cndb_keepv) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "%s: keepv allocation: @@e", err, __func__);
        return err;
    }

    cndb->cndb_tagv = calloc(1, sz);
    if (!cndb->cndb_tagv) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "%s: tagv allocation: @@e", err, __func__);
        return err;
    }

    cndb->cndb_cbuf = calloc(1, CNDB_CBUFSZ_DEFAULT);
    if (!cndb->cndb_cbuf) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "%s: cbuf allocation: @@e", err, __func__);
        return err;
    }

    cndb->cndb_cbufsz = CNDB_CBUFSZ_DEFAULT;

    cndb->cndb_min_entries = entries;
    cndb->cndb_entries = entries;
    cndb->cndb_entries_high_water = (entries / 4) * 3;
    /* [HSE_REVISIT] consider making cndb_workc_margin an rparam */
    cndb->cndb_workc_margin = CNDB_WORKC_MARGIN_DEFAULT;
    cndb->cndb_ds = ds;
    cndb->cndb_rdonly = rdonly;
    cndb->cndb_kvdb_health = health;

    /* First txid is 1 */
    atomic64_set(&cndb->cndb_txid, 1);
    mutex_init(&cndb->cndb_lock);
    mutex_init(&cndb->cndb_cnv_lock);

    return 0;
}

merr_t
cndb_open(
    struct mpool *      ds,
    bool                rdonly,
    atomic64_t *        ikvdb_seqno,
    size_t              cndb_entries,
    u64                 oid1,
    u64                 oid2,
    struct kvdb_health *health,
    struct cndb **      cndb_out)
{
    struct cndb *cndb = NULL;
    merr_t       err;

    cndb = calloc(1, sizeof(*cndb));
    if (!cndb) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "%s: cndb allocation failed: @@e", err, __func__);
        return err;
    }

    err = cndb_init(cndb, ds, rdonly, ikvdb_seqno, cndb_entries, oid1, oid2, health);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " initialization failed");
        goto errout;
    }

    err = mpool_mdc_open(ds, oid1, oid2, 0, &cndb->cndb_mdc);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " mdc open failed");
        goto errout;
    }

    *cndb_out = cndb;

    return 0;

errout:
    assert(cndb);
    free(cndb->cndb_cbuf);
    free(cndb->cndb_keepv);
    free(cndb->cndb_workv);
    free(cndb->cndb_tagv);
    free(cndb);

    return err;
}

/* PRIVATE */
merr_t
mtx2omf(struct cndb *cndb, void *omf, union cndb_mtu *mtu)
{
    struct cndb_oid *    mto = NULL;
    struct cndb_txc *    mtc = (void *)mtu;
    struct cndb_txd *    mtd = (void *)mtu;
    struct cndb_oid_omf *omo = NULL;
    struct cndb_txc_omf *txc = omf;
    struct cndb_txd_omf *txd = omf;

    int    i;
    size_t sz = 0;

    switch (mtu->h.mth_type) {
        case CNDB_TYPE_TX:
            cndb_set_hdr(omf, CNDB_TYPE_TX, sizeof(struct cndb_tx_omf));
            omf_set_tx_id(omf, mtu->x.mtx_id);
            omf_set_tx_nc(omf, mtu->x.mtx_nc);
            omf_set_tx_nd(omf, mtu->x.mtx_nd);
            omf_set_tx_seqno(omf, mtu->x.mtx_seqno);
            omf_set_tx_ingestid(omf, mtu->x.mtx_ingestid);
            break;
        case CNDB_TYPE_TXC:
            sz = sizeof(struct cndb_txc_omf) +
                 (sizeof(struct cndb_oid_omf) * (mtc->mtc_kcnt + mtc->mtc_vcnt));

            if (sz > cndb->cndb_cbufsz) {
                merr_t err = merr(EMLINK);

                CNDB_LOGTX(
                    err,
                    cndb,
                    mtxid(mtu),
                    HSE_ERR,
                    " tag %lu size %zd exceeds limit %zd",
                    (ulong)mtxtag(mtu),
                    sz,
                    cndb->cndb_cbufsz);

                kvdb_health_event(cndb->cndb_kvdb_health, KVDB_HEALTH_FLAG_CNDBFAIL, err);
                return err;
            }

            cndb_set_hdr(omf, CNDB_TYPE_TXC, sz);
            omf_set_tx_id(omf, mtu->x.mtx_id);
            omf_set_txc_cnid(omf, mtc->mtc_cnid);
            omf_set_txc_id(omf, mtc->mtc_id);
            omf_set_txc_tag(omf, mtc->mtc_tag);
            omf_set_txc_keepvbc(omf, mtc->mtc_keepvbc);
            omf_set_txc_kcnt(omf, mtc->mtc_kcnt);
            omf_set_txc_vcnt(omf, mtc->mtc_vcnt);

            mto = (void *)&mtc[1];
            omo = (void *)&txc[1];
            for (i = 0; i < mtc->mtc_kcnt; i++)
                omf_set_cndb_oid(&omo[i], mto[i].mmtx_oid);

            mto += mtc->mtc_kcnt;
            omo += mtc->mtc_kcnt;
            for (i = 0; i < mtc->mtc_vcnt; i++)
                omf_set_cndb_oid(&omo[i], mto[i].mmtx_oid);
            break;
        case CNDB_TYPE_TXM:
            cndb_set_hdr(omf, CNDB_TYPE_TXM, sizeof(struct cndb_txm_omf));
            omf_set_txm_cnid(omf, mtu->m.mtm_cnid);
            omf_set_txm_id(omf, mtu->m.mtm_id);
            omf_set_txm_tag(omf, mtu->m.mtm_tag);
            omf_set_txm_level(omf, mtu->m.mtm_level);
            omf_set_txm_offset(omf, mtu->m.mtm_offset);
            omf_set_txm_dgen(omf, mtu->m.mtm_dgen);
            omf_set_txm_vused(omf, mtu->m.mtm_vused);
            omf_set_txm_compc(omf, mtu->m.mtm_compc);
            omf_set_txm_scatter(omf, mtu->m.mtm_scatter);
            break;
        case CNDB_TYPE_TXD:
            sz = sizeof(struct cndb_txd_omf) + (sizeof(struct cndb_oid_omf) * mtd->mtd_n_oids);

            if (sz > cndb->cndb_cbufsz) {
                merr_t err = merr(EMLINK);

                CNDB_LOGTX(
                    err,
                    cndb,
                    mtxid(mtu),
                    HSE_ERR,
                    " tag %lu size %zd exceeds limit %zd",
                    (ulong)mtxtag(mtu),
                    sz,
                    cndb->cndb_cbufsz);

                kvdb_health_event(cndb->cndb_kvdb_health, KVDB_HEALTH_FLAG_CNDBFAIL, err);
                return err;
            }

            cndb_set_hdr(omf, CNDB_TYPE_TXD, sz);
            omf_set_txd_cnid(omf, mtd->mtd_cnid);
            omf_set_txd_id(omf, mtd->mtd_id);
            omf_set_txd_tag(omf, mtd->mtd_tag);
            omf_set_txd_n_oids(omf, mtd->mtd_n_oids);

            mto = (void *)&mtd[1];
            omo = (void *)&txd[1];
            for (i = 0; i < mtd->mtd_n_oids; i++)
                omf_set_cndb_oid(&omo[i], mto[i].mmtx_oid);
            break;
        case CNDB_TYPE_ACK:
            cndb_set_hdr(omf, CNDB_TYPE_ACK, sizeof(struct cndb_ack_omf));
            omf_set_ack_txid(omf, mtu->a.mta_txid);
            omf_set_ack_type(omf, mtu->a.mta_type);
            omf_set_ack_tag(omf, mtu->a.mta_tag);
            omf_set_ack_cnid(omf, mtu->a.mta_cnid);
            break;
        case CNDB_TYPE_NAK:
            cndb_set_hdr(omf, CNDB_TYPE_NAK, sizeof(struct cndb_nak_omf));
            omf_set_nak_txid(omf, mtu->n.mtn_txid);
            break;
        default:
            break;
    }

    return 0;
}

/* PRIVATE */
merr_t
cndb_realloc(struct cndb *cndb, size_t entries)
{
    size_t            sz;
    void **           workv_new = NULL;
    void **           keepv_new = NULL;
    struct cndb_idx **tagv_new = NULL;
    merr_t            err = 0;

    if (entries == cndb->cndb_entries)
        return 0; /* nothing to do */

    /* [HSE_REVISIT] realloc is tempting but avoided here because:
     *
     * 1) compaction and rollover assume arrays of equal size, making this
     *    an all-or-nothing operation.
     * 2) the back-out logic for realloc would be more complicated
     * 3) realloc does not zero new elements of the array
     * 4) realloc is not guaranteed to be nicer to the heap than this
     *
     * Therefore, we keep it as straightforward as possible.
     */

    sz = entries * sizeof(void *);

    keepv_new = calloc(1, sz);
    if (!keepv_new) {
        err = merr(ev(ENOMEM));
        goto errout;
    }

    workv_new = calloc(1, sz);
    if (!workv_new) {
        err = merr(ev(ENOMEM));
        goto errout;
    }

    tagv_new = calloc(1, sz);
    if (!tagv_new) {
        err = merr(ev(ENOMEM));
        goto errout;
    }

    if (cndb->cndb_keepv)
        memcpy(keepv_new, cndb->cndb_keepv, cndb->cndb_keepc * sizeof(void *));

    if (cndb->cndb_workv)
        memcpy(workv_new, cndb->cndb_workv, cndb->cndb_workc * sizeof(void *));

    if (cndb->cndb_tagv)
        memcpy(tagv_new, cndb->cndb_tagv, cndb->cndb_tagc * sizeof(*tagv_new));

    free(cndb->cndb_keepv);
    free(cndb->cndb_workv);
    free(cndb->cndb_tagv);

    cndb->cndb_keepv = keepv_new;
    cndb->cndb_workv = workv_new;
    cndb->cndb_tagv = tagv_new;

    CNDB_LOG(
        0,
        cndb,
        HSE_NOTICE,
        " old entries %lu -> new entries %lu",
        (ulong)cndb->cndb_entries,
        entries);

    cndb->cndb_entries = entries;
    cndb->cndb_entries_high_water = (entries / 4) * 3;

    return 0;

errout:
    free(keepv_new);
    free(workv_new);
    free(tagv_new);

    if (entries < cndb->cndb_entries)
        return 0; /* failure to shrink is not an error */

    return err;
}

/* PRIVATE */
merr_t
cndb_mdc_grow(struct cndb *cndb, size_t capreq)
{
    assert(cndb->cndb_compacted);

    /* [HSE_REVISIT] implement transactional MDC growth
     * theory of operation: cndb_make will provision two MDCs, one of the
     * size indicated by cparams/defaults and one that is 50% larger. When
     * growth is necessary, this function will write the compacted set into
     * the reserve MDC, switch active MDCs, delete the old MDC and initiate
     * a work queue item to create the next reserve MDC, 50% larger than the
     * one just put into service.
     *
     * This approach transforms what would be a several second pause into
     * several seconds of elevated contention for I/O bandwidth.
     */
    return merr(ev(EFBIG));
}

/* PRIVATE */
void
cndb_shrink(struct cndb *cndb)
{
    size_t new_entries = (cndb->cndb_entries * 2) / 3;
    size_t workc_min = cndb->cndb_workc + cndb->cndb_workc_margin;

    if (new_entries < workc_min)
        return;

    if (new_entries < cndb->cndb_keepc)
        return;

    if (new_entries < cndb->cndb_min_entries)
        return;

    CNDB_LOG(
        0, cndb, HSE_DEBUG, " old entries %lu -> new entries %lu", cndb->cndb_entries, new_entries);

    /* if we fail to shrink, cndb remains unchanged and we can continue */
    cndb_realloc(cndb, new_entries);
}

/* PRIVATE */
merr_t
cndb_grow(struct cndb *cndb, size_t capreq)
{
    size_t count, new_entries;
    size_t new_capreq;

    count = cndb->cndb_workc + cndb->cndb_keepc;
    assert(count <= cndb->cndb_entries);

    if (count == cndb->cndb_entries) {
        merr_t err;

        new_entries = (count * 3) / 2;
        err = cndb_realloc(cndb, new_entries);
        if (ev(err))
            return err;

        CNDB_LOG(0, cndb, HSE_DEBUG, " grew entries from %lu to %lu\n", count, new_entries);
    }

    /* MDC grow not needed */
    if (capreq == 0)
        return 0;

    if (capreq < cndb->cndb_captgt)
        return 0;

    /* [HSE_REVISIT] we want this growth to be small enough to have a chance
     * of succeeding but large enough to not need to grow again soon
     */
    new_capreq = (capreq * 3) / 2;
    return ev(cndb_mdc_grow(cndb, new_capreq));
}

/* PRIVATE */
merr_t
cndb_cnv_get(struct cndb *cndb, u64 cnid, struct cndb_cn **cn_out)
{
    int             i;
    struct cndb_cn *cn;
    merr_t          err = 0;

    if (!cndb) {
        err = merr(EINVAL);
        hse_alog(HSE_ERR "%s: cndb unspecified", __func__);
        return err;
    }

    for (i = 0; i < cndb->cndb_cnc; i++) {
        cn = cndb->cndb_cnv[i];
        if (cn && cn->cn_cnid == cnid) {
            if (cn_out)
                *cn_out = cn;
            return 0;
        }
    }

    err = merr(ENOENT);
    CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu not found", (ulong)cnid);

    return err;
}

/* PRIVATE */
merr_t
cndb_cnv_blob_set(struct cndb *cndb, struct cndb_cn *cn, size_t metasz, void *meta)
{
    merr_t err = 0;
    size_t newsz = sizeof(struct cndb_info_omf) + metasz;
    void * p; /* because checkfiles said so */

    if (newsz != cn->cn_cbufsz) {
        p = realloc(cn->cn_cbuf, newsz);
        if (!p) {
            err = merr(ENOMEM);
            CNDB_LOG(err, cndb, HSE_ERR, " cannot adopt metadata (%zd)", metasz);
            return err;
        }
        cn->cn_cbuf = p;
        cn->cn_cbufsz = newsz;
    }

    if (meta)
        memcpy(cn->cn_cbuf->cninfo_meta, meta, metasz);

    return 0;
}

/* Create a new cndb_cn and add to cndb_cnv */
/* PRIVATE */
merr_t
cndb_cnv_add(
    struct cndb *       cndb,
    u32                 flags,
    struct kvs_cparams *cp,
    u64                 cnid,
    const char *        name,
    size_t              metasz,
    void *              meta)
{
    struct cndb_cn *cn = NULL;
    int             i;
    merr_t          err = 0;
    bool            update = false;

    /* failed kvs add or updated meta results in superceded record */
    for (i = 0; i < cndb->cndb_cnc; i++) {
        cn = cndb->cndb_cnv[i];
        if (cn->cn_cnid == cnid) {
            update = true;
            goto update_entry;
        }
    }

    if (cndb->cndb_cnc == NELEM(cndb->cndb_cnv)) {
        err = merr(ENFILE);
        CNDB_LOG(err, cndb, HSE_ERR, " cannot add cn %s", name);
        return err;
    }

    cn = calloc(1, sizeof(*cn));
    if (!cn) {
        err = merr(ENOMEM);
        CNDB_LOG(err, cndb, HSE_ERR, " cannot add cn %s", name);
        return err;
    }

update_entry:
    cn->cn_cp = *cp;

    cn->cn_flags = flags;
    cn->cn_cnid = cnid;
    strlcpy(cn->cn_name, name, sizeof(cn->cn_name));

    err = cndb_cnv_blob_set(cndb, cn, metasz, meta);
    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " cannot add cn %s", name);

    if (!update) {
        if (err)
            free(cn);
        else
            cndb->cndb_cnv[cndb->cndb_cnc++] = cn;
    }

    return err;
}

/* drop a cndb_cn from cndb_cnv */
/* PRIVATE */
merr_t
cndb_cnv_del(struct cndb *cndb, int idx)
{
    int c;

    assert(idx >= 0 && idx < cndb->cndb_cnc);

    free(cndb->cndb_cnv[idx]->cn_cbuf);
    free(cndb->cndb_cnv[idx]);
    cndb->cndb_cnv[idx] = NULL;

    c = cndb->cndb_cnc - idx - 1;
    assert(c >= 0);
    if (c > 0)
        memmove(&cndb->cndb_cnv[idx], &cndb->cndb_cnv[idx + 1], c * sizeof(struct cndb_cn *));
    cndb->cndb_cnv[--cndb->cndb_cnc] = NULL;

    return 0;
}

/* PRIVATE */
merr_t
cndb_import_md(struct cndb *cndb, struct cndb_hdr_omf *buf, union cndb_mtu **mtu)
{
    int             typ = omf_cnhdr_type((struct cndb_hdr_omf *)buf);
    merr_t          err = 0;
    union cndb_mtu *lmtu = NULL; /* local mtu */

    *mtu = NULL;
    if (HSE_UNLIKELY(typ == CNDB_TYPE_VERSION)) {
        err = merr(EPROTO);
        CNDB_LOG(err, cndb, HSE_ERR, " bad preamble (type %d)", typ);
        return err;
    }

    err = cndb_record_unpack(cndb->cndb_version, buf, &lmtu);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " bad record (type %d)", typ);
        free(lmtu);
        return err;
    }

    if (typ == CNDB_TYPE_INFO) {
        struct cndb_info * mti = &lmtu->i;
        struct kvs_cparams cp = {
            .cp_fanout = 1 << mti->mti_fanout_bits,
            .cp_pfx_len = mti->mti_prefix_len,
            .cp_sfx_len = mti->mti_sfx_len,
            .cp_pfx_pivot = mti->mti_prefix_pivot,
        };

        err = cndb_cnv_add(
            cndb,
            mti->mti_flags,
            &cp,
            mti->mti_cnid,
            mti->mti_name,
            mti->mti_metasz,
            mti->mti_meta);
        if (err)
            CNDB_LOG(err, cndb, HSE_ERR, " cn %s adoption failed", mti->mti_name);
        free(lmtu);
        return err;
    }

    /* This cn is removed, recovery will be handled during cndb_compact() */
    if (typ == CNDB_TYPE_INFOD) {
        struct cndb_cn *cn = NULL;

        err = cndb_cnv_get(cndb, lmtu->i.mti_cnid, &cn);
        free(lmtu);
        if (err) {
            CNDB_LOG(err, cndb, HSE_ERR, " cn %s already deleted", lmtu->i.mti_name);
            return err;
        }

        /* [HSE_REVISIT] cndb_compact() will enforce the limit that
         * only one kvs can be removed at a time, but there is an
         * opportunity to enforce this limit earlier.
         */
        cn->cn_removed = true;
        return 0;
    }

    if (typ == CNDB_TYPE_META)
        cndb->cndb_seqno = max(cndb->cndb_seqno, lmtu->e.mte_seqno_max);

    if (cndb->cndb_workc >= cndb->cndb_entries) {
        err = cndb_grow(cndb, 0);
        if (err) {
            CNDB_LOG(err, cndb, HSE_ERR, " table full");
            free(lmtu);
            return err;
        }
    }

    cndb->cndb_workv[cndb->cndb_workc++] = lmtu;
    *mtu = lmtu;

    return 0;
}

/* PRIVATE */
u64
mtxcnid(union cndb_mtu *mtu)
{
    switch (mtu->h.mth_type) {
        case CNDB_TYPE_TXC:
            return mtu->c.mtc_cnid;
        case CNDB_TYPE_TXM:
            return mtu->m.mtm_cnid;
        case CNDB_TYPE_TXD:
            return mtu->d.mtd_cnid;
        case CNDB_TYPE_ACK:
            return mtu->a.mta_cnid;
        default:
            return 0;
    }
}

/* PRIVATE */
u64
mtxtag(union cndb_mtu *mtu)
{
    switch (mtu->h.mth_type) {
        case CNDB_TYPE_ACK:
            return mtu->a.mta_tag;
        case CNDB_TYPE_TXC:
            return mtu->c.mtc_tag;
        case CNDB_TYPE_TXM:
            return mtu->m.mtm_tag;
        case CNDB_TYPE_TXD:
            return mtu->d.mtd_tag;
        default:
            return 0;
    }
}

/* PRIVATE */
u64
mtxid(union cndb_mtu *mtu)
{
    switch (mtu->h.mth_type) {
        case CNDB_TYPE_TX:
            return mtu->x.mtx_id;
        case CNDB_TYPE_ACK:
            return mtu->a.mta_txid;
        case CNDB_TYPE_NAK:
            return mtu->n.mtn_txid;
        case CNDB_TYPE_TXC:
            return mtu->c.mtc_id;
        case CNDB_TYPE_TXM:
            return mtu->m.mtm_id;
        case CNDB_TYPE_TXD:
            return mtu->d.mtd_id;
        default:
            return 0;
    }
}

/* PRIVATE */
int
cndb_cmp(const void *a, const void *b)
{
    union cndb_mtu *aa = *(void **)a;
    union cndb_mtu *bb = *(void **)b;
    int             rc;

    /* order records by txid, then by type then by tag */
    rc = mtxid(aa) - mtxid(bb);

    if (!rc) {

        rc = aa->h.mth_type - bb->h.mth_type;
        if (!rc)
            rc = mtxtag(aa) - mtxtag(bb);
    }

    return rc;
}

/* PRIVATE */
merr_t
cndb_tagalloc(struct cndb *cndb, struct cndb_txc *txc, struct cndb_tx *tx, bool full)
{
    struct cndb_idx *p;
    merr_t           err = 0;

    if (cndb->cndb_tagc >= cndb->cndb_entries) {
        err = merr(EMLINK);
        CNDB_LOG(err, cndb, HSE_ERR, " too many tags");
        return err;
    }

    p = calloc(1, sizeof(*p));
    if (!p) {
        err = merr(ENOMEM);
        CNDB_LOG(err, cndb, HSE_ERR, " allocation failed");
        return err;
    }

    p->cdx_tag = txc->mtc_tag;
    p->cdx_tx = tx;
    p->cdx_txc = txc;
    p->cdx_full = full;

    cndb->cndb_tagv[cndb->cndb_tagc++] = p;

    return err;
}

static int
idxcmp(u64 *t, const struct cndb_idx **p)
{
    return *t - (*p)->cdx_tag;
}

static struct cndb_idx **
idxfind(struct cndb *cndb, u64 tag)
{
    struct cndb_idx **p;

    p = bsearch(&tag, cndb->cndb_tagv, cndb->cndb_tagc, sizeof(struct cndb_idx *), (void *)idxcmp);

    return p;
}

/* PRIVATE */
merr_t
cndb_tagack(struct cndb *cndb, u64 tag, struct cndb_ack *ack)
{
    struct cndb_idx **p;
    merr_t            err = 0;

    p = idxfind(cndb, tag);
    if (!p) {
        err = merr(EIDRM);
        CNDB_LOGTX(err, cndb, mtxid((void *)ack), HSE_ERR, " extinct tag %lu", (ulong)tag);
        return err;
    }

    (*p)->cdx_ack = ack;

    return 0;
}

/* PRIVATE */
merr_t
cndb_tagmeta(struct cndb *cndb, struct cndb_txm *txm)
{
    struct cndb_idx **p;
    u64               tag = txm->mtm_tag;
    merr_t            err = 0;

    p = idxfind(cndb, tag);
    if (!p) {
        err = merr(EIDRM);
        CNDB_LOGTX(err, cndb, mtxid((void *)txm), HSE_ERR, " extinct tag %lu", (ulong)tag);
        return err;
    }

    (*p)->cdx_txm = txm;

    return err;
}

/* PRIVATE */
merr_t
cndb_tagdel(struct cndb *cndb, u64 tag)
{
    struct cndb_idx **p;
    merr_t            err = 0;

    p = idxfind(cndb, tag);
    if (!p) {
        err = merr(EL2NSYNC);
        CNDB_LOG(err, cndb, HSE_ERR, " extinct tag %lu", (ulong)tag);
        return err;
    }

    if (!(*p)->cdx_tx) {
        err = merr(EIDRM);
        CNDB_LOG(err, cndb, HSE_ERR, " tag %lu metadata missing", (ulong)tag);
        return err;
    }

    /* mark this kvset as removed from the tx */
    (*p)->cdx_tx->mtx_nc--;
    (*p)->cdx_txc->mtc_id = 0; /* mark txc as transient */
    (*p)->cdx_txm->mtm_id = 0; /* mark txm as transient */

    if (((*p)->cdx_tx->mtx_nc == 0) && ((*p)->cdx_tx->mtx_nd == 0)) {
        if ((*p)->cdx_full) {
            (*p)->cdx_tx->mtx_id = 0;    /* mark tx as transient */
            (*p)->cdx_ack->mta_txid = 0; /* mark ack as transient */
        }
    }

    (*p)->cdx_tx = NULL;
    (*p)->cdx_txc = NULL;
    (*p)->cdx_txm = NULL;
    (*p)->cdx_ack = NULL;

    return err;
}

static merr_t
cndb_drop_mtx(struct cndb *cndb, union cndb_mtu *mtu, struct cndb_tx *txp)
{
    merr_t err = 0;

    switch (mtu->h.mth_type) {

        case CNDB_TYPE_TXC:
            txp->mtx_nc--;
            mtu->c.mtc_keepvbc = 0; /* delete all mblocks */
            err = cndb_blkdel(cndb, mtu, txp->mtx_id);
            break;
        case CNDB_TYPE_TXD:
            txp->mtx_nd--;
            break;
        default:
            break;
    }

    return err;
}

static merr_t
md_keep(struct cndb *cndb, int from, int to);

struct txstate {
    int  ackd;
    int  c;
    int  m;
    int  d;
    bool nak;
    bool ackc;
};

/* PRIVATE */
merr_t
cndb_blklist_add(struct cndb *cndb, u64 txid, struct blk_list *blks, u32 c, u64 *p)
{
    merr_t err = 0;
    u32    bx;

    for (bx = 0; bx < c; bx++, p++) {
        CNDB_LOGTX(0, cndb, txid, HSE_NOTICE, " un-acked mblock %lx", (ulong)*p);
        err = blk_list_append(blks, *p);
        if (err) {
            CNDB_LOGTX(err, cndb, txid, HSE_ERR, " mblock %lx blklist append failed", (ulong)*p);
            break;
        }
    }

    return err;
}

/* PRIVATE */
merr_t
cndb_blkdel(struct cndb *cndb, union cndb_mtu *mtu, u64 txid)
{
    struct blk_list blks;
    u32             bx;
    merr_t          err = 0;
    u64 *           p;
    u32             c;

    struct cndb_txd *txd = (void *)mtu;
    struct cndb_txc *txc = (void *)mtu;

    enum { KBLK, VBLK } pass;

    if (cndb->cndb_rdonly)
        return 0;

    assert(mtu->h.mth_type == CNDB_TYPE_TXD || mtu->h.mth_type == CNDB_TYPE_TXC);

    blk_list_init(&blks);

    if (mtu->h.mth_type == CNDB_TYPE_TXD) {
        p = (void *)&txd[1];
        c = txd->mtd_n_oids;
    } else {
        p = (void *)&txc[1];
        c = txc->mtc_kcnt;
    }

    for (pass = KBLK; pass <= VBLK; pass++) {
        err = cndb_blklist_add(cndb, txid, &blks, c, p);
        if (ev(err, HSE_ERR))
            goto done;

        if (mtu->h.mth_type != CNDB_TYPE_TXC)
            break;

        /* Append the vblocks to the list, skipping the ones to keep */
        p += c + txc->mtc_keepvbc;
        c = txc->mtc_vcnt - txc->mtc_keepvbc;
    }

    for (bx = 0; !err && bx < blks.n_blks; ++bx) {
        struct mblock_props props = { 0 };

        err = mpool_mblock_props_get(cndb->cndb_ds, blks.blks[bx].bk_blkid, &props);
        if (err) {
            if (merr_errno(err) != ENOENT) {
                CNDB_LOGTX(
                    err,
                    cndb,
                    txid,
                    HSE_ERR,
                    "block %lx delete failed",
                    (ulong)blks.blks[bx].bk_blkid);
                goto done;
            }

            CNDB_LOGTX(
                0, cndb, txid, HSE_NOTICE, "extinct block %lx ", (ulong)blks.blks[bx].bk_blkid);
            err = 0;
            continue;
        }

        CNDB_LOGTX(
            0,
            cndb,
            txid,
            HSE_NOTICE,
            " %s block %lx",
            (props.mpr_iscommitted) ? "delete" : "abort",
            (ulong)blks.blks[bx].bk_blkid);

        if (props.mpr_iscommitted)
            err = delete_mblock(cndb->cndb_ds, &blks.blks[bx]);
        else
            err = abort_mblock(cndb->cndb_ds, &blks.blks[bx]);

        if (err) {
            CNDB_LOGTX(
                err,
                cndb,
                txid,
                HSE_ERR,
                "block %lx %s failed",
                (ulong)blks.blks[bx].bk_blkid,
                props.mpr_iscommitted ? "delete" : "abort");
            goto done;
        }
    }

done:
    blk_list_free(&blks);
    return err;
}

static merr_t
md_rollforward(struct cndb *cndb, int from, int to, int unseen)
{
    int               c = to - from + unseen;
    int               i, j;
    union cndb_mtu ** mtud = NULL;
    union cndb_mtu ** mtua;
    union cndb_mtu *  mtu;
    int               d, seenacks;
    int               txrecs;
    struct cndb_ack **ack = NULL;
    int *             dacks = NULL;
    void **           workv;
    size_t            workc;
    int               recoveracks = 0;
    merr_t            err = 0;
    u64               txid = mtxid(cndb->cndb_workv[from]);

    CNDB_LOGTX(0, cndb, txid, HSE_NOTICE, " retry %d deletes", unseen);

    cndb_validate_vector(cndb->cndb_workv, cndb->cndb_workc);
    cndb_validate_vector(cndb->cndb_keepv, cndb->cndb_keepc);

    /* There are (to - from) records in the tx, with (unseen) missing acks.
     * We greedily allocate (c = (to - from + unseen)) entries, twice.  The
     * first (c) entries, mtud, will hold the complete set of TXD
     * records.  The second (c) entries, mtua, will first hold any
     * extant ACK-D records.  Later, mtua is re-used to reconstruct the full
     * transaction, and passed to md_keep() for adoption.
     */
    mtud = calloc(2 * c, sizeof(*mtud));
    if (!mtud) {
        err = merr(ENOMEM);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        return err;
    }
    mtua = mtud + c;

    dacks = calloc(c, sizeof(int));
    if (!dacks) {
        err = merr(ENOMEM);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        goto done;
    }

    for (i = from, d = 0, seenacks = 0; i < to; i++) {
        mtu = cndb->cndb_workv[i];

        if (mtu->h.mth_type == CNDB_TYPE_TXD)
            mtud[d++] = mtu;

        if (mtu->h.mth_type == CNDB_TYPE_ACK && mtu->a.mta_type == CNDB_ACK_TYPE_D)
            mtua[seenacks++] = mtu;
    }

    cndb_validate_vector(cndb->cndb_workv, cndb->cndb_workc);
    cndb_validate_vector(cndb->cndb_keepv, cndb->cndb_keepc);
    cndb_validate_vector((void **)mtud, d);
    cndb_validate_vector((void **)mtua, seenacks);

    for (i = 0; i < d; i++)
        for (j = 0; j < seenacks && dacks[i] == 0; j++)
            if (mtud[i]->d.mtd_tag == mtua[j]->a.mta_tag)
                dacks[i] = 1;

    /* 1) save cndb_workv, cndb_workc
     * 2) construct a complete transaction in mtua
     * 3) substitute mtua and count for cndb_workv, cndb_workc
     * 4) call md_keep
     * 5) restore cndb_workv, cndb_workc
     * 6) if md_keep fails, return failure
     * 7) loop through (mtud, dacks) deleting un-acked mblocks
     * 8) do not ack, because we roll the log over after recovery
     * 9) NULL from:to in workv
     */

    /* Step 1 */
    workv = cndb->cndb_workv;
    workc = cndb->cndb_workc;

    /* Step 2 */
    memset(mtua, 0, c * sizeof(*mtua));
    for (i = from, txrecs = 0; i < to; i++)
        mtua[txrecs++] = workv[i];

    ack = calloc(unseen, sizeof(*ack));
    if (ev(!ack))
        goto done;

    for (i = 0; i < d && recoveracks < unseen; i++) {
        if (dacks[i])
            continue;

        ack[recoveracks] = calloc(1, sizeof(struct cndb_ack));
        if (!ack[recoveracks]) {
            err = merr(ENOMEM);
            CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
            goto done;
        }

        ack[recoveracks]->hdr.mth_type = CNDB_TYPE_ACK;
        ack[recoveracks]->mta_type = CNDB_ACK_TYPE_D;
        ack[recoveracks]->mta_txid = mtud[i]->d.mtd_id;
        ack[recoveracks]->mta_tag = mtud[i]->d.mtd_tag;

        mtua[txrecs++] = (union cndb_mtu *)ack[recoveracks++];
    }

    /* we started with (to - from) records and added (unseen) acks.
     * (txrecs) therefore equals (c), calculated on entry
     */
    assert(c == txrecs);
    cndb_validate_vector((void **)mtua, txrecs);

    CNDB_LOGTX(0, cndb, txid, HSE_NOTICE, ", %d records", txrecs);
    /* Step 3 */
    cndb->cndb_workv = (void **)mtua;
    cndb->cndb_workc = txrecs;

    /* Step 4 */
    qsort(
        cndb->cndb_workv,
        cndb->cndb_workc,
        sizeof(cndb->cndb_workv[0]),
        cndb_cmp); /* order records so md_keep() can validate */

    cndb_validate_vector((void **)mtua, txrecs);
    cndb_validate_vector(cndb->cndb_workv, cndb->cndb_workc);
    cndb_validate_vector(cndb->cndb_keepv, cndb->cndb_keepc);

    /* We substituted mtua for workv, and want to adopt items [0:txrecs] */
    err = md_keep(cndb, 0, txrecs);

    /* Step 5 */
    cndb->cndb_workv = workv;
    cndb->cndb_workc = workc;

    cndb_validate_vector((void **)mtua, txrecs);
    cndb_validate_vector(cndb->cndb_workv, cndb->cndb_workc);
    cndb_validate_vector(cndb->cndb_keepv, cndb->cndb_keepc);

    /* Step 6 */
    if (err) {
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, " roll forward failed");
        goto done;
    }

    /* Step 7 */
    for (i = 0; i < d; i++)
        if (!dacks[i]) {
            err = cndb_blkdel(cndb, mtud[i], txid);
            /* cndb_blkdel() logs verbosely, count only */
            if (ev(err, HSE_ERR))
                goto done;
        }

    cndb_validate_vector(cndb->cndb_workv, cndb->cndb_workc);
    cndb_validate_vector(cndb->cndb_keepv, cndb->cndb_keepc);

    /* Step 8 is an explicit NOP */
    /* Step 9 */
    for (i = from; i < to; i++)
        workv[i] = NULL;

    cndb_validate_vector(cndb->cndb_workv, cndb->cndb_workc);
    cndb_validate_vector(cndb->cndb_keepv, cndb->cndb_keepc);
done:
    /* On success, cndb has adopted each element */
    if (ack && err)
        for (i = 0; i < recoveracks; i++)
            free(ack[i]);
    free(ack);
    free(mtud);
    free(dacks);

    if (err)
        cndb->cndb_rdonly = true;

    cndb_validate_vector(cndb->cndb_workv, cndb->cndb_workc);
    cndb_validate_vector(cndb->cndb_keepv, cndb->cndb_keepc);
    return err;
}

static merr_t
md_rollback(struct cndb *cndb, int from, int to)
{
    int             i;
    union cndb_mtu *mtu;
    merr_t          err = 0;
    /* we will roll backward
     * 1) loop [from:to].  for each c record:
     *        delete kblocks
     *        if (!keepvbc)
     *              delete vblocks
     * 2) deallocate each record and remove it from workv.
     */

    CNDB_LOGTX(0, cndb, mtxid(cndb->cndb_workv[from]), HSE_NOTICE, " rollback");

    for (i = from; i < to; i++) {
        mtu = cndb->cndb_workv[i];

        if (mtu->h.mth_type == CNDB_TYPE_TXC) {
            /* cndb_blkdel() logs verbosely, count only */
            err = cndb_blkdel(cndb, mtu, mtxid(mtu));
            if (ev(err, HSE_ERR))
                break;
        }

        free(mtu);
        cndb->cndb_workv[i] = NULL;
    }

    if (err)
        cndb->cndb_rdonly = true;

    return err;
}

static merr_t
md_reap(struct cndb *cndb, int from, int to, struct txstate *needed, struct txstate *seen)
{
    u64    txid;
    merr_t err = 0;

    txid = mtxid(cndb->cndb_workv[from]);

    if (seen->ackc) {
        int unseen;

        /* We want to roll forward.  We require that needed and seen
         * match except for the number of ackd's.  If that isn't true
         * and we have an ack-C, kvdb didn't follow the protocol and we
         * cannot recover.
         */
        if (seen->c != needed->c || seen->m != needed->m || seen->nak || seen->d != needed->d) {
            err = merr(EPROTO);
            CNDB_LOGTX(err, cndb, txid, HSE_ERR, " unrecoverable");
            return err;
        }

        unseen = seen->d - seen->ackd;
        CNDB_LOGTX(0, cndb, txid, HSE_NOTICE, " recoverable(%d)", unseen);

        err = md_rollforward(cndb, from, to, unseen);
        if (err)
            CNDB_LOGTX(err, cndb, txid, HSE_ERR, " recovery failed ");
        return err;
    }

    CNDB_LOGTX(0, cndb, txid, HSE_NOTICE, " incomple, rollback");

    err = md_rollback(cndb, from, to);
    if (err)
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, " rollback failed");

    return err;
}

void
cndb_get_ingestid(struct cndb *cndb, struct cndb_tx *tx)
{
    struct cndb_ingest_replay *ing_rep;
    u64                        ingestid;
    u64                        txid;

    ing_rep = &cndb->cndb_ing_rep;
    ingestid = tx->mtx_ingestid;
    txid = tx->mtx_id;
    if (ingestid == CNDB_INVAL_INGESTID)
        return;

    if ((ing_rep->cir_ingestid == CNDB_INVAL_INGESTID) || (txid > ing_rep->cir_txid)) {
        ing_rep->cir_ingestid = ingestid;
        ing_rep->cir_txid = txid;
    }
}

static merr_t
md_keep(struct cndb *cndb, int from, int to)
{
    int    c = to - from;
    int    i;
    u64 *  tc = NULL;
    u64 *  tm = NULL;
    u64 *  td = NULL;
    u64 *  ta = NULL;
    int    nc = 0, nm = 0, nd = 0, na = 0;
    merr_t err = 0;

    struct cndb_tx * txp = NULL;
    struct cndb_ack *cack = NULL;

    void **workv = cndb->cndb_workv;
    void **keepv = cndb->cndb_keepv;
    u64    txid = mtxid(cndb->cndb_workv[from]);

    /* The simplest transaction is TX, TXD, ACKD */
    if (c <= 2) {
        err = merr(EPROTO);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        return err;
    }

    tc = calloc(c, sizeof(void *));
    tm = calloc(c, sizeof(void *));
    td = calloc(c, sizeof(void *));
    ta = calloc(c, sizeof(void *));

    if (!tc || !tm || !td || !ta) {
        err = merr(ENOMEM);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        goto errout;
    }

    for (i = from; i < to; i++) {
        union cndb_mtu *mtu = workv[i];

        switch (mtu->h.mth_type) {
            case CNDB_TYPE_TX:
                txp = workv[i];
                cndb_get_ingestid(cndb, txp);
                break;
            case CNDB_TYPE_TXC:
                if (mtu->c.mtc_kcnt == 0 && mtu->c.mtc_vcnt == 0) {
                    /* mark empty kvset for removal */
                    txp->mtx_nc--;
                    mtu->c.mtc_id = 0;
                    break;
                }

                tc[nc++] = mtu->c.mtc_tag;
                err = cndb_tagalloc(cndb, &mtu->c, txp, true);
                if (err) {
                    CNDB_LOGTX(
                        err,
                        cndb,
                        txid,
                        HSE_ERR,
                        " tag %lu "
                        "index failed",
                        (ulong)tc[nc - 1]);
                    goto errout;
                }

                break;
            case CNDB_TYPE_TXD:
                txp->mtx_nd--;
                if (!txp->mtx_nd && !txp->mtx_nc) {
                    txp->mtx_id = 0;
                    cack->mta_txid = 0;
                }
                mtu->d.mtd_id = 0; /* don't keep txd */
                td[nd++] = mtu->d.mtd_tag;
                break;
            case CNDB_TYPE_TXM:
                err = cndb_tagack(cndb, tc[nm], cack);
                if (err) {
                    CNDB_LOGTX(
                        err,
                        cndb,
                        txid,
                        HSE_ERR,
                        " tag %lu "
                        "ack failed",
                        (ulong)tc[nm]);
                    goto errout;
                }

                tm[nm++] = mtu->m.mtm_tag;
                err = cndb_tagmeta(cndb, &mtu->m);
                if (err) {
                    CNDB_LOGTX(
                        err,
                        cndb,
                        txid,
                        HSE_ERR,
                        " tag %lu "
                        "meta failed",
                        (ulong)tm[nm - 1]);
                    goto errout;
                }

                break;
            case CNDB_TYPE_ACK:
                if (mtu->a.mta_type == CNDB_ACK_TYPE_D) {
                    assert(mtu->a.mta_txid);
                    ta[na++] = mtu->a.mta_tag;
                    err = cndb_tagdel(cndb, mtu->a.mta_tag);
                    mtu->a.mta_txid = 0; /* don't keep ack-D */
                    if (err) {
                        CNDB_LOGTX(
                            err, cndb, txid, HSE_ERR, " tag %lu delete failed", (ulong)ta[na - 1]);
                        goto errout;
                    }
                } else {
                    cack = &mtu->a;
                }
                break;
            default:
                break;
        }

        keepv[cndb->cndb_keepc++] = workv[i];
        workv[i] = NULL;
    }

    if (nc != nm || nd != na) {
        err = merr(EPROTO);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        goto errout;
    }

    /* caller verified that we have the requisite number of tags, we should
     * verify the tags actually match.
     *
     * this is a hard error:  it isn't possible to recover mismatched tags,
     * this can only happen if the log is corrupted or if the messages
     * were corrupted by a logic error on the way in.
     *
     * cndb_replay() will mark cndb_rdonly if cndb_compact fails.
     */
    if (memcmp(tc, tm, nc * sizeof(*tc))) {
        err = merr(EBADMSG);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        goto errout;
    }

    if (memcmp(td, ta, nd * sizeof(*td))) {
        err = merr(EBADMSG);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        goto errout;
    }

errout:
    free(tc);
    free(tm);
    free(td);
    free(ta);

    return err;
}

/* md_partial_keep() checks if the incomplete transaction has an ack-C or not.
 * If it does not, leave the transaction as is in workv. But if it does, add an
 * entry to cndb->cndb_tagv[]. So if a kvset created in the incomplete txn is
 * deleted by a subsequent completed txn, the kvset to be deleted can be found.
 */
static merr_t
md_partial_keep(struct cndb *cndb, int from, int to, struct txstate *needed, struct txstate *seen)
{
    int    c = to - from;
    int    i;
    int    nc = 0, nm = 0;
    u64 *  tc = NULL;
    u64 *  tm = NULL;
    merr_t err = 0;

    struct cndb_tx * txp = NULL;
    struct cndb_ack *cack = NULL;

    void **workv = cndb->cndb_workv;
    u64    txid = mtxid(cndb->cndb_workv[from]);

    if (!seen->ackc)
        return 0; /* nothing to do */

    /* The simplest transaction is TX, TXC, ACKC */
    if (c <= 2) {
        err = merr(EPROTO);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        return err;
    }

    tc = calloc(c, sizeof(void *));
    tm = calloc(c, sizeof(void *));

    if (!tc || !tm) {
        err = merr(ENOMEM);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        goto errout;
    }

    for (i = from; i < to; i++) {
        union cndb_mtu *mtu = workv[i];

        switch (mtu->h.mth_type) {
            case CNDB_TYPE_TX:
                txp = workv[i];
                break;
            case CNDB_TYPE_TXC:
                if (mtu->c.mtc_kcnt == 0 && mtu->c.mtc_vcnt == 0)
                    break;

                tc[nc++] = mtu->c.mtc_tag;
                err = cndb_tagalloc(cndb, &mtu->c, txp, false);
                if (err) {
                    CNDB_LOGTX(
                        err,
                        cndb,
                        txid,
                        HSE_ERR,
                        " tag %lu "
                        "index failed",
                        (ulong)tc[nc - 1]);
                    goto errout;
                }
                break;
            case CNDB_TYPE_TXD:
                break;
            case CNDB_TYPE_TXM:
                err = cndb_tagack(cndb, tc[nm], cack);
                if (err) {
                    CNDB_LOGTX(
                        err,
                        cndb,
                        txid,
                        HSE_ERR,
                        " tag %lu "
                        "ack failed",
                        (ulong)tc[nm]);
                    goto errout;
                }

                tm[nm++] = mtu->m.mtm_tag;
                err = cndb_tagmeta(cndb, &mtu->m);
                if (err) {
                    CNDB_LOGTX(
                        err,
                        cndb,
                        txid,
                        HSE_ERR,
                        " tag %lu "
                        "meta failed",
                        (ulong)tm[nm - 1]);
                    goto errout;
                }
                break;
            case CNDB_TYPE_ACK:
                if (mtu->a.mta_type != CNDB_ACK_TYPE_D)
                    cack = &mtu->a;
                break;
            default:
                break;
        }
    }

    if (memcmp(tc, tm, nc * sizeof(*tc))) {
        err = merr(EBADMSG);
        CNDB_LOGTX(err, cndb, txid, HSE_ERR, "");
        goto errout;
    }

errout:
    free(tc);
    free(tm);

    return err;
}

static merr_t
keep_or_reap(struct cndb *cndb, struct txstate *needed, struct txstate *seen, int from, int to)
{
    /* [HSE_REVISIT] multi-cn ingest imposes disadvantageous semantics on
     * recovery.  It is not possible to run recovery when any kvs is open,
     * because it is not known whether any records absent from workv/keepv
     * are still in-flight or whether they are truly missing.
     *
     * Even if we could discern whether a particular un-acked C record goes
     * to a closed kvs, it is inappropriate to roll a TX back while any kvs
     * involved in the TX remains open.  It is also inappropriate to roll
     * such a TX forward. In either case, there may be work in-flight that
     * recovery would duplicate or contradict.
     *
     * It is important to be aware of this limitation when defining fault
     * injection tests, but in live systems it is unlikely to be a problem
     * for the following reasons:
     *
     * 1) In an actual logging fault (e.g. a transient bus error) we return
     *    an error from the cndb layer. The application must either handle
     *    that error or fail itself.
     * 2) In an actual table insertion failure (e.g., ENOMEM) we return an
     *    error from the cndb layer. The application must either handle that
     *    error or fail itself.
     * 3) In a fault injection scenario which drops only the log message,
     *    selective kvs open/close isn't a problem because complete
     *    transactions (needing no recovery) are in-memory.
     * 4) In a fault injection scenario which deliberatly corrupts the log
     *    message on media, selective kvs open/close isn't a problem because
     *    complete transactions (needing no recovery) are in-memory.
     * 5) In a fault injection scenario which silently drops both the log
     *    message and table entry without an error, selective kvs open/close
     *    presents a challange. CNDB cannot distinguish this injected fault
     *    (a missing message in its internal tables) from activity that is
     *    in flight at the next compaction. This is a wholly contrived case,
     *    and will not happen without deliberate fault injection or program
     *    defect.
     * 6) If case (5) occurred because of some program defect, the kvs in
     *    question will seem to be missing a key until it is recovered.
     *    After the next kvdb open (i.e. recovery), all of the salvageable
     *    kvsets will be recovered and be visible again.
     */

    /* md_keep(), md_partial_keep(), and md_reap() log plenty, count only */
    if (memcmp(needed, seen, sizeof(*needed)))
        return ev(
            (cndb->cndb_refcnt) ? md_partial_keep(cndb, from, to, needed, seen)
                                : md_reap(cndb, from, to, needed, seen),
            HSE_ERR);
    else
        return ev(md_keep(cndb, from, to), HSE_ERR);
}

static void
tagv_wipe(struct cndb *cndb)
{
    int i;

    for (i = 0; i < cndb->cndb_tagc; i++) {
        free(cndb->cndb_tagv[i]);
        cndb->cndb_tagv[i] = NULL;
    }

    cndb->cndb_tagc = 0;
}

/* PRIVATE */
void
cndb_defragment(struct cndb *cndb)
{
    int i, j;

    /* defragment keepv */
    for (i = 0, j = 0; i < cndb->cndb_keepc; i++) {
        if (cndb->cndb_keepv[i] == NULL)
            continue;

        if (mtxid(cndb->cndb_keepv[i]) == 0) {
            free(cndb->cndb_keepv[i]);
            cndb->cndb_keepv[i] = NULL;
            continue;
        }
        cndb->cndb_keepv[j++] = cndb->cndb_keepv[i];
    }
    cndb->cndb_keepc = j;

    /* defragment workv */
    for (i = 0, j = 0; i < cndb->cndb_workc; i++) {
        if (cndb->cndb_workv[i] == NULL)
            continue;

        /* Incomplete TXN entries marked for deletion */
        if (mtxid(cndb->cndb_workv[i]) == 0) {
            free(cndb->cndb_workv[i]);
            cndb->cndb_workv[i] = NULL;
            continue;
        }
        cndb->cndb_workv[j++] = cndb->cndb_workv[i];
    }
    cndb->cndb_workc = j;
}

merr_t
cndb_compact(struct cndb *cndb)
{
    size_t i, j;
    u64    txid;
    merr_t err = 0;

    struct txstate needed;
    struct txstate seen;

    CNDB_LOG(
        0,
        cndb,
        HSE_DEBUG,
        " compact starting, %lu records (%lu/%lu)",
        (ulong)(cndb->cndb_workc + cndb->cndb_keepc),
        (ulong)cndb->cndb_workc,
        (ulong)cndb->cndb_keepc);

    tagv_wipe(cndb);
    cndb->cndb_tagc = 0;

    qsort(cndb->cndb_workv, cndb->cndb_workc, sizeof(cndb->cndb_workv[0]), cndb_cmp);

    memset(&needed, 0, sizeof(needed));
    needed.ackc = true;
    memset(&seen, 0, sizeof(seen));

    txid = 0; /* the first valid txid is 1 */

    for (i = j = 0; i < cndb->cndb_workc; i++) {
        union cndb_mtu *mtu = cndb->cndb_workv[i];

        if (txid != mtxid(mtu)) {
            if (txid) {
                /* keep/reap/partial_keep log sufficiently */
                err = keep_or_reap(cndb, &needed, &seen, j, i);
                if (ev(err, HSE_ERR))
                    goto errout;
            }

            memset(&seen, 0, sizeof(seen));

            /* first rec with new txid is TX else TX is missing */
            if (mtu->h.mth_type != CNDB_TYPE_TX) {
                err = merr(EPROTO);
                CNDB_LOGTX(err, cndb, txid, HSE_ERR, " missing TX start");
                goto errout;
            }

            needed.c = mtu->x.mtx_nc;
            needed.d = mtu->x.mtx_nd;
            needed.m = needed.c;
            needed.ackd = needed.d;
            j = i;
            txid = mtxid(mtu);

            continue;
        }

        switch (mtu->h.mth_type) {
            case CNDB_TYPE_TXC:
                seen.c++;
                if (mtu->c.mtc_kcnt == 0 && mtu->c.mtc_vcnt == 0)
                    needed.m--;
                continue;
            case CNDB_TYPE_TXD:
                seen.d++;
                continue;
            case CNDB_TYPE_TXM:
                seen.m++;
                continue;
            case CNDB_TYPE_NAK:
                seen.nak = true;
                continue;
            case CNDB_TYPE_ACK:
                if (mtu->a.mta_type == CNDB_ACK_TYPE_D) {
                    assert(mtu->a.mta_txid);
                    seen.ackd++;
                } else {
                    seen.ackc = true;
                }
                continue;
            case CNDB_TYPE_META:
                continue;
            default:
                err = merr(EPROTO);
                CNDB_LOGTX(err, cndb, txid, HSE_ERR, " unknown type %d", mtu->h.mth_type);
                goto errout;
        }
    }

    /* check the last record set */
    if (txid) {
        err = keep_or_reap(cndb, &needed, &seen, j, i);
        if (ev(err, HSE_ERR))
            goto errout;
    }

    cndb_defragment(cndb);

errout:
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " compact failed");
    } else {
        CNDB_LOG(
            0,
            cndb,
            HSE_DEBUG,
            " compact finished, %lu records "
            "(%lu/%lu)",
            (ulong)(cndb->cndb_workc + cndb->cndb_keepc),
            (ulong)cndb->cndb_workc,
            (ulong)cndb->cndb_keepc);
        cndb->cndb_compacted = true;
    }

    return err;
}

void
cndb_getref(struct cndb *cndb)
{
    mutex_lock(&cndb->cndb_lock);
    cndb->cndb_refcnt++;
    mutex_unlock(&cndb->cndb_lock);
}

void
cndb_putref(struct cndb *cndb)
{
    mutex_lock(&cndb->cndb_lock);
    cndb->cndb_refcnt--;
    mutex_unlock(&cndb->cndb_lock);
}

static merr_t
cndb_rollover(struct cndb *cndb);

static merr_t
cndb_read(struct cndb *cndb, size_t *len)
{
    merr_t err = 0;
    void * p; /* because checkfiles said so */

    do {
        err = mpool_mdc_read(cndb->cndb_mdc, cndb->cndb_cbuf, cndb->cndb_cbufsz, len);
        if (merr_errno(err) == EOVERFLOW) {
            p = realloc(cndb->cndb_cbuf, *len);
            if (!p) {
                err = merr(ENOMEM);
                CNDB_LOG(err, cndb, HSE_ERR, " buffer realloc (%ld) failed", *len);
                return err;
            }
            cndb->cndb_cbuf = p;
            cndb->cndb_cbufsz = *len;
        }
    } while (merr_errno(err) == EOVERFLOW);

    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " read failed");

    return err;
}

static u64
cndb_ikvdb_seqno_get(struct cndb *cndb)
{
    atomic64_t *p = cndb->cndb_ikvdb_seqno;

    return p ? atomic64_read(p) : 0;
}

merr_t
cndb_replay(struct cndb *cndb, u64 *seqno, u64 *ingestid)
{
    merr_t          err = 0;
    size_t          len = 0;
    u64             otag;
    u64             otxid;
    int             i;
    union cndb_mtu *mtu;

    cndb->cndb_ing_rep.cir_ingestid = CNDB_INVAL_INGESTID;
    cndb->cndb_ing_rep.cir_txid = 0;
    *ingestid = CNDB_INVAL_INGESTID;

    /* First txid is 1 */
    atomic64_set(&cndb->cndb_txid, 1);

    cndb->cndb_keepc = 0;
    cndb->cndb_workc = 0;

    /* First record must be a valid version record */
    err = cndb_read(cndb, &len);
    /* cndb_read() logs sufficiently, count only */
    if (ev(err, HSE_ERR))
        return err;

    if (len == 0) {
        err = merr(ENODATA);
        CNDB_LOG(err, cndb, HSE_ERR, " empty version record");
        return err;
    }

    /*
     * The first record must be the version record and its
     * fields type, version and magic must always be at the same place.
     */
    if (omf_cnhdr_type(cndb->cndb_cbuf) != CNDB_TYPE_VERSION) {
        err = merr(EPROTO);
        CNDB_LOG(err, cndb, HSE_ERR, " missing version record");
        return err;
    }

    if (omf_cnver_magic(cndb->cndb_cbuf) != CNDB_MAGIC) {
        err = merr(EUNATCH);
        CNDB_LOG(err, cndb, HSE_ERR, " bad magic");
        return err;
    }

    cndb->cndb_version = omf_cnver_version(cndb->cndb_cbuf);
    if (cndb->cndb_version > CNDB_VERSION) {
        err = merr(EPROTONOSUPPORT);
        CNDB_LOG(
            err,
            cndb,
            HSE_ERR,
            " media (cndb version %u) is newer"
            " than software (cndb version %u), please update",
            cndb->cndb_version,
            CNDB_VERSION);
        return err;
    }
    if (cndb->cndb_version != CNDB_VERSION) {
        if (cndb->cndb_rdonly)
            CNDB_LOG(
                0,
                cndb,
                HSE_NOTICE,
                " read-only media uses "
                "deprecated cndb version %u, next R/W use will"
                " update to cndb version %u",
                cndb->cndb_version,
                CNDB_VERSION);
        else
            CNDB_LOG(
                0,
                cndb,
                HSE_NOTICE,
                " upgrading media from "
                "cndb version %u to cndb version %u",
                cndb->cndb_version,
                CNDB_VERSION);
    }

    /*
     * Unpack completely the version record.
     */
    cndb_record_unpack(cndb->cndb_version, cndb->cndb_cbuf, &mtu);
    cndb->cndb_captgt = mtu->v.mtv_captgt;
    free(mtu);

    cndb->cndb_high_water = CNDB_HIGH_WATER(cndb);

    cndb->cndb_seqno = cndb_ikvdb_seqno_get(cndb);
    otxid = 0, otag = 0;
    while (1) {
        err = cndb_read(cndb, &len);
        if (len == 0 || ev(err, HSE_ERR))
            break;

        err = cndb_import_md(cndb, cndb->cndb_cbuf, &mtu);
        if (ev(err, HSE_ERR))
            return err;

        /* discover the highest tag in use. */
        if (mtu && mtu->h.mth_type == CNDB_TYPE_TXC) {
            if (otag < mtu->c.mtc_tag)
                otag = mtu->c.mtc_tag;
            continue;
        }

        /* discover the highest txid, and seqno in use. */
        if (mtu && mtu->h.mth_type == CNDB_TYPE_TX) {
            if (cndb->cndb_seqno < mtu->x.mtx_seqno)
                cndb->cndb_seqno = mtu->x.mtx_seqno;
            if (otxid < mtu->x.mtx_id)
                otxid = mtu->x.mtx_id + mtu->x.mtx_nc;
            continue;
        }
    }

    *seqno = cndb->cndb_seqno;

    if (err && merr_errno(err) != ENOMSG) {
        CNDB_LOG(err, cndb, HSE_ERR, " read failed");
        return err;
    }

    if (cndb->cndb_rdonly)
        err = cndb_compact(cndb);
    else
        err = cndb_rollover(cndb);

    if (!err) {
        if (cndb->cndb_workc) {
            /* [HSE_REVISIT] implement more sophisticated workqueue
             * recovery with retries instead
             */
            cndb->cndb_rdonly = true;
            err = merr(EUCLEAN);
            CNDB_LOG(err, cndb, HSE_ERR, "");
        }
    } else {
        CNDB_LOG(err, cndb, HSE_ERR, " %s failed", cndb->cndb_rdonly ? "compact" : "rollover");
    }

    for (i = 0, cndb->cndb_cnid = 0; i < cndb->cndb_cnc; i++)
        if (cndb->cndb_cnid < cndb->cndb_cnv[i]->cn_cnid)
            cndb->cndb_cnid = cndb->cndb_cnv[i]->cn_cnid;

    cndb->cndb_cnid++;

    /* the next txid must always be greater than the highest tag */
    if (otag > otxid)
        otxid = otag;
    atomic64_set(&cndb->cndb_txid, otxid + 1);

    if (err)
        kvdb_health_error(cndb->cndb_kvdb_health, err);
    else
        /*
         * Return the ingestid of the latest successful ingest.
         */
        *ingestid = cndb->cndb_ing_rep.cir_ingestid;

    return err;
}

u64
cndb_seqno(struct cndb *cndb)
{
    return cndb->cndb_seqno;
}

merr_t
cndb_cn_count(struct cndb *cndb, u32 *cnt)
{
    mutex_lock(&cndb->cndb_cnv_lock);
    *cnt = cndb->cndb_cnc;
    mutex_unlock(&cndb->cndb_cnv_lock);

    return 0;
}

merr_t
cndb_cn_blob_get(struct cndb *cndb, u64 cnid, size_t *blobsz, void **blob)
{
    struct cndb_cn *cn = NULL;
    merr_t          err = 0;
    void *          p = NULL;
    size_t          sz = 0;

    if (!cndb || !blobsz || !blob)
        return merr(ev(EINVAL, HSE_ERR));

    mutex_lock(&cndb->cndb_cnv_lock);
    err = cndb_cnv_get(cndb, cnid, &cn);
    mutex_unlock(&cndb->cndb_cnv_lock);

    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu", (ulong)cnid);
        return err;
    }

    if (cn->cn_cbufsz > sizeof(struct cndb_info_omf)) {
        sz = cn->cn_cbufsz - sizeof(struct cndb_info_omf);
        p = calloc(1, sz);
        if (!p) {
            err = merr(ENOMEM);
            CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu", (ulong)cnid);
            return err;
        }

        memcpy(p, &cn->cn_cbuf->cninfo_meta, sz);
    }

    *blob = p;
    *blobsz = sz;

    return 0;
}

merr_t
cndb_cn_blob_set(struct cndb *cndb, u64 cnid, size_t blobsz, void *blob)
{
    struct cndb_cn *cn = NULL;
    merr_t          err = 0;
    size_t          sz;

    struct cndb_info_omf *inf;

    if (!cndb)
        return merr(ev(EINVAL, HSE_ERR));

    mutex_lock(&cndb->cndb_cnv_lock);
    err = cndb_cnv_get(cndb, cnid, &cn);
    mutex_unlock(&cndb->cndb_cnv_lock);

    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu cannot update blob", (ulong)cnid);
        return err;
    }

    err = cndb_cnv_blob_set(cndb, cn, blobsz, blob);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu cannot update blob", (ulong)cnid);
        return err;
    }

    inf = (void *)cn->cn_cbuf;
    sz = cn->cn_cbufsz;
    cndb_info2omf(CNDB_TYPE_INFO, cn, inf);

    /* Even though cNDB has the new metadata in-memory, the caller must
     * retry before proceeding with any updates that require the new
     * metadata persist on media.
     */
    err = cndb_journal(cndb, inf, sz);
    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu metadata update failed", (ulong)cnid);

    return err;
}

merr_t
cndb_cn_info_idx(
    struct cndb *        cndb,
    u32                  idx,
    u64 *                cnid,
    u32 *                flags,
    struct kvs_cparams **cp,
    char *               name,
    size_t               namelen)
{
    merr_t          err = 0;
    struct cndb_cn *cn;

    mutex_lock(&cndb->cndb_cnv_lock);
    if (idx >= cndb->cndb_cnc) {
        err = ev(merr(ESTALE), HSE_ERR);
        goto errout;
    }

    cn = cndb->cndb_cnv[idx];

    /* [HSE_REVISIT] is it useful to provide refcnt or removed? */
    if (cnid)
        *cnid = cn->cn_cnid;
    if (cp)
        *cp = &cn->cn_cp;
    if (flags)
        *flags = cn->cn_flags;
    if (name)
        strlcpy(name, cn->cn_name, namelen);

errout:
    mutex_unlock(&cndb->cndb_cnv_lock);
    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " extinct cn idx %d", idx);
    return err;
}

merr_t
cndb_cn_close(struct cndb *cndb, u64 cnid)
{
    merr_t          err = 0;
    struct cndb_cn *cn = NULL;

    mutex_lock(&cndb->cndb_cnv_lock);
    mutex_lock(&cndb->cndb_lock);
    err = cndb_cnv_get(cndb, cnid, &cn);

    if (ev(err, HSE_ERR))
        goto done;

    if (!cn->cn_refcnt) {
        err = merr(ev(ESTALE, HSE_ERR));
        goto done;
    }

    cn->cn_refcnt--;
done:
    mutex_unlock(&cndb->cndb_lock);
    mutex_unlock(&cndb->cndb_cnv_lock);
    if (err) {
        if (merr_errno(err) == ESTALE)
            CNDB_LOG(
                err, cndb, HSE_ERR, " cn %s cnid %lu already closed", cn->cn_name, (ulong)cnid);
        else
            CNDB_LOG(err, cndb, HSE_ERR, "cnid %lu", (ulong)cnid);
    }
    return err;
}

merr_t
cndb_cn_instantiate(struct cndb *cndb, u64 cnid, void *ctx, cn_init_callback *cb)
{
    int               i, b;
    merr_t            err = 0;
    struct kvset_meta km = {};
    struct cndb_txc * txc = NULL;
    struct cndb_txm * txm = NULL;
    struct cndb_cn *  cn = NULL;
    u32               nk = 0, nv = 0;
    u64 *             kb = NULL, *vb = NULL;

    blk_list_init(&km.km_kblk_list);
    blk_list_init(&km.km_vblk_list);

    mutex_lock(&cndb->cndb_lock);

    err = cndb_cnv_get(cndb, cnid, &cn);

    if (ev(err, HSE_ERR))
        goto done;

    if (cn->cn_refcnt) {
        err = merr(ev(EBUSY, HSE_ERR));
        goto done;
    }

    cn->cn_refcnt++;

    /* Processes which open, close, and re-open cN require a compact.
     */
    if (!cndb->cndb_compacted) {
        if (cndb->cndb_rdonly)
            err = cndb_compact(cndb);
        else
            err = cndb_rollover(cndb);
    }

    if (ev(err, HSE_ERR))
        goto done;

    km.km_capped = cn->cn_flags & CN_CFLAG_CAPPED;
    km.km_restored = true;

    for (i = 0; i < cndb->cndb_tagc; i++) {
        struct cndb_idx *tag;

        /* Reset n_blks in each blk_list instead of calling
         * blk_list_free() to avoid re-allocating on each iteration.
         */
        km.km_kblk_list.n_blks = 0;
        km.km_vblk_list.n_blks = 0;

        tag = cndb->cndb_tagv[i];

        txc = tag->cdx_txc;
        if (!txc)
            continue;

        if (txc->mtc_cnid != cnid)
            continue;

        txm = tag->cdx_txm;

        /* we matched a txc to a txm */
        km.km_dgen = txm->mtm_dgen;
        km.km_compc = txm->mtm_compc;
        km.km_scatter = txm->mtm_scatter;
        km.km_vused = txm->mtm_vused;
        km.km_node_level = txm->mtm_level;
        km.km_node_offset = txm->mtm_offset;

        nk = txc->mtc_kcnt;
        nv = txc->mtc_vcnt;

        kb = (u64 *)&txc[1];
        vb = &kb[nk];

        for (b = 0; b < nk && !err; b++)
            err = blk_list_append(&km.km_kblk_list, kb[b]);

        if (ev(err, HSE_ERR))
            goto done;

        for (b = 0; b < nv && !err; b++)
            err = blk_list_append(&km.km_vblk_list, vb[b]);

        if (ev(err, HSE_ERR))
            goto done;

        err = cb(ctx, &km, txm->mtm_tag);
        if (ev(err, HSE_ERR))
            goto done;
    }

done:
    blk_list_free(&km.km_kblk_list);
    blk_list_free(&km.km_vblk_list);

    mutex_unlock(&cndb->cndb_lock);
    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu instantiation failed", (ulong)cnid);
    return err;
}

static merr_t
cndb_cull_loop(struct cndb *cndb, void **vector, size_t count, u64 drop_cnid)
{
    struct cndb_tx * txp = NULL;
    struct cndb_ack *cack = NULL;
    merr_t           err = 0;
    int              i;

    for (i = 0; i < count; i++) {
        union cndb_mtu *mtu = vector[i];

        if (mtu->h.mth_type == CNDB_TYPE_TX) {
            if (txp && (txp->mtx_nc == 0 && txp->mtx_nd == 0)) {
                cack->mta_txid = 0;
                txp->mtx_id = 0;
            }
            txp = &mtu->x;
        }

        if (mtu->h.mth_type == CNDB_TYPE_ACK && mtu->a.mta_type == CNDB_ACK_TYPE_C)
            cack = &mtu->a;

        if (drop_cnid && mtxcnid(vector[i]) == drop_cnid) {
            err = cndb_drop_mtx(cndb, mtu, txp);
            if (err) {
                CNDB_LOGTX(
                    err,
                    cndb,
                    mtxid(mtu),
                    HSE_ERR,
                    " cnid %lu drop record %d failed",
                    (ulong)drop_cnid,
                    i);
                return err;
            }
            free(vector[i]);
            vector[i] = NULL;
        }
    }

    if (txp && (txp->mtx_nc == 0 && txp->mtx_nd == 0)) {
        if (cack)
            cack->mta_txid = 0;
        txp->mtx_id = 0;
    }

    return 0;
}

static merr_t
cndb_cull(struct cndb *cndb, u64 drop_cnid)
{
    merr_t err = 0;

    /* [HSE_REVISIT] This function leaves orphans in tagv, which will
     * never be referenced and will be wiped on next cndb_compact().
     *
     * consider restructuring so that tagv is always empty except during
     * compaction, by moving tagv_wipe() calls to the end of cndb_compact()
     * and removing the tagv_wipe() call from cndb_close()
     */
    err = cndb_cull_loop(cndb, cndb->cndb_keepv, cndb->cndb_keepc, drop_cnid);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu keepv drop failed", (ulong)drop_cnid);
        goto errout;
    }

    err = cndb_cull_loop(cndb, cndb->cndb_workv, cndb->cndb_workc, drop_cnid);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " cnid %lu workv drop failed", (ulong)drop_cnid);
        goto errout;
    }

    cndb_defragment(cndb);

errout:
    return err;
}

/**
 * cndb_rollover()
 * @cndb:
 *
 * Only function writing in the cndb mdc beside cndb_accept()
 * This function switches the passive-active mlogs of the cndb mdc
 * and write the whole cndb metadata in the new active mlog.
 */
static merr_t
cndb_rollover(struct cndb *cndb)
{
    void * sav = NULL;
    int    i;
    merr_t err = 0;
    size_t sz;
    u64    drop_cnid = 0;
    int    drop_idx = -1;

    struct cndb_hdr_omf * buf = (void *)cndb->cndb_cbuf;
    struct cndb_ver_omf * ver = NULL;
    struct cndb_meta_omf *meta = NULL;
    struct cndb_info_omf *inf = NULL;

    CNDB_LOG(0, cndb, HSE_DEBUG, " rollover starting");

    /* Append workv to keepv, then clear workv */
    memcpy(
        &cndb->cndb_keepv[cndb->cndb_keepc],
        &cndb->cndb_workv[0],
        cndb->cndb_workc * sizeof(void *));
    memset(&cndb->cndb_workv[0], 0, cndb->cndb_entries * sizeof(void *));

    /* Swap keepv and workv */
    sav = cndb->cndb_workv;
    cndb->cndb_workc += cndb->cndb_keepc;
    cndb->cndb_workv = cndb->cndb_keepv;
    cndb->cndb_keepc = 0;
    cndb->cndb_keepv = sav;

    err = cndb_compact(cndb);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " compact failed");
        goto errout;
    }

    err = mpool_mdc_cstart(cndb->cndb_mdc);
    if (err) {
        cndb->cndb_mdc = NULL; /* cstart closes the MDC on error */
        CNDB_LOG(err, cndb, HSE_ERR, " cstart failed");
        goto errout;
    }

    ver = (void *)buf;
    cndb_set_hdr(&ver->hdr, CNDB_TYPE_VERSION, sizeof(*ver));
    omf_set_cnver_magic(ver, CNDB_MAGIC);
    omf_set_cnver_version(ver, CNDB_VERSION);
    omf_set_cnver_captgt(ver, cndb->cndb_captgt);

    err = mpool_mdc_append(cndb->cndb_mdc, ver, sizeof(*ver), false);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " version write failed");
        goto errout;
    }

    meta = (void *)buf;
    cndb_set_hdr(&meta->hdr, CNDB_TYPE_META, sizeof(*meta));
    omf_set_cnmeta_seqno_max(meta, max_t(u64, cndb->cndb_seqno, cndb_ikvdb_seqno_get(cndb)));

    err = mpool_mdc_append(cndb->cndb_mdc, meta, sizeof(*meta), false);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " meta write failed");
        goto errout;
    }

    for (i = 0; i < cndb->cndb_cnc; i++) {
        struct cndb_cn *cn;

        cn = cndb->cndb_cnv[i];
        if (cn->cn_removed) {
            if (drop_cnid || (drop_idx != -1)) {
                err = merr(EPROTO);
                CNDB_LOG(
                    err,
                    cndb,
                    HSE_ERR,
                    " nested kvs drop (%lu, %lu)",
                    (ulong)drop_cnid,
                    (ulong)cn->cn_cnid);
                goto errout;
            }
            drop_idx = i;
            drop_cnid = cn->cn_cnid;
            continue;
        }

        inf = (void *)cn->cn_cbuf;
        sz = sizeof(*inf);
        memset(inf, 0, sz);

        sz = cn->cn_cbufsz;
        cndb_info2omf(CNDB_TYPE_INFO, cn, inf);

        err = mpool_mdc_append(cndb->cndb_mdc, inf, sz, false);
        if (err) {
            CNDB_LOG(err, cndb, HSE_ERR, " info %lu failed", (ulong)cn->cn_cnid);
            goto errout;
        }
    }

    if (drop_cnid) {
        cndb_cnv_del(cndb, drop_idx);
        err = cndb_cull(cndb, drop_cnid);
        if (err) {
            CNDB_LOG(err, cndb, HSE_ERR, " cull cnid %lu failed", (ulong)drop_cnid);
            goto errout;
        }
        cndb_defragment(cndb);
    }

    /* ensure no uninitialized bytes in the output record.
     *
     * the first pass has no predecessor, so use the entire buffer size.
     * subsequent passes clear only the bytes used by the prior pass.
     */
    sz = sizeof(cndb->cndb_cbuf);

    for (i = 0; i < cndb->cndb_keepc; i++) {
        memset(buf, 0, sz);

        err = mtx2omf(cndb, buf, cndb->cndb_keepv[i]);
        if (err) {
            CNDB_LOGTX(
                err, cndb, mtxid(cndb->cndb_keepv[i]), HSE_ERR, " OMF conversion failed (keepv)");
            goto errout;
        }

        sz = omf_cnhdr_len(buf) + sizeof(struct cndb_hdr_omf);
        err = mpool_mdc_append(cndb->cndb_mdc, buf, sz, false);
        if (err) {
            CNDB_LOGTX(err, cndb, mtxid(cndb->cndb_keepv[i]), HSE_ERR, " append failed (keepv)");
            goto errout;
        }
    }

    for (i = 0; i < cndb->cndb_workc; i++) {
        memset(buf, 0, sz);

        err = mtx2omf(cndb, buf, cndb->cndb_workv[i]);
        if (err) {
            CNDB_LOGTX(
                err, cndb, mtxid(cndb->cndb_keepv[i]), HSE_ERR, " OMF conversion failed (workv)");
            goto errout;
        }

        sz = omf_cnhdr_len(buf) + sizeof(struct cndb_hdr_omf);
        err = mpool_mdc_append(cndb->cndb_mdc, buf, sz, false);
        if (err) {
            CNDB_LOGTX(err, cndb, mtxid(cndb->cndb_keepv[i]), HSE_ERR, " append failed (workv)");
            goto errout;
        }
    }

    err = mpool_mdc_cend(cndb->cndb_mdc);
    if (err) {
        cndb->cndb_mdc = NULL; /* cend closes the MDC on error */
        CNDB_LOG(err, cndb, HSE_ERR, " cend failed");
        goto errout;
    }

errout:
    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " rollover failed");
    else
        CNDB_LOG(0, cndb, HSE_DEBUG, " cndb rollover finished");

    ver = NULL;
    inf = NULL;
    return err;
}

/* PRIVATE */
/**
 * cndb_accept() - appends one record in the cndb mdc
 *
 * Only function beside cndb_rollover() to write in the cndb mdc.
 *
 * @cndb:
 * @data: the record in omf format
 */
static merr_t
cndb_accept(struct cndb *cndb, void *data, size_t sz)
{
    merr_t          err;
    size_t          usage = 0;
    u32             mtlen;
    union cndb_mtu *mtu = NULL;
    int             count;
    static int      odometer;

    assert(cndb->cndb_kvdb_health);

    if (cndb->cndb_rdonly) {
        err = merr(EROFS);
        CNDB_LOG(err, cndb, HSE_ERR, "");
        goto errout;
    }

    err = mpool_mdc_usage(cndb->cndb_mdc, &usage);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " statistics unavailable");
        goto errout;
    }

    count = cndb->cndb_workc + cndb->cndb_keepc;
    if (!(count % 1024))
        CNDB_LOG(
            0,
            cndb,
            HSE_DEBUG,
            " journal count %d entries %ld odometer %d",
            count,
            (ulong)cndb->cndb_entries,
            odometer++);
    assert(count <= cndb->cndb_entries);

    if (count >= cndb->cndb_entries_high_water || usage >= cndb->cndb_high_water) {
        err = cndb_rollover(cndb);
        if (err) {
            cndb->cndb_rdonly = true;
            CNDB_LOG(err, cndb, HSE_ERR, " rollover failed");
            goto errout;
        }

        err = mpool_mdc_usage(cndb->cndb_mdc, &usage);
        if (err) {
            CNDB_LOG(err, cndb, HSE_ERR, " statistics unavailable");
            goto errout;
        }

        count = cndb->cndb_workc + cndb->cndb_keepc;
        if (count >= cndb->cndb_entries_high_water) {
            err = cndb_grow(cndb, usage + sz);
            if (err)
                CNDB_LOG(
                    err,
                    cndb,
                    HSE_WARNING,
                    " working set "
                    " watermark exceeded count %d hwm %zd",
                    count,
                    cndb->cndb_entries_high_water);
            err = 0; /* suppress because working set has room */
        }

        if ((usage + sz) >= cndb->cndb_captgt || count >= cndb->cndb_entries) {
            cndb->cndb_rdonly = true;
            err = merr(ENOSPC);
            CNDB_LOG(err, cndb, HSE_ERR, " MDC full");
            kvdb_health_event(cndb->cndb_kvdb_health, KVDB_HEALTH_FLAG_CNDBFAIL, err);
            goto errout;
        }

        goto accept_record;
    }

    /* Don't shrink unless about 1/3 is empty */
    if (cndb->cndb_entries > ((count * 3) / 2))
        cndb_shrink(cndb);

accept_record:

    if (omf_cnhdr_type(data) != CNDB_TYPE_INFO && omf_cnhdr_type(data) != CNDB_TYPE_INFOD) {
        err = omf2len(data, CNDB_VERSION, &mtlen);
        if (err || !mtlen) {
            err = merr(EPROTO);
            CNDB_LOG(err, cndb, HSE_ERR, " invalid record");
            goto errout;
        }

        mtu = calloc(1, mtlen);
        if (!mtu) {
            err = merr(ENOMEM);
            CNDB_LOG(err, cndb, HSE_ERR, "");
            goto errout;
        }

        err = omf2mtx(mtu, &mtlen, data, CNDB_VERSION);
        if (err) {
            CNDB_LOG(err, cndb, HSE_ERR, " invalid OMF");
            free(mtu);
            goto errout;
        }
        cndb->cndb_workv[cndb->cndb_workc++] = mtu;
        cndb->cndb_compacted = false;
        count = cndb->cndb_workc + cndb->cndb_keepc;
        assert(count <= cndb->cndb_entries);
    }

    err = mpool_mdc_append(cndb->cndb_mdc, data, sz, true);
    if (err) {
        struct cndb_hdr_omf *hdr = data;

        kvdb_health_error(cndb->cndb_kvdb_health, err);
        CNDB_LOGTX(err, cndb, mtxid(mtu), HSE_ERR, " append failed (type %d)", hdr->cnhdr_type);
    }

errout:
    return err;
}

merr_t
cndb_journal(struct cndb *cndb, void *data, size_t sz)
{
    merr_t err;

    mutex_lock(&cndb->cndb_lock);
    err = cndb_accept(cndb, data, sz);
    mutex_unlock(&cndb->cndb_lock);

    return ev(err, HSE_ERR);
}

/* PRIVATE */
merr_t
cndb_journal_adopt(struct cndb *cndb, void **data, size_t sz)
{
    merr_t err;

    mutex_lock(&cndb->cndb_lock);
    err = cndb_accept(cndb, *data, sz);

    if (sz > cndb->cndb_cbufsz) {
        free(cndb->cndb_cbuf);
        cndb->cndb_cbufsz = sz;
        cndb->cndb_cbuf = *data;

        *data = NULL; /* prevent caller from freeing */
    }
    mutex_unlock(&cndb->cndb_lock);

    return ev(err, HSE_ERR);
}

merr_t
cndb_close(struct cndb *cndb)
{
    merr_t err = 0;
    int    i;

    if (!cndb)
        return 0;

    mutex_lock(&cndb->cndb_lock);

    if (cndb->cndb_mdc) {
        err = mpool_mdc_close(cndb->cndb_mdc);
        if (err)
            CNDB_LOG(err, cndb, HSE_ERR, " MDC close failed");
    }

    for (i = 0; i < cndb->cndb_cnc; i++) {
        free(cndb->cndb_cnv[i]->cn_cbuf);
        free(cndb->cndb_cnv[i]);
    }

    for (i = 0; i < cndb->cndb_workc; i++)
        free(cndb->cndb_workv[i]);

    for (i = 0; i < cndb->cndb_keepc; i++)
        free(cndb->cndb_keepv[i]);

    tagv_wipe(cndb);
    free(cndb->cndb_tagv);
    free(cndb->cndb_keepv);
    free(cndb->cndb_workv);
    free(cndb->cndb_cbuf);

    mutex_unlock(&cndb->cndb_lock);
    free(cndb);

    return err;
}

struct kvs_cparams *
cndb_cn_cparams(struct cndb *cndb, u64 cnid)
{
    struct cndb_cn *cn = NULL;

    if (ev(cndb_cnv_get(cndb, cnid, &cn)))
        return NULL;

    return &cn->cn_cp;
}

merr_t
cndb_cn_make2(struct cndb *cndb, struct kvs_cparams *cparams, u64 *cnid_out, const char *name)
{
    merr_t               err;
    struct cndb_info_omf info = {};
    u32                  fanout_bits = 0;
    u32                  flags = 0;

    if (cparams->cp_fanout < 2 || cparams->cp_fanout > 16) {
        err = merr(EINVAL);
        CNDB_LOG(err, cndb, HSE_ERR, " cp_fanout");
        goto done;
    }
    fanout_bits = ilog2(cparams->cp_fanout);

    cndb_set_hdr(&info.hdr, CNDB_TYPE_INFO, sizeof(info));
    omf_set_cninfo_fanout_bits(&info, fanout_bits);
    omf_set_cninfo_prefix_len(&info, cparams->cp_pfx_len);
    omf_set_cninfo_sfx_len(&info, cparams->cp_sfx_len);
    omf_set_cninfo_prefix_pivot(&info, cparams->cp_pfx_pivot);
    omf_set_cninfo_name(&info, (unsigned char *)name, strlen(name));

    if (cparams->cp_kvs_ext01)
        flags |= CN_CFLAG_CAPPED;

    omf_set_cninfo_flags(&info, flags);

    mutex_lock(&cndb->cndb_cnv_lock);
    *cnid_out = cndb->cndb_cnid++;
    err = cndb_cnv_add(cndb, flags, cparams, *cnid_out, name, 0, NULL);
    mutex_unlock(&cndb->cndb_cnv_lock);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " cn %s add failed", name);
        goto done;
    }

    omf_set_cninfo_cnid(&info, *cnid_out);
    err = cndb_journal(cndb, &info, sizeof(info));
    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " cn %s adoption failed", name);

done:
    return err;
}

merr_t
cndb_cn_make(struct cndb *cndb, struct kvs_cparams *cparams, u64 *cnid_out, char *name)
{
    merr_t err;

    if (strnlen(name, CNDB_CN_NAME_MAX) >= CNDB_CN_NAME_MAX) {
        err = merr(ENAMETOOLONG);
        CNDB_LOG(err, cndb, HSE_ERR, " cn %s", name);
        return err;
    }

    err = cn_make(cndb->cndb_ds, cparams, cndb->cndb_kvdb_health);
    if (err) {
        CNDB_LOG(err, cndb, HSE_ERR, " cn %s creation failed", name);
        return err;
    }

    err = cndb_cn_make2(cndb, cparams, cnid_out, name);
    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, " cn %s adoption failed", name);

    return err;
}

merr_t
cndb_cn_drop(struct cndb *cndb, u64 cnid)
{
    struct cndb_cn *     cn = NULL;
    struct cndb_info_omf inf;
    const char *         msg = "";
    merr_t               err;
    bool                 ro;

    mutex_lock(&cndb->cndb_cnv_lock);
    mutex_lock(&cndb->cndb_lock);
    ro = cndb->cndb_rdonly;
    mutex_unlock(&cndb->cndb_lock);

    if (ev(ro)) {
        err = merr(EROFS);
        goto done;
    }

    err = cndb_cnv_get(cndb, cnid, &cn);
    if (ev(err)) {
        msg = " lookup failed";
        goto done;
    }

    if (ev(cn->cn_refcnt)) {
        err = merr(EBUSY);
        goto done;
    }

    memset(&inf, 0, sizeof(inf));
    cndb_info2omf(CNDB_TYPE_INFOD, cn, &inf);

    assert(cn->cn_cnid == cnid);
    cn->cn_removed = true;
    cn = NULL; /* Might be freed by cndb_journal() */

    err = cndb_journal(cndb, &inf, sizeof(inf));
    if (ev(err)) {
        msg = " drop tx failed";
        goto done;
    }

    /* cndb_rollover() removes the specified cn and culls its metadata.
     *
     * TODO: As a temporary measure, call cndb_compact() to purge
     * orphans from cndb_tagv[].  See cndb_cull() for more detail.
     */
    mutex_lock(&cndb->cndb_lock);
    err = cndb_rollover(cndb);
    if (!err)
        err = cndb_compact(cndb);
    mutex_unlock(&cndb->cndb_lock);

    msg = " rollover failed, cndb_cn_drop may be retried on next r/w open";

done:
    mutex_unlock(&cndb->cndb_cnv_lock);

    if (err)
        CNDB_LOG(err, cndb, HSE_ERR, "cnid %lu%s", (ulong)cnid, msg);

    return err;
}

static u64
cndb_txn_nextid(struct cndb *cndb, int nc)
{
    return atomic64_fetch_add(nc, &cndb->cndb_txid);
}

merr_t
cndb_txn_start(struct cndb *cndb, u64 *txid, u64 ingestid, int nc, int nd, u64 seqno)
{
    struct cndb_tx_omf tx = {};
    merr_t             err;

    cndb->cndb_seqno = max(cndb->cndb_seqno, seqno);

    *txid = cndb_txn_nextid(cndb, nc ?: 1);

    cndb_set_hdr(&tx.hdr, CNDB_TYPE_TX, sizeof(tx));
    omf_set_tx_id(&tx, *txid);
    omf_set_tx_nc(&tx, nc);
    omf_set_tx_nd(&tx, nd);
    omf_set_tx_seqno(&tx, cndb->cndb_seqno);
    omf_set_tx_ingestid(&tx, ingestid);

    err = ev(cndb_journal(cndb, &tx, sizeof(tx)), HSE_ERR);
    return err;
}

merr_t
cndb_txn_txc(
    struct cndb *         cndb,
    u64                   txid,
    u64                   cnid,
    u64 *                 tag,
    struct kvset_mblocks *mblocks,
    u32                   keepvbc)
{
    struct cndb_txc_omf  txcbuf[1024 / sizeof(struct cndb_txc_omf)];
    struct cndb_txc_omf *txc = txcbuf;
    merr_t               err;
    int                  i, cnt;
    size_t               sz;
    struct cndb_oid_omf *pblks;

    /* [HSE_REVISIT] consider optimizing empty C / Cmeta records away
     * and relaxing the requirement that when the tx record specifies
     * a count of C records, that many records must exist even if some
     * are empty.
     */
    if (mblocks == NULL)
        cnt = 0;
    else
        cnt = mblocks->kblks.n_blks + mblocks->vblks.n_blks;

    sz = sizeof(*txc) + cnt * sizeof(u64);
    ev(sz > cndb->cndb_cbufsz);

    if (ev(sz > sizeof(txcbuf) || sz > cndb->cndb_cbufsz)) {
        txc = malloc(sz);
        if (!txc) {
            err = merr(ev(ENOMEM, HSE_ERR));
            goto out;
        }
    }

    memset(txc, 0, sz);

    pblks = (void *)&txc[1];

    cndb_set_hdr(&txc->hdr, CNDB_TYPE_TXC, sz);
    omf_set_txc_cnid(txc, cnid);
    omf_set_txc_id(txc, txid);

    /* tags for a given txid start at txid and monotonically increase */
    *tag = *tag ? *tag + 1 : txid;
    omf_set_txc_tag(txc, *tag);

    omf_set_txc_keepvbc(txc, keepvbc);
    if (mblocks) {
        omf_set_txc_kcnt(txc, mblocks->kblks.n_blks);
        omf_set_txc_vcnt(txc, mblocks->vblks.n_blks);

        for (i = 0; i < mblocks->kblks.n_blks; i++)
            omf_set_cndb_oid(pblks++, mblocks->kblks.blks[i].bk_blkid);

        for (i = 0; i < mblocks->vblks.n_blks; i++)
            omf_set_cndb_oid(pblks++, mblocks->vblks.blks[i].bk_blkid);
    }

    err = cndb_journal_adopt(cndb, (void **)&txc, sz);
    ev(err, HSE_ERR);

out:
    if (txc != txcbuf)
        free(txc);

    return err;
}

merr_t
cndb_txn_txd(struct cndb *cndb, u64 txid, u64 cnid, u64 tag, int n_oids, u64 *oidv)
{
    struct cndb_txd_omf  txdbuf[1024 / sizeof(struct cndb_txd_omf)];
    struct cndb_txd_omf *txd = txdbuf;
    merr_t               err;
    size_t               sz;
    struct cndb_oid_omf *pblks;
    int                  i;

    if (ev(txid <= tag, HSE_ERR)) {
        assert(txid > tag);
        return merr(EL2NSYNC);
    }

    sz = n_oids * sizeof(*oidv) + sizeof(*txd);

    if (ev(sz > sizeof(txdbuf) || sz > cndb->cndb_cbufsz)) {
        txd = malloc(sz);
        if (!txd) {
            err = merr(ev(ENOMEM, HSE_ERR));
            goto out;
        }
    }

    memset(txd, 0, sz);

    pblks = (void *)&txd[1];

    cndb_set_hdr(&txd->hdr, CNDB_TYPE_TXD, sz);
    omf_set_txd_cnid(txd, cnid);
    omf_set_txd_id(txd, txid);
    omf_set_txd_tag(txd, tag);
    omf_set_txd_n_oids(txd, n_oids);

    for (i = 0; i < n_oids; i++)
        omf_set_cndb_oid(pblks++, oidv[i]);

    err = cndb_journal_adopt(cndb, (void **)&txd, sz);
    ev(err, HSE_ERR);

out:
    if (txd != txdbuf)
        free(txd);

    return err;
}

merr_t
cndb_txn_meta(struct cndb *cndb, u64 txid, u64 cnid, u64 tag, struct kvset_meta *km)
{
    struct cndb_txm_omf txm = {};
    merr_t              err;

    assert(tag != 0);

    cndb_set_hdr(&txm.hdr, CNDB_TYPE_TXM, sizeof(txm));
    omf_set_txm_cnid(&txm, cnid);
    omf_set_txm_id(&txm, txid);
    omf_set_txm_tag(&txm, tag);
    omf_set_txm_level(&txm, km->km_node_level);
    omf_set_txm_offset(&txm, km->km_node_offset);
    omf_set_txm_dgen(&txm, km->km_dgen);
    omf_set_txm_vused(&txm, km->km_vused);
    omf_set_txm_compc(&txm, km->km_compc);
    omf_set_txm_scatter(&txm, km->km_scatter);

    err = cndb_journal(cndb, &txm, sizeof(txm));

    return ev(err, HSE_ERR);
}

/* PRIVATE */
merr_t
cndb_txn_ack(struct cndb *cndb, u64 txid, u64 tag, u64 cnid)
{
    struct cndb_ack_omf ack = {};
    merr_t              err;

    assert(txid);
    cndb_set_hdr(&ack.hdr, CNDB_TYPE_ACK, sizeof(ack));
    omf_set_ack_txid(&ack, txid);
    omf_set_ack_cnid(&ack, cnid);
    omf_set_ack_tag(&ack, tag);
    omf_set_ack_type(&ack, tag ? CNDB_ACK_TYPE_D : CNDB_ACK_TYPE_C);

    err = cndb_journal(cndb, &ack, sizeof(ack));

    return ev(err, HSE_ERR);
}

merr_t
cndb_txn_ack_c(struct cndb *cndb, u64 txid)
{
    int t = nfault_probe(cndb_probes, CNDB_PROBE_DROP_ACKC);

    if (t != NFAULT_TRIG_NONE)
        return 0;

    return cndb_txn_ack(cndb, txid, 0, 0);
}

merr_t
cndb_txn_ack_d(struct cndb *cndb, u64 txid, u64 tag, u64 cnid)
{
    int t = nfault_probe(cndb_probes, CNDB_PROBE_DROP_ACKD);

    if (t != NFAULT_TRIG_NONE)
        return 0;

    return cndb_txn_ack(cndb, txid, tag, cnid);
}

merr_t
cndb_txn_nak(struct cndb *cndb, u64 txid)
{
    struct cndb_nak_omf nak = {};
    merr_t              err;

    cndb_set_hdr(&nak.hdr, CNDB_TYPE_NAK, sizeof(nak));
    omf_set_nak_txid(&nak, txid);

    err = cndb_journal(cndb, &nak, sizeof(nak));

    return ev(err, HSE_ERR);
}

/**
 * cndb_cn_initializer() - Only used in tests
 */
struct cndb_cn
cndb_cn_initializer(unsigned int fanout_bits, unsigned int pfx_len, u64 cnid)
{
    struct cndb_cn cn = {};

    cn.cn_cp.cp_fanout = 1 << fanout_bits;
    cn.cn_cp.cp_pfx_len = 1 << fanout_bits;
    cn.cn_cnid = cnid;

    return cn;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cndb_ut.h"
#include "cndb_ut_impl.i"
#include "cndb_internal_ut.h"
#include "cndb_internal_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
