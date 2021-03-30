/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Exported API of the HSE struct ikvs
 */

#include <stdalign.h>

#include <hse/hse.h>
#include <hse/kvdb_perfc.h>

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/perfc.h>
#include <hse_util/darray.h>
#include <hse_util/timing.h>
#include <hse_util/fmt.h>
#include <hse_util/byteorder.h>
#include <hse_util/slab.h>
#include <hse_util/table.h>

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/cn_cursor.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cursor.h>

#include "kvs_params.h"

/* "pkvsl" stands for Public KVS interface Latencies" */
struct perfc_name kvs_pkvsl_perfc_op[] = {
    NE(PERFC_LT_PKVSL_KVS_PUT, 3, "kvs_put latency", "kvs_put_lat", 7),
    NE(PERFC_LT_PKVSL_KVS_GET, 3, "kvs_get latency", "kvs_get_lat", 7),
    NE(PERFC_LT_PKVSL_KVS_DEL, 3, "kvs_delete latency", "kvs_del_lat", 7),

    NE(PERFC_LT_PKVSL_KVS_PFX_PROBE, 3, "kvs_prefix_probe latency", "kvs_pfx_probe_lat"),
    NE(PERFC_LT_PKVSL_KVS_PFX_DEL, 3, "kvs_prefix_delete latency", "kvs_pfx_del_lat"),

    NE(PERFC_LT_PKVSL_KVS_CURSOR_CREATE, 2, "kvs_cursor_create latency", "kvs_cursor_create_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_UPDATE, 2, "kvs_cursor_update latency", "kvs_cursor_update_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_SEEK, 2, "kvs_cursor_seek latency", "kvs_cursor_seek_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_READFWD,
       2,
       "kvs_cursor_read forward latency",
       "kvs_cursor_readfwd_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_READREV,
       2,
       "kvs_cursor_read reverse latency",
       "kvs_cursor_readrev_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_DESTROY,
       2,
       "kvs_cursor_destroy latency",
       "kvs_cursor_destroy_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_FULL, 2, "full cursor lifetime", "cursor_lifetime_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_INIT, 2, "kvs_cursor_init latency", "kvs_cursor_init_lat"),
};

NE_CHECK(
    kvs_pkvsl_perfc_op,
    PERFC_EN_PKVSL,
    "public kvs interface latencies perfc ops table/enum mismatch");

struct mpool;

/*-  Key Value Store  -------------------------------------------------------*/

static atomic_t           kvs_init_ref;

static merr_t
kvs_create(struct ikvs **kvs, struct kvs_rparams *rp);

static void
kvs_destroy(struct ikvs *kvs);

void
kvs_perfc_init(void);

void
kvs_perfc_fini(void)
{
    kvs_cursor_perfc_fini();
}

static void
kvs_perfc_alloc(const char *mp_name, const char *kvs_name, struct ikvs *kvs)
{
    char   dbname_buf[DT_PATH_COMP_ELEMENT_LEN];
    size_t n;

    dbname_buf[0] = 0;

    n = strlcpy(dbname_buf, mp_name, sizeof(dbname_buf));
    if (ev(n >= sizeof(dbname_buf)))
        return;
    n = strlcat(dbname_buf, IKVDB_SUB_NAME_SEP, sizeof(dbname_buf));
    if (ev(n >= sizeof(dbname_buf)))
        return;
    n = strlcat(dbname_buf, kvs_name, sizeof(dbname_buf));
    if (ev(n >= sizeof(dbname_buf)))
        return;

    kvs_cursor_perfc_alloc(dbname_buf, &kvs->ikv_cc_pc, &kvs->ikv_cd_pc);

    /* Measure Public KVS interface Latencies */
    if (perfc_ctrseti_alloc(
            COMPNAME, dbname_buf, kvs_pkvsl_perfc_op, PERFC_EN_PKVSL, "set", &kvs->ikv_pkvsl_pc))
        hse_log(HSE_ERR "cannot alloc kvs perf counters");
}

static void
kvs_perfc_free(struct ikvs *kvs)
{
    kvs_cursor_perfc_free(&kvs->ikv_cc_pc, &kvs->ikv_cd_pc);
    perfc_ctrseti_free(&kvs->ikv_pkvsl_pc);
}

/*
 * Resources allocated after a successful open are listed here in order of
 * allocation.  The kvs_close function must free resources listed on the
 * right side in reverse order of allocation.
 *
 *    Allocator              ->  Freer
 *    ---------                  ------
 *    kvs_create                 kvs_destroy
 *    cn_open                    cn_close
 *    c0_open                    c0_close
 *
 * [HSE_REVISIT]: Perhaps this arg list can be trimmed some ...
 */
merr_t
kvs_open(
    struct ikvdb *      kvdb,
    struct kvdb_kvs *   kvs,
    const char *        mp_name,
    struct mpool *      ds,
    struct cndb *       cndb,
    struct kvs_rparams *rp,
    struct kvdb_health *health,
    struct cn_kvdb *    cn_kvdb,
    uint                flags)
{
    merr_t       err;
    struct ikvs *ikvs = 0;
    const char * kvs_name = kvdb_kvs_name(kvs);
    u64          cnid = kvdb_kvs_cnid(kvs);

    assert(health);

    err = kvs_create(&ikvs, rp);
    if (ev(err))
        goto err_exit;

    /* [HSE_REVISIT]: we need to remove dt entries if open fails, and also
     * in kvs_close().  In the meantime, do not fail the open if adding
     * dt entries fails.
     */

    ikvs->ikv_ds = ds;
    ikvs->ikv_mpool_name = strdup(mp_name);
    ikvs->ikv_kvs_name = strdup(kvs_name);

    if (!ikvs->ikv_mpool_name || !ikvs->ikv_kvs_name) {
        err = merr(ev(ENOMEM));
        goto err_exit;
    }

    /* avoid using caller's rp struct.  use our copy in ikvs struct. */
    rp = 0;

    err = cn_open(
        cn_kvdb,
        ds,
        kvs,
        cndb,
        cnid,
        &ikvs->ikv_rp,
        mp_name,
        kvs_name,
        health,
        flags,
        &ikvs->ikv_cn);
    if (ev(err))
        goto err_exit;

    err = c0_open(kvdb, &ikvs->ikv_rp, ikvs->ikv_cn, ikvs->ikv_ds, &ikvs->ikv_c0);
    if (ev(err))
        goto err_exit;

    ikvs->ikv_pfx_len = c0_get_pfx_len(ikvs->ikv_c0);
    ikvs->ikv_sfx_len = cn_get_sfx_len(ikvs->ikv_cn);

    err = qctx_te_mem_init();
    if (ev(err))
        goto err_exit;

    err = kvs_rparams_add_to_dt(mp_name, kvs_name, &ikvs->ikv_rp);
    if (ev(err))
        hse_log(HSE_WARNING "Unable to add run-time parameters"
                            " to data tree");

    kvs_perfc_alloc(mp_name, kvs_name, ikvs);

    kvdb_kvs_set_ikvs(kvs, ikvs);

    return 0;

err_exit:
    if (ikvs) {
        if (ikvs->ikv_c0)
            c0_close(ikvs->ikv_c0);
        if (ikvs->ikv_cn)
            cn_close(ikvs->ikv_cn);
        kvs_destroy(ikvs);
    }

    return err;
}

struct mpool *
kvs_ds_get(struct ikvs *ikvs)
{
    return ikvs ? ikvs->ikv_ds : NULL;
}

struct cn *
kvs_cn(struct ikvs *ikvs)
{
    return ikvs ? ikvs->ikv_cn : 0;
}

/*
 * Resources freed by kvs_close:
 *    c0_close
 *    cn_close
 *    kvs_destroy
 */
merr_t
kvs_close(struct ikvs *ikvs)
{
    merr_t err = 0;

    if (ev(!ikvs))
        return merr(EINVAL);

    cn_disable_maint(ikvs->ikv_cn, true);

    ikvs_cursor_reap(ikvs);

    err = c0_close(ikvs->ikv_c0);
    if (err)
        hse_elog(HSE_ERR "%s: c0_close @@e", err, __func__);

    err = cn_close(ikvs->ikv_cn);
    if (err)
        hse_elog(HSE_ERR "%s: cn_close @@e", err, __func__);

    kvs_perfc_free(ikvs);

    err = kvs_rparams_remove_from_dt(ikvs->ikv_mpool_name, ikvs->ikv_kvs_name);
    if (err)
        hse_elog(HSE_ERR "%s: kvs_rparams_remove_from_dt @@e", err, __func__);

    kvs_destroy(ikvs);

    return err;
}

struct perfc_set *
ikvs_perfc_pkvsl(struct ikvs *ikvs)
{
    if (ikvs->ikv_rp.kvs_debug & 2)
        return &ikvs->ikv_pkvsl_pc;

    return NULL;
}

merr_t
ikvs_put(
    struct ikvs *            kvs,
    struct hse_kvdb_opspec * os,
    struct kvs_ktuple *      kt,
    const struct kvs_vtuple *vt,
    u64                      seqno)
{
    struct perfc_set *pkvsl_pc = ikvs_perfc_pkvsl(kvs);

    struct c0 *c0 = kvs->ikv_c0;
    size_t     sfx_len;
    size_t     hashlen;
    u64        tstart;
    merr_t     err;

    tstart = perfc_lat_start(pkvsl_pc);

    sfx_len = kvs->ikv_sfx_len;
    hashlen = kt->kt_len - sfx_len;
    kt->kt_hash = key_hash64(kt->kt_data, hashlen);

    /* Assert that either
     *  1. This is NOT a suffixed tree, OR
     *  2. keylen is at least pfx_len + sfx_len
     */
    if (ev(sfx_len && kt->kt_len < sfx_len + kvs->ikv_pfx_len)) {
        hse_log(
            HSE_ERR "%s is a suffixed kvs. Keys must be at least "
                    "pfx_len(%u) + sfx_len(%u) bytes long.",
            kvs->ikv_kvs_name,
            kvs->ikv_pfx_len,
            kvs->ikv_sfx_len);
        return merr(EINVAL);
    }

    if (HSE_UNLIKELY(os && os->kop_txn))
        err = kvdb_ctxn_put(kvdb_ctxn_h2h(os->kop_txn), c0, kt, vt);
    else
        err = c0_put(c0, kt, vt, seqno);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_PUT, tstart);

    return err;
}

merr_t
ikvs_get(
    struct ikvs *           kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    u64                     seqno,
    enum key_lookup_res *   res,
    struct kvs_buf *        vbuf)
{
    struct perfc_set *pkvsl_pc = ikvs_perfc_pkvsl(kvs);
    struct c0 *       c0 = kvs->ikv_c0;
    struct cn *       cn = kvs->ikv_cn;
    struct kvdb_ctxn *ctxn;
    size_t            hashlen;
    u64               tstart;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    hashlen = kt->kt_len - kvs->ikv_sfx_len;
    kt->kt_hash = key_hash64(kt->kt_data, hashlen);

    ctxn = (os && os->kop_txn) ? kvdb_ctxn_h2h(os->kop_txn) : 0;

    if (!ctxn)
        err = c0_get(c0, kt, seqno, 0, res, vbuf);
    else
        err = kvdb_ctxn_get(ctxn, c0, cn, kt, res, vbuf);

    if (!err && *res == NOT_FOUND) {
        if (ctxn) {
            err = kvdb_ctxn_get_view_seqno(ctxn, &seqno);
            if (ev(err))
                return err;
        }

        err = cn_get(cn, kt, seqno, res, vbuf);
    }

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_GET, tstart);

    return err;
}

merr_t
ikvs_del(struct ikvs *kvs, struct hse_kvdb_opspec *os, struct kvs_ktuple *kt, u64 seqno)
{
    struct perfc_set *pkvsl_pc = ikvs_perfc_pkvsl(kvs);
    struct kvdb_ctxn *ctxn = 0;
    struct c0 *       c0 = kvs->ikv_c0;
    size_t            sfx_len;
    size_t            hashlen;
    u64               tstart;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    sfx_len = kvs->ikv_sfx_len;
    hashlen = kt->kt_len - sfx_len;
    kt->kt_hash = key_hash64(kt->kt_data, hashlen);

    /* Assert that either
     *  1. This is NOT a suffixed tree, OR
     *  2. keylen is at least pfx_len + sfx_len
     */
    if (ev(sfx_len && kt->kt_len < sfx_len + kvs->ikv_pfx_len)) {
        hse_log(
            HSE_ERR "%s is a suffixed kvs. Keys must be at least "
                    "pfx_len(%u) + sfx_len(%u) bytes long.",
            kvs->ikv_kvs_name,
            kvs->ikv_pfx_len,
            kvs->ikv_sfx_len);
        return merr(EINVAL);
    }
    if (os && os->kop_txn)
        ctxn = kvdb_ctxn_h2h(os->kop_txn);

    if (!ctxn)
        err = c0_del(c0, kt, seqno);
    else
        err = kvdb_ctxn_del(ctxn, c0, kt);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_DEL, tstart);

    return err;
}

merr_t
ikvs_prefix_del(struct ikvs *kvs, struct hse_kvdb_opspec *os, struct kvs_ktuple *kt, u64 seqno)
{
    struct perfc_set *pkvsl_pc = ikvs_perfc_pkvsl(kvs);
    struct kvdb_ctxn *ctxn = 0;
    u64               tstart;
    merr_t            err;

    tstart = perfc_lat_start(pkvsl_pc);

    if (!kt->kt_hash)
        kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);

    if (os && os->kop_txn)
        ctxn = kvdb_ctxn_h2h(os->kop_txn);

    if (!ctxn)
        err = c0_prefix_del(kvs->ikv_c0, kt, seqno);
    else
        err = kvdb_ctxn_prefix_del(ctxn, kvs->ikv_c0, kt);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_PFX_DEL, tstart);

    return ev(err);
}

/*-  Prefix Probe -----------------------------------------------------*/

merr_t
ikvs_pfx_probe(
    struct ikvs *           kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    u64                     seqno,
    enum key_lookup_res *   res,
    struct kvs_buf *        kbuf,
    struct kvs_buf *        vbuf)
{
    struct perfc_set *pkvsl_pc = ikvs_perfc_pkvsl(kvs);
    struct c0 *       c0 = kvs->ikv_c0;
    struct cn *       cn = kvs->ikv_cn;
    struct kvdb_ctxn *ctxn;
    struct query_ctx  qctx;
    u64               tstart;
    merr_t            err;
    int               i;

    tstart = perfc_lat_start(pkvsl_pc);

    if (ev(kvs->ikv_sfx_len == 0)) {
        hse_log(HSE_ERR "Prefix probe not supported because kvs is "
                        "not suffixed");
        return merr(EINVAL);
    }

    qctx.qtype = QUERY_PROBE_PFX;
    qctx.pos = qctx.ntombs = qctx.seen = 0;

    for (i = 0; i < TT_WIDTH; i++)
        qctx.tomb_tree[i] = RB_ROOT;

    if (!kt->kt_hash)
        kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);

    ctxn = (os && os->kop_txn) ? kvdb_ctxn_h2h(os->kop_txn) : 0;
    if (!ctxn)
        err = c0_pfx_probe(c0, kt, seqno, 0, res, &qctx, kbuf, vbuf);
    else
        err = kvdb_ctxn_pfx_probe(ctxn, c0, cn, kt, res, &qctx, kbuf, vbuf);

    if (*res == FOUND_PTMB || qctx.seen > 1)
        goto done;

    if (!err && (*res == FOUND_VAL || *res == NOT_FOUND)) {
        if (ctxn) {
            err = kvdb_ctxn_get_view_seqno(ctxn, &seqno);
            if (ev(err))
                return err;
        }

        err = cn_pfx_probe(cn, kt, seqno, res, &qctx, kbuf, vbuf);
    }

    if (ev(err))
        return err;

    qctx_te_mem_reset();

done:
    perfc_rec_sample(&kvs->ikv_cd_pc, PERFC_DI_CD_TOMBSPERPROBE, qctx.ntombs);

    switch (qctx.seen) {
        case 0:
            *res = NOT_FOUND;
            break;
        case 1:
            *res = FOUND_VAL;
            break;
        default:
            *res = FOUND_MULTIPLE;
    }

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_PFX_PROBE, tstart);

    return 0;
}

static merr_t
kvs_create(struct ikvs **ikvs_out, struct kvs_rparams *rp)
{
    struct cache_bucket *bkt;
    struct ikvs *        ikvs;
    size_t               sz;
    int                  i, n;
    int                  nmax;

    *ikvs_out = NULL;

    ikvs = alloc_aligned(sizeof(*ikvs), alignof(*ikvs));
    if (ev(!ikvs))
        return merr(ENOMEM);

    memset(ikvs, 0, sizeof(*ikvs));
    ikvs->ikv_rp = *rp;

    nmax = 1024;
    n = NELEM(ikvs->ikv_curcachev) * nmax;
    sz = sizeof(*bkt) * n;

    bkt = alloc_aligned(sz, PAGE_SIZE);
    if (ev(!bkt)) {
        free_aligned(ikvs);
        return merr(ENOMEM);
    }

    memset(bkt, 0, sz);
    ikvs->ikv_curcache_bktmem = bkt;

    for (i = 0; i < NELEM(ikvs->ikv_curcachev); ++i) {
        struct curcache *cca;
        int              j;

        cca = ikvs->ikv_curcachev + i;
        mutex_init(&cca->cca_lock);
        cca->cca_root = RB_ROOT;

        for (j = 0; j < nmax; ++j) {
            ikvs_cursor_bkt_free(cca, bkt);
            ++bkt;
        }
    }

    *ikvs_out = ikvs;

    return 0;
}

static void
kvs_destroy(struct ikvs *kvs)
{
    int i;

    if (ev(!kvs)) {
        assert(kvs);
        return;
    }

    for (i = 0; i < NELEM(kvs->ikv_curcachev); ++i)
        mutex_destroy(&kvs->ikv_curcachev[i].cca_lock);

    free_aligned(kvs->ikv_curcache_bktmem);

    free((void *)kvs->ikv_mpool_name);
    free((void *)kvs->ikv_kvs_name);
    free_aligned(kvs);
}

merr_t
kvs_init(void)
{
    merr_t err;

    if (atomic_inc_return(&kvs_init_ref) > 1)
        return 0;

    err = kvs_cursor_zone_alloc();
    if (ev(err))
        atomic_dec(&kvs_init_ref);

    return err;
}

void
kvs_fini(void)
{
    if (atomic_dec_return(&kvs_init_ref) > 0)
        return;

    kvs_cursor_zone_free();
}
