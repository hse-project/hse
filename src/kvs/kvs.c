/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Exported API of the HSE struct ikvs
 */

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

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/cn_cursor.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cursor.h>

#include "kvs_params.h"

struct mpool;

/*-  Key Value Store  -------------------------------------------------------*/

/**
 * struct cache_bucket - a list of cursors per rb_node
 * @node:     how we link into rb tree
 * @list:     list of cached cursors
 * @oldest:   insertion time (ns) of oldest cursor on %list
 * @cnt:      number of cursors on %list
 * @freeme:   if %true, bucket must be freed via %free()
 */
struct cache_bucket {
    struct rb_node          node;
    struct kvs_cursor_impl *list;
    u64                     oldest;
    int                     cnt;
    bool                    freeme;
} __aligned(SMP_CACHE_BYTES);

struct curcache {
    struct mutex         cca_lock;
    struct rb_root       cca_root;
    struct cache_bucket *cca_bkt_head;
} __aligned(SMP_CACHE_BYTES * 2);

struct ikvs {
    uint             ikv_sfx_len;
    uint             ikv_pfx_len;
    struct c0 *      ikv_c0;
    struct c1 *      ikv_c1;
    struct cn *      ikv_cn;
    struct mpool *   ikv_ds;
    struct perfc_set ikv_pkvsl_pc; /* Public kvs interfaces Lat. */
    struct perfc_set ikv_cc_pc;
    struct perfc_set ikv_cd_pc;

    struct kvs_rparams ikv_rp;

    const char *ikv_kvs_name;
    const char *ikv_mpool_name;
    struct cache_bucket *ikv_curcache_bktmem;

    struct curcache ikv_curcachev[7];
};

struct perfc_name kvs_cc_perfc_op[] = {
    NE(PERFC_BA_CC_RESTORE, 2, "Count of cursor restores", "c_restores"),
    NE(PERFC_BA_CC_ALLOC, 2, "Count of cursor allocations", "c_allocations"),

    NE(PERFC_BA_CC_RETIRE_C0, 3, "Count of cursor retires due to c0 age", "c_ret_c0"),
    NE(PERFC_BA_CC_RETIRE_CN, 3, "Count of cursor retires due to cN age", "c_ret_cN"),
    NE(PERFC_BA_CC_SAVE, 3, "Count of cursor saves", "c_saves"),
    NE(PERFC_BA_CC_SAVE_DESTROY, 3, "Count of cursor restore failures", "c_rest_fails"),
    NE(PERFC_BA_CC_EAGAIN_C0, 3, "Count of c0 EAGAIN's", "c_c0_eagain"),
    NE(PERFC_BA_CC_EAGAIN_CN, 3, "Count of cN EAGAIN's", "c_cN_eagain"),
    NE(PERFC_BA_CC_INIT_CREATE_C0, 3, "Count of c0 cursor init/creates", "c_c0_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_C0, 3, "Count of c0 cursor init/updates", "c_c0_initup"),
    NE(PERFC_BA_CC_INIT_CREATE_CN, 3, "Count of cN cursor init/creates", "c_cN_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_CN, 3, "Count of cN cursor init/updates", "c_cN_initup"),
    NE(PERFC_BA_CC_UPDATED_C0, 3, "Count of c0 cursor updates", "c_c0up"),
    NE(PERFC_BA_CC_UPDATED_CN, 3, "Count of cN cursor updates", "c_cNup"),
    NE(PERFC_BA_CC_DESTROY, 3, "Count of cursor destroys", "c_destroys"),
    NE(PERFC_BA_CC_UPDATE, 3, "Count of cursor updates", "c_updates"),
    NE(PERFC_BA_CC_SEEK, 3, "Count of cursor seeks", "c_seeks"),
    NE(PERFC_BA_CC_SEEK_READ, 3, "Count of cursor replenishes", "c_replenish"),
    NE(PERFC_BA_CC_EOF, 3, "Count of cursor eof", "c_eofs"),
    NE(PERFC_BA_CC_READ_C0, 2, "Count of cursor c0 reads", "c_c0_reads"),
    NE(PERFC_BA_CC_READ_CN, 2, "Count of cursor cN reads", "c_cN_reads"),
    NE(PERFC_BA_CC_TOMB_C0, 3, "Count of cursor c0 tomb reads", "c_c0_tomb_reads"),
    NE(PERFC_BA_CC_TOMB_SPAN, 3, "Count of cursor c0 tomb spans", "c_c0_tombspan"),
    NE(PERFC_BA_CC_TOMB_SPAN_INV, 3, "Count of cursor c0 tomb span inv ", "c_c0_tombspan_inv"),
    NE(PERFC_BA_CC_TOMB_INV_KVMS, 3, "Count of tomb invalidates (kvms) ", "c_c0_tombspan_inv_kvms"),
    NE(PERFC_BA_CC_TOMB_INV_PUTS, 3, "Count of tomb invalidates (puts) ", "c_c0_tombspan_inv_puts"),
    NE(PERFC_BA_CC_TOMB_INV_TXN, 3, "Count of tomb invalidates (txns) ", "c_c0_tombspan_inv_txn"),
    NE(PERFC_BA_CC_TOMB_FLUSH, 3, "Count of tomb c0 flush ", "c_c0_tomb_flush"),
    NE(PERFC_BA_CC_TOMB_SKIPS, 3, "Count of cursor c0 tomb skips", "c_c0_tomb_skips"),
    NE(PERFC_BA_CC_TOMB_SKIPLEN, 3, "Count of cursor c0 tombs skipped (len)", "c_c0_tombs_skipped"),
    NE(PERFC_BA_CC_TOMB_SPAN_ADD, 3, "Count of cursor c0 tombs added to span", "c_c0_tombs_add"),
    NE(PERFC_BA_CC_TOMB_SPAN_TIME, 3, "Tomb span build time since invalidate", "c_c0_tombspan_"
                                                                               "time")
};

NE_CHECK(kvs_cc_perfc_op, PERFC_EN_CC, "cursor cache perfc ops table/enum mismatch");

struct perfc_name kvs_cd_perfc_op[] = {
    NE(PERFC_LT_CD_CREATE_CN, 2, "cn cursor create latency", "c_lat_create_cn", 7),
    NE(PERFC_LT_CD_UPDATE_CN, 2, "cn cursor update latency", "c_lat_update_cn", 7),
    NE(PERFC_LT_CD_READ_CN, 2, "cn cursor read latency", "c_lat_read_cn", 7),
    NE(PERFC_LT_CD_SEEK_CN, 2, "cn cursor seek latency", "c_lat_seek_cn", 7),
    NE(PERFC_LT_CD_CREATE_C0, 2, "c0 cursor create latency", "c_lat_create_c0", 7),
    NE(PERFC_LT_CD_UPDATE_C0, 2, "c0 cursor update latency", "c_lat_update_c0", 7),
    NE(PERFC_LT_CD_READ_C0, 2, "c0 cursor read latency", "c_lat_read_c0", 7),
    NE(PERFC_LT_CD_SEEK_C0, 2, "c0 cursor seek latency", "c_lat_seek_c0", 7),
    NE(PERFC_DI_CD_READPERSEEK, 2, "Cursor reads per seek", "c_dist_readperseek", 7),
    NE(PERFC_DI_CD_TOMBSPERPROBE, 2, "Tombs seens per pfx probe", "c_dist_tombsperprobe", 7),

    NE(PERFC_LT_CD_SAVE, 2, "cursor save latency", "c_lat_save", 7),
    NE(PERFC_LT_CD_RESTORE, 2, "cursor restore latency", "c_lat_restore", 7),

    NE(PERFC_DI_CD_ACTIVEKVSETS_CN, 2, "Active kvsets in the cursor's view", "c_dist_activekvsets"),
};

NE_CHECK(kvs_cd_perfc_op, PERFC_EN_CD, "cursor dist perfc ops table/enum mismatch");

/* "pkvsl" stands for Public KVS interface Latencies" */
struct perfc_name kvs_pkvsl_perfc_op[] = {
    NE(PERFC_LT_PKVSL_KVS_PUT, 3, "kvs_put latency", "kvs_put_lat", 7),
    NE(PERFC_LT_PKVSL_KVS_GET, 3, "kvs_get latency", "kvs_get_lat", 7),
    NE(PERFC_LT_PKVSL_KVS_DEL, 3, "kvs_delete latency", "kvs_del_lat", 7),

    NE(PERFC_LT_PKVSL_KVS_PFX_PROBE, 3, "kvs_prefix_probe latency", "kvs_pfx_probe_lat"),
    NE(PERFC_LT_PKVSL_KVS_PFX_DEL, 3, "kvs_prefix_delete latency", "kvs_pfx_del_lat"),

    NE(PERFC_LT_PKVSL_KVS_CURSOR_CREATE, 3, "kvs_cursor_create latency", "kvs_cursor_create_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_UPDATE, 3, "kvs_cursor_update latency", "kvs_cursor_update_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_SEEK, 3, "kvs_cursor_seek latency", "kvs_cursor_seek_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_READFWD,
       3,
       "kvs_cursor_read forward latency",
       "kvs_cursor_readfwd_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_READREV,
       3,
       "kvs_cursor_read reverse latency",
       "kvs_cursor_readrev_lat"),
    NE(PERFC_LT_PKVSL_KVS_CURSOR_DESTROY,
       3,
       "kvs_cursor_destroy latency",
       "kvs_cursor_destroy_lat"),
};

NE_CHECK(
    kvs_pkvsl_perfc_op,
    PERFC_EN_PKVSL,
    "public kvs interface latencies perfc ops table/enum mismatch");

/*
 * A cursor resides in one of two places, exclusively:
 * the ikvdb_kvs.kk_cursors list if it is active,
 * the ikvs.cursor_cache tree if it is inactive (and cached).
 *
 * Cached cursors may be retired completely after aging sufficiently.
 * Retiring a cursor is simply destroying the underlying object.
 *
 * The kvs_close path must release all cached cursors, but must
 * strip out the underlaying structures of active cursors, marking
 * the cursor with ESTALE.  This allows applications that have read
 * from a cursor to continue to use the key/value pointers in this
 * cursor after the kvs has been closed.
 */

struct curcache_entry {
    u64                     cc_cn_ttl;
    u64                     cc_c0_ttl;
    struct kvs_cursor_impl *cc_next;
};

/**
 * struct kvs_cursor_tombs -
 * @kct_min:          min key in tombstone span
 * @kct_max:          max c0 key in tombstone span
 * @kct_cnmax:        max cn key in tombstone span
 * @kct_min_len:      kct_min key len
 * @kct_max_len:      kct_max key len
 * @kct_cnmax_len:    kct_cnmax key len
 * @kct_seq:          last seqno at which this tombstone span was valid
 * @kct_width:        number of c0 tombstones in this span
 * @kct_start:        time at which this tombstone span was first recorded
 * @kct_update:       set if we need to update the max key (new/updated span)
 * @kct_skip:         set if the cursor seek used this span to skip tombstones
 * @kct_cn_eof:       set if the span was used in the last seek and cn returned eof
 * @kct_valid:        is the tombstone span valid
 */
struct kvs_cursor_tombs {
    char kct_min[HSE_KVS_KLEN_MAX];
    char kct_max[HSE_KVS_KLEN_MAX];
    char kct_cnmax[HSE_KVS_KLEN_MAX];
    u32  kct_min_len;
    u32  kct_max_len;
    u32  kct_cnmax_len;
    u64  kct_seq;
    u64  kct_width;
    u64  kct_start;
    bool kct_update;
    bool kct_skip;
    bool kct_cn_eof;
    bool kct_valid;
};

struct kvs_cursor_impl {
    struct hse_kvs_cursor   kci_handle;
    struct curcache_entry   kci_cache;
    struct perfc_set *      kci_cc_pc;
    struct perfc_set *      kci_cd_pc;
    struct ikvs *           kci_kvs;
    struct c0_cursor *      kci_c0cur;
    struct kvs_cursor_tombs kci_tombs;
    struct cursor_summary   kci_summary;

    /* current values for each cursor read */
    void *             kci_cncur;
    struct kvs_kvtuple kci_c0kv;
    struct kvs_kvtuple kci_cnkv;
    const void *       kci_seekkey;
    u32                kci_seeklen;
    u32                kci_limit_len;
    void *             kci_limit;

    struct kvs_kvtuple *kci_last; /* last tuple read */
    u8 *                kci_last_kbuf;
    u32                 kci_last_klen;

    u32 kci_ready : 2;
    u32 kci_eof : 2;
    u32 kci_seek : 2;
    u32 kci_peek : 1;
    u32 kci_toss : 1;
    u32 kci_reverse : 1;
    u32 kci_unused : 15;
    u32 kci_pfx_len : 8;

    u64    kci_pfxhash;
    merr_t kci_err; /* bad cursor, must destroy */

    char kci_prefix[];
} __aligned(SMP_CACHE_BYTES);

static struct kmem_cache *kvs_cursor_zone;
static atomic_t           kvs_init_ref;

static merr_t
kvs_create(struct ikvs **kvs, struct kvs_rparams *rp);

static void
kvs_destroy(struct ikvs *kvs);

static void
ikvs_cursor_reap(struct ikvs *kvs);

void
kvs_perfc_init(void)
{
    struct perfc_ivl *ivl;
    int               i;
    u64               boundv[PERFC_IVL_MAX];
    merr_t            err;

    /* Allocate interval instance for the distribution counters (pow2). */
    for (i = 0; i < PERFC_IVL_MAX; i++)
        boundv[i] = 1 << i;

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &ivl);
    if (err) {
        hse_elog(HSE_WARNING "cursor perfc, unable to allocate pow2 ivl: @@e", err);
        return;
    }

    kvs_cd_perfc_op[PERFC_DI_CD_READPERSEEK].pcn_ivl = ivl;
    kvs_cd_perfc_op[PERFC_DI_CD_ACTIVEKVSETS_CN].pcn_ivl = ivl;
    kvs_cd_perfc_op[PERFC_DI_CD_TOMBSPERPROBE].pcn_ivl = ivl;
}

void
kvs_perfc_fini(void)
{
    const struct perfc_ivl *ivl;

    ivl = kvs_cd_perfc_op[PERFC_DI_CD_READPERSEEK].pcn_ivl;
    if (ev(!ivl))
        return;

    kvs_cd_perfc_op[PERFC_DI_CD_READPERSEEK].pcn_ivl = 0;
    kvs_cd_perfc_op[PERFC_DI_CD_TOMBSPERPROBE].pcn_ivl = 0;
    kvs_cd_perfc_op[PERFC_DI_CD_ACTIVEKVSETS_CN].pcn_ivl = 0;

    perfc_ivl_destroy(ivl);
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

    if (perfc_ctrseti_alloc(
            COMPNAME, dbname_buf, kvs_cc_perfc_op, PERFC_EN_CC, "set", &kvs->ikv_cc_pc))
        hse_log(HSE_ERR "cannot alloc kvs perf counters");

    if (perfc_ctrseti_alloc(
            COMPNAME, dbname_buf, kvs_cd_perfc_op, PERFC_EN_CD, "set", &kvs->ikv_cd_pc))
        hse_log(HSE_ERR "cannot alloc kvs perf counters");

    /* Measure Public KVS interface Latencies */
    if (perfc_ctrseti_alloc(
            COMPNAME, dbname_buf, kvs_pkvsl_perfc_op, PERFC_EN_PKVSL, "set", &kvs->ikv_pkvsl_pc))
        hse_log(HSE_ERR "cannot alloc kvs perf counters");
}

static void
kvs_perfc_free(struct ikvs *ikvs)
{
    perfc_ctrseti_free(&ikvs->ikv_cc_pc);
    perfc_ctrseti_free(&ikvs->ikv_cd_pc);
    perfc_ctrseti_free(&ikvs->ikv_pkvsl_pc);
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

    ikvdb_get_c1(kvdb, &ikvs->ikv_c1);

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

    if (ikvs->ikv_c1 && !ikvs->ikv_rp.rdonly) {
        err = c1_sync(ikvs->ikv_c1);
        if (err)
            hse_elog(HSE_ERR "%s: c1_sync @@e", err, __func__);
    }

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

    if (unlikely(os && os->kop_txn))
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

/*-  Cursor Support  --------------------------------------------------*/

/*
 * ikvs cursors combine the separate c0, cN and Tx cursors.
 *
 * The underlying cursor reads copy their key and value internally,
 * returning pointers to them.  This allows the underlying strata
 * to change independent of its present iterator position.  This also
 * allows pointers to the cached information to be used without further
 * copies.
 *
 * Thus, each underlying cursor has state:
 *      we either have a cached value (ready)
 *      or we are at eof (eof)
 *      or we need to attempt to read (!ready && !eof)
 *
 * If the ikvs cursor encounters an error from the underlying cursor,
 * the only way to recover is to destroy the ikvs cursor and create another.
 * In particular, update does NOT clear the error state, and no effort is
 * made to attempt to recover a partial cursor.
 */

#define bit_on(x, y) ((cursor->x & y) == y)
enum { BIT_NONE = 0, BIT_C0 = 1, BIT_CN = 2, BIT_BOTH = 3 };

#define cursor_h2r(h) container_of(h, struct kvs_cursor_impl, kci_handle)

#define node2bucket(n) container_of(n, struct cache_bucket, node)

/**
 * ikvs_cursor_bkt_alloc() - allocate a cursor cache node
 * @cca:  ptr to cursor cache
 *
 * Caller must hold the cursor cache lock.
 */
static struct cache_bucket *
ikvs_cursor_bkt_alloc(struct curcache *cca)
{
    struct cache_bucket *bkt;

    bkt = cca->cca_bkt_head;
    if (bkt) {
        cca->cca_bkt_head = *(void **)bkt;
    } else {
        bkt = calloc(1, sizeof(*bkt));
        if (bkt)
            bkt->freeme = true;
        ev(1);
    }

    return bkt;
}

/**
 * ikvs_cursor_bkt_free() - free a cursor cache node
 * @cca:  ptr to cursor cache
 * @bkt:  ptr to bucket to free
 *
 * Caller must hold the cursor cache lock.
 */
static void
ikvs_cursor_bkt_free(struct curcache *cca, struct cache_bucket *bkt)
{
    if (bkt->freeme) {
        free(bkt);
        ev(1);
    } else {
        *(void **)bkt = cca->cca_bkt_head;
        cca->cca_bkt_head = bkt;
    }
}

static void
ikvs_curcache_preen(
    struct curcache *cca,
    struct ikvs *    kvs,
    u64              now,
    uint *           c0_retiredp,
    uint *           cn_retiredp)
{
    struct rb_node *        node;
    struct kvs_cursor_impl *todo;
    uint                    c0_retired;
    uint                    cn_retired;

    c0_retired = 0;
    cn_retired = 0;
    todo = NULL;

    mutex_lock(&cca->cca_lock);
    node = rb_first(&cca->cca_root);

    for (; node; node = rb_next(node)) {
        struct cache_bucket *    b = node2bucket(node);
        struct kvs_cursor_impl **pp;
        u64                      oldest;

        if (now < b->oldest)
            continue;

        /* for each cursor in list */
        oldest = U64_MAX;
        pp = &b->list;

        while (*pp) {
            struct kvs_cursor_impl *cur = *pp;

            if (now >= cur->kci_cache.cc_cn_ttl) {
                --b->cnt;
                *pp = cur->kci_cache.cc_next;
                cur->kci_cache.cc_next = todo;
                todo = cur;
                ++c0_retired;
                ++cn_retired;
                continue;
            }

            /* [HSE_REVISIT] Get this c0_cursor_destroy()
             * call out from under the lock...
             */
            if (now >= cur->kci_cache.cc_c0_ttl) {
                if (cur->kci_c0cur) {
                    cur->kci_cache.cc_c0_ttl = U64_MAX;
                    c0_cursor_destroy(cur->kci_c0cur);
                    cur->kci_c0cur = 0;
                    ++c0_retired;
                }
            }

            if (cur->kci_cache.cc_cn_ttl < oldest)
                oldest = cur->kci_cache.cc_cn_ttl;
            if (cur->kci_cache.cc_c0_ttl < oldest)
                oldest = cur->kci_cache.cc_c0_ttl;

            pp = &(*pp)->kci_cache.cc_next;
        }

        if (b->cnt == 0) {
            rb_erase(node, &cca->cca_root);

            /* iterator now invalid -- catch it next time */
            ikvs_cursor_bkt_free(cca, b);
            break;
        }

        if (oldest > b->oldest)
            b->oldest = oldest;
    }
    mutex_unlock(&cca->cca_lock);

    /* [MU_REVIST] Offload cleanup to a workqueue...
     */
    while (todo) {
        struct kvs_cursor_impl *cur = todo;

        todo = cur->kci_cache.cc_next;
        ikvs_cursor_destroy(&cur->kci_handle);
    }

    *c0_retiredp += c0_retired;
    *cn_retiredp += cn_retired;
}

/*
 * ikvs_maint_task - periodic maintenance on ikvs structures (cursors)
 *
 * This routine must be called periodically to give back resources
 * that have been held too long.  Both c0 and cn have resources claimed
 * by cursors in applications, which may not be cooperative with the
 * underlying needs.  This task works against the cursor cache.
 *
 * HSE_REVISIT:
 * There will be a peer task in ikvdb that works against the active cursors.
 * It will need to call into the working part of this loop.
 *
 * Currently, this function is called with the ikdb_lock held, ugh...
 */
void
ikvs_maint_task(struct ikvs *kvs, u64 now)
{
    uint c0_retired = 0;
    uint cn_retired = 0;
    int  i;

    for (i = 0; i < NELEM(kvs->ikv_curcachev); ++i)
        ikvs_curcache_preen(kvs->ikv_curcachev + i, kvs, now, &c0_retired, &cn_retired);

    if (c0_retired > 0)
        perfc_add(&kvs->ikv_cc_pc, PERFC_BA_CC_RETIRE_C0, c0_retired);
    if (cn_retired > 0)
        perfc_add(&kvs->ikv_cc_pc, PERFC_BA_CC_RETIRE_CN, cn_retired);

    cn_periodic(kvs->ikv_cn, now);
}

/*
 * for each node in tree: remove from tree, destroy cursor
 *
 * the rb_erase invalidates iteration, thus we loop on
 * the first entry, hoping this minimizes rebalancing
 *
 * NB: since reap is called during close, it is not a problem
 * to keep the tree locked at this point
 */
static void
ikvs_cursor_reap(struct ikvs *kvs)
{
    struct curcache *cca;
    struct rb_node * node;
    int              i;

    for (i = 0; i < NELEM(kvs->ikv_curcachev); ++i) {
        cca = kvs->ikv_curcachev + i;

        mutex_lock(&cca->cca_lock);
        node = rb_first(&cca->cca_root);

        while (node) {
            struct cache_bucket *b = node2bucket(node);

            while (b->list) {
                struct kvs_cursor_impl *cur = b->list;

                b->list = cur->kci_cache.cc_next;
                ikvs_cursor_destroy(&cur->kci_handle);
            }

            rb_erase(node, &cca->cca_root);
            ikvs_cursor_bkt_free(cca, b);

            node = rb_first(&cca->cca_root);
        }
        mutex_unlock(&cca->cca_lock);
    }
}

static struct curcache *
ikvs_td2cca(struct ikvs *kvs, u64 pfxhash)
{
    u64 i = pfxhash ?: pthread_self();

    return kvs->ikv_curcachev + (i % NELEM(kvs->ikv_curcachev));
}

static int
ikvs_curcache_cmp(
    const struct kvs_cursor_impl *cur,
    const void *                  prefix,
    size_t                        pfx_len,
    bool                          reverse)
{
    if (reverse && !cur->kci_reverse)
        return -1;
    else if (!reverse && cur->kci_reverse)
        return 1;

    if (prefix && !cur->kci_prefix)
        return -1;
    else if (!prefix && cur->kci_prefix)
        return 1;

    if (!prefix && !cur->kci_prefix)
        return 0;

    return keycmp(prefix, pfx_len, cur->kci_prefix, cur->kci_pfx_len);
}

static struct kvs_cursor_impl *
ikvs_curcache_insert(struct curcache *cca, struct kvs_cursor_impl *cur)
{
    struct rb_node **       link, *parent;
    struct rb_root *        root;
    struct kvs_cursor_impl *old;
    struct cache_bucket *   b;
    int                     rc;

    mutex_lock(&cca->cca_lock);
    root = &cca->cca_root;
    link = &root->rb_node;
    parent = 0;

    while (*link) {
        parent = *link;
        old = node2bucket(parent)->list;

        rc = ikvs_curcache_cmp(old, cur->kci_prefix, cur->kci_pfx_len, cur->kci_reverse);
        if (rc < 0)
            link = &(*link)->rb_left;
        else if (rc > 0)
            link = &(*link)->rb_right;
        else
            break;
    }

    /*
     * if *link, this is the cursor to replace
     * else cursor does not exist, and this is insert point
     */

    if (*link) {
        b = node2bucket(parent);
        cur->kci_cache.cc_next = b->list;
        b->list = cur;
        ++b->cnt;
        cur = NULL;
    } else {
        b = ikvs_cursor_bkt_alloc(cca);
        if (b) {
            b->list = cur;
            b->cnt = 1;
            b->oldest = cur->kci_cache.cc_cn_ttl;
            cur->kci_cache.cc_next = 0;

            rb_link_node(&b->node, parent, link);
            rb_insert_color(&b->node, root);
            cur = NULL;
        }
    }
    mutex_unlock(&cca->cca_lock);

    return cur;
}

static struct kvs_cursor_impl *
ikvs_curcache_remove(struct curcache *cca, const void *prefix, size_t pfx_len, bool reverse)
{
    struct rb_node *        node;
    struct kvs_cursor_impl *cur;
    struct cache_bucket *   b;
    int                     rc;

    mutex_lock(&cca->cca_lock);
    node = cca->cca_root.rb_node;
    cur = NULL;
    b = 0;

    while (node) {
        b = node2bucket(node);
        cur = b->list;

        rc = ikvs_curcache_cmp(cur, prefix, pfx_len, reverse);
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else
            break;
    }

    if (node) {
        assert(b);
        b->list = cur->kci_cache.cc_next;
        cur->kci_cache.cc_next = 0;
        --b->cnt;
        if (b->list == 0) {
            rb_erase(node, &cca->cca_root);
            ikvs_cursor_bkt_free(cca, b);
        }
    } else {
        cur = NULL;
    }
    mutex_unlock(&cca->cca_lock);

    return cur;
}

static void
ikvs_cursor_reset(struct kvs_cursor_impl *cursor, int bit)
{
    struct ikvs *kvs = cursor->kci_kvs;

    cursor->kci_ready &= ~bit;
    cursor->kci_eof &= ~bit;
    cursor->kci_seek &= ~bit;
    cursor->kci_peek &= ~bit;
    cursor->kci_toss = 1;

    cursor->kci_cc_pc = NULL;
    cursor->kci_cd_pc = NULL;

    if (kvs->ikv_rp.kvs_debug & 16)
        cursor->kci_cc_pc = &kvs->ikv_cc_pc;
    if (kvs->ikv_rp.kvs_debug & 32)
        cursor->kci_cd_pc = &kvs->ikv_cd_pc;
}

__attribute__((__noinline__))
static struct kvs_cursor_impl *
ikvs_cursor_restore(struct ikvs *kvs, const void *prefix, size_t pfx_len, u64 pfxhash, bool reverse)
{
    struct kvs_cursor_impl *cur;
    struct curcache *       cca;
    u64                     tstart;

    tstart = perfc_lat_startu(&kvs->ikv_cd_pc, PERFC_LT_CD_RESTORE);

    cca = ikvs_td2cca(kvs, pfxhash);
    cur = ikvs_curcache_remove(cca, prefix, pfx_len, reverse);
    if (!cur)
        return NULL;

    perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_RESTORE, tstart);

    if (cur->kci_c0cur) {
        struct c0_cursor *c0cur = cur->kci_c0cur;
        merr_t            err;

        err = c0_cursor_restore(c0cur);
        if (ev(err)) {
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_SAVE_DESTROY);
            ikvs_cursor_destroy(&cur->kci_handle);
            return 0;
        }
    }

    return cur;
}

static void
cursor_summary_log(struct kvs_cursor_impl *cur)
{
    struct cursor_summary *s = &cur->kci_summary;
    char                   buf[512], gbuf[128], ctime[32], utime[32], pfx[32];
    int                    i, j, o;

    o = 0;
    i = s->n_dgen & 3;

    if (cur->kci_pfx_len)
        fmt_hex(pfx, sizeof(pfx), cur->kci_prefix, cur->kci_pfx_len);
    else
        strlcpy(pfx, "(null)", sizeof(pfx));

    if (s->dgen[i]) {
        /* dgen buffer has wrapped */
        for (j = 0; j < 4; ++j) {
            o += sprintf(gbuf + o, "%lu,", (ulong)s->dgen[i]);
            i = (i + 1) & 3;
        }
    } else {
        for (j = 0; j < i; ++j)
            o += sprintf(gbuf + o, "%lu,", (ulong)s->dgen[j]);
        if (i == 0)
            o += sprintf(gbuf + o, "%u,", 0);
    }
    gbuf[--o] = 0;

    fmt_time(ctime, sizeof(ctime), s->created);
    fmt_time(utime, sizeof(utime), s->updated);

    snprintf(
        buf,
        sizeof(buf),
        "skidx %d pfx %s len %d created %s updated %s dgen %s "
        "view 0x%lu readc0 %u readcn %u kvms %u kvset %u "
        "ingest %u trim %u bind %u upd %u eof %d",
        s->skidx,
        pfx,
        cur->kci_pfx_len,
        ctime,
        utime,
        gbuf,
        (ulong)s->seqno,
        s->read_c0,
        s->read_cn,
        s->n_kvms,
        s->n_kvset,
        s->n_dgen,
        s->n_trim,
        s->n_bind,
        s->n_update,
        cur->kci_eof);

    hse_log(HSE_NOTICE "cursor: %p %s", cur, buf);
}

static void
_perfc_readperseek_record(struct kvs_cursor_impl *cur)
{
    if (!cur->kci_summary.util)
        return;

    perfc_rec_sample(cur->kci_cd_pc, PERFC_DI_CD_READPERSEEK, cur->kci_summary.util);
    cur->kci_summary.util = 0;
}

static void
ikvs_cursor_save(struct kvs_cursor_impl *cur)
{
    struct perfc_set *cc_pc, *cd_pc;
    struct curcache * cca;
    struct ikvs *     kvs = cur->kci_kvs;
    merr_t            err;
    u64               tstart;
    u64               now;
    u64               c0_age, cn_age;

    if (unlikely(kvs->ikv_rp.kvs_debug & 64)) {
        cursor_summary_log(cur);
        _perfc_readperseek_record(cur);
    }

    cd_pc = cur->kci_cd_pc;
    cc_pc = cur->kci_cc_pc;

    /* this is how cursor caching is disabled */
    c0_age = kvs->ikv_rp.c0_cursor_ttl;
    cn_age = kvs->ikv_rp.cn_cursor_ttl;

    if (cn_age == 0 || c0_age == 0)
        goto discard;

    err = c0_cursor_save(cur->kci_c0cur);
    if (ev(err))
        goto discard;

    /*
     * theory: this cursor has a more recent set of resources than
     * a cached cursor, so release the older resources and replace
     * with the more current
     */
    tstart = perfc_lat_start(cd_pc);
    now = tstart ?: get_time_ns();
    cur->kci_cache.cc_cn_ttl = now + cn_age * 1048576;
    cur->kci_cache.cc_c0_ttl = now + c0_age * 1048576;

    cca = ikvs_td2cca(kvs, cur->kci_pfxhash);
    cur = ikvs_curcache_insert(cca, cur);

    /*
     * NB: it is unsafe to use cur after the unlock, because
     * ikvs_maint_task may destroy it if we lose our context;
     * remember kvs before we insert cur, and use kvs after
     * since the kvs will remain addressable during this call.
     */
    perfc_lat_record(cd_pc, PERFC_LT_CD_SAVE, tstart);
    perfc_inc(cc_pc, PERFC_BA_CC_SAVE);

discard:
    if (cur) {
        perfc_inc(cc_pc, PERFC_BA_CC_SAVE_DESTROY);
        ikvs_cursor_destroy(&cur->kci_handle);
    }
}

struct hse_kvs_cursor *
ikvs_cursor_alloc(struct ikvs *kvs, const void *prefix, size_t pfx_len, bool reverse)
{
    struct kvs_cursor_impl *cur;
    size_t                  len;
    u64                     pfxhash;

    pfxhash = (prefix && pfx_len > 0) ? key_hash64(prefix, pfx_len) : 0;

    cur = ikvs_cursor_restore(kvs, prefix, pfx_len, pfxhash, reverse);
    if (cur) {
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_RESTORE);

        /*
         * A cached cursor's state must be reset.
         * To avoid a redundant seek, set the seek flag:
         * if read is next operation, must seek to start,
         * else if seek is done, already at correct location
         */
        ikvs_cursor_reset(cur, BIT_BOTH);

        return &cur->kci_handle;
    }

    len = reverse ? HSE_KVS_KLEN_MAX : pfx_len;

    cur = kmem_cache_alloc(kvs_cursor_zone);
    if (ev(!cur))
        return NULL;

    memset(cur, 0, sizeof(*cur));
    if (kvs->ikv_rp.kvs_debug & 16)
        cur->kci_cc_pc = &kvs->ikv_cc_pc;
    if (kvs->ikv_rp.kvs_debug & 32)
        cur->kci_cd_pc = &kvs->ikv_cd_pc;
    cur->kci_kvs = kvs;
    cur->kci_pfx_len = pfx_len;
    cur->kci_pfxhash = pfxhash;
    if (prefix)
        memcpy(cur->kci_prefix, prefix, pfx_len);

    cur->kci_last_kbuf = (void *)cur->kci_prefix + len;
    cur->kci_limit = (void *)cur->kci_last_kbuf + HSE_KVS_KLEN_MAX;
    cur->kci_limit_len = 0;
    cur->kci_handle.kc_filter.kcf_maxkey = 0;
    cur->kci_toss = 1;

    /*
     * Store the key to seek to, for cached cursors.
     * For forward cached cursors, seek to the cursor prefix.
     * For reverse ones, seek to the largest key matching the cursor prefix.
     */
    if (reverse)
        memset(cur->kci_prefix + pfx_len, 0xFF, HSE_KVS_KLEN_MAX - pfx_len);

    cur->kci_reverse = reverse;

    perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_ALLOC);

    return &cur->kci_handle;
}

void
ikvs_cursor_free(struct hse_kvs_cursor *cursor)
{
    if (cursor->kc_err)
        ikvs_cursor_destroy(cursor);
    else
        ikvs_cursor_save(cursor_h2r(cursor));
}

static __always_inline u64
                       now(void)
{
    struct timespec ts;

    get_realtime(&ts);

    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void
ikvs_cursor_tombs_invalidate(struct kvs_cursor_impl *cursor)
{
    struct kvs_cursor_tombs *tombs = &cursor->kci_tombs;

    tombs->kct_valid = false;
    tombs->kct_cn_eof = false;
    tombs->kct_update = false;
    tombs->kct_max_len = 0;
    tombs->kct_min_len = 0;
    tombs->kct_cnmax_len = 0;
    perfc_inc(&cursor->kci_kvs->ikv_cc_pc, PERFC_BA_CC_TOMB_SPAN_INV);
    perfc_set(
        cursor->kci_cc_pc, PERFC_BA_CC_TOMB_SPAN_TIME, (get_time_ns() - tombs->kct_start) / 1000);
}

static void
ikvs_cursor_tombs_update(struct kvs_cursor_impl *cur, u32 flags)
{
    if (!(flags & CURSOR_FLAG_TOMBS_INV_KVMS) && !(flags & CURSOR_FLAG_TOMBS_INV_PUTS))
        return;

    ikvs_cursor_tombs_invalidate(cur);

    if (flags & CURSOR_FLAG_TOMBS_INV_KVMS)
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_TOMB_INV_KVMS);
    if (flags & CURSOR_FLAG_TOMBS_INV_PUTS)
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_TOMB_INV_PUTS);
    if (flags & CURSOR_FLAG_TOMBS_FLUSH)
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_TOMB_FLUSH);
}

merr_t
ikvs_cursor_init(struct hse_kvs_cursor *cursor)
{
    struct kvs_cursor_impl *cur = cursor_h2r(cursor);
    struct ikvs *           kvs = cur->kci_kvs;
    void *                  c0 = kvs->ikv_c0;
    void *                  cn = kvs->ikv_cn;
    u64                     seqno = cursor->kc_seq;
    merr_t                  err = 0;
    u32                     flags;
    bool                    updated;
    struct kvs_ktuple       kt_min, kt_max;
    struct kvs_ktuple *     tmin = 0, *tmax = 0;
    u64                     tstart;

    /* no context: update must seek to beginning */
    cur->kci_last = 0;

    /* summaries are only useful if debugging is enabled */
    if (kvs->ikv_rp.kvs_debug & 64) {
        memset(&cur->kci_summary, 0, sizeof(cur->kci_summary));
        cur->kci_summary.addr = cur;
        cur->kci_summary.seqno = seqno;
        cur->kci_summary.created = now();
    }

    if (!cur->kci_c0cur) {
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_CREATE_C0);

        tstart = perfc_lat_start(cur->kci_cd_pc);
        err = c0_cursor_create(
            c0,
            seqno,
            cur->kci_reverse,
            cur->kci_prefix,
            cur->kci_pfx_len,
            &cur->kci_summary,
            &cur->kci_c0cur);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_CREATE_C0, tstart);
    } else {
        /* Check that the cursor can see the tombspan valid at kct_seqno. */
        if (unlikely(cur->kci_tombs.kct_valid)) {
            if (seqno >= cur->kci_tombs.kct_seq) {
                kt_min.kt_data = cur->kci_tombs.kct_min;
                kt_min.kt_len = cur->kci_tombs.kct_min_len;
                kt_max.kt_data = cur->kci_tombs.kct_max;
                kt_max.kt_len = cur->kci_tombs.kct_max_len;
                tmin = &kt_min;
                tmax = &kt_max;
            } else {
                ikvs_cursor_tombs_invalidate(cur);
            }
        }

        tstart = perfc_lat_start(cur->kci_cd_pc);
        err = c0_cursor_update(cur->kci_c0cur, seqno, tmin, tmax, &flags);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_C0, tstart);

        if (flags & CURSOR_FLAG_SEQNO_CHANGE)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_UPDATE_C0);

        if (unlikely(cur->kci_tombs.kct_valid))
            ikvs_cursor_tombs_update(cur, flags);

        cur->kci_seek |= BIT_C0; /* lazy init, must seek */
    }
    if (ev(err)) {
        if (merr_errno(err) == EAGAIN)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_EAGAIN_C0);
        goto error;
    }

    if (!cur->kci_cncur) {
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_CREATE_CN);

        tstart = perfc_lat_start(cur->kci_cd_pc);
        err = cn_cursor_create(
            cn,
            seqno,
            cur->kci_reverse,
            cur->kci_prefix,
            cur->kci_pfx_len,
            &cur->kci_summary,
            &cur->kci_cncur);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_CREATE_CN, tstart);
    } else {
        tstart = perfc_lat_start(cur->kci_cd_pc);
        err = cn_cursor_update(cur->kci_cncur, seqno, &updated);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_CN, tstart);

        if (updated)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_UPDATE_CN);
        cur->kci_seek |= BIT_CN;
    }
    if (ev(merr_errno(err) == EAGAIN))
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_EAGAIN_CN);

    if (!err) {
        u32 active, total;

        cn_cursor_active_kvsets(cur->kci_cncur, &active, &total);
        perfc_rec_sample(cur->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN, active);
    }

error:
    cursor->kc_err = err;
    return err;
}

void
ikvs_cursor_tombspan_check(struct hse_kvs_cursor *handle)
{
    struct kvs_cursor_impl * cursor = (void *)handle;
    struct kvdb_ctxn_bind *  bind = handle->kc_bind;
    struct kvs_cursor_tombs *tombs = &cursor->kci_tombs;

    /*
     * The tombspan is detected and updated by the cursor. The transaction
     * that this cursor is bound to may still be active/aborted/committed.
     * Preserve the tombspan only if it committed; or if it aborted and no
     * changes were made within the transaction.
     * Note the seqno at which this tombstone span is still valid.
     * This is to guard against invalid tombspan extension (newly read
     * tombstones that haven't committed yet as per the cursor's view).
     * The tombspan is validated prior to use in cursor_update.
     */
    if (unlikely(tombs->kct_valid && bind && bind->b_update)) {
        tombs->kct_seq = bind->b_seq;
        if (!bind->b_preserve) {
            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_TOMB_INV_TXN);
            ikvs_cursor_tombs_invalidate(cursor);
        }
    }
}

merr_t
ikvs_cursor_bind_txn(struct hse_kvs_cursor *handle, struct kvdb_ctxn *ctxn)
{
    struct kvs_cursor_impl *cursor = (void *)handle;
    merr_t                  err;

    if (ev(!cursor->kci_c0cur))
        return merr(ENXIO);

    ++cursor->kci_summary.n_bind;
    err = c0_cursor_bind_txn(cursor->kci_c0cur, ctxn);

    if (ev(merr_errno(err) == EAGAIN))
        perfc_inc(&cursor->kci_kvs->ikv_cc_pc, PERFC_BA_CC_EAGAIN_C0);

    return err;
}

void
ikvs_cursor_destroy(struct hse_kvs_cursor *handle)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_DESTROY);

    if (handle->kc_bind)
        kvdb_ctxn_cursor_unbind(handle->kc_bind);
    if (cursor->kci_c0cur)
        c0_cursor_destroy(cursor->kci_c0cur);

    if (cursor->kci_cncur)
        cn_cursor_destroy(cursor->kci_cncur);

    kmem_cache_free(kvs_cursor_zone, cursor);
}

merr_t
ikvs_cursor_update(struct hse_kvs_cursor *handle, u64 seqno)
{
    struct kvs_cursor_impl *cursor = (void *)handle;
    struct kvdb_ctxn_bind * bind = handle->kc_bind;
    struct kvs_ktuple       kt_min, kt_max;
    struct kvs_ktuple *     tmin = 0, *tmax = 0;
    u32                     flags;
    bool                    updated;
    u64                     tstart;

    perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATE);

    ++cursor->kci_summary.n_update;
    cursor->kci_summary.seqno = seqno;
    cursor->kci_summary.updated = now();

    _perfc_readperseek_record(cursor);

    if (bind)
        handle->kc_gen = atomic64_read(&bind->b_gen);

    /* Check that this cursor can see the tombspan committed at kct_seq. */
    if (unlikely(cursor->kci_tombs.kct_valid)) {
        if (seqno >= cursor->kci_tombs.kct_seq) {
            kt_min.kt_data = cursor->kci_tombs.kct_min;
            kt_min.kt_len = cursor->kci_tombs.kct_min_len;
            kt_max.kt_data = cursor->kci_tombs.kct_max;
            kt_max.kt_len = cursor->kci_tombs.kct_max_len;
            tmin = &kt_min;
            tmax = &kt_max;
        } else {
            ikvs_cursor_tombs_invalidate(cursor);
        }
    }

    tstart = perfc_lat_start(cursor->kci_cd_pc);
    cursor->kci_err = c0_cursor_update(cursor->kci_c0cur, seqno, tmin, tmax, &flags);
    if (ev(cursor->kci_err)) {
        if (merr_errno(cursor->kci_err) == EAGAIN)
            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_EAGAIN_C0);
        return cursor->kci_err;
    }
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_C0, tstart);

    if (flags & CURSOR_FLAG_SEQNO_CHANGE)
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATED_C0);

    if (unlikely(cursor->kci_tombs.kct_valid))
        ikvs_cursor_tombs_update(cursor, flags);

    /*
     * c0 updates:
     * a) may have added a new key to an active kvms
     *    fix is to reset eof and try again
     * b) may have regressed the view seqno, and cached key no longer vis
     *    fix is to toss the cached key and re-seek to find visible
     * c) may have changed the visible value for the cached key
     *    fix is to seek after update
     */
    cursor->kci_eof &= ~BIT_BOTH;
#if 0
    if (updated) {
        cursor->kci_ready &= ~BIT_C0;
        cursor->kci_seek |= BIT_C0;
    }
#else
    /* HSE_REVISIT: there MUST be a way to know if this is necessary */
    cursor->kci_ready &= ~BIT_C0;
    cursor->kci_seek |= BIT_C0;
#endif

    /*
     * cn updates:
     * a) all the iterators may have changed, and cn is not presently
     *    positionally stable: force a seek if it changed
     * b) if view seqno was updated, but no ingest, still need to
     *    update the wbt iterators, because new keys may become visible
     */
    tstart = perfc_lat_start(cursor->kci_cd_pc);
    cursor->kci_err = cn_cursor_update(cursor->kci_cncur, seqno, &updated);
    if (ev(cursor->kci_err)) {
        if (merr_errno(cursor->kci_err) == EAGAIN)
            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_EAGAIN_CN);

        return cursor->kci_err;
    }
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_CN, tstart);

    if (updated) {
        u32 active, total;

        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATED_CN);

        cursor->kci_ready &= ~BIT_CN;
        cursor->kci_seek |= BIT_CN;

        cn_cursor_active_kvsets(cursor->kci_cncur, &active, &total);
        perfc_rec_sample(cursor->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN, active);
    }

    return 0;
}

merr_t
ikvs_cursor_seek(
    struct hse_kvs_cursor *handle,
    const void *           key,
    u32                    len,
    const void *           limit,
    u32                    limit_len,
    struct kvs_ktuple *    kt)
{
    struct kvs_cursor_impl * cursor = (void *)handle;
    struct kvs_cursor_tombs *tombs = &cursor->kci_tombs;
    struct kvs_kvtuple       kvt;
    bool                     eof;
    void *                   kmin, *kmax;
    u32                      kmin_len, kmax_len, cn_klen;
    const void *             cnkey;
    u64                      tstart;
    u32                      active, total;

    if (limit_len > HSE_KVS_KLEN_MAX)
        return merr(EINVAL);

    if (ev(cursor->kci_err)) {
        if (ev(merr_errno(cursor->kci_err) != EAGAIN))
            return cursor->kci_err;

        cursor->kci_err = 0;
    }

    perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_SEEK);

    /* invalidate the cached results, resets eof */
    ikvs_cursor_reset(cursor, BIT_BOTH);

    if (limit && limit_len) {
        memcpy(cursor->kci_limit, limit, limit_len);
        handle->kc_filter.kcf_maxkey = cursor->kci_limit;
        handle->kc_filter.kcf_maxklen = cursor->kci_limit_len = limit_len;
    } else {
        handle->kc_filter.kcf_maxkey = NULL;
        handle->kc_filter.kcf_maxklen = 0;
    }

    if (ev(cursor->kci_reverse && handle->kc_filter.kcf_maxkey))
        return merr(EINVAL);

    if (!key) {
        key = cursor->kci_prefix;
        len = cursor->kci_reverse ? HSE_KVS_KLEN_MAX : cursor->kci_pfx_len;
    }

    cnkey = cursor->kci_seekkey = key;
    cn_klen = cursor->kci_seeklen = len;
    tombs->kct_skip = false;

    if (unlikely(tombs->kct_valid)) {
        kmin = cursor->kci_tombs.kct_min;
        kmin_len = cursor->kci_tombs.kct_min_len;
        kmax = cursor->kci_tombs.kct_max;
        kmax_len = cursor->kci_tombs.kct_max_len;

        /*
         * If the key that we are seeking to is the min of the current
         * tombstone span, seek to the max span key. This is safe if this
         * transaction hasn't made any mutations. We may also seek to a
         * distinct key in cn (if larger)/set EOF based on the results
         * of the last seek during which this tombspan was valid.
         */
        if (!keycmp(tombs->kct_min, tombs->kct_min_len, key, len)) {
            if (c0_cursor_ctxn_preserve_tombspan(
                    cursor->kci_c0cur, kmin, kmin_len, kmax, kmax_len)) {
                key = tombs->kct_max;
                len = tombs->kct_max_len;
                if (keycmp(tombs->kct_cnmax, tombs->kct_cnmax_len, key, len) <= 0) {
                    cnkey = tombs->kct_max;
                    cn_klen = tombs->kct_max_len;
                } else {
                    /* Seek to the last cn key, if larger. */
                    cnkey = tombs->kct_cnmax;
                    cn_klen = tombs->kct_cnmax_len;
                }

                /* We hit an EOF in cn cursor during the last seek. */
                if (tombs->kct_cn_eof)
                    cursor->kci_eof |= BIT_CN;

                tombs->kct_skip = true;
                perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_TOMB_SKIPS);
                perfc_add(cursor->kci_cc_pc, PERFC_BA_CC_TOMB_SKIPLEN, tombs->kct_width);
            } else {
                perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_TOMB_INV_PUTS);
                ikvs_cursor_tombs_invalidate(cursor);
            }
        }
    }

    tstart = perfc_lat_start(cursor->kci_cd_pc);
    cursor->kci_err = c0_cursor_seek(
        cursor->kci_c0cur, key, len, handle->kc_filter.kcf_maxkey ? &handle->kc_filter : 0, 0);

    if (ev(cursor->kci_err)) {
        if (merr_errno(cursor->kci_err) == EAGAIN)
            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_EAGAIN_C0);

        return cursor->kci_err;
    }
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_SEEK_C0, tstart);

    /*
     * HSE_REVISIT:
     * make cn_cursor_seek lazy: if c0 finds exact, remember it
     * for the next read operation and then seek cn
     */

    tstart = perfc_lat_start(cursor->kci_cd_pc);
    cursor->kci_err = cn_cursor_seek(
        cursor->kci_cncur,
        cnkey,
        cn_klen,
        handle->kc_filter.kcf_maxkey ? &handle->kc_filter : 0,
        0);

    if (ev(cursor->kci_err))
        return cursor->kci_err;
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_SEEK_CN, tstart);

    /* Record cursor reads since last create/update/seek and reset util */
    _perfc_readperseek_record(cursor);

    /*
     * Consider these order of operations:
     *  put a=1; del a; cursor_create; seek a; read
     * Seek does not do a merge, and cannot skip tombstones.
     * However, the found key may be a tombstone, which should not
     * be reported to the user.
     *
     * Further, seek must remember the key found to handle the use case:
     * seek / update / read.
     *
     * This requires doing a peek (read) operation to merge and
     * properly remove tombstones.  See ikvdb_kvs_cursor_read.
     *
     * NB: cursor->last is maintained by ikvs_cursor_read, which
     * is always called, thus last is correct even for seeks!
     */

    cursor->kci_peek = 1;
    tombs->kct_update = false;
    ikvs_cursor_read(handle, &kvt, &eof);
    if (eof || ev(cursor->kci_err)) {
        if (unlikely(cursor->kci_tombs.kct_valid))
            ikvs_cursor_tombs_invalidate(cursor);
        if (kt)
            kt->kt_len = 0;
        return cursor->kci_err;
    }
    /* Do not count the sacrificial read towards cursor utilization */
    cursor->kci_summary.util--;

    if (kt) {
        kt->kt_data = kvt.kvt_key.kt_data;
        kt->kt_len = kvt.kvt_key.kt_len;
    }

    cn_cursor_active_kvsets(cursor->kci_cncur, &active, &total);
    perfc_rec_sample(cursor->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN, active);

    if (unlikely(tombs->kct_update)) {
        /*
         * Set max key for a new span or expand an existing one.
         * If a span is expanded, the key sought to must be larger.
         */
        assert(
            !tombs->kct_skip ||
            keycmp(kvt.kvt_key.kt_data, kvt.kvt_key.kt_len, tombs->kct_max, tombs->kct_max_len) >=
                0);
        tombs->kct_max_len = kvt.kvt_key.kt_len;
        memcpy(tombs->kct_max, kvt.kvt_key.kt_data, kvt.kvt_key.kt_len);

        /*
         * Since we detected new tombstones, we must confirm the bound transaction commits
         * the tombstones for this expanded span to be valid.
         */
        if (handle->kc_bind)
            handle->kc_bind->b_update = true;
        tombs->kct_update = false;
    }

    /* This flag is used to prevent tossing the last read key in this seek
     * when this seek is followed by update and read. A call to read will
     * perform a seek only when it's preceded by an update or create. In other
     * words, when read sees this flag set, the order of operations has been
     * [seek, update, read] and it should skip tossing the key.
     */
    cursor->kci_toss = 0;
    return 0;
}

static inline int
pfx_cmp(struct kvs_cursor_impl *cursor)
{
    return keycmp(
        cursor->kci_c0kv.kvt_key.kt_data,
        cursor->kci_c0kv.kvt_key.kt_len,
        cursor->kci_cnkv.kvt_key.kt_data,
        cursor->kci_c0kv.kvt_key.kt_len);
}

static inline int
cursor_cmp(struct kvs_cursor_impl *cursor)
{
    return keycmp(
        cursor->kci_c0kv.kvt_key.kt_data,
        cursor->kci_c0kv.kvt_key.kt_len,
        cursor->kci_cnkv.kvt_key.kt_data,
        cursor->kci_cnkv.kvt_key.kt_len);
}

static merr_t
ikvs_cursor_replenish_impl(struct kvs_cursor_impl *cursor, int bit)
{
    struct perfc_set *cc_pc, *cd_pc;
    merr_t            err;
    bool              toss = false;
    bool              eof;

    const void *key;
    int         klen;
    bool        need_seek = (cursor->kci_seek & bit) == bit;
    u64         tstart;

    cc_pc = cursor->kci_cc_pc;
    cd_pc = cursor->kci_cd_pc;

    /*
     * If this was a cached cursor, and no seek was done,
     * make it look like a newly created cursor by seeking to the start.
     *
     * If this was an updated cursor, reposition the cursor to the
     * last found key, and toss it if found.
     */
    if (need_seek) {
        struct kvs_kvtuple *last = cursor->kci_last;

        if (last) {
            key = cursor->kci_last_kbuf;
            klen = cursor->kci_last_klen;
        } else {
            /*
             * Seek to the min/max key that matches the cursor
             * prefix based on cursor direction.
             */
            key = cursor->kci_prefix;
            if (!cursor->kci_reverse)
                klen = cursor->kci_pfx_len;
            else
                klen = HSE_KVS_KLEN_MAX;
        }

        perfc_inc(cc_pc, PERFC_BA_CC_SEEK_READ);

        tstart = perfc_lat_start(cd_pc);

        if (bit == BIT_C0) {
            err = c0_cursor_seek(cursor->kci_c0cur, key, klen, 0, 0);
            perfc_lat_record(cd_pc, PERFC_LT_CD_SEEK_C0, tstart);
            if (ev(merr_errno(err) == EAGAIN))
                perfc_inc(cc_pc, PERFC_BA_CC_EAGAIN_C0);
        } else {
            err = cn_cursor_seek(cursor->kci_cncur, key, klen, 0, 0);
            perfc_lat_record(cd_pc, PERFC_LT_CD_SEEK_CN, tstart);
            if (ev(merr_errno(err) == EAGAIN))
                perfc_inc(cc_pc, PERFC_BA_CC_EAGAIN_CN);
        }
        if (ev(err))
            return err;

        cursor->kci_seek &= ~bit;
    }

repeat:
    tstart = perfc_lat_start(cd_pc);

    if (bit == BIT_C0) {
        err = c0_cursor_read(cursor->kci_c0cur, &cursor->kci_c0kv, &eof);
        perfc_lat_record(cd_pc, PERFC_LT_CD_READ_C0, tstart);

        key = cursor->kci_c0kv.kvt_key.kt_data;
        klen = cursor->kci_c0kv.kvt_key.kt_len;

        if (ev(merr_errno(err) == EAGAIN))
            perfc_inc(cc_pc, PERFC_BA_CC_EAGAIN_C0);
    } else {
        err = cn_cursor_read(cursor->kci_cncur, &cursor->kci_cnkv, &eof);
        perfc_lat_record(cd_pc, PERFC_LT_CD_READ_CN, tstart);

        key = cursor->kci_cnkv.kvt_key.kt_data;
        klen = cursor->kci_cnkv.kvt_key.kt_len;

        if (ev(merr_errno(err) == EAGAIN))
            perfc_inc(cc_pc, PERFC_BA_CC_EAGAIN_CN);
    }

    /* If we needed to seek, toss read key if it matches last and kci_toss is true */
    if (need_seek && cursor->kci_last) {
        if (!keycmp(key, klen, cursor->kci_last_kbuf, cursor->kci_last_klen) &&
            cursor->kci_toss)
            toss = true;
    }

    if (eof)
        cursor->kci_eof |= bit;
    else if (!err)
        cursor->kci_ready |= bit;

    if (toss && (cursor->kci_ready & bit)) {
        toss = false;
        cursor->kci_ready &= ~bit;
        goto repeat;
    }

    return ev(err);
}

static merr_t
ikvs_cursor_replenish(struct kvs_cursor_impl *cursor, bool *eofp)
{
    struct kvs_cursor_tombs *tombs;
    merr_t                   err = 0;
    int                      rc;
    bool                     c0tomb;
    bool                     all_tombs = true;
    u64                      read_tombs = 0;
    bool                     need_seek = (cursor->kci_seek > 0);

    do {
        if (need_seek && cursor->kci_last) {
            memcpy(
                cursor->kci_last_kbuf,
                cursor->kci_last->kvt_key.kt_data,
                cursor->kci_last->kvt_key.kt_len);

            cursor->kci_last_klen = cursor->kci_last->kvt_key.kt_len;
        }

        if (!bit_on(kci_ready, BIT_C0) && !bit_on(kci_eof, BIT_C0)) {
            err = ikvs_cursor_replenish_impl(cursor, BIT_C0);
            if (ev(err)) {
                if (merr_errno(err) != EAGAIN)
                    cursor->kci_err = err;
                return err;
            }
        }

        if (!bit_on(kci_ready, BIT_CN) && !bit_on(kci_eof, BIT_CN)) {
            err = ikvs_cursor_replenish_impl(cursor, BIT_CN);
            if (ev(err)) {
                if (merr_errno(err) != EAGAIN)
                    cursor->kci_err = err;
                return err;
            }
        }

        *eofp = (cursor->kci_ready == BIT_NONE);
        if (*eofp)
            break;

        /*
         * c0 tombstones must annihilate matching keys in c0 + cn;
         * invalidate cn if key is same; then invalidate c0
         */
        c0tomb = bit_on(kci_ready, BIT_C0) && HSE_CORE_IS_TOMB(cursor->kci_c0kv.kvt_value.vt_data);
        if (c0tomb) {
            void *vt_data = cursor->kci_c0kv.kvt_value.vt_data;
            bool  c0ptomb = HSE_CORE_IS_PTOMB(vt_data);

            all_tombs = all_tombs && !c0ptomb;

            if (bit_on(kci_ready, BIT_CN)) {
                /* [HSE_REVISIT] when rc == 0 and c0ptomb is
                 * true, we can move the cn cursor iterators
                 * past the prefix
                 */
                rc = c0ptomb ? pfx_cmp(cursor) : cursor_cmp(cursor);

                if (cursor->kci_reverse)
                    rc = -rc;

                if (rc == 0) {
                    cursor->kci_ready &= ~BIT_CN;
                } else if (rc < 0) {
                    cursor->kci_ready &= ~BIT_C0;
                    read_tombs++;
                } else {
                    /* not yet visible */
                    c0tomb = 0;
                }
            } else {
                cursor->kci_ready &= ~BIT_C0;
                read_tombs++;
            }
        }
    } while (c0tomb);

    perfc_add(cursor->kci_cc_pc, PERFC_BA_CC_TOMB_C0, read_tombs);

    /*
     * If this is a seek and a span of tombstones was read, track a new
     * tombstone span or extend an existing one.
     */
    tombs = &cursor->kci_tombs;
    if (unlikely(
            (tombs->kct_skip || (read_tombs >= TOMBSPAN_MIN_WIDTH && all_tombs)) &&
            cursor->kci_peek && !*eofp && !cursor->kci_reverse)) {
        if (tombs->kct_skip) {
            /*
             * Tombstones were skipped during seek, but new ones
             * were read. Extend the ongoing tombstone span to
             * include the newly read tombstones.
             */
            assert(tombs->kct_valid);
            tombs->kct_width = tombs->kct_width + read_tombs;
            tombs->kct_update = true;

            perfc_add(cursor->kci_cc_pc, PERFC_BA_CC_TOMB_SPAN_ADD, read_tombs);
        } else {
            /* Invalidate the old span (if any) and create a new one. */
            if (tombs->kct_valid)
                ikvs_cursor_tombs_invalidate(cursor);

            tombs->kct_start = get_time_ns();
            tombs->kct_width = read_tombs;
            tombs->kct_min_len = cursor->kci_seeklen;
            memcpy(tombs->kct_min, cursor->kci_seekkey, tombs->kct_min_len);
            tombs->kct_valid = true;
            tombs->kct_update = true;

            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_TOMB_SPAN);
        }
    }

    return 0;
}

merr_t
ikvs_cursor_read(struct hse_kvs_cursor *handle, struct kvs_kvtuple *kvt, bool *eofp)
{
    struct kvs_cursor_impl *cursor = (void *)handle;
    int                     oready;
    int                     rc;

    if (ev(cursor->kci_err)) {
        if (ev(merr_errno(cursor->kci_err) != EAGAIN))
            return cursor->kci_err;

        cursor->kci_err = 0;
    }

    if (cursor->kci_ready != BIT_BOTH)
        cursor->kci_err = ikvs_cursor_replenish(cursor, eofp);
    else
        *eofp = false;

    cursor->kci_toss = 1;
    if (cursor->kci_err)
        return ev(cursor->kci_err);

    /* if there is no c0 or no cn, then other one wins */
    if (cursor->kci_ready == BIT_C0)
        rc = 0;
    else if (cursor->kci_ready == BIT_CN)
        rc = 1;
    else if (cursor->kci_ready == BIT_BOTH) {
        rc = cursor_cmp(cursor);
        if (cursor->kci_reverse)
            rc = -rc;
    } else {
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_EOF);
        assert(*eofp);
        return 0;
    }

    cursor->kci_summary.util++;
    oready = cursor->kci_ready;

    /*
     * If this cursor tracks a tombspan, note the key we need to seek the cn
     * cursor to (if larger). This may avoid repeatedly reading tombstones
     * in cn (spans that are distinct from the ones being tracked in c0).
     */
    if (unlikely(cursor->kci_tombs.kct_update)) {
        struct kvs_cursor_tombs *tombs = &cursor->kci_tombs;
        struct kvs_ktuple *      cnkey = &cursor->kci_cnkv.kvt_key;

        if (cursor->kci_eof & BIT_CN)
            cursor->kci_tombs.kct_cn_eof = true;

        if (cursor->kci_ready & BIT_CN) {
            if (rc < 0) {
                assert(
                    keycmp(cnkey->kt_data, cnkey->kt_len, tombs->kct_cnmax, tombs->kct_cnmax_len) >=
                    0);
                tombs->kct_cnmax_len = cnkey->kt_len;
                memcpy(tombs->kct_cnmax, cnkey->kt_data, cnkey->kt_len);
            } else {
                tombs->kct_cnmax_len = 0;
            }
        }
    }

    if (rc <= 0) {
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_READ_C0);

        ++cursor->kci_summary.read_c0;
        cursor->kci_last = &cursor->kci_c0kv;
        cursor->kci_ready &= ~BIT_C0;

        /* if same key in cn, ignore it */
        if (rc == 0)
            cursor->kci_ready &= ~BIT_CN;

    } else {
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_READ_CN);

        ++cursor->kci_summary.read_cn;
        cursor->kci_last = &cursor->kci_cnkv;
        cursor->kci_ready &= ~BIT_CN;
    }

    *kvt = *cursor->kci_last;

    /* see comments in seek; do not change data state if peek */
    if (cursor->kci_peek) {
        cursor->kci_peek = 0;
        cursor->kci_ready = oready;
    }

    return 0;
}

#undef bit_on

static merr_t
kvs_create(struct ikvs **ikvs_out, struct kvs_rparams *rp)
{
    struct cache_bucket *bkt;
    struct ikvs *        ikvs;
    size_t               sz;
    int                  i, n;
    int                  nmax;

    *ikvs_out = NULL;

    ikvs = alloc_aligned(sizeof(*ikvs), __alignof(*ikvs));
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
    struct kmem_cache *zone;
    size_t             sz;

    if (atomic_inc_return(&kvs_init_ref) > 1)
        return 0;

    sz = sizeof(struct kvs_cursor_impl);
    sz += HSE_KVS_KLEN_MAX * 3;

    zone = kmem_cache_create("cursor", sz, SMP_CACHE_BYTES, 0, NULL);
    if (ev(!zone)) {
        atomic_dec(&kvs_init_ref);
        return merr(ENOMEM);
    }

    kvs_cursor_zone = zone;

    return 0;
}

void
kvs_fini(void)
{
    if (atomic_dec_return(&kvs_init_ref) > 0)
        return;

    kmem_cache_destroy(kvs_cursor_zone);
    kvs_cursor_zone = NULL;
}
