/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_ikvdb
#define MTF_MOCK_IMPL_kvs

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/c1_replay.h>
#include <hse_ikvdb/c1_perfc.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0skm.h>
#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/c0skm_perfc.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/cn_perfc.h>
#include <hse_ikvdb/ctxn_perfc.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/diag_kvdb.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/throttle_perfc.h>
#include <hse_ikvdb/rparam_debug_flags.h>
#include <hse_ikvdb/hse_params_internal.h>
#include <hse_ikvdb/mclass_policy.h>
#include "kvdb_omf.h"

#include "kvdb_log.h"
#include "kvdb_kvs.h"
#include "active_ctxn_set.h"
#include "kvdb_keylock.h"
#include "sos_log.h"

#include <mpool/mpool.h>

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/string.h>
#include <hse_util/seqno.h>
#include <hse_util/darray.h>
#include <hse_util/rest_api.h>
#include <hse_util/log2.h>
#include <hse_util/atomic.h>

#include <3rdparty/xxhash.h>
#include <3rdparty/cJSON.h>

#include "kvdb_rest.h"
#include "kvdb_params.h"

struct perfc_set kvdb_pkvdbl_pc __read_mostly;
struct perfc_set kvdb_pc __read_mostly;

struct perfc_set kvdb_metrics_pc __read_mostly;
struct perfc_set c0_metrics_pc __read_mostly;

BUILD_BUG_ON_MSG(
    (sizeof(uintptr_t) != sizeof(u64)),
    "code relies on pointers being 64-bits in size");

#define ikvdb_h2r(handle) container_of(handle, struct ikvdb_impl, ikdb_handle)

struct ikvdb {
};

/* Max buckets in ctxn cache.  Must be prime for best results.
 */
#define KVDB_CTXN_BKT_MAX (61)

/* Simple fixed-size stack for caching ctxn objects.
 */
struct kvdb_ctxn_bkt {
    spinlock_t        kcb_lock;
    uint              kcb_ctxnc;
    struct kvdb_ctxn *kcb_ctxnv[7];
} __aligned(SMP_CACHE_BYTES);

/**
 * struct ikvdb_impl - private representation of a kvdb
 * @ikdb_handle:        handle for users of struct ikvdb_impl's
 * @ikdb_rdonly:        bool indicating read-only mode
 * @ikdb_work_stop:
 * @ikdb_ctxn_set:      kvdb transaction set
 * @ikdb_ctxn_op:       transaction performance counters
 * @ikdb_keylock:       handle to the KVDB keylock
 * @ikdb_c0sk:          c0sk handle
 * @ikdb_health:
 * @ikdb_ds:            dataset
 * @ikdb_log:           KVDB log handle
 * @ikdb_cndb:          CNDB handle
 * @ikdb_workqueue:
 * @ikdb_maint_work:
 * @ikdb_curcnt:        number of active cursors
 * @ikdb_curcnt_max:    maximum number of active cursors
 * @ikdb_seqno:         current sequence number for the struct ikvdb
 * @ikdb_seqno_cur:     oldest seqno of cursors
 * @ikdb_c1:            Opaque structure for c1
 * @ikdb_c1_callback    c1 specific c0sk event handlers
 * @ikdb_profile:       hse params stored as profile
 * @ikdb_rp:            KVDB run time params
 * @ikdb_ctxn_cache:    ctxn cache
 * @ikdb_lock:          protects ikdb_kvs_vec/ikdb_kvs_cnt writes
 * @ikdb_kvs_cnt:       number of KVSes in ikdb_kvs_vec
 * @ikdb_kvs_vec:       vector of KVDB KVSes
 * @ikdb_cndb_oid1:
 * @ikdb_cndb_oid2:
 * @ikdb_c1_oid1:       First OID of c1 MDC
 * @ikdb_c1_oid2:       Second OID of c1 MDC
 * @ikdb_mpname:        KVDB mpool name
 *
 * Note:  The first group of fields are read-mostly and some of them are
 * heavily concurrently accessed, hence they live in the first cache line.
 * Only add a new field to this group if it is read-mostly and would not push
 * the first field of %ikdb_health out of the first cache line.  Similarly,
 * the group of fields which contains %ikdb_seqno is heavily concurrently
 * accessed and heavily modified. Only add a new field to this group if it
 * will fit into the existing unused pad space.
 */
struct ikvdb_impl {
    struct ikvdb          ikdb_handle;
    bool                  ikdb_rdonly;
    bool                  ikdb_work_stop;
    struct kvdb_ctxn_set *ikdb_ctxn_set;
    struct perfc_set      ikdb_ctxn_op;
    struct kvdb_keylock * ikdb_keylock;
    struct c0sk *         ikdb_c0sk;
    struct kvdb_health    ikdb_health;
    struct csched *       ikdb_csched;
    struct cn_kvdb *      ikdb_cn_kvdb;

    struct throttle ikdb_throttle;

    struct sos_log *    ikdb_sos;
    void *              ikdb_sos_buf;
    size_t              ikdb_sos_buf_sz;
    struct delayed_work ikdb_sos_dwork;

    struct mpool *           ikdb_ds;
    struct kvdb_log *        ikdb_log;
    struct cndb *            ikdb_cndb;
    struct workqueue_struct *ikdb_workqueue;
    struct active_ctxn_set * ikdb_active_txn_set;
    struct c1 *              ikdb_c1;
    struct kvdb_callback     ikdb_c1_callback;
    struct hse_params *      ikdb_profile;

    __aligned(SMP_CACHE_BYTES) atomic_t ikdb_curcnt;
    u32 ikdb_curcnt_max;

    __aligned(SMP_CACHE_BYTES) atomic64_t ikdb_seqno;
    atomic64_t ikdb_seqno_cur;

    __aligned(SMP_CACHE_BYTES) struct kvdb_rparams ikdb_rp;
    struct kvdb_ctxn_bkt ikdb_ctxn_cache[KVDB_CTXN_BKT_MAX];

    /* Put the mostly cold data at end of the structure to improve
     * the density of the hotter data.
     */
    struct mutex       ikdb_lock;
    u32                ikdb_kvs_cnt;
    struct kvdb_kvs *  ikdb_kvs_vec[HSE_KVS_COUNT_MAX];
    struct work_struct ikdb_maint_work;
    struct work_struct ikdb_throttle_work;

    struct mclass_policy ikdb_mpolicies[HSE_MPOLICY_COUNT];

    u64  ikdb_cndb_oid1;
    u64  ikdb_cndb_oid2;
    u64  ikdb_c1_oid1;
    u64  ikdb_c1_oid2;
    char ikdb_mpname[MPOOL_NAMESZ_MAX];
};

static merr_t
ikvdb_flush_int(struct ikvdb_impl *self)
{
    return c0sk_flush(self->ikdb_c0sk, NULL);
}

static merr_t
ikvdb_sync_int(struct ikvdb_impl *self)
{
    return ev(c0sk_sync(self->ikdb_c0sk));
}

struct ikvdb *
ikvdb_kvdb_handle(struct ikvdb_impl *self)
{
    return &self->ikdb_handle;
}

static merr_t
ikvdb_c1_make(
    struct kvdb_log *    log,
    struct mpool *       ds,
    u64 *                oid1,
    u64 *                oid2,
    struct kvdb_cparams *cparams,
    struct kvdb_log_tx **tx)
{
    merr_t err;

    err = c1_alloc(ds, cparams, oid1, oid2);
    if (ev(err))
        return err;

    err = kvdb_log_mdc_create(log, KVDB_LOG_MDC_ID_C1, *oid1, *oid2, tx);
    if (ev(err))
        goto make_exit;

    err = c1_make(ds, cparams, *oid1, *oid2);
    if (ev(err))
        goto make_exit2;

    err = kvdb_log_done(log, *tx);
    if (ev(err))
        goto make_exit2;

    return 0;

make_exit2:
    kvdb_log_abort(log, *tx);

make_exit:
    c1_free(ds, *oid1, *oid2);

    return err;
}

static merr_t
ikvdb_c1_open(struct ikvdb_impl *self, struct mpool *ds, u64 ingestid)
{
    merr_t err;

    /* If c1 is disabled at create time, leave it disabled at open time
     * as well. The KVDB run-time parameter "dur_enable" is not honored
     * in this scenario.
     */
    if (!self->ikdb_c1_oid1) {
        assert(!self->ikdb_c1_oid1);
        self->ikdb_c1 = NULL;

        return 0;
    }

    /* c1 is enabled at kvdb open time. */
    if (self->ikdb_rp.dur_enable && self->ikdb_c1_oid1) {

        assert(self->ikdb_c1_oid2);

        err = c1_open(
            ds,
            self->ikdb_rdonly,
            self->ikdb_c1_oid1,
            self->ikdb_c1_oid2,
            ingestid,
            self->ikdb_mpname,
            &self->ikdb_rp,
            &self->ikdb_handle,
            self->ikdb_c0sk,
            &self->ikdb_c1);

        return ev(err);
    }

    /* c1 is disabled at kvdb open time. Need c1 replay. */
    assert(self->ikdb_rp.dur_enable == 0);
    assert(self->ikdb_c1_oid2);

    err = c1_open(
        ds,
        self->ikdb_rdonly,
        self->ikdb_c1_oid1,
        self->ikdb_c1_oid2,
        ingestid,
        self->ikdb_mpname,
        &self->ikdb_rp,
        &self->ikdb_handle,
        self->ikdb_c0sk,
        &self->ikdb_c1);
    if (ev(err))
        return err;

    err = c1_close(self->ikdb_c1);
    self->ikdb_c1 = NULL;

    return 0;
}

static void
ikvdb_c1_cningest_status_callback(
    struct ikvdb *ikdb,
    unsigned long seqnum,
    unsigned long status,
    unsigned long cnid,
    const void *  key,
    unsigned int  key_len)
{
    struct ikvdb_impl *self = ikvdb_h2r(ikdb);
    merr_t             err = status;

    if (self->ikdb_c1) {
        struct kvs_ktuple kt;

        kvs_ktuple_init(&kt, key, key_len);
        c1_cningest_status(self->ikdb_c1, seqnum, err, cnid, &kt);
    }
}

static void
ikvdb_c1_install_callbacks(struct ikvdb_impl *self)
{
    struct kvdb_callback *cb = &self->ikdb_c1_callback;

    if (!self->ikdb_c1) {
        c0sk_install_callback(self->ikdb_c0sk, NULL);
        return;
    }

    cb->kc_cbarg = &self->ikdb_handle;
    cb->kc_cn_ingest_callback = ikvdb_c1_cningest_status_callback;

    c0sk_install_callback(self->ikdb_c0sk, cb);
}

/*
 * c1 REPLAY functions - c1 to ikvdb implemented by ikvdb
 */
struct ikvdb_c1_replay {
    struct hse_kvs **kvs;
    unsigned int     count;
};

/*
 * ikvdb_c1_replay_get_kvs returns struct hse_kvs if a matching cnid
 * is found.
 */
struct hse_kvs *
ikvdb_c1_replay_get_kvs(struct ikvdb_c1_replay *replay, u64 ikdb_cn_id)
{
    int              i;
    struct kvdb_kvs *kvs;

    for (i = 0; i < replay->count; i++) {
        kvs = (struct kvdb_kvs *)replay->kvs[i];
        if (kvs->kk_cnid == ikdb_cn_id)
            return replay->kvs[i];
    }

    return NULL;
}

void
ikvdb_set_replaying(struct ikvdb *ikdb)
{
    struct ikvdb_impl *self;

    if (ev(!ikdb))
        return;

    self = ikvdb_h2r(ikdb);

    if (self->ikdb_c0sk)
        c0sk_set_replaying(self->ikdb_c0sk);
}

void
ikvdb_unset_replaying(struct ikvdb *ikdb)
{
    struct ikvdb_impl *self;

    if (ev(!ikdb))
        return;

    self = ikvdb_h2r(ikdb);

    if (self->ikdb_c0sk)
        c0sk_unset_replaying(self->ikdb_c0sk);
}

/*
 * ikvdb_c1_replay_open is an important as far as c1 replay is
 * concerned. It goes through the list of kvses in a kvdb.
 * It first invokes ikvdb_get_names to get the list of kvses and
 * then invokes ikvdb_kvs_open on them to obtain kvs handles. These
 * handles are later used by c1 replay function to ingest contents
 * of c1 into kvdb.
 */
merr_t
ikvdb_c1_replay_open(struct ikvdb *ikdb, struct ikvdb_c1_replay **ikvdbhandle)
{
    merr_t                  err;
    unsigned int            count;
    int                     i;
    int                     kvs_size;
    char **                 kvsv = NULL;
    struct hse_kvs **       kvs;
    struct ikvdb_c1_replay *out;

    if (!ikdb)
        return 0;

    out = malloc(sizeof(*out));
    if (!out)
        return merr(ev(ENOMEM));

    err = ikvdb_get_names(ikdb, &count, &kvsv);
    if (ev(err)) {
        free(out);
        return err;
    }

    kvs_size = sizeof(*kvs) * count;

    kvs = malloc(kvs_size);
    if (!out) {
        ikvdb_free_names(ikdb, kvsv);
        free(out);
        return merr(ev(ENOMEM));
    }

    out->kvs = kvs;
    out->count = count;

    for (i = 0; i < count; i++) {
        err = ikvdb_kvs_open(ikdb, kvsv[i], NULL, IKVS_OFLAG_REPLAY, &kvs[i]);
        if (ev(err)) {
            hse_log(HSE_WARNING "ikvdb_kvs_open %s error %d", kvsv[i], merr_errno(err));
            break;
        }
    }

    ikvdb_free_names(ikdb, kvsv);

    if (ev(err)) {
        free(out);
        while (i-- > 0)
            (void)ikvdb_kvs_close(kvs[i]);
        free(kvs);
        return err;
    }

    *ikvdbhandle = out;

    return 0;
}

merr_t
ikvdb_c1_replay_close(struct ikvdb *ikdb, struct ikvdb_c1_replay *replay)
{
    unsigned int i;
    merr_t       err;

    if (!ikdb)
        return 0;

    err = ikvdb_sync_int(ikvdb_h2r(ikdb));

    for (i = 0; i < replay->count; i++)
        (void)ikvdb_kvs_close(replay->kvs[i]);

    free(replay->kvs);
    free(replay);

    return err;
}

void
ikvdb_c1_set_seqno(struct ikvdb *ikdb, u64 seqno)
{
    struct ikvdb_impl *self;

    if (ev(!ikdb))
        return;

    self = ikvdb_h2r(ikdb);

    if (seqno > atomic64_read(&self->ikdb_seqno))
        atomic64_set(&self->ikdb_seqno, seqno);
}

merr_t
ikvdb_c1_replay_put(
    struct ikvdb *           ikdb,
    struct ikvdb_c1_replay * replay,
    u64                      seqno,
    u64                      cnid,
    struct hse_kvdb_opspec * os,
    struct kvs_ktuple *      kt,
    const struct kvs_vtuple *vt)
{
    struct hse_kvs * kvs;
    struct kvdb_kvs *kk;

    if (!ikdb)
        return 0;

    kvs = ikvdb_c1_replay_get_kvs(replay, cnid);
    if (!kvs) {
        /* It's possible that this KVS got dropped just prior
         * to crash. Skip replaying this key, if there's no kvs
         * instance corresponding to the specified cnid.
         */
        hse_log(
            HSE_WARNING "%s: Replay detected dropped KVS, "
                        "id: %lu",
            __func__,
            (ulong)cnid);
        return 0;
    }

    kk = (struct kvdb_kvs *)kvs;
    assert(kk);

    return ikvs_put(kk->kk_ikvs, os, kt, vt, HSE_ORDNL_TO_SQNREF(seqno));
}

merr_t
ikvdb_c1_replay_del(
    struct ikvdb *          ikdb,
    struct ikvdb_c1_replay *replay,
    u64                     seqno,
    u64                     cnid,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    struct kvs_vtuple *     vt)
{
    struct hse_kvs * kvs;
    struct kvdb_kvs *kk;
    u64              tombval;

    if (!ikdb)
        return 0;

    kvs = ikvdb_c1_replay_get_kvs(replay, cnid);
    if (!kvs) {
        /* It's possible that this KVS got dropped just prior
         * to crash. Skip replaying this key, if there's no kvs
         * instance corresponding to the specified cnid.
         */
        hse_log(
            HSE_WARNING "%s: Replay detected dropped KVS, "
                        "id: %lu",
            __func__,
            (ulong)cnid);
        return 0;
    }

    kk = (struct kvdb_kvs *)kvs;
    assert(kk);

    tombval = *(u64 *)vt->vt_data;
    if (tombval == (u64)HSE_CORE_TOMB_REG)
        return ikvs_del(kk->kk_ikvs, os, kt, HSE_ORDNL_TO_SQNREF(seqno));

    assert(tombval == (u64)HSE_CORE_TOMB_PFX);

    return ikvs_prefix_del(kk->kk_ikvs, os, kt, HSE_ORDNL_TO_SQNREF(seqno));
}

void
ikvdb_perfc_alloc(struct ikvdb_impl *self)
{
    char   dbname_buf[DT_PATH_COMP_ELEMENT_LEN];
    size_t n;

    dbname_buf[0] = 0;

    n = strlcpy(dbname_buf, self->ikdb_mpname, sizeof(dbname_buf));
    if (ev(n >= sizeof(dbname_buf)))
        return;

    if (perfc_ctrseti_alloc(
            COMPNAME, dbname_buf, ctxn_perfc_op, PERFC_EN_CTXNOP, "set", &self->ikdb_ctxn_op))
        hse_log(HSE_ERR "cannot alloc ctxn op perf counters");
}

static void
ikvdb_perfc_free(struct ikvdb_impl *self)
{
    perfc_ctrseti_free(&self->ikdb_ctxn_op);
}

merr_t
validate_kvs_name(const char *name)
{
    int name_len;

    if (ev(!name || !*name))
        return merr(EINVAL);

    name_len = strnlen(name, HSE_KVS_NAME_LEN_MAX);

    if (name_len == HSE_KVS_NAME_LEN_MAX)
        return merr(ev(ENAMETOOLONG));

    /* Does the name contain invalid characters ?
     * i.e. char apart from [-_A-Za-z0-9]
     */
    while (*name && name_len-- > 0) {
        if (ev(!isalnum(*name) && *name != '_' && *name != '-'))
            return merr(EINVAL);
        ++name;
    }

    if (ev(*name))
        return merr(ev(ENAMETOOLONG));

    return 0;
}

merr_t
ikvdb_make(
    struct mpool *       ds,
    u64                  oid1, /* kvdb oids */
    u64                  oid2,
    struct kvdb_cparams *cparams,
    u64                  captgt)
{
    struct kvdb_log *   log = NULL;
    merr_t              err;
    u64                 cndb_o1, cndb_o2;
    u64                 cndb_captgt;
    u64                 c1_oid1, c1_oid2;
    struct kvdb_log_tx *tx = NULL;

    c1_oid2 = 0;
    c1_oid2 = 0;
    cndb_o1 = 0;
    cndb_o2 = 0;

    err = kvdb_log_open(ds, &log, O_RDWR);
    if (ev(err))
        goto out;

    err = kvdb_log_make(log, captgt);
    if (ev(err))
        goto out;

    cndb_captgt = 0;
    err = cndb_alloc(ds, &cndb_captgt, &cndb_o1, &cndb_o2);
    if (ev(err))
        goto out;

    err = kvdb_log_mdc_create(log, KVDB_LOG_MDC_ID_CNDB, cndb_o1, cndb_o2, &tx);
    if (ev(err))
        goto out;

    err = cndb_make(ds, cndb_captgt, cndb_o1, cndb_o2);
    if (ev(err)) {
        kvdb_log_abort(log, tx);
        goto out;
    }

    err = kvdb_log_done(log, tx);
    if (ev(err))
        goto out;

    err = ikvdb_c1_make(log, ds, &c1_oid1, &c1_oid2, cparams, &tx);

out:
    /* Failed ikvdb_make() indicates that the caller or operator should
     * destroy the kvdb: recovery is not possible.
     */
    kvdb_log_close(log);

    return err;
}

static void
ikvdb_sos_sched(struct ikvdb_impl *self);

static void
ikvdb_sos_worker(struct work_struct *work)
{
    struct ikvdb_impl *         self;
    merr_t                      err;
    struct yaml_context         yc;
    union dt_iterate_parameters dip;
    time_t                      t;
    struct timeval              tv;
    struct tm                   tm;
    char                        tmp[128];

    const char *iso_time_fmt = "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ";

    self = container_of(work, struct ikvdb_impl, ikdb_sos_dwork.work);

    if (!self->ikdb_rp.sos_log)
        goto resched;

    /* Open SOS log.  It might be the first open.  If log is already open
     * it'll be a no-op or a rollover to a new log file.
     */
    err = sos_log_open(self->ikdb_sos);
    if (ev(err))
        goto resched;

    memset(&yc, 0, sizeof(yc));
    yc.yaml_buf = self->ikdb_sos_buf;
    yc.yaml_buf_sz = self->ikdb_sos_buf_sz;

    memset(&dip, 0, sizeof(dip));
    dip.yc = &yc;

    yaml_start_element_type(&yc, "sos_debug");

    /* Note: using Greenwich mean time. */
    gettimeofday(&tv, NULL);
    t = tv.tv_sec;
    gmtime_r(&t, &tm);
    snprintf(
        tmp,
        sizeof(tmp),
        iso_time_fmt,
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tv.tv_usec);

    yaml_element_field(&yc, "timestamp", tmp);

    snprintf(tmp, sizeof(tmp), "%d", getpid());
    yaml_element_field(&yc, "pid", tmp);

    yaml_start_element_type(&yc, "event_counters");

    dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, "/data/event_counter", &dip, 0, 0, 0);

    yaml_end_element_type(&yc); /* event_counters */
    yaml_end_element_type(&yc); /*sos_debug*/

    sos_log_write(self->ikdb_sos, yc.yaml_buf, yc.yaml_offset);

resched:
    ikvdb_sos_sched(self);
}

static void
ikvdb_sos_sched(struct ikvdb_impl *self)
{
    bool succ __maybe_unused;
    uint      msecs;

    /* If 'ikdb_rp.sos_log == 0', then we will not write data
     * to sos log, but we still keep the delayed work active so it can
     * respond to changes made via the REST interface.  The delayed work
     * task will simply requeue if 'ikdb_rp.sos_log == 0'.
     */
    msecs = self->ikdb_rp.sos_log;
    if (!msecs)
        msecs = 1000;

    INIT_DELAYED_WORK(&self->ikdb_sos_dwork, ikvdb_sos_worker);
    succ = queue_delayed_work(self->ikdb_workqueue, &self->ikdb_sos_dwork, msecs_to_jiffies(msecs));
    assert(succ);
}

static void
ikvdb_throttle_task(struct work_struct *work)
{
    struct ikvdb_impl *self;
    u64                last_throttle_update = 0;
    u64                thr_update_ns;

    self = container_of(work, struct ikvdb_impl, ikdb_throttle_work);
    thr_update_ns = self->ikdb_rp.throttle_update_ns;

    while (!self->ikdb_work_stop) {
        u64 tstart = get_time_ns();

        if (tstart > (last_throttle_update + thr_update_ns)) {
            throttle_update(&self->ikdb_throttle);
            last_throttle_update = tstart;
        }

        tstart = (get_time_ns() - tstart) / (10 * 1000 * 1000);
        if (tstart < 10)
            msleep(10 - tstart);
    }
}

static void
ikvdb_maint_task(struct work_struct *work)
{
    struct ikvdb_impl *self;
    uint               i;

    self = container_of(work, struct ikvdb_impl, ikdb_maint_work);

    while (!self->ikdb_work_stop) {
        u64 tstart = get_time_ns();

        /* [HSE_REVISIT] move from big lock to using refcnts for
         * accessing KVSes in the kvs vector. Here and in all admin
         * functions
         */
        mutex_lock(&self->ikdb_lock);
        for (i = 0; i < self->ikdb_kvs_cnt; i++) {
            struct kvdb_kvs *kvs = self->ikdb_kvs_vec[i];

            if (kvs && kvs->kk_ikvs)
                ikvs_maint_task(kvs->kk_ikvs, tstart);
        }
        mutex_unlock(&self->ikdb_lock);

        /* Try to maintain slightly more than a 100ms period.
         */
        tstart = (get_time_ns() - tstart) / (1024 * 1024);
        if (tstart < 100)
            msleep(100 - tstart);
    }
}

static void
ikvdb_init_throttle_params(struct ikvdb_impl *self)
{
    if (self->ikdb_rdonly)
        return;

    /* Hand out throttle sensors */
    csched_throttle_sensor(
        self->ikdb_csched, throttle_sensor(&self->ikdb_throttle, THROTTLE_SENSOR_CSCHED));

    c0sk_throttle_sensor(
        self->ikdb_c0sk, throttle_sensor(&self->ikdb_throttle, THROTTLE_SENSOR_C0SK));

    c0skm_dtime_throttle_sensor(
        self->ikdb_c0sk, throttle_sensor(&self->ikdb_throttle, THROTTLE_SENSOR_C0SKM_DTIME));

    c0skm_dsize_throttle_sensor(
        self->ikdb_c0sk, throttle_sensor(&self->ikdb_throttle, THROTTLE_SENSOR_C0SKM_DSIZE));
}

static void
ikvdb_txn_init(struct ikvdb_impl *self)
{
    int i;

    for (i = 0; i < NELEM(self->ikdb_ctxn_cache); ++i) {
        struct kvdb_ctxn_bkt *bkt = self->ikdb_ctxn_cache + i;

        spin_lock_init(&bkt->kcb_lock);
    }
}

static void
ikvdb_txn_fini(struct ikvdb_impl *self)
{
    int i;

    for (i = 0; i < NELEM(self->ikdb_ctxn_cache); ++i) {
        struct kvdb_ctxn_bkt *bkt = self->ikdb_ctxn_cache + i;
        int                   j;

        for (j = 0; j < bkt->kcb_ctxnc; ++j)
            kvdb_ctxn_free(bkt->kcb_ctxnv[j]);
    }
}

merr_t
ikvdb_diag_cndb(struct ikvdb *handle, struct cndb **cndb)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (!self || !cndb)
        return merr(ev(EINVAL));

    *cndb = self->ikdb_cndb;

    return 0;
}

merr_t
ikvdb_diag_c1(struct ikvdb *handle, u64 ingestid, struct c1 **c1)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    merr_t             err;

    if (!self || !c1)
        return merr(ev(EINVAL));

    if (!self->ikdb_rdonly)
        return merr(ev(EINVAL));

    err = ikvdb_c1_open(self, self->ikdb_ds, ingestid);
    if (ev(err))
        return err;

    *c1 = self->ikdb_c1;

    return 0;
}

/* exposes kvs details to, e.g., kvck */
merr_t
ikvdb_diag_kvslist(struct ikvdb *handle, struct diag_kvdb_kvs_list *list, int len, int *kvscnt)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    int    i, c;
    merr_t err;

    if (!handle || !list || !kvscnt)
        return merr(ev(EINVAL));

    err = cndb_cn_count(self->ikdb_cndb, &self->ikdb_kvs_cnt);
    if (ev(err))
        return err;

    c = (len < self->ikdb_kvs_cnt) ? len : self->ikdb_kvs_cnt;

    *kvscnt = self->ikdb_kvs_cnt;

    for (i = 0; i < c; i++) {
        u64 cnid = 0;

        err = cndb_cn_info_idx(
            self->ikdb_cndb, i, &cnid, NULL, NULL, list[i].kdl_name, sizeof(list[i].kdl_name));
        if (ev(err))
            break;

        list[i].kdl_cnid = cnid;
    }

    return err;
}

/* ikvdb_diag_open() - open relevant media streams with minimal processing. */
merr_t
ikvdb_diag_open(
    const char *         mp_name,
    struct mpool *       ds,
    struct kvdb_rparams *rparams,
    struct ikvdb **      handle)
{
    struct ikvdb_impl *self;
    size_t             n;
    merr_t             err;

    /* [HSE_REVISIT] consider factoring out this code into ikvdb_cmn_open
     * and calling that from here and ikvdb_open.
     */
    self = alloc_aligned(sizeof(*self), __alignof(*self), GFP_KERNEL);
    if (!self)
        return merr(ev(ENOMEM));

    memset(self, 0, sizeof(*self));

    n = strlcpy(self->ikdb_mpname, mp_name, sizeof(self->ikdb_mpname));
    if (n >= sizeof(self->ikdb_mpname)) {
        err = merr(ev(ENAMETOOLONG));
        goto err_exit1;
    }

    self->ikdb_ds = ds;

    assert(rparams);
    self->ikdb_rp = *rparams;
    self->ikdb_rdonly = rparams->read_only;
    rparams = &self->ikdb_rp;

    atomic_set(&self->ikdb_curcnt, 0);

    ikvdb_txn_init(self);

    err = active_ctxn_set_create(&self->ikdb_active_txn_set, &self->ikdb_seqno);
    if (ev(err))
        goto err_exit0;

    err =
        kvdb_keylock_create(&self->ikdb_keylock, rparams->keylock_tables, rparams->keylock_entries);
    if (ev(err))
        goto err_exit1;

    err = kvdb_log_open(ds, &self->ikdb_log, rparams->read_only ? O_RDONLY : O_RDWR);
    if (ev(err))
        goto err_exit2;

    err = kvdb_log_replay(
        self->ikdb_log,
        &self->ikdb_cndb_oid1,
        &self->ikdb_cndb_oid2,
        &self->ikdb_c1_oid1,
        &self->ikdb_c1_oid2);
    if (ev(err))
        goto err_exit3;

    err = cndb_open(
        ds,
        self->ikdb_rdonly,
        &self->ikdb_seqno,
        rparams->cndb_entries,
        self->ikdb_cndb_oid1,
        self->ikdb_cndb_oid2,
        &self->ikdb_health,
        &self->ikdb_cndb);

    if (!ev(err)) {
        *handle = &self->ikdb_handle;
        return 0;
    }

err_exit3:
    kvdb_log_close(self->ikdb_log);

err_exit2:
    kvdb_keylock_destroy(self->ikdb_keylock);

err_exit1:
    active_ctxn_set_destroy(self->ikdb_active_txn_set);

err_exit0:
    ikvdb_txn_fini(self);
    free_aligned(self);
    *handle = NULL;

    return err;
}

merr_t
ikvdb_diag_close(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    merr_t             err;
    merr_t             ret = 0; /* store the first error encountered */

    self->ikdb_work_stop = true;
    mutex_lock(&self->ikdb_lock);

    err = cndb_close(self->ikdb_cndb);
    if (ev(err))
        ret = ret ?: err;

    err = kvdb_log_close(self->ikdb_log);
    if (ev(err))
        ret = ret ?: err;

    mutex_unlock(&self->ikdb_lock);

    ikvdb_txn_fini(self);

    active_ctxn_set_destroy(self->ikdb_active_txn_set);

    kvdb_keylock_destroy(self->ikdb_keylock);
    mutex_destroy(&self->ikdb_lock);

    free_aligned(self);

    return ret;
}

/** ikvdb_rest_register() - install rest handlers for KVSes and the kvs list
 * @self:       self
 * @handle:     ikvdb handle
 */
static void
ikvdb_rest_register(struct ikvdb_impl *self, struct ikvdb *handle)
{
    int    i;
    merr_t err;

    for (i = 0; i < self->ikdb_kvs_cnt; i++) {
        err = kvs_rest_register(
            self->ikdb_mpname, self->ikdb_kvs_vec[i]->kk_name, self->ikdb_kvs_vec[i]);
        if (err)
            hse_elog(
                HSE_WARNING "%s/%s REST registration failed: @@e",
                err,
                self->ikdb_mpname,
                self->ikdb_kvs_vec[i]->kk_name);
    }

    err = kvdb_rest_register(self->ikdb_mpname, handle);
    if (err)
        hse_elog(HSE_WARNING "%s REST registration failed: @@e", err, self->ikdb_mpname);
}

/** ikvdb_maint_start() - start maintenance work queue
 * @self:       self
 */
static merr_t
ikvdb_maint_start(struct ikvdb_impl *self)
{
    merr_t err;

    self->ikdb_work_stop = false;
    self->ikdb_workqueue = alloc_workqueue("kvdb_maint", 0, 3);
    if (!self->ikdb_workqueue) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "%s cannot start kvdb maintenance", err, self->ikdb_mpname);
        return err;
    }

    INIT_WORK(&self->ikdb_maint_work, ikvdb_maint_task);
    if (!queue_work(self->ikdb_workqueue, &self->ikdb_maint_work)) {
        err = merr(EBUG);
        hse_elog(HSE_ERR "%s cannot start kvdb maintenance", err, self->ikdb_mpname);
        return err;
    }

    INIT_WORK(&self->ikdb_throttle_work, ikvdb_throttle_task);
    if (!queue_work(self->ikdb_workqueue, &self->ikdb_throttle_work)) {
        err = merr(EBUG);
        hse_elog(HSE_ERR "%s cannot start kvdb throttle", err, self->ikdb_mpname);
        return err;
    }

    return 0;
}

static struct kvdb_kvs *
kvdb_kvs_create(void)
{
    struct kvdb_kvs *kvs;

    kvs = alloc_aligned(sizeof(*kvs), __alignof(*kvs), GFP_KERNEL);
    if (kvs) {
        memset(kvs, 0, sizeof(*kvs));
        mutex_init(&kvs->kk_cursors_lock);
        INIT_LIST_HEAD(&kvs->kk_cursors);
        atomic_set(&kvs->kk_refcnt, 0);
    }

    return kvs;
}

static void
kvdb_kvs_destroy(struct kvdb_kvs *kvs)
{
    if (kvs) {
        assert(atomic_read(&kvs->kk_refcnt) == 0);
        mutex_destroy(&kvs->kk_cursors_lock);
        memset(kvs, -1, sizeof(*kvs));
        free_aligned(kvs);
    }
}

/** ikvdb_cndb_open() - instantiate multi-kvs metadata
 * @self:       self
 * @seqno:      sequence number (output)
 * @ingestid:   ingest id (output)
 */
static merr_t
ikvdb_cndb_open(struct ikvdb_impl *self, u64 *seqno, u64 *ingestid)
{
    merr_t           err = 0;
    int              i;
    struct kvdb_kvs *kvs;

    err = cndb_open(
        self->ikdb_ds,
        self->ikdb_rdonly,
        &self->ikdb_seqno,
        self->ikdb_rp.cndb_entries,
        self->ikdb_cndb_oid1,
        self->ikdb_cndb_oid2,
        &self->ikdb_health,
        &self->ikdb_cndb);
    if (ev(err))
        goto err_exit;

    err = cndb_replay(self->ikdb_cndb, seqno, ingestid);
    if (ev(err))
        goto err_exit;

    err = cndb_cn_count(self->ikdb_cndb, &self->ikdb_kvs_cnt);
    if (ev(err))
        goto err_exit;

    for (i = 0; i < self->ikdb_kvs_cnt; i++) {
        kvs = kvdb_kvs_create();
        if (ev(!kvs)) {
            err = merr(ENOMEM);
            goto err_exit;
        }

        self->ikdb_kvs_vec[i] = kvs;

        err = cndb_cn_info_idx(
            self->ikdb_cndb,
            i,
            &kvs->kk_cnid,
            &kvs->kk_flags,
            &kvs->kk_cparams,
            kvs->kk_name,
            sizeof(kvs->kk_name));
        if (ev(err))
            goto err_exit;
    }

err_exit:
    return err;
}

/** ikvdb_low_mem_adjust() - configure for constrained memory environment
 * @self:       self
 */
static void
ikvdb_low_mem_adjust(struct ikvdb_impl *self)
{
    struct kvdb_rparams  dflt = kvdb_rparams_defaults();
    struct kvdb_rparams *rp = &self->ikdb_rp;

    ulong mavail;
    uint  scale;

    hse_log(HSE_WARNING "configuring %s for constrained memory environment", self->ikdb_mpname);

    /* The default parameter values in this function enables us to run
     * in a memory constrained cgroup. Scale the parameter values based
     * on the available memory. This function is called only when the
     * total RAM is <= 32G. Based on some experiments, the scale factor
     * is set to 8G.
     */
    hse_meminfo(NULL, &mavail, 30);
    scale = mavail / 8;
    scale = max_t(uint, 1, scale);

    if (rp->c0_heap_cache_sz_max == dflt.c0_heap_cache_sz_max)
        rp->c0_heap_cache_sz_max = min_t(u64, 1024 * 1024 * 128UL * scale, HSE_C0_CCACHE_SZ_MAX);

    if (rp->c0_heap_sz == dflt.c0_heap_sz)
        rp->c0_heap_sz = min_t(u64, 1024 * 1024 * 16UL * scale, HSE_C0_CHEAP_SZ_MAX);

    if (rp->c0_ingest_width == dflt.c0_ingest_width)
        rp->c0_ingest_width = HSE_C0_INGEST_WIDTH_DFLT;

    if (rp->c0_ingest_delay == dflt.c0_ingest_delay)
        rp->c0_ingest_delay = 0;

    if (rp->c0_coalesce_sz == dflt.c0_coalesce_sz)
        rp->c0_coalesce_sz = (rp->c0_heap_sz * rp->c0_ingest_width) >> 20;

    if (rp->c0_ingest_threads == dflt.c0_ingest_threads)
        rp->c0_ingest_threads = min_t(u64, scale, HSE_C0_INGEST_THREADS_DFLT);

    if (rp->c0_mutex_pool_sz == dflt.c0_mutex_pool_sz)
        rp->c0_mutex_pool_sz = 5;

    if (rp->throttle_c0_hi_th == dflt.throttle_c0_hi_th)
        rp->throttle_c0_hi_th = (2 * rp->c0_heap_sz * rp->c0_ingest_width) >> 20;

    if (rp->txn_heap_sz == dflt.txn_heap_sz)
        rp->txn_heap_sz = min_t(u64, 1024 * 1024 * 16UL * scale, HSE_C0_CHEAP_SZ_MAX);

    if (rp->txn_ingest_width == dflt.txn_ingest_width)
        rp->txn_ingest_width = HSE_C0_INGEST_WIDTH_DFLT;

    if (rp->txn_ingest_delay == dflt.txn_ingest_delay)
        rp->txn_ingest_delay = 0;

    c0kvs_reinit(rp->c0_heap_cache_sz_max);
}

merr_t
ikvdb_open(const char *mp_name, struct mpool *ds, struct hse_params *params, struct ikvdb **handle)
{
    merr_t              err;
    struct ikvdb_impl * self;
    struct kvdb_rparams rp;
    u64                 seqno = 0; /* required by unit test */
    ulong               mavail;
    size_t              n;
    int                 i;
    u64                 ingestid;

    self = alloc_aligned(sizeof(*self), __alignof(*self), GFP_KERNEL);
    if (ev(!self)) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        return err;
    }

    memset(self, 0, sizeof(*self));
    mutex_init(&self->ikdb_lock);
    ikvdb_txn_init(self);
    self->ikdb_ds = ds;

    n = strlcpy(self->ikdb_mpname, mp_name, sizeof(self->ikdb_mpname));
    if (n >= sizeof(self->ikdb_mpname)) {
        err = merr(ENAMETOOLONG);
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err2;
    }

    rp = hse_params_to_kvdb_rparams(params, NULL);

    hse_params_to_mclass_policies(params, self->ikdb_mpolicies, NELEM(self->ikdb_mpolicies));

    self->ikdb_rp = rp;
    self->ikdb_rdonly = rp.read_only;
    self->ikdb_profile = params;

    rp = self->ikdb_rp;

    hse_meminfo(NULL, &mavail, 30);
    if (rp.low_mem || mavail < 32)
        ikvdb_low_mem_adjust(self);

    kvdb_rparams_print(&rp);

    throttle_init(&self->ikdb_throttle, &self->ikdb_rp);

    if (!self->ikdb_rdonly) {
        err = csched_create(
            csched_rp_policy(&self->ikdb_rp),
            self->ikdb_ds,
            &self->ikdb_rp,
            self->ikdb_mpname,
            &self->ikdb_health,
            &self->ikdb_csched);
        if (err) {
            hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
            goto err1;
        }
    }

    /* Set max number of cursors per kvdb such that max memory used by
     * cursors is limited to about 10% of system memory.
     */
    self->ikdb_curcnt_max = (((mavail << 30) * 10) / 100) >> 20;
    atomic_set(&self->ikdb_curcnt, 0);

    err = active_ctxn_set_create(&self->ikdb_active_txn_set, &self->ikdb_seqno);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = kvdb_keylock_create(&self->ikdb_keylock, rp.keylock_tables, rp.keylock_entries);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = kvdb_log_open(ds, &self->ikdb_log, self->ikdb_rdonly ? O_RDONLY : O_RDWR);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = kvdb_log_replay(
        self->ikdb_log,
        &self->ikdb_cndb_oid1,
        &self->ikdb_cndb_oid2,
        &self->ikdb_c1_oid1,
        &self->ikdb_c1_oid2);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = ikvdb_cndb_open(self, &seqno, &ingestid);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    atomic64_set(&self->ikdb_seqno, seqno);
    atomic64_set(&self->ikdb_seqno_cur, U64_MAX);

    err = kvdb_ctxn_set_create(
        &self->ikdb_ctxn_set, self->ikdb_rp.txn_timeout, self->ikdb_rp.txn_wkth_delay);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = cn_kvdb_create(&self->ikdb_cn_kvdb);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = c0sk_open(
        &self->ikdb_rp,
        ds,
        self->ikdb_mpname,
        &self->ikdb_health,
        self->ikdb_csched,
        &self->ikdb_seqno,
        &self->ikdb_c0sk);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    *handle = &self->ikdb_handle;

    if (!self->ikdb_rdonly) {
        err = ikvdb_maint_start(self);
        if (err) {
            hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
            goto err1;
        }
    }

    /* NOTE: c1 replay happens inside this call, which is before this
     * object (struct ikvdb_impl) is fully initialized.  Certain items
     * must be initialized before c1 replay, other items must be
     * initialized after.
     */
    err = ikvdb_c1_open(self, ds, ingestid);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = c0skm_open(self->ikdb_c0sk, &self->ikdb_rp, self->ikdb_c1, mp_name);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    /* SOS Log
     */
    self->ikdb_sos_buf_sz = 32 * 1024;
    self->ikdb_sos_buf = malloc(self->ikdb_sos_buf_sz);
    if (!self->ikdb_sos_buf) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = sos_log_create(self->ikdb_mpname, &self->ikdb_rp, &self->ikdb_sos);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    if (!self->ikdb_rdonly)
        ikvdb_sos_sched(self);

    /*
     * Install c1 related callbacks for c0sk to use
     */
    ikvdb_c1_install_callbacks(self);

    ikvdb_perfc_alloc(self);
    kvdb_keylock_perfc_init(self->ikdb_keylock, &self->ikdb_ctxn_op);

    err = kvdb_rparams_add_to_dt(self->ikdb_mpname, &self->ikdb_rp);
    if (err)
        hse_elog(HSE_WARNING "cannot record %s runtime params: @@e", err, mp_name);

    ikvdb_rest_register(self, *handle);

    throttle_init_params(&self->ikdb_throttle, &self->ikdb_rp);
    ikvdb_init_throttle_params(self);

    return 0;

err1:
    free(self->ikdb_sos_buf);
    c1_close(self->ikdb_c1);
    c0sk_close(self->ikdb_c0sk);
    self->ikdb_work_stop = true;
    destroy_workqueue(self->ikdb_workqueue);
    cn_kvdb_destroy(self->ikdb_cn_kvdb);
    for (i = 0; i < self->ikdb_kvs_cnt; i++)
        kvdb_kvs_destroy(self->ikdb_kvs_vec[i]);
    kvdb_ctxn_set_destroy(self->ikdb_ctxn_set);
    cndb_close(self->ikdb_cndb);
    kvdb_log_close(self->ikdb_log);
    kvdb_keylock_destroy(self->ikdb_keylock);
    active_ctxn_set_destroy(self->ikdb_active_txn_set);
    csched_destroy(self->ikdb_csched);
    throttle_fini(&self->ikdb_throttle);

err2:
    ikvdb_txn_fini(self);
    mutex_destroy(&self->ikdb_lock);
    free_aligned(self);
    *handle = NULL;

    return err;
}

bool
ikvdb_rdonly(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    return self->ikdb_rdonly;
}

void
ikvdb_get_c0sk(struct ikvdb *handle, struct c0sk **out)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    *out = self->ikdb_c0sk;
}

void
ikvdb_get_c1(struct ikvdb *handle, struct c1 **out)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    *out = self->ikdb_c1;
}

struct csched *
ikvdb_get_csched(struct ikvdb *handle)
{
    return handle ? ikvdb_h2r(handle)->ikdb_csched : 0;
}

struct mclass_policy *
ikvdb_get_mclass_policy(struct ikvdb *handle, const char *name)
{
    struct ikvdb_impl *   self = ikvdb_h2r(handle);
    struct mclass_policy *policy = self->ikdb_mpolicies;
    int                   i;

    for (i = 0; i < HSE_MPOLICY_COUNT; i++, policy++)
        if (!strcmp(policy->mc_name, name))
            return policy;

    return NULL;
}

static int
get_kvs_index(struct kvdb_kvs **list, const char *kvs_name, int *avail)
{
    int i, av = -1;

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        if (!list[i])
            av = av < 0 ? i : av;
        else if (!strcmp(kvs_name, list[i]->kk_name))
            return i;
    }

    if (avail)
        *avail = av;

    return -1;
}

static void
drop_kvs_index(struct ikvdb *handle, int idx)
{
    int                c;
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    c = self->ikdb_kvs_cnt - idx - 1;
    kvdb_kvs_destroy(self->ikdb_kvs_vec[idx]);
    if (c)
        memmove(
            &self->ikdb_kvs_vec[idx], &self->ikdb_kvs_vec[idx + 1], c * sizeof(struct kvdb_kvs *));
    self->ikdb_kvs_vec[--self->ikdb_kvs_cnt] = NULL;
}

struct ikvdb_impl *
kvdb_kvs_parent(struct kvdb_kvs *kk)
{
    return kk->kk_parent;
}

struct kvs_cparams *
kvdb_kvs_cparams(struct kvdb_kvs *kk)
{
    return kk->kk_cparams;
}

u32
kvdb_kvs_flags(struct kvdb_kvs *kk)
{
    return kk->kk_flags;
}

u64
kvdb_kvs_cnid(struct kvdb_kvs *kk)
{
    return kk->kk_cnid;
}

char *
kvdb_kvs_name(struct kvdb_kvs *kk)
{
    return kk->kk_name;
}

void
kvdb_kvs_set_ikvs(struct kvdb_kvs *kk, struct ikvs *ikvs)
{
    kk->kk_ikvs = ikvs;
}

merr_t
ikvdb_kvs_make(struct ikvdb *handle, const char *kvs_name, struct hse_params *params)
{
    merr_t             err = 0;
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    struct kvdb_kvs *  kvs;
    struct kvs_cparams kvs_cparams, profile;
    int                idx;

    if (self->ikdb_rdonly)
        return merr(ev(EROFS));

    err = validate_kvs_name(kvs_name);
    if (ev(err))
        return err;

    /* load profile */
    profile = hse_params_to_kvs_cparams(self->ikdb_profile, kvs_name, NULL);

    /* overwrite with new params */
    kvs_cparams = hse_params_to_kvs_cparams(params, kvs_name, &profile);

    err = kvs_cparams_validate(&kvs_cparams);
    if (ev(err))
        return err;

    kvs = kvdb_kvs_create();
    if (ev(!kvs))
        return merr(ENOMEM);

    strlcpy(kvs->kk_name, kvs_name, sizeof(kvs->kk_name));

    mutex_lock(&self->ikdb_lock);

    if (self->ikdb_kvs_cnt >= HSE_KVS_COUNT_MAX) {
        err = merr(ev(ENOSPC));
        goto err_out;
    }

    if (get_kvs_index(self->ikdb_kvs_vec, kvs_name, &idx) >= 0) {
        err = merr(ev(EEXIST));
        goto err_out;
    }

    assert(idx >= 0); /* assert we found an empty slot */

    if (kvs_cparams.cp_fanout < 2 || kvs_cparams.cp_fanout > 16) {
        err = merr(ev(EINVAL));
        goto err_out;
    }
    kvs->kk_flags = cn_cp2cflags(&kvs_cparams);

    err = cndb_cn_make(self->ikdb_cndb, &kvs_cparams, &kvs->kk_cnid, kvs->kk_name);
    if (ev(err))
        goto err_out;

    kvs->kk_cparams = cndb_cn_cparams(self->ikdb_cndb, kvs->kk_cnid);

    if (ev(!kvs->kk_cparams)) {
        cndb_cn_drop(self->ikdb_cndb, kvs->kk_cnid);
        err = merr(EBUG);
        goto err_out;
    }

    assert(kvs->kk_cparams);

    self->ikdb_kvs_cnt++;
    self->ikdb_kvs_vec[idx] = kvs;

    mutex_unlock(&self->ikdb_lock);

    /* Register in kvs make instead of open so all KVSes can be queried for
     * info
     */
    err = kvs_rest_register(
        self->ikdb_mpname, self->ikdb_kvs_vec[idx]->kk_name, self->ikdb_kvs_vec[idx]);
    if (ev(err))
        hse_elog(
            HSE_WARNING "rest: %s registration failed: @@e", err, self->ikdb_kvs_vec[idx]->kk_name);

    return 0;

err_out:
    mutex_unlock(&self->ikdb_lock);
    kvdb_kvs_destroy(kvs);
    return err;
}

merr_t
ikvdb_kvs_drop(struct ikvdb *handle, const char *kvs_name)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    struct kvdb_kvs *  kvs;
    int                idx;
    merr_t             err;

    if (self->ikdb_rp.read_only)
        return merr(ev(EROFS));

    err = validate_kvs_name(kvs_name);
    if (ev(err))
        return err;

    mutex_lock(&self->ikdb_lock);

    idx = get_kvs_index(self->ikdb_kvs_vec, kvs_name, NULL);
    if (idx < 0) {
        err = merr(ev(ENOENT));
        goto err_out;
    }

    kvs = self->ikdb_kvs_vec[idx];

    if (kvs->kk_ikvs) {
        err = merr(ev(EBUSY));
        goto err_out;
    }

    kvs_rest_deregister(self->ikdb_mpname, kvs->kk_name);

    /* kvs_rest_deregister() waits until all active rest requests
     * have finished. Verify that the refcnt has gone down to zero
     */
    assert(atomic_read(&kvs->kk_refcnt) == 0);

    err = cndb_cn_drop(self->ikdb_cndb, kvs->kk_cnid);
    if (ev(err))
        goto err_out;

    drop_kvs_index(handle, idx);

err_out:
    mutex_unlock(&self->ikdb_lock);
    return err;
}

merr_t
ikvdb_get_names(struct ikvdb *handle, unsigned int *count, char ***kvs_list)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    int                i, slot = 0;
    char **            kvsv;
    char *             name;

    kvsv = calloc(HSE_KVS_COUNT_MAX, sizeof(*kvsv) + HSE_KVS_NAME_LEN_MAX);
    if (!kvsv)
        return merr(ev(ENOMEM));

    mutex_lock(&self->ikdb_lock);

    /* seek to start of the section holding the strings */
    name = (char *)&kvsv[self->ikdb_kvs_cnt];

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        struct kvdb_kvs *kvs = self->ikdb_kvs_vec[i];

        if (!kvs)
            continue;

        strlcpy(name, kvs->kk_name, HSE_KVS_NAME_LEN_MAX);

        kvsv[slot++] = name;
        name += HSE_KVS_NAME_LEN_MAX;
    }

    *kvs_list = kvsv;

    if (count)
        *count = self->ikdb_kvs_cnt;

    mutex_unlock(&self->ikdb_lock);
    return 0;
}

void
ikvdb_free_names(struct ikvdb *handle, char **kvsv)
{
    free(kvsv);
}

void
ikvdb_kvs_count(struct ikvdb *handle, unsigned int *count)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    *count = self->ikdb_kvs_cnt;
}

merr_t
ikvdb_kvs_open(
    struct ikvdb *     handle,
    const char *       kvs_name,
    struct hse_params *params,
    uint               flags,
    struct hse_kvs **  kvs_out)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    struct kvdb_kvs *  kvs;
    int                idx;
    struct kvs_rparams rp, profile;
    merr_t             err;

    /* load profile */
    profile = hse_params_to_kvs_rparams(self->ikdb_profile, kvs_name, NULL);

    /* overwrite with CLI/API changes */
    rp = hse_params_to_kvs_rparams(params, kvs_name, &profile);

    rp.rdonly = self->ikdb_rp.read_only; /* inherit from kvdb */

    err = kvs_rparams_validate(&rp);
    if (ev(err))
        return err;

    /*
     * Install c1 related callbacks for c0sk to use
     */
    ikvdb_c1_install_callbacks(self);

    if (rp.kv_print_config)
        kvs_rparams_print(&rp);

    mutex_lock(&self->ikdb_lock);

    idx = get_kvs_index(self->ikdb_kvs_vec, kvs_name, NULL);
    if (idx < 0) {
        err = merr(ev(ENOENT));
        goto err_out;
    }

    kvs = self->ikdb_kvs_vec[idx];

    if (kvs->kk_ikvs) {
        err = merr(ev(EBUSY));
        goto err_out;
    }

    kvs->kk_parent = self;

    /* Need a lock to prevent ikvdb_close from freeing up resources from
     * under us
     */

    err = kvs_open(
        handle,
        kvs,
        self->ikdb_mpname,
        self->ikdb_ds,
        self->ikdb_cndb,
        &rp,
        &self->ikdb_health,
        self->ikdb_cn_kvdb,
        flags);
    if (ev(err))
        goto err_out;

    atomic_inc(&kvs->kk_refcnt);

    *kvs_out = (struct hse_kvs *)kvs;
    mutex_unlock(&self->ikdb_lock);

    return 0;

err_out:
    mutex_unlock(&self->ikdb_lock);
    return err;
}

merr_t
ikvdb_kvs_close(struct hse_kvs *handle)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent = kk->kk_parent;
    merr_t             err;
    struct ikvs *      ikvs_tmp;

    mutex_lock(&parent->ikdb_lock);

    if (!kk->kk_ikvs) {
        mutex_unlock(&parent->ikdb_lock);
        return merr(ev(EBADF));
    }

    ikvs_tmp = kk->kk_ikvs;
    kk->kk_ikvs = 0;

    mutex_unlock(&parent->ikdb_lock);

    /* if refcnt goes down to 1, it would mean we have the only ref.
     * Set it to 0 and proceed
     * if not, keep spinning
     */
    while (atomic_cmpxchg(&kk->kk_refcnt, 1, 0) > 1)
        __builtin_ia32_pause();

    err = kvs_close(ikvs_tmp);

    return err;
}

/* PRIVATE */
struct cn *
ikvdb_kvs_get_cn(struct hse_kvs *kvs)
{
    struct kvdb_kvs *kk = (struct kvdb_kvs *)kvs;

    return kvs_cn(kk->kk_ikvs);
}

struct mpool *
ikvdb_mpool_get(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    return handle ? self->ikdb_ds : NULL;
}

merr_t
ikvdb_close(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    unsigned int       i;
    merr_t             err;
    merr_t             ret = 0; /* store the first error encountered */

    /* Shutdown workqueue
     */
    if (!self->ikdb_rdonly) {
        while (!cancel_delayed_work(&self->ikdb_sos_dwork))
            msleep(250);
        self->ikdb_work_stop = true;
        destroy_workqueue(self->ikdb_workqueue);
    }

    sos_log_destroy(self->ikdb_sos);
    free(self->ikdb_sos_buf);

    /* Deregistering this url before trying to get ikdb_lock prevents
     * a deadlock between this call and an ongoing call to ikvdb_get_names()
     */
    kvdb_rest_deregister(self->ikdb_mpname);

    mutex_lock(&self->ikdb_lock);

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        struct kvdb_kvs *kvs = self->ikdb_kvs_vec[i];

        if (!kvs)
            continue;

        if (kvs->kk_ikvs)
            atomic_dec(&kvs->kk_refcnt);

        kvs_rest_deregister(self->ikdb_mpname, kvs->kk_name);

        /* kvs_rest_deregister() waits until all active rest requests
         * have finished. Verify that the refcnt has gone down to zero
         */
        assert(atomic_read(&kvs->kk_refcnt) == 0);

        if (kvs->kk_ikvs) {
            err = kvs_close(kvs->kk_ikvs);
            if (ev(err))
                ret = ret ?: err;
        }

        self->ikdb_kvs_vec[i] = NULL;
        kvdb_kvs_destroy(kvs);
    }

    /* c0sk can only be closed after all c0s. This ensures that there are
     * no references to c0sk at this point.
     */
    if (self->ikdb_c0sk) {
        err = c0sk_close(self->ikdb_c0sk);
        if (ev(err))
            ret = ret ?: err;
    }

    cn_kvdb_destroy(self->ikdb_cn_kvdb);

    err = kvdb_rparams_remove_from_dt(self->ikdb_mpname);
    if (err)
        hse_elog(
            HSE_ERR "%s: Failed to remove %s KVDB rparams "
                    "from data tree @@e",
            err,
            __func__,
            self->ikdb_mpname);

    err = cndb_close(self->ikdb_cndb);
    if (ev(err))
        ret = ret ?: err;

    err = kvdb_log_close(self->ikdb_log);
    if (ev(err))
        ret = ret ?: err;

    if (self->ikdb_c1) {
        err = c1_close(self->ikdb_c1);
        if (ev(err))
            ret = ret ?: err;
    }

    mutex_unlock(&self->ikdb_lock);

    ikvdb_txn_fini(self);

    kvdb_ctxn_set_destroy(self->ikdb_ctxn_set);

    kvdb_keylock_destroy(self->ikdb_keylock);

    active_ctxn_set_destroy(self->ikdb_active_txn_set);

    csched_destroy(self->ikdb_csched);

    mutex_destroy(&self->ikdb_lock);

    throttle_fini(&self->ikdb_throttle);

    ikvdb_perfc_free(self);

    free_aligned(self);

    return ret;
}

/**
 * ikvdb_throttle() - sleep after a successful put
 * @p:
 * @start: time in ns at which the put op began
 * @len:   total key + value length for the put
 */
static inline void
ikvdb_throttle(struct ikvdb_impl *p, u64 start, u32 len)
{
    long delay __maybe_unused;

    if (!throttle_active(&p->ikdb_throttle))
        return;

    delay = throttle(&p->ikdb_throttle, start, len);
    if (delay > 0)
        perfc_rec_sample(&kvdb_metrics_pc, PERFC_DI_KVDBMETRICS_THROTTLE, delay);
}

merr_t
ikvdb_kvs_put(
    struct hse_kvs *         handle,
    struct hse_kvdb_opspec * os,
    struct kvs_ktuple *      kt,
    const struct kvs_vtuple *vt)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent;
    u64                put_seqno;
    merr_t             err;
    u64                start;

    start = kvdb_kop_is_priority(os) ? 0 : get_time_ns();

    if (ev(!handle))
        return merr(EINVAL);

    parent = kk->kk_parent;
    if (ev(parent->ikdb_rdonly))
        return merr(EROFS);

    /* puts do not stop on block deletion failures. */
    err = kvdb_health_check(
        &parent->ikdb_health, KVDB_HEALTH_FLAG_ALL & ~KVDB_HEALTH_FLAG_DELBLKFAIL);
    if (ev(err))
        return err;

    put_seqno = kvdb_kop_is_txn(os) ? 0 : HSE_SQNREF_SINGLE;

    err = ikvs_put(kk->kk_ikvs, os, kt, vt, put_seqno);
    if (err) {
        ev(merr_errno(err) != ECANCELED);
        return err;
    }

    if (start > 0)
        ikvdb_throttle(parent, start, kt->kt_len + vt->vt_len);

    return 0;
}

merr_t
ikvdb_kvs_pfx_probe(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    enum key_lookup_res *   res,
    struct kvs_buf *        kbuf,
    struct kvs_buf *        vbuf)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *p;
    u64                view_seqno;

    if (ev(!handle))
        return merr(EINVAL);

    p = kk->kk_parent;

    view_seqno = kvdb_kop_is_txn(os) ? 0 : atomic64_read(&p->ikdb_seqno);

    return ikvs_pfx_probe(kk->kk_ikvs, os, kt, view_seqno, res, kbuf, vbuf);
}

merr_t
ikvdb_kvs_get(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    enum key_lookup_res *   res,
    struct kvs_buf *        vbuf)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *p;
    u64                view_seqno;

    if (ev(!handle))
        return merr(EINVAL);

    p = kk->kk_parent;

    view_seqno = kvdb_kop_is_txn(os) ? 0 : atomic64_read(&p->ikdb_seqno);

    return ikvs_get(kk->kk_ikvs, os, kt, view_seqno, res, vbuf);
}

merr_t
ikvdb_kvs_del(struct hse_kvs *handle, struct hse_kvdb_opspec *os, struct kvs_ktuple *kt)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent;
    u64                del_seqno;
    merr_t             err;

    if (ev(!handle))
        return merr(EINVAL);

    parent = kk->kk_parent;
    if (ev(parent->ikdb_rdonly))
        return merr(EROFS);

    /* tombstone puts do not stop on block deletion failures. */
    err = kvdb_health_check(
        &parent->ikdb_health, KVDB_HEALTH_FLAG_ALL & ~KVDB_HEALTH_FLAG_DELBLKFAIL);
    if (ev(err))
        return err;

    del_seqno = kvdb_kop_is_txn(os) ? 0 : HSE_SQNREF_SINGLE;

    err = ikvs_del(kk->kk_ikvs, os, kt, del_seqno);
    if (ev(err))
        return err;

    return 0;
}

merr_t
ikvdb_kvs_prefix_delete(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    size_t *                kvs_pfx_len)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent;
    merr_t             err;
    u32                ct_pfx_len;
    u64                pdel_seqno;

    if (ev(!handle))
        return merr(EINVAL);

    parent = kk->kk_parent;
    if (ev(parent->ikdb_rdonly))
        return merr(EROFS);

    ct_pfx_len = kk->kk_cparams->cp_pfx_len;
    if (kvs_pfx_len)
        *kvs_pfx_len = ct_pfx_len;

    if (ev(!kt->kt_data || kt->kt_len != ct_pfx_len))
        return merr(EINVAL);
    if (ev(kt->kt_len == 0))
        return merr(ENOENT);

    pdel_seqno = kvdb_kop_is_txn(os) ? 0 : HSE_SQNREF_SINGLE;

    /* Prefix tombstone deletes all current keys with a matching prefix -
     * those with a sequence number up to but excluding the current seqno.
     * Insert prefix tombstone with a higher seqno. Use a higher sequence
     * number to allow newer mutations (after prefix) to be distinguished.
     */
    err = ikvs_prefix_del(kk->kk_ikvs, os, kt, pdel_seqno);
    if (ev(err))
        return err;

    return 0;
}

/*-  IKVDB Cursors --------------------------------------------------*/

/*
 * IKVDB cursors allow iteration over a single KVS' c0, cN, and ctxn.
 * The normal life-cycle is create-iterate-destroy, where iterate has
 * several verbs: seek, read, bind, and update.  Cursors are single-threaded
 * and they are stateful.  These states are:
 *
 * 0 nil - cursor does not exist
 * 1 use - cursor has been created, and is iteratable
 * 2 err - cursor is in error and must be destroyed
 * 3 txn - cursor is bound to a transaction
 * 4 inv - cursor is invalid, either because the txn commited/aborted
 *         or because the cursor was holding onto resources too long
 *         and they were removed.
 *
 * These states are operated on by direct calls into kvdb, or indirectly
 * due to an asynchronous timeout, or an error resulting from a kvdb call.
 *
 * The state transition table (dashes represent invalid verbs for a state):
 *
 *              0/nil   1/use   2/err   3/txn   4/inv
 *      create  1       -       -       -       -
 *      destroy -       0       0       0       0
 *      update  -       1a      -       3b      1a
 *      bind    -       3c      -       -       3c
 *      commit  -       -       -       4       -
 *      abort   -       -       -       4       -
 *
 * a - view seqno is updated as in create
 * b - view seqno remains same, but all existing keys in txn become visible
 * c - view seqno is set to the transactions view
 *
 * Seek and read are available in states 1 and 3, and return ESTALE in 4.
 * They can only operate over the keys visible at the time of the create
 * or last update.
 *
 * State 2 can only occur if there is an error in an underlying operation.
 *
 * Transactions only interact with bound cursors (state 3); transaction
 * puts and dels after bind are invisible until a subsequent update,
 * just as puts and dels after create are invisible until an update.
 *
 * Both create and update may return EAGAIN.  This does not create an error
 * condition, as simply repeating the call may succeed.
 */

static void
update_cursor_horizon(struct kvdb_kvs *kk)
{
    struct hse_kvs_cursor *oldest;
    u64                    seq;

    /* caller must hold kk_cursors_lock */

    if (list_empty(&kk->kk_cursors)) {
        seq = U64_MAX;
    } else {
        oldest = list_last_entry(&kk->kk_cursors, struct hse_kvs_cursor, kc_link);
        seq = oldest->kc_seq;
    }

    atomic64_set(&kk->kk_parent->ikdb_seqno_cur, seq);
}

static bool
cursor_insert_horizon(struct hse_kvs_cursor *cursor, uint64_t *seqno)
{
    struct kvdb_kvs *kk = cursor->kc_kvs;

    /* Add to cursor list only if this is NOT part of a txn. */
    if (*seqno == HSE_SQNREF_UNDEFINED) {
        *seqno = atomic64_fetch_add(1, &kk->kk_parent->ikdb_seqno);
        list_add(&cursor->kc_link, &kk->kk_cursors);
        return true;
    }

    return false;
}

static void
cursor_reserve_seqno(struct hse_kvs_cursor *cursor, uint64_t *seqno)

{
    struct kvdb_kvs *kk = cursor->kc_kvs;

    mutex_lock(&kk->kk_cursors_lock);
    cursor->kc_added_to_list = cursor_insert_horizon(cursor, seqno);
    if (cursor->kc_added_to_list)
        update_cursor_horizon(kk);
    mutex_unlock(&kk->kk_cursors_lock);
}

static void
cursor_release_seqno(struct hse_kvs_cursor *cursor)
{
    struct kvdb_kvs *kk = cursor->kc_kvs;

    if (!cursor->kc_added_to_list)
        return;

    mutex_lock(&kk->kk_cursors_lock);
    list_del(&cursor->kc_link);
    update_cursor_horizon(kk);
    mutex_unlock(&kk->kk_cursors_lock);
}

static merr_t
cursor_bind_txn(struct hse_kvs_cursor *cursor, struct kvdb_ctxn *ctxn)
{
    merr_t err;

    if (ev(cursor->kc_err))
        return merr(cursor->kc_err);

    assert(!cursor->kc_bind);

    cursor->kc_bind = kvdb_ctxn_cursor_bind(ctxn);
    if (!cursor->kc_bind)
        return merr(ev(ECANCELED));

    err = ikvs_cursor_bind_txn(cursor, ctxn);
    if (ev(err)) {
        kvdb_ctxn_cursor_unbind(cursor->kc_bind);
        cursor->kc_bind = 0;
        return err;
    }

    return 0;
}

static merr_t
cursor_unbind_txn(struct hse_kvs_cursor *cur)
{
    struct kvdb_ctxn_bind *bind = cur->kc_bind;

    if (bind) {
        ikvs_cursor_tombspan_check(cur);
        cur->kc_gen = -1;
        cur->kc_bind = 0;

        /*
         * Retain the view seqno of the current transaction if the
         * static view flag is set.
         * If the flag isn't set, a committed txn unbind sets the view
         * to commit_sn + 1 and an aborted txn unbind sets the view to
         * the current KVDB seqno.
         */
        if (!(cur->kc_flags & HSE_KVDB_KOP_FLAG_STATIC_VIEW))
            cur->kc_seq = bind->b_seq;

        kvdb_ctxn_cursor_unbind(bind);
        ikvs_cursor_bind_txn(cur, 0);
    }
    return 0;
}

merr_t
ikvdb_kvs_cursor_create(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    const void *            prefix,
    size_t                  pfx_len,
    struct hse_kvs_cursor **cursorp)
{
    struct kvdb_kvs *      kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *    ikvdb = kk->kk_parent;
    struct kvdb_ctxn *     ctxn = 0;
    struct kvdb_ctxn *     bind = 0;
    struct hse_kvs_cursor *cur = 0;
    int                    reverse;
    merr_t                 err;
    unsigned int           cursor_cnt;
    u64                    vseq, tstart;
    struct perfc_set *     pkvsl_pc;

    *cursorp = NULL;

    pkvsl_pc = ikvs_perfc_pkvsl(kk->kk_ikvs);
    tstart = perfc_lat_start(pkvsl_pc);

    reverse = false;
    cursor_cnt = atomic_read(&ikvdb->ikdb_curcnt);
    if (ev(cursor_cnt >= ikvdb->ikdb_curcnt_max)) {
        hse_log(
            HSE_WARNING "Number of open cursors (%u) has exceeded "
                        "the max allowed cursors (%u)",
            cursor_cnt,
            ikvdb->ikdb_curcnt_max);
        return merr(ECANCELED);
    }

    /*
     * There are 3 types of cursors:
     * 1. those that create their own view.
     * 2. those that use the transaction's view.
     * 3. those that bind to a transaction's lifecycle.
     *
     * The final type is a special cursor that can iterate over
     * the contents of a transaction.  But it also becomes stale
     * upon each update to the transaction, and is automatically
     * canceled when the transaction completes (commit or abort).
     *
     * These types are distinguished here.
     */

    if (os) {
        reverse = kvdb_kop_is_reverse(os);
        if (os->kop_txn)
            ctxn = kvdb_ctxn_h2h(os->kop_txn);
        if (kvdb_kop_is_bind_txn(os)) {
            bind = ctxn;
            if (ev(!bind))
                return merr(EINVAL);
        }
    }

    vseq = HSE_SQNREF_UNDEFINED;
    if (ctxn) {
        err = kvdb_ctxn_get_view_seqno(ctxn, &vseq);
        if (ev(err))
            return err;
    }

    /* The initialization sequence is driven by the way the sequence
     * number horizon is tracked, which requires atomically getting a
     * cursor's view sequence number and inserting the cursor at the head
     * of the list of cursors.  This must be done prior to cursor
     * creation, hence the need to separate cursor alloc from cursor
     * init/create.  The steps are:
     *  - allocate cursor struct
     *  - register cursor (atomic get seqno, add to kk_cursors)
     *  - initialize cursor
     * The failure path must unregister the cursor from kk_cursors.
     */
    cur = ikvs_cursor_alloc(kk->kk_ikvs, prefix, pfx_len, reverse);
    if (ev(!cur))
        return merr(ENOMEM);

    cur->kc_pkvsl_pc = pkvsl_pc;

    /* if we have a transaction at all, use its view seqno... */
    cur->kc_seq = vseq;
    cur->kc_flags = os ? os->kop_flags : 0;
    cur->kc_cursor_cnt = &ikvdb->ikdb_curcnt;
    atomic_inc(cur->kc_cursor_cnt);
    perfc_inc(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURCNT);

    cur->kc_kvs = kk;
    cur->kc_gen = 0;
    cur->kc_bind = 0;

    /* Temporarily lock a view until this cursor gets refs on cn kvsets. */
    cursor_reserve_seqno(cur, &cur->kc_seq);
    err = ikvs_cursor_init(cur);
    cursor_release_seqno(cur);

    /* ... but only bind lifecycle if asked */
    if (!ev(err) && bind)
        err = cursor_bind_txn(cur, bind);

    if (ev(err)) {
        ikvdb_kvs_cursor_destroy(cur);
        cur = 0;
    }

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_CREATE, tstart);

    *cursorp = cur;

    return err;
}

merr_t
ikvdb_kvs_cursor_update(struct hse_kvs_cursor *cur, struct hse_kvdb_opspec *os)
{
    struct kvdb_ctxn_bind *bound;
    struct kvdb_ctxn *     ctxn;
    struct kvdb_ctxn *     bind = 0;
    u64                    seqno;
    merr_t                 err;
    u64                    tstart;

    tstart = perfc_lat_start(cur->kc_pkvsl_pc);

    /* a cursor in error cannot be updated - must be destroyed */
    if (ev(cur->kc_err))
        return cur->kc_err;

    /*
     * Update is allowed to unbind a txn, bind to a new txn,
     * change from txn A to txn B without a unbind, or just
     * update its view seqno.
     *
     * If the txn is committed or aborted, update retains the
     * view seqno, and tosses the kvms.
     *
     * Updates cannot restore a cursor in error.  Such cursors
     * must be destroyed.  There are too many possible recovery
     * actions to handle with update; destroy and recreate.
     */

    cur->kc_seq = HSE_SQNREF_UNDEFINED;

    ctxn = kvdb_kop_is_txn(os) ? kvdb_ctxn_h2h(os->kop_txn) : NULL;
    if (ctxn) {
        /* this is a recoverable error */
        err = kvdb_ctxn_get_view_seqno(ctxn, &cur->kc_seq);
        if (ev(err))
            return err;
    }

    bound = cur->kc_bind;
    if (bound) {
        struct hse_kvdb_opspec unbindme;

        HSE_KVDB_OPSPEC_INIT(&unbindme);
        unbindme.kop_flags = HSE_KVDB_KOP_FLAG_BIND_TXN;

        /* if os is nil, this is the finish of a txn commit/abort */
        if (!os)
            os = &unbindme;

        if (kvdb_kop_is_bind_txn(os)) {
            if (!ctxn || ctxn != bound->b_ctxn) {
                /* save view seq; do not change in unbind */
                seqno = cur->kc_seq;
                cursor_unbind_txn(cur);
                cur->kc_seq = seqno;
                bind = ctxn;
            }
        } else if (ctxn) {
            return ev(merr(EINVAL));
        }
    } else if (ctxn) {
        if (kvdb_kop_is_bind_txn(os))
            bind = ctxn;
    }

    /* Temporarily reserve seqno until this cursor gets refs on
     * cn kvsets.
     */
    cursor_reserve_seqno(cur, &cur->kc_seq);
    cur->kc_err = ikvs_cursor_update(cur, cur->kc_seq);
    cursor_release_seqno(cur);

    if (!cur->kc_err && bind)
        cur->kc_err = cursor_bind_txn(cur, bind);

    cur->kc_flags = os ? os->kop_flags : 0;

    perfc_lat_record(cur->kc_pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_UPDATE, tstart);

    return ev(cur->kc_err);
}

static merr_t
cursor_refresh(struct hse_kvs_cursor *cur)
{
    struct kvdb_ctxn_bind *bind = cur->kc_bind;
    merr_t                 err = 0;
    int                    up = 0;

    if (!bind->b_ctxn) {
        /* canceled: txn was committed or aborted since last look */
        err = cursor_unbind_txn(cur);
        if (ev(err))
            return err;
        ++up;

    } else if (atomic64_read(&bind->b_gen) != cur->kc_gen) {
        /* stale or canceled: txn was updated since last look */
        ++up;
    }

    if (up)
        err = ikvs_cursor_update(cur, cur->kc_seq);

    return ev(err);
}

merr_t
ikvdb_kvs_cursor_seek(
    struct hse_kvs_cursor * cur,
    struct hse_kvdb_opspec *os,
    const void *            key,
    size_t                  len,
    const void *            limit,
    size_t                  limit_len,
    struct kvs_ktuple *     kt)
{
    merr_t err;
    u64    tstart;

    tstart = perfc_lat_start(cur->kc_pkvsl_pc);

    if (ev(kvdb_kop_is_txn(os)))
        return merr(EINVAL);

    if (ev(cur->kc_err)) {
        if (ev(merr_errno(cur->kc_err) != EAGAIN))
            return cur->kc_err;

        cur->kc_err = ikvs_cursor_update(cur, cur->kc_seq);
        if (ev(cur->kc_err))
            return cur->kc_err;
    }

    if (cur->kc_bind) {
        cur->kc_err = cursor_refresh(cur);
        if (ev(cur->kc_err))
            return cur->kc_err;
    }

    /* errors on seek are not fatal */
    err = ikvs_cursor_seek(cur, key, (u32)len, limit, (u32)limit_len, kt);

    perfc_lat_record(cur->kc_pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_SEEK, tstart);

    return ev(err);
}

merr_t
ikvdb_kvs_cursor_read(
    struct hse_kvs_cursor * cur,
    struct hse_kvdb_opspec *os,
    const void **           key,
    size_t *                key_len,
    const void **           val,
    size_t *                val_len,
    bool *                  eof)
{
    struct kvs_kvtuple kvt;
    merr_t             err;
    u64                tstart;

    tstart = perfc_lat_start(cur->kc_pkvsl_pc);

    if (ev(kvdb_kop_is_txn(os)))
        return merr(EINVAL);

    if (ev(cur->kc_err)) {
        if (ev(merr_errno(cur->kc_err) != EAGAIN))
            return cur->kc_err;

        cur->kc_err = ikvs_cursor_update(cur, cur->kc_seq);
        if (ev(cur->kc_err))
            return cur->kc_err;
    }

    if (cur->kc_bind) {
        cur->kc_err = cursor_refresh(cur);
        if (ev(cur->kc_err))
            return cur->kc_err;
    }

    err = ikvs_cursor_read(cur, &kvt, eof);
    if (ev(err))
        return err;
    if (*eof)
        return 0;

    *key = kvt.kvt_key.kt_data;
    *key_len = kvt.kvt_key.kt_len;
    *val = kvt.kvt_value.vt_data;
    *val_len = kvt.kvt_value.vt_len;

    perfc_lat_record(
        cur->kc_pkvsl_pc,
        cur->kc_flags & HSE_KVDB_KOP_FLAG_REVERSE ? PERFC_LT_PKVSL_KVS_CURSOR_READREV
                                                  : PERFC_LT_PKVSL_KVS_CURSOR_READFWD,
        tstart);

    return 0;
}

merr_t
ikvdb_kvs_cursor_destroy(struct hse_kvs_cursor *cur)
{
    struct perfc_set *pkvsl_pc;
    u64               tstart;

    if (!cur)
        return 0;

    pkvsl_pc = cur->kc_pkvsl_pc;
    tstart = perfc_lat_start(pkvsl_pc);

    cursor_unbind_txn(cur);

    atomic_dec(cur->kc_cursor_cnt);
    perfc_dec(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURCNT);

    ikvs_cursor_free(cur);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_DESTROY, tstart);

    return 0;
}

void
ikvdb_compact(struct ikvdb *handle, int flags)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_rdonly))
        return;

    csched_compact_request(self->ikdb_csched, flags);
}

void
ikvdb_compact_status(struct ikvdb *handle, struct hse_kvdb_compact_status *status)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_rdonly))
        return;

    csched_compact_status(self->ikdb_csched, status);
}

merr_t
ikvdb_sync(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (self->ikdb_rdonly)
        return merr(ev(EROFS));

    if (!self->ikdb_c1)
        return ikvdb_sync_int(self);

    return c0skm_sync(self->ikdb_c0sk);
}

merr_t
ikvdb_flush(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (self->ikdb_rdonly)
        return merr(ev(EROFS));

    if (!self->ikdb_c1)
        return ikvdb_flush_int(self);

    return c0skm_flush(self->ikdb_c0sk);
}

u64
ikvdb_horizon(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    u64                horizon;
    u64                b, c;
    u64                a;

    b = atomic64_read(&self->ikdb_seqno_cur);
    c = active_ctxn_set_horizon(self->ikdb_active_txn_set);

    /* Must read a after b and c to test assertions. */
    a = atomic64_read(&self->ikdb_seqno);
    assert(b == U64_MAX || a >= b);
    assert(a >= c);

    horizon = min_t(u64, b, c);

    perfc_set(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_SEQNO, a);
    perfc_set(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURHORIZON, horizon);
    perfc_set(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_HORIZON, horizon);

    return horizon;
}

static __always_inline struct kvdb_ctxn_bkt *
ikvdb_txn_tid2bkt(struct ikvdb_impl *self)
{
    u64 tid = pthread_self();

    return self->ikdb_ctxn_cache + (tid % NELEM(self->ikdb_ctxn_cache));
}

struct hse_kvdb_txn *
ikvdb_txn_alloc(struct ikvdb *handle)
{
    struct ikvdb_impl *   self = ikvdb_h2r(handle);
    struct kvdb_ctxn_bkt *bkt = ikvdb_txn_tid2bkt(self);
    struct kvdb_ctxn *    ctxn = NULL;

    spin_lock(&bkt->kcb_lock);
    if (bkt->kcb_ctxnc > 0)
        ctxn = bkt->kcb_ctxnv[--bkt->kcb_ctxnc];
    spin_unlock(&bkt->kcb_lock);

    if (ctxn)
        return &ctxn->ctxn_handle;

    ctxn = kvdb_ctxn_alloc(
        self->ikdb_keylock,
        &self->ikdb_seqno,
        self->ikdb_ctxn_set,
        self->ikdb_active_txn_set,
        self->ikdb_c0sk);
    if (ev(!ctxn))
        return NULL;

    perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_ALLOC);

    return &ctxn->ctxn_handle;
}

void
ikvdb_txn_free(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    struct ikvdb_impl *   self = ikvdb_h2r(handle);
    struct kvdb_ctxn_bkt *bkt = ikvdb_txn_tid2bkt(self);
    struct kvdb_ctxn *    ctxn;

    if (!txn)
        return;

    ctxn = kvdb_ctxn_h2h(txn);
    kvdb_ctxn_abort(ctxn);

    spin_lock(&bkt->kcb_lock);
    if (bkt->kcb_ctxnc < NELEM(bkt->kcb_ctxnv)) {
        bkt->kcb_ctxnv[bkt->kcb_ctxnc++] = ctxn;
        ctxn = NULL;
    }
    spin_unlock(&bkt->kcb_lock);

    if (ctxn) {
        perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_FREE);

        kvdb_ctxn_free(ctxn);
    }
}

merr_t
ikvdb_txn_begin(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    merr_t             err;

    perfc_inc(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);
    perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_BEGIN);

    err = kvdb_ctxn_begin(kvdb_ctxn_h2h(txn));

    if (ev(err))
        perfc_dec(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);

    return err;
}

merr_t
ikvdb_txn_commit(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    merr_t             err;
    u64                lstart;

    lstart = perfc_lat_startu(&self->ikdb_ctxn_op, PERFC_LT_CTXNOP_COMMIT);
    perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_COMMIT);

    err = kvdb_ctxn_commit(kvdb_ctxn_h2h(txn));

    perfc_dec(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);
    perfc_lat_record(&self->ikdb_ctxn_op, PERFC_LT_CTXNOP_COMMIT, lstart);

    return err;
}

merr_t
ikvdb_txn_abort(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_ABORT);

    kvdb_ctxn_abort(kvdb_ctxn_h2h(txn));

    perfc_dec(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);

    return 0;
}

enum kvdb_ctxn_state
ikvdb_txn_state(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    return kvdb_ctxn_get_state(kvdb_ctxn_h2h(txn));
}

/*-  Perf Counter Support  --------------------------------------------------*/

/*
 * Perf counters, once allocated, are only released upon module fini.
 * This preserves the user-space counters until they can be emitted,
 * and allows counters to be accumulated in use cases where multiple
 * open/close per application lifetime are employed.
 *
 * Therefore, the pointers to the allocated counters (cf cn_perfc_alloc())
 * are remembered here, and released after emitting.  It is possible for
 * an application to open several different datasets, each with its own
 * set of perf counters.  All these are remembered, then emitted and
 * released here.
 *
 * The intervals used by the perf counters are customized once here,
 * then set in the static structures at init time.
 *
 * Finally, there are a couple of configurable items set here:
 *      1. Should hse messages be sent to stderr?
 *      2. Are perf counters enabled?
 *
 * The only public APIs is:
 *      void kvdb_perfc_register(void *);
 */

static struct darray kvdb_perfc_reg;

/*
 * kvdb_perfc_register - remember this perfc pointer until module fini
 *
 * NB: It is NOT fatal to have an error here.  It simply means the
 * memory will not be freed on module fini.
 */
void
kvdb_perfc_register(void *pc)
{
    if (darray_append_uniq(&kvdb_perfc_reg, pc) != 0)
        hse_log(
            HSE_ERR "kvdb_perfc_register: cannot register"
                    " perf counter #%d for %s",
            kvdb_perfc_reg.cur + 1,
            perfc_ctrseti_path(pc));
}

/*
 * This function is called once at constructor time.
 * The variables that control log verbosity and perf counters
 * must be set at compile time -- there is no before-this
 * configuration to change at this point.
 *
 * However, setter methods are available from this point
 * forward, so these defaults can be overridden programatically.
 */

static void
kvdb_perfc_initialize(void)
{
    perfc_verbosity = 2;

    kvdb_perfc_init();
    kvs_perfc_init();
    c0sk_perfc_init();
    c0skm_perfc_init();
    c1_perfc_init();
    cn_perfc_init();
    throttle_perfc_init();

    hse_openlog(COMPNAME, 0);

    if (perfc_ctrseti_alloc(COMPNAME, "global", kvdb_perfc_op, PERFC_EN_KVDBOP, "set", &kvdb_pc))
        hse_log(HSE_ERR "cannot alloc kvdb op perf counters");
    else
        kvdb_perfc_register(&kvdb_pc);

    if (perfc_ctrseti_alloc(
            COMPNAME, "global", kvdb_perfc_pkvdbl_op, PERFC_EN_PKVDBL, "set", &kvdb_pkvdbl_pc))
        hse_log(HSE_ERR "cannot alloc kvdb public op perf counters");
    else
        kvdb_perfc_register(&kvdb_pkvdbl_pc);

    if (perfc_ctrseti_alloc(
            COMPNAME, "global", c0_metrics_perfc, PERFC_EN_C0METRICS, "set", &c0_metrics_pc))
        hse_log(HSE_ERR "cannot alloc c0 metrics perf counters");
    else
        kvdb_perfc_register(&c0_metrics_pc);

    if (perfc_ctrseti_alloc(
            COMPNAME, "global", kvdb_metrics_perfc, PERFC_EN_KVDBMETRICS, "set", &kvdb_metrics_pc))
        hse_log(HSE_ERR "cannot alloc kvdb metrics perf counters");
    else
        kvdb_perfc_register(&kvdb_metrics_pc);
}

static void
kvdb_perfc_finish(void)
{
    darray_apply(&kvdb_perfc_reg, (darray_func)perfc_ctrseti_free);
    darray_fini(&kvdb_perfc_reg);

    throttle_perfc_fini();
    cn_perfc_fini();
    c1_perfc_fini();
    c0skm_perfc_fini();
    c0sk_perfc_fini();
    kvs_perfc_fini();
    kvdb_perfc_fini();
}

/* [HSE_REVISIT]
 * 4 MiB, as we dump the entire data tree into this buffer, i.e., /data. There
 * is no deterministic way to determine a max bound for this buffer size.
 * So, if you notice truncated YAML contents in dt.log, it is due to this
 * buffer size.
 */
#define DT_BUFSZ (4 * 1024 * 1024)

static void
log_dt(void)
{
    const char *dt_out = "/var/log/hse/dt.log";
    int         fd;
    merr_t      err;

    fd = open(dt_out, O_WRONLY | O_APPEND);
    if (fd != -1) {
        time_t      t;
        struct tm * tm;
        ssize_t     cc;
        char        tmp[64];
        static char buf[DT_BUFSZ]; /* 4 MiB, use bss here */
        char *      path = "/data";

        struct yaml_context yc = {
            .yaml_buf = buf,
            .yaml_buf_sz = sizeof(buf),
            .yaml_indent = 0,
            .yaml_offset = 0,
        };
        union dt_iterate_parameters dip = { .yc = &yc };

        time(&t);
        tm = localtime(&t);
        flock(fd, LOCK_EX);
        snprintf(
            tmp,
            sizeof(tmp),
            "%04d-%02d-%02dT%02d.%02d.%02d",
            tm->tm_year + 1900,
            tm->tm_mon + 1,
            tm->tm_mday,
            tm->tm_hour,
            tm->tm_min,
            tm->tm_sec);
        yaml_start_element_type(&yc, tmp);

        snprintf(tmp, sizeof(tmp), "%d", getpid());
        yaml_element_field(&yc, "pid", tmp);

        dt_iterate_cmd(dt_data_tree, DT_OP_EMIT, path, &dip, 0, 0, 0);
        yaml_end_element(&yc);
        yaml_end_element_type(&yc);

        cc = write(fd, buf, yc.yaml_offset);
        if (cc != yc.yaml_offset) {
            err = cc == -1 ? merr(errno) : merr(EIO);
            hse_elog(
                HSE_WARNING "data tree could not be dumped "
                            "to %s: @@e",
                err,
                dt_out);
        }

        flock(fd, LOCK_UN);
        close(fd);
    }
}

/* Called once by load() at program start or module load time.
 */
merr_t
ikvdb_init(void)
{
    merr_t err;

    kvdb_perfc_initialize();
    kvs_init();

    err = c0_init();
    if (err)
        goto errout;

    err = cn_init();
    if (err) {
        c0_fini();
        goto errout;
    }

errout:
    if (err) {
        kvs_fini();
        log_dt();
        kvdb_perfc_finish();
    }

    return err;
}

/* Called once by unload() at program termination or module unload time.
 */
void
ikvdb_fini(void)
{
    cn_fini();
    c0_fini();
    log_dt();
    kvs_fini();
    kvdb_perfc_finish();
}

#define KVDB_EXPORT_FSIZE_MAX 0x100000000LL /* 4GB */

/**
 * ikvdb_kvs_import: import k-v pairs from file
 *                   for each k-v pair, we import keylen, vlen, key and
 *                   value from the file
 * @work:
 */
static void
ikvdb_kvs_import(struct work_struct *work)
{

    struct kvdb_bak_work *  bak;
    void *                  key = NULL, *val = NULL;
    size_t                  klen, vlen;
    int                     fd;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    struct hse_kvdb_opspec  opspec = { 0 };
    merr_t                  err = 0;
    u64                     cnt = 0;
    void *                  dbuf, *beg, *end;
    u64                     fsize;
    struct stat             st;
    struct kvdb_kvmeta_omf *kvmt;

    bak = container_of(work, struct kvdb_bak_work, bak_work);

    if (stat(bak->bak_fname, &st) != 0) {
        bak->bak_err = merr(ev(errno, HSE_ERR));
        return;
    }

    fsize = st.st_size;

    fd = open(bak->bak_fname, O_RDONLY, 0);
    if (fd == -1) {
        bak->bak_err = merr(errno);
        hse_elog(HSE_ERR "Failed to open file %s, @@e", bak->bak_err, bak->bak_fname);
        return;
    }

    dbuf = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (dbuf == MAP_FAILED) {
        close(fd);
        bak->bak_err = merr(errno);
        hse_elog(HSE_ERR "Failed to mmap file %s %lu, @@e", bak->bak_err, bak->bak_fname, fsize);
        return;
    }

    beg = dbuf;
    end = dbuf + fsize;

    hse_log(HSE_DEBUG "Import start on %s", bak->bak_fname);

    while (beg < end) {
        kvmt = (struct kvdb_kvmeta_omf *)beg;
        klen = omf_kvmt_klen(kvmt);
        vlen = omf_kvmt_vlen(kvmt);
        if (klen > HSE_KVS_KLEN_MAX) {
            err = merr(ev(ENAMETOOLONG, HSE_ERR));
            break;
        }

        if (klen == 0) {
            err = merr(ev(ENOENT, HSE_ERR));
            break;
        }

        if (vlen > HSE_KVS_VLEN_MAX) {
            err = merr(ev(EMSGSIZE, HSE_ERR));
            break;
        }

        beg += sizeof(*kvmt);
        if (beg + klen + vlen > end) {
            err = merr(ev(EFAULT, HSE_ERR));
            break;
        }

        key = beg;
        beg += klen;
        val = beg;
        beg += vlen;

        kvs_ktuple_init_nohash(&kt, (void *)key, klen);
        kvs_vtuple_init(&vt, (void *)val, vlen);

        err = ikvdb_kvs_put(bak->bak_kvs, &opspec, &kt, &vt);
        if (err) {
            hse_elog(HSE_ERR "Failed to put key value pair, @@e", err);
            break;
        }
        cnt++;
    }

    munmap(dbuf, fsize);
    close(fd);

    hse_log(
        HSE_DEBUG "Import %ld out of %ld k-v pairs from %s", cnt, bak->bak_kvcnt, bak->bak_fname);

    bak->bak_err = err;
}

/**
 * KVDB_DUMP_CUR_VER - dump version understood by this binary
 * @KVDB_DUMP_VER1:
 */
#define KVDB_DUMP_VER1 1
#define KVDB_DUMP_CUR_VER KVDB_DUMP_VER1

/**
 * ikvdb_import_toc() - import kvdb/kvs meta data from TOC file
 *                     TOC is in JSON format
 * @path: where the dump files are
 * @kvdb_cparams: kvdb create time parameters
 * @kvscnt: number of kvs in this kvdb
 * @kvsi: import meta data into kvsi structs
 *
 * An example of a TOC file in JSON format
 * {
 *      "version":      1,
 *      "name":        "db1",
 *      "kvscnt":       1,
 *      "cndb_captgt":  0,
 *      "dur_enable":   1,
 *      "dur_capacity": 8589934592,
 *      "KVSs": [{
 *            "name":        "kvs1",
 *            "filecnt":      64,
 *            "kvcnt":        1000000000,
 *            "pfx_len":      0,
 *            "fanout":       8,
 *            "kvs_ext01":    0
 *      }]
 * }
 */
static merr_t
ikvdb_import_toc(
    const char *         path,
    struct kvdb_cparams *kvdb_cparams,
    int *                kvscnt,
    struct kvs_import *  kvsi)
{
    FILE *      f;
    char *      buf, *cjson_str;
    int         buflen, len;
    cJSON *     TOC;
    cJSON *     kvsv_json;
    cJSON *     kvs_json;
    int         ver;
    int         i, cnt;
    char *      name;
    char        fname[PATH_MAX];
    merr_t      err = 0;
    char        mp_name[MPOOL_NAMESZ_MAX];
    int         kvs_cnt;
    u32         crc, crc_rd;
    struct stat stbuf;

    len = snprintf(fname, sizeof(fname), "%s/TOC", path);
    if (len >= sizeof(fname)) {
        err = merr(EINVAL);
        hse_elog(HSE_ERR "Export path is too long %s, @@e", err, path);
        return err;
    }

    /* Open TOC file */
    f = fopen(fname, "r");
    if (!f) {
        err = merr(errno);
        hse_elog(HSE_ERR "Failed to open TOC file %s, @@e", err, fname);
        return err;
    }

    /* Find the size of TOC file */
    err = stat(fname, &stbuf);
    if (ev(err) || (!S_ISREG(stbuf.st_mode)) || (stbuf.st_size <= 0)) {
        err = merr(errno);
        hse_elog(HSE_ERR "Invalid TOC file %s, @@e", err, fname);
        fclose(f);
        return err;
    }

    buflen = stbuf.st_size;
    err = fseek(f, 0, SEEK_SET);
    if (ev(err)) {
        err = merr(errno);
        hse_elog(HSE_ERR "fseek failed %s, @@e", err, fname);
        fclose(f);
        return err;
    }

    buf = malloc(buflen);
    if (!buf) {
        err = merr(ev(ENOMEM, HSE_ERR));
        fclose(f);
        return err;
    }

    /*
     * Read TOC file into buffer
     * The size of TOC file is at most a few KBytes, we can read entire
     * file all at once
     */
    len = fread(buf, 1, buflen, f);
    fclose(f);
    if (len != buflen) {
        err = merr(errno);
        hse_elog(HSE_ERR "Failed to read TOC file %s, @@e", err, fname);
        free(buf);
        return err;
    }

    crc_rd = le32_to_cpu(*((u32 *)buf));

    cjson_str = buf + 4;
    crc = XXH32((const u8 *)cjson_str, buflen - 4, 0);
    if (crc != crc_rd) {
        err = merr(ev(EINVAL, HSE_ERR));
        hse_elog(
            HSE_ERR "Corrupted TOC, mismatched calculated"
                    " crc 0x%x, but read 0x%x, @@e",
            err,
            crc,
            crc_rd);
        free(buf);
        return err;
    }

    /* Parse json format meta data read from TOC */
    TOC = cJSON_Parse(cjson_str);
    ver = cJSON_GetObjectItem(TOC, "version")->valueint;
    if (ver > KVDB_DUMP_CUR_VER) {
        err = merr(ev(ENOTSUP, HSE_ERR));
        hse_elog(HSE_ERR "TOC version %d is not supported @@e", err, ver);
        goto errout;
    }

    name = cJSON_GetObjectItem(TOC, "name")->valuestring;
    strlcpy(mp_name, name, MPOOL_NAMESZ_MAX);

    kvs_cnt = cJSON_GetObjectItem(TOC, "kvscnt")->valueint;

    if (kvdb_cparams) {
        *kvdb_cparams = kvdb_cparams_defaults();
        kvdb_cparams->dur_capacity = cJSON_GetObjectItem(TOC, "dur_capacity")->valuedouble;
    }

    if (!kvscnt || !kvsi)
        /* Don't need to import kvs meta data */
        goto errout;

    *kvscnt = kvs_cnt;

    kvsv_json = cJSON_GetObjectItem(TOC, "KVSs");
    cnt = cJSON_GetArraySize(kvsv_json);
    if (cnt != *kvscnt) {
        err = merr(EINVAL);
        hse_elog(
            HSE_ERR "Failed to import kvdb %s, kvs "
                    "count mismatched in TOC, %d, %d, @@e",
            err,
            mp_name,
            *kvscnt,
            cnt);
        goto errout;
    }

    if (cnt > HSE_KVS_COUNT_MAX) {
        err = merr(EINVAL);
        hse_elog(HSE_ERR "Too many KVSs %d in KVDB %s, @@e", err, cnt, mp_name);
        goto errout;
    }

    for (i = 0; i < cnt; i++) {
        char val_buf[64];

        kvs_json = cJSON_GetArrayItem(kvsv_json, i);
        name = cJSON_GetObjectItem(kvs_json, "name")->valuestring;
        memset(kvsi[i].kvsi_name, 0, sizeof(kvsi[i].kvsi_name));
        strlcpy(kvsi[i].kvsi_name, name, sizeof(kvsi[i].kvsi_name));

        hse_params_create(&kvsi[i].kvsi_params);

        kvsi[i].kvsi_fcnt = cJSON_GetObjectItem(kvs_json, "filecnt")->valueint;
        kvsi[i].kvsi_kvcnt = cJSON_GetObjectItem(kvs_json, "kvcnt")->valueint;

        snprintf(
            val_buf, sizeof(val_buf), "%d", cJSON_GetObjectItem(kvs_json, "pfx_len")->valueint);
        err = hse_params_set(kvsi[i].kvsi_params, "kvs.pfx_len", val_buf);
        if (ev(err))
            goto errout;

        snprintf(
            val_buf, sizeof(val_buf), "%d", cJSON_GetObjectItem(kvs_json, "pfx_pivot")->valueint);
        err = hse_params_set(kvsi[i].kvsi_params, "kvs.pfx_pivot", val_buf);
        if (ev(err))
            goto errout;

        snprintf(val_buf, sizeof(val_buf), "%d", cJSON_GetObjectItem(kvs_json, "fanout")->valueint);
        err = hse_params_set(kvsi[i].kvsi_params, "kvs.fanout", val_buf);
        if (ev(err))
            goto errout;

        snprintf(
            val_buf, sizeof(val_buf), "%d", cJSON_GetObjectItem(kvs_json, "kvs_ext01")->valueint);
        err = hse_params_set(kvsi[i].kvsi_params, "kvs.kvs_ext01", val_buf);
        if (ev(err))
            goto errout;
    }

errout:
    cJSON_Delete(TOC);
    free(buf);
    return err;
}

merr_t
ikvdb_import_kvdb_cparams(const char *path, struct kvdb_cparams *kvdb_cparams)
{
    return ikvdb_import_toc(path, kvdb_cparams, NULL, NULL);
}

merr_t
ikvdb_import(struct ikvdb *handle, const char *path)
{
    struct kvdb_cparams      kvdb_cparams;
    int                      i, j;
    int                      job;
    int                      kvscnt = 0;
    int                      done = 0;
    merr_t                   err = 0;
    struct kvdb_bak_work *   bak;
    struct workqueue_struct *wq;
    struct kvs_import *      kvsi;
    int                      total = 0;
    int                      len;

    /* Import all the meta data required for this import from TOC file */
    kvsi = calloc(HSE_KVS_COUNT_MAX, sizeof(*kvsi));
    if (!kvsi)
        return merr(ev(ENOMEM, HSE_ERR));

    err = ikvdb_import_toc(path, &kvdb_cparams, &kvscnt, kvsi);
    if (ev(err, HSE_ERR)) {
        hse_log(HSE_ERR "Failed to import TOC from path %s", path);
        free(kvsi);
        return err;
    }

    /* Count the total number of data files */
    total = 0;
    for (i = 0; i < kvscnt; i++) {
        if (kvsi[i].kvsi_kvcnt > 0)
            total += kvsi[i].kvsi_fcnt;
    }

    /*
     * During kvdb export, the data in each kvs is dumped into multiple
     * data files, 4GB each.
     * We will next create one workqueue job for each of these data files
     * and queue them into a workqueue
     */
    bak = calloc(total, sizeof(*bak));
    if (!bak) {
        err = merr(ev(ENOMEM, HSE_ERR));
        free(kvsi);
        return err;
    }

    wq = alloc_workqueue("dbimport", 0, WQ_MAX_ACTIVE);
    if (!wq) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "Failed to alloc import workqueues, @@e", err);
        free(kvsi);
        free(bak);
        return err;
    }

    job = 0;
    for (i = 0; i < kvscnt; i++) {
        /* For each KVS ... */
        err = ikvdb_kvs_make(handle, kvsi[i].kvsi_name, kvsi[i].kvsi_params);
        if (err && (merr_errno(err) != EEXIST)) {
            hse_elog(HSE_ERR "Failed to create kvs %s, @@e", err, kvsi[i].kvsi_name);
            break;
        }

        hse_params_destroy(kvsi[i].kvsi_params);

        err = ikvdb_kvs_open(handle, kvsi[i].kvsi_name, 0, 0, &kvsi[i].kvsi_kvs);
        if (err) {
            hse_elog(HSE_ERR "Failed to open kvs %s, @@e", err, kvsi[i].kvsi_name);
            ikvdb_kvs_drop(handle, kvsi[i].kvsi_name);
            break;
        }

        /*
         * Create one workqueue job for each data file
         */
        if (kvsi[i].kvsi_kvcnt > 0) {
            for (j = 0; j < kvsi[i].kvsi_fcnt; j++) {
                bak[job].bak_kvs = kvsi[i].kvsi_kvs;
                len = snprintf(
                    bak[job].bak_fname,
                    sizeof(bak[job].bak_fname),
                    "%s/%s_%d",
                    path,
                    kvsi[i].kvsi_name,
                    j);
                if (len >= sizeof(bak[job].bak_fname)) {
                    err = merr(EINVAL);
                    hse_elog(
                        HSE_ERR "name %s is truncated,"
                                " @@e",
                        err,
                        bak[job].bak_fname);
                    goto errout;
                }
                INIT_WORK(&bak[job].bak_work, ikvdb_kvs_import);
                queue_work(wq, &bak[job].bak_work);
                job++;
            }
        }
    }

errout:
    /* Wait until all the workqueue jobs complete */
    destroy_workqueue(wq);

    /*
     * Check the results of all workqueue jobs, if any one
     * failed, failed the whole import
     */
    if (!err) {
        for (i = 0; i < job; i++) {
            if (bak[i].bak_err)
                err = bak[i].bak_err;
            else
                done++;
        }
    }

    for (i = 0; i < kvscnt; i++)
        ikvdb_kvs_close(kvsi[i].kvsi_kvs);

    free(bak);
    free(kvsi);
    hse_log(HSE_DEBUG "%d out of %d import jobs have completed", done, job);

    return err;
}

/**
 * ikvdb_kvs_export(): worker function for exporting a kvs into
 *                     one or multiple data files, each data file
 *                     has a 4GB size limit
 * @work
 */
static void
ikvdb_kvs_export(struct work_struct *work)
{
    struct kvdb_bak_work * bak;
    struct hse_kvs_cursor *cur;
    struct kvdb_kvmeta_omf kvmt;
    const void *           key, *val;
    size_t                 klen, vlen;
    bool                   eof;
    FILE *                 f = 0;
    int                    fd;
    u64                    fsize = -1;
    int                    filecnt = 0;
    char                   fname[PATH_MAX];
    int                    len;

    bak = container_of(work, struct kvdb_bak_work, bak_work);
    bak->bak_err = 0;
    bak->bak_kvcnt = 0;

    cur = bak->bak_cur;

    eof = false;

    while (true) {
        /*
         * Create a new data file, if the current one exceeds
         * the size limit
         */
        if (fsize > KVDB_EXPORT_FSIZE_MAX) {
            len = snprintf(fname, sizeof(fname), "%s_%d", bak->bak_fname, filecnt);

            if (len >= sizeof(fname)) {
                bak->bak_err = merr(EINVAL);
                hse_elog(
                    HSE_ERR "File name %s is truncated,"
                            " @@e",
                    bak->bak_err,
                    fname);
                break;
            }

            if (f) {
                fclose(f);
                f = NULL;
            }

            fsize = 0;
            filecnt++;

            fd = open(fname, O_CREAT | O_TRUNC | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
            if (fd < 0) {
                bak->bak_err = merr(errno);
                hse_elog(HSE_ERR "Failed to open file %s, @@e", bak->bak_err, fname);
                break;
            }
            f = fdopen(fd, "w");
            if (!f) {
                close(fd);
                bak->bak_err = merr(errno);
                hse_elog(HSE_ERR "Failed to fdopen file %s,@@e", bak->bak_err, fname);
                break;
            }
        }

        bak->bak_err = ikvdb_kvs_cursor_read(cur, 0, &key, &klen, &val, &vlen, &eof);
        if (ev(bak->bak_err, HSE_ERR))
            break;

        if (eof)
            break;

        /* Convert kvmt to little endian, if needed */
        omf_set_kvmt_klen(&kvmt, klen);
        omf_set_kvmt_vlen(&kvmt, vlen);
        fwrite(&kvmt, sizeof(kvmt), 1, f);
        fwrite(key, sizeof(char), klen, f);
        fwrite(val, sizeof(char), vlen, f);

        bak->bak_kvcnt++;
        fsize += klen + vlen + sizeof(klen) + sizeof(vlen);
    }

    if (f)
        fclose(f);

    ikvdb_kvs_cursor_destroy(cur);

    bak->bak_fcnt = filecnt;
}

/**
 * ikvdb_export_toc() - export kvdb and kvs meta data into TOC file
 * @path: dump directory
 * @mp_name:
 * @kvdb_cparams:
 * @kvscnt:
 * @kvsv: kvs names
 * @kvs_cparams:
 * @bak:
 */
static merr_t
ikvdb_export_toc(
    const char *          path,
    const char *          mp_name,
    struct kvdb_cparams * kvdb_cparams,
    int                   kvscnt,
    char **               kvsv,
    struct kvs_cparams *  kvs_cparams,
    struct kvdb_bak_work *bak)
{
    int    i;
    cJSON *TOC;
    cJSON *kvs;
    cJSON *KVSs = NULL;
    char * string = NULL;
    merr_t err = 0;
    char   fname[PATH_MAX];
    FILE * f;
    int    fd;
    int    len;
    int    ver = KVDB_DUMP_CUR_VER;
    u32    crc, crc_le;

    TOC = cJSON_CreateObject();
    if (!TOC) {
        err = merr(ev(ENOMEM, HSE_ERR));
        goto errout;
    }

    cJSON_AddNumberToObject(TOC, "version", ver);
    cJSON_AddStringToObject(TOC, "name", mp_name);
    cJSON_AddNumberToObject(TOC, "kvscnt", kvscnt);
    cJSON_AddNumberToObject(TOC, "dur_capacity", kvdb_cparams->dur_capacity);

    KVSs = cJSON_CreateArray();
    if (!KVSs) {
        err = merr(ev(ENOMEM, HSE_ERR));
        goto errout;
    }

    for (i = 0; i < kvscnt; i++) {
        kvs = cJSON_CreateObject();
        if (!kvs) {
            err = merr(ev(ENOMEM, HSE_ERR));
            break;
        }

        cJSON_AddStringToObject(kvs, "name", kvsv[i]);
        cJSON_AddNumberToObject(kvs, "filecnt", bak[i].bak_fcnt);
        cJSON_AddNumberToObject(kvs, "kvcnt", bak[i].bak_kvcnt);
        cJSON_AddNumberToObject(kvs, "pfx_len", kvs_cparams[i].cp_pfx_len);
        cJSON_AddNumberToObject(kvs, "pfx_pivot", kvs_cparams[i].cp_pfx_pivot);
        cJSON_AddNumberToObject(kvs, "fanout", kvs_cparams[i].cp_fanout);
        cJSON_AddNumberToObject(kvs, "kvs_ext01", kvs_cparams[i].cp_kvs_ext01);
        cJSON_AddItemToArray(KVSs, kvs);
    }

    cJSON_AddItemToObject(TOC, "KVSs", KVSs);
    if (ev(err))
        goto errout;

    /* Print JSON struct into a buffer, then dump it into TOC file */
    string = cJSON_Print(TOC);

    len = snprintf(fname, sizeof(fname), "%s/TOC", path);
    if (len >= sizeof(fname)) {
        err = merr(EINVAL);
        hse_elog(
            HSE_ERR "Export TOC file name %s is truncated,"
                    " @@e",
            err,
            fname);
        goto errout;
    }

    fd = open(fname, O_CREAT | O_TRUNC | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "Failed to open file %s, @@e", err, fname);
        goto errout;
    }
    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        err = merr(errno);
        hse_elog(HSE_ERR "Failed to fdopen file %s, @@e", err, fname);
        goto errout;
    }

    crc = XXH32((const u8 *)string, strlen(string), 0);
    crc_le = cpu_to_le32(crc);

    fwrite(&crc_le, sizeof(crc_le), 1, f);
    fprintf(f, "%s", string);
    fclose(f);
errout:
    free(string);
    cJSON_Delete(TOC);
    return err;
}

merr_t
ikvdb_export(struct ikvdb *handle, struct kvdb_cparams *kvdb_cparams, const char *path)
{
    struct ikvdb_impl *      kvdb = ikvdb_h2r(handle);
    char **                  kvsv;
    struct kvs_cparams *     kvs_cparams;
    unsigned int             count;
    merr_t                   err;
    int                      i;
    struct hse_kvs *         kvs;
    struct hse_kvs_cursor *  cur;
    struct hse_kvdb_opspec   opspec = { 0 };
    struct workqueue_struct *wq;
    struct kvdb_bak_work *   bak;
    time_t                   t;
    char                     pname[PATH_MAX];
    int                      rc;
    struct tm *              tmp;
    char                     timestr[128];
    int                      done = 0;
    int                      len;

    if (access(path, W_OK)) {
        err = merr(errno);
        hse_elog(HSE_ERR "Failed to open directory %s, @@e", err, path);
        return err;
    }

    /*
     * Create directory "<path>/<mpname>/<timestamp>
     * e.g.: /tmp/mp1/2018-09-20-18-04-42
     */
    snprintf(pname, sizeof(pname), "%s/%s/", path, kvdb->ikdb_mpname);
    rc = mkdir(pname, S_IRWXU);
    if (rc && errno != EEXIST) {
        err = merr(errno);
        hse_elog(HSE_ERR "Failed to create dir %s, @@e", err, pname);
        return err;
    }

    /* Generate timestamp string, append it to directory name */
    time(&t);
    tmp = localtime(&t);
    snprintf(
        timestr,
        sizeof(timestr),
        "%4d-%02d-%02d-%02d-%02d-%02d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec);

    len = strlcat(pname, timestr, sizeof(pname));
    if (len >= sizeof(pname)) {
        err = merr(EINVAL);
        hse_elog(
            HSE_ERR "Export path name %s is truncated,"
                    " @@e",
            err,
            pname);
        return err;
    }

    rc = mkdir(pname, S_IRWXU);
    if (rc && errno != EEXIST) {
        err = merr(errno);
        hse_elog(HSE_ERR "Failed to create dir %s, @@e", err, pname);
        return err;
    }

    err = ikvdb_get_names(handle, &count, &kvsv);
    if (ev(err, HSE_ERR))
        return err;

    if (count == 0)
        return 0;

    bak = calloc(count, sizeof(*bak));
    if (!bak) {
        ikvdb_free_names(handle, kvsv);
        return merr(ev(ENOMEM, HSE_ERR));
    }

    kvs_cparams = calloc(count, sizeof(*kvs_cparams));
    if (!kvs_cparams) {
        free(bak);
        ikvdb_free_names(handle, kvsv);
        return merr(ev(ENOMEM, HSE_ERR));
    }

    wq = alloc_workqueue("dbexport", 0, count);
    if (!wq) {
        err = merr(ENOMEM);
        hse_elog(HSE_ERR "Failed to alloc export workqueues, @@e", err);
        goto errout;
    }

    for (i = 0; i < count; i++) {
        int n;

        err = ikvdb_kvs_open(handle, kvsv[i], 0, 0, &kvs);
        if (err) {
            hse_elog(HSE_ERR "Failed to open kvs %s, @@e", err, kvsv[i]);
            goto errout;
        }

        kvs_cparams[i].cp_pfx_len = ((struct kvdb_kvs *)kvs)->kk_cparams->cp_pfx_len;
        kvs_cparams[i].cp_pfx_pivot = ((struct kvdb_kvs *)kvs)->kk_cparams->cp_pfx_pivot;
        kvs_cparams[i].cp_fanout = ((struct kvdb_kvs *)kvs)->kk_cparams->cp_fanout;
        kvs_cparams[i].cp_kvs_ext01 =
            (((struct kvdb_kvs *)kvs)->kk_flags & CN_CFLAG_CAPPED) ? 1 : 0;

        err = ikvdb_kvs_cursor_create(kvs, &opspec, NULL, 0, &cur);
        if (err) {
            hse_elog(
                HSE_ERR "Failed to create cursor for kvdb"
                        " %s kvs %s, @@e",
                err,
                kvdb->ikdb_mpname,
                kvsv[i]);
            goto errout;
        }

        bak[i].bak_kvs = kvs;
        n = snprintf(bak[i].bak_fname, sizeof(bak[i].bak_fname), "%s/%s", pname, kvsv[i]);
        if (n >= sizeof(bak[i].bak_fname)) {
            err = merr(EINVAL);
            goto errout;
        }

        bak[i].bak_cur = cur;
        INIT_WORK(&bak[i].bak_work, ikvdb_kvs_export);
        queue_work(wq, &bak[i].bak_work);
    }

errout:
    /* Wait for all exporting jobs finish */
    destroy_workqueue(wq);

    /* Check the status of all dump threads */
    if (!err) {
        for (i = 0; i < count; i++) {
            if (bak[i].bak_err)
                err = bak[i].bak_err;
            else
                done++;
        }
    }

    /* Dump the export summary/meta data to TOC file */
    if (!err)
        err =
            ikvdb_export_toc(pname, kvdb->ikdb_mpname, kvdb_cparams, count, kvsv, kvs_cparams, bak);

    ikvdb_free_names(handle, kvsv);
    free(kvs_cparams);
    free(bak);
    return err;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "ikvdb_ut_impl.i"
#include "kvs_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
