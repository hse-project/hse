/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_ikvdb
#define MTF_MOCK_IMPL_kvs

#include "_config.h"

#include <stdalign.h>

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/cn_perfc.h>
#include <hse_ikvdb/ctxn_perfc.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/c0snr_set.h>
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
#include "viewset.h"
#include "kvdb_keylock.h"

#include <mpool/mpool.h>

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/string.h>
#include <hse_util/seqno.h>
#include <hse_util/darray.h>
#include <hse_util/rest_api.h>
#include <hse_util/log2.h>
#include <hse_util/atomic.h>
#include <hse_util/vlb.h>
#include <hse_util/compression_lz4.h>
#include <hse_util/token_bucket.h>
#include <hse_util/xrand.h>

#include <xxhash.h>
#if CJSON_FROM_SUBPROJECT == 1
#include <cJSON.h>
#else
#include <cjson/cJSON.h>
#endif
#include "kvdb_rest.h"
#include "kvdb_params.h"

#include <syscall.h>

/* tls_vbuf[] is a thread-local buffer used as a compression output buffer
 * by ikvdb_kvs_put() and for small direct reads by kvset_lookup_val().
 */
thread_local char tls_vbuf[32 * 1024] HSE_ALIGNED(PAGE_SIZE);
const size_t  tls_vbufsz = sizeof(tls_vbuf);

struct perfc_set kvdb_pkvdbl_pc HSE_READ_MOSTLY;
struct perfc_set kvdb_pc        HSE_READ_MOSTLY;

struct perfc_set kvdb_metrics_pc HSE_READ_MOSTLY;
struct perfc_set c0_metrics_pc   HSE_READ_MOSTLY;

BUILD_BUG_ON_MSG(
    (sizeof(uintptr_t) != sizeof(u64)),
    "code relies on pointers being 64-bits in size");

#define ikvdb_h2r(handle) container_of(handle, struct ikvdb_impl, ikdb_handle)

struct ikvdb {
};

/* Max buckets in ctxn cache.  Must be prime for best results.
 */
#define KVDB_CTXN_BKT_MAX (17)

/* Simple fixed-size stack for caching ctxn objects.
 */
struct kvdb_ctxn_bkt {
    spinlock_t        kcb_lock HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    uint              kcb_ctxnc;
    struct kvdb_ctxn *kcb_ctxnv[15];
};

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
 * @ikdb_curcnt:        number of active cursors (lazily updated)
 * @ikdb_curcnt_max:    maximum number of active cursors
 * @ikdb_cur_ticket:    ticket lock ticket dispenser (serializes ikvdb_cur_list access)
 * @ikdb_cur_serving:   ticket lock "now serving" number
 * @ikdb_seqno:         current sequence number for the struct ikvdb
 * @ikdb_cur_list:      list of cursors holding the cursor horizon
 * @ikdb_cur_horizon:   oldest seqno in cursor ikdb_cur_list
 * @ikdb_rp:            KVDB run time params
 * @ikdb_ctxn_cache:    ctxn cache
 * @ikdb_lock:          protects ikdb_kvs_vec/ikdb_kvs_cnt writes
 * @ikdb_kvs_cnt:       number of KVSes in ikdb_kvs_vec
 * @ikdb_kvs_vec:       vector of KVDB KVSes
 * @ikdb_maint_work:
 * @ikdb_profile:       hse params stored as profile
 * @ikdb_cndb_oid1:
 * @ikdb_cndb_oid2:
 * @ikdb_mpname:        KVDB mpool name
 *
 * Note:  The first group of fields are read-mostly and some of them are
 * heavily concurrently accessed, hence they live in the first cache line.
 * Only add a new field to this group if it is read-mostly and would not push
 * the first field of %ikdb_health out of the first cache line.  Similarly,
 * the group of fields which contains %ikdb_seqno is heavily concurrently
 * accessed and heavily modified. Only add a new field to this group if it
 * will be accessed just before or after accessing %ikdb_seqno.
 */
struct ikvdb_impl {
    struct ikvdb          ikdb_handle;
    bool                  ikdb_rdonly;
    bool                  ikdb_work_stop;
    struct kvdb_ctxn_set *ikdb_ctxn_set;
    struct c0snr_set     *ikdb_c0snr_set;
    struct perfc_set      ikdb_ctxn_op;
    struct kvdb_keylock * ikdb_keylock;
    struct c0sk *         ikdb_c0sk;
    struct kvdb_health    ikdb_health;

    struct throttle ikdb_throttle;

    struct csched *          ikdb_csched;
    struct cn_kvdb *         ikdb_cn_kvdb;
    struct mpool *           ikdb_ds;
    struct kvdb_log *        ikdb_log;
    struct cndb *            ikdb_cndb;
    struct workqueue_struct *ikdb_workqueue;
    struct viewset          *ikdb_txn_viewset;
    struct viewset          *ikdb_cur_viewset;

    struct tbkt ikdb_tb HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    u64 ikdb_tb_burst;
    u64 ikdb_tb_rate;

    u64          ikdb_tb_dbg;
    u64          ikdb_tb_dbg_next;
    atomic64_t   ikdb_tb_dbg_ops;
    atomic64_t   ikdb_tb_dbg_bytes;
    atomic64_t   ikdb_tb_dbg_sleep_ns;

    atomic_t ikdb_curcnt HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    u32      ikdb_curcnt_max;

    atomic64_t           ikdb_seqno HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct kvdb_rparams  ikdb_rp HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct kvdb_ctxn_bkt ikdb_ctxn_cache[KVDB_CTXN_BKT_MAX];

    /* Put the mostly cold data at end of the structure to improve
     * the density of the hotter data.
     */
    struct mutex       ikdb_lock;
    u32                ikdb_kvs_cnt;
    struct kvdb_kvs *  ikdb_kvs_vec[HSE_KVS_COUNT_MAX];
    struct work_struct ikdb_maint_work;
    struct work_struct ikdb_throttle_work;
    struct hse_params *ikdb_profile;

    struct mclass_policy ikdb_mpolicies[HSE_MPOLICY_COUNT];

    u64  ikdb_cndb_oid1;
    u64  ikdb_cndb_oid2;
    char ikdb_mpname[MPOOL_NAMESZ_MAX];
};

struct ikvdb *
ikvdb_kvdb_handle(struct ikvdb_impl *self)
{
    return &self->ikdb_handle;
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
    struct kvdb_log_tx *tx = NULL;

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

out:
    /* Failed ikvdb_make() indicates that the caller or operator should
     * destroy the kvdb: recovery is not possible.
     */
    kvdb_log_close(log);

    return err;
}

static inline
void
ikvdb_tb_configure(
    struct ikvdb_impl  *self,
    u64                 burst,
    u64                 rate,
    bool                initialize)
{
    if (initialize)
        tbkt_init(&self->ikdb_tb, burst, rate);
    else
        tbkt_adjust(&self->ikdb_tb, burst, rate);
}

static
void
ikvdb_rate_limit_set(struct ikvdb_impl *self, u64 rate)
{
    u64 burst = rate / 2;

    /* cache debug params from KVDB runtime params */
    self->ikdb_tb_dbg = self->ikdb_rp.throttle_debug & THROTTLE_DEBUG_TB_MASK;

    /* debug: manual control: get burst and rate from rparams  */
    if (HSE_UNLIKELY(self->ikdb_tb_dbg & THROTTLE_DEBUG_TB_MANUAL)) {
        burst = self->ikdb_rp.throttle_burst;
        rate  = self->ikdb_rp.throttle_rate;
    }

    if (burst != self->ikdb_tb_burst || rate != self->ikdb_tb_rate) {
        self->ikdb_tb_burst = burst;
        self->ikdb_tb_rate = rate;
        ikvdb_tb_configure(self, self->ikdb_tb_burst, self->ikdb_tb_rate, false);
    }

    if (self->ikdb_tb_dbg) {

        u64 now = get_time_ns();

        if (now > self->ikdb_tb_dbg_next) {

            /* periodic debug output */
            long dbg_ops      = atomic64_read(&self->ikdb_tb_dbg_ops);
            long dbg_bytes    = atomic64_read(&self->ikdb_tb_dbg_bytes);
            long dbg_sleep_ns = atomic64_read(&self->ikdb_tb_dbg_sleep_ns);

            hse_log(
                HSE_NOTICE
                " tbkt_debug: manual %d shunt %d ops %8ld  bytes %10ld"
                " sleep_ns %12ld burst %10lu rate %10lu raw %10lu",
                (bool)(self->ikdb_tb_dbg & THROTTLE_DEBUG_TB_MANUAL),
                (bool)(self->ikdb_tb_dbg & THROTTLE_DEBUG_TB_SHUNT),
                dbg_ops, dbg_bytes, dbg_sleep_ns,
                self->ikdb_tb_burst,
                self->ikdb_tb_rate,
                throttle_delay(&self->ikdb_throttle));

            atomic64_sub(dbg_ops, &self->ikdb_tb_dbg_ops);
            atomic64_sub(dbg_bytes, &self->ikdb_tb_dbg_bytes);
            atomic64_sub(dbg_sleep_ns, &self->ikdb_tb_dbg_sleep_ns);

            self->ikdb_tb_dbg_next = now + NSEC_PER_SEC;
        }
    }
}

static void
ikvdb_throttle_task(struct work_struct *work)
{
    struct ikvdb_impl *self;
    u64                throttle_update_prev = 0;

    self = container_of(work, struct ikvdb_impl, ikdb_throttle_work);

    while (!self->ikdb_work_stop) {

        u64 tstart = get_time_ns();

        if (tstart > throttle_update_prev + self->ikdb_rp.throttle_update_ns) {

            uint raw  = throttle_update(&self->ikdb_throttle);
            u64  rate = throttle_raw_to_rate(raw);

            ikvdb_rate_limit_set(self, rate);
            throttle_update_prev = tstart;
        }

        /* Sleep for 10ms minus processing overhead.  Does not account
         * for sleep time variance, but does account for timer slack
         * to minimize drift.
         */
        tstart = (get_time_ns() - tstart + timer_slack) / 1000;
        if (tstart < 10000)
            usleep(10000 - tstart);
    }
}

static void
ikvdb_maint_task(struct work_struct *work)
{
    struct ikvdb_impl *self;
    u64 curcnt_warn = 0;
    u64 maxdelay;

    self = container_of(work, struct ikvdb_impl, ikdb_maint_work);

    maxdelay = 10000; /* 10ms initial delay time */

    while (!self->ikdb_work_stop) {
        uint64_t vadd = 0, vsub = 0, curcnt;
        u64 tstart = get_time_ns();
        uint i;

        /* Lazily sample the active cursor count and update ikdb_curcnt if necessary.
         * ikvdb_kvs_cursor_create() checks ikdb_curcnt to prevent the creation
         * of an excessive number of cursors.
         */
        perfc_read(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURCNT, &vadd, &vsub);

        curcnt = (vadd > vsub) ? (vadd - vsub) : 0;

        if (atomic_read(&self->ikdb_curcnt) != curcnt) {
            atomic_set(&self->ikdb_curcnt, curcnt);

            if (ev(curcnt > self->ikdb_curcnt_max && tstart > curcnt_warn)) {
                hse_log(HSE_WARNING "%s: active cursors (%lu) > max allowed (%u)",
                        __func__, curcnt, self->ikdb_curcnt_max);

                curcnt_warn = tstart + NSEC_PER_SEC * 15;
            }
        }

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

        /* Sleep for 100ms minus processing overhead.  Does not account
         * for sleep time variance.  Divide delta by 1024 rather than
         * 1000 to facilitate intentional drift.
         */
        tstart = (get_time_ns() - tstart) / 1024;
        if (tstart < maxdelay)
            usleep(maxdelay - tstart);

        /* Use a smaller delay at program start to avoid unnecessarily
         * holding up a short lived program.  Once we hit 100ms we'll
         * stop incrementing maxdelay.
         */
        if (maxdelay < 100000)
            maxdelay += 3000;
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
    int i, j;

    for (i = 0; i < NELEM(self->ikdb_ctxn_cache); ++i) {
        struct kvdb_ctxn_bkt *bkt = self->ikdb_ctxn_cache + i;

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
    self = alloc_aligned(sizeof(*self), alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));

    n = strlcpy(self->ikdb_mpname, mp_name, sizeof(self->ikdb_mpname));
    if (ev(n >= sizeof(self->ikdb_mpname))) {
        err = merr(ENAMETOOLONG);
        goto err_exit0;
    }

    self->ikdb_ds = ds;

    assert(rparams);
    self->ikdb_rp = *rparams;
    self->ikdb_rdonly = rparams->read_only;
    rparams = &self->ikdb_rp;

    atomic_set(&self->ikdb_curcnt, 0);

    ikvdb_txn_init(self);

    err = viewset_create(&self->ikdb_txn_viewset, &self->ikdb_seqno);
    if (ev(err))
        goto err_exit0;

    err = viewset_create(&self->ikdb_cur_viewset, &self->ikdb_seqno);
    if (ev(err))
        goto err_exit1;

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
        &self->ikdb_cndb_oid2);
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
    viewset_destroy(self->ikdb_cur_viewset);
    viewset_destroy(self->ikdb_txn_viewset);

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

    viewset_destroy(self->ikdb_cur_viewset);
    viewset_destroy(self->ikdb_txn_viewset);

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

    kvs = alloc_aligned(sizeof(*kvs), alignof(*kvs));
    if (kvs) {
        memset(kvs, 0, sizeof(*kvs));
        kvs->kk_vcompmin = UINT_MAX;
        atomic_set(&kvs->kk_refcnt, 0);
    }

    return kvs;
}

static void
kvdb_kvs_destroy(struct kvdb_kvs *kvs)
{
    if (kvs) {
        assert(atomic_read(&kvs->kk_refcnt) == 0);
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
ikvdb_open(
    const char *             mp_name,
    struct mpool *           ds,
    const struct hse_params *params,
    struct ikvdb **          handle)
{
    merr_t              err;
    struct ikvdb_impl * self;
    struct kvdb_rparams rp;
    u64                 seqno = 0; /* required by unit test */
    ulong               mavail;
    size_t              sz, n;
    int                 i;
    u64                 ingestid;

    self = alloc_aligned(sizeof(*self), alignof(*self));
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

    err = hse_params_to_kvdb_rparams(params, NULL, &rp);
    if (ev(err))
        return err;

    hse_params_to_mclass_policies(params, self->ikdb_mpolicies, NELEM(self->ikdb_mpolicies));

    self->ikdb_rp = rp;
    self->ikdb_rdonly = rp.read_only;
    if (params) {
        self->ikdb_profile = hse_params_clone(params);
        if (ev(!self->ikdb_profile)) {
            err = merr(ENOMEM);
            goto err2;
        }
    }

    rp = self->ikdb_rp;

    hse_meminfo(NULL, &mavail, 0);
    if (rp.low_mem || (mavail >> 30) < 32)
        ikvdb_low_mem_adjust(self);

    kvdb_rparams_print(&rp);

    throttle_init(&self->ikdb_throttle, &self->ikdb_rp);
    throttle_init_params(&self->ikdb_throttle, &self->ikdb_rp);

    self->ikdb_tb_burst = self->ikdb_rp.throttle_burst;
    self->ikdb_tb_rate  = self->ikdb_rp.throttle_rate;

    ikvdb_tb_configure(self, self->ikdb_tb_burst, self->ikdb_tb_rate, true);

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

    /* Set max number of active cursors per kvdb such that max
     * memory use is limited to about 10% of system memory.
     */
    sz = (mavail * HSE_CURACTIVE_SZ_PCT) / 100;
    sz = clamp_t(size_t, sz, HSE_CURACTIVE_SZ_MIN, HSE_CURACTIVE_SZ_MAX);
    self->ikdb_curcnt_max = sz / HSE_CURSOR_SZ_MIN;

    atomic_set(&self->ikdb_curcnt, 0);

    err = viewset_create(&self->ikdb_txn_viewset, &self->ikdb_seqno);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = viewset_create(&self->ikdb_cur_viewset, &self->ikdb_seqno);
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
        &self->ikdb_cndb_oid2);
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

    err = kvdb_ctxn_set_create(
        &self->ikdb_ctxn_set, self->ikdb_rp.txn_timeout, self->ikdb_rp.txn_wkth_delay);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, mp_name);
        goto err1;
    }

    err = c0snr_set_create(kvdb_ctxn_abort, &self->ikdb_c0snr_set);
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

    ikvdb_perfc_alloc(self);
    kvdb_keylock_perfc_init(self->ikdb_keylock, &self->ikdb_ctxn_op);

    err = kvdb_rparams_add_to_dt(self->ikdb_mpname, &self->ikdb_rp);
    if (err)
        hse_elog(HSE_WARNING "cannot record %s runtime params: @@e", err, mp_name);

    ikvdb_rest_register(self, *handle);

    ikvdb_init_throttle_params(self);

    return 0;

err1:
    c0sk_close(self->ikdb_c0sk);
    self->ikdb_work_stop = true;
    destroy_workqueue(self->ikdb_workqueue);
    cn_kvdb_destroy(self->ikdb_cn_kvdb);
    for (i = 0; i < self->ikdb_kvs_cnt; i++)
        kvdb_kvs_destroy(self->ikdb_kvs_vec[i]);
    c0snr_set_destroy(self->ikdb_c0snr_set);
    kvdb_ctxn_set_destroy(self->ikdb_ctxn_set);
    cndb_close(self->ikdb_cndb);
    kvdb_log_close(self->ikdb_log);
    kvdb_keylock_destroy(self->ikdb_keylock);
    viewset_destroy(self->ikdb_cur_viewset);
    viewset_destroy(self->ikdb_txn_viewset);
    csched_destroy(self->ikdb_csched);
    throttle_fini(&self->ikdb_throttle);

err2:
    ikvdb_txn_fini(self);
    mutex_destroy(&self->ikdb_lock);
    hse_params_free(self->ikdb_profile);
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
ikvdb_kvs_make(struct ikvdb *handle, const char *kvs_name, const struct hse_params *params)
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
    err = hse_params_to_kvs_cparams(self->ikdb_profile, kvs_name, NULL, &profile);
    if (ev(err))
        return err;

    /* overwrite with new params */
    err = hse_params_to_kvs_cparams(params, kvs_name, &profile, &kvs_cparams);
    if (ev(err))
        return err;

    err = kvs_cparams_validate(&kvs_cparams);
    if (ev(err))
        return err;

    kvs = kvdb_kvs_create();
    if (ev(!kvs))
        return merr(ENOMEM);

    strlcpy(kvs->kk_name, kvs_name, sizeof(kvs->kk_name));

    mutex_lock(&self->ikdb_lock);

    if (self->ikdb_kvs_cnt >= HSE_KVS_COUNT_MAX) {
        err = merr(ev(EINVAL));
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
ikvdb_kvs_query_tree(struct hse_kvs *kvs, struct yaml_context *yc, int fd, bool list)
{
    return kvs_rest_query_tree((struct kvdb_kvs *)kvs, yc, fd, list);
}

merr_t
ikvdb_kvs_open(
    struct ikvdb *           handle,
    const char *             kvs_name,
    const struct hse_params *params,
    uint                     flags,
    struct hse_kvs **        kvs_out)
{
    const struct compress_ops *cops;
    struct ikvdb_impl *        self = ikvdb_h2r(handle);
    struct kvdb_kvs *          kvs;
    int                        idx;
    struct kvs_rparams         rp, profile;
    merr_t                     err;

    /* load profile */
    err = hse_params_to_kvs_rparams(self->ikdb_profile, kvs_name, NULL, &profile);
    if (ev(err))
        return err;

    /* overwrite with CLI/API changes */
    err = hse_params_to_kvs_rparams(params, kvs_name, &profile, &rp);
    if (ev(err))
        return err;

    rp.rdonly = self->ikdb_rp.read_only; /* inherit from kvdb */

    err = kvs_rparams_validate(&rp);
    if (ev(err))
        return err;

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
    kvs->kk_seqno = &self->ikdb_seqno;
    kvs->kk_viewset = self->ikdb_cur_viewset;

    kvs->kk_vcompmin = UINT_MAX;
    cops = vcomp_compress_ops(&rp);
    if (cops) {
        assert(cops->cop_compress && cops->cop_estimate);

        kvs->kk_vcompress = cops->cop_compress;
        kvs->kk_vcompmin = max_t(uint, CN_SMALL_VALUE_THRESHOLD, rp.vcompmin);

        kvs->kk_vcompbnd = cops->cop_estimate(NULL, tls_vbufsz);
        kvs->kk_vcompbnd = tls_vbufsz - (kvs->kk_vcompbnd - tls_vbufsz);
        assert(kvs->kk_vcompbnd < tls_vbufsz);

        assert(cops->cop_estimate(NULL, HSE_KVS_VLEN_MAX) < HSE_KVS_VLEN_MAX + PAGE_SIZE * 2);
    }

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
    struct ikvs *      ikvs;

    mutex_lock(&parent->ikdb_lock);
    ikvs = kk->kk_ikvs;
    if (ikvs) {
        kk->kk_vcompmin = UINT_MAX;
        kk->kk_ikvs = NULL;
    }
    mutex_unlock(&parent->ikdb_lock);

    if (ev(!ikvs))
        return merr(EBADF);

    /* if refcnt goes down to 1, it would mean we have the only ref.
     * Set it to 0 and proceed
     * if not, keep spinning
     */
    while (atomic_cmpxchg(&kk->kk_refcnt, 1, 0) > 1)
        usleep(333);

    err = kvs_close(ikvs);

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
        self->ikdb_work_stop = true;
        destroy_workqueue(self->ikdb_workqueue);
    }

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

    mutex_unlock(&self->ikdb_lock);

    ikvdb_txn_fini(self);

    kvdb_ctxn_set_destroy(self->ikdb_ctxn_set);

    c0snr_set_destroy(self->ikdb_c0snr_set);

    kvdb_keylock_destroy(self->ikdb_keylock);

    viewset_destroy(self->ikdb_cur_viewset);
    viewset_destroy(self->ikdb_txn_viewset);

    csched_destroy(self->ikdb_csched);

    mutex_destroy(&self->ikdb_lock);

    throttle_fini(&self->ikdb_throttle);

    ikvdb_perfc_free(self);

    hse_params_free(self->ikdb_profile);

    free_aligned(self);

    return ret;
}

static
void
ikvdb_throttle(struct ikvdb_impl *self, u64 bytes)
{
    u64 sleep_ns;

    sleep_ns = tbkt_request(&self->ikdb_tb, bytes);
    tbkt_delay(sleep_ns);

    if (self->ikdb_tb_dbg) {
        atomic64_inc(&self->ikdb_tb_dbg_ops);
        atomic64_add(bytes, &self->ikdb_tb_dbg_bytes);
        atomic64_add(sleep_ns, &self->ikdb_tb_dbg_sleep_ns);
    }
}

static inline bool
is_write_allowed(
    struct ikvs *           kvs,
    struct hse_kvdb_opspec *os)
{
    bool kvs_is_txn = kvs_txn_is_enabled(kvs);
    bool op_is_txn  = os && os->kop_txn;

    return kvs_is_txn ^ op_is_txn ? false : true;
}

static inline bool
is_read_allowed(
    struct ikvs *           kvs,
    struct hse_kvdb_opspec *os)
{
    return os && os->kop_txn && !kvs_txn_is_enabled(kvs) ? false : true;
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
    struct kvs_vtuple  vtbuf;
    u64                put_seqno;
    merr_t             err;
    uint               vlen, clen;
    size_t             vbufsz;
    void *             vbuf;

    if (ev(!handle))
        return merr(EINVAL);

    if (ev(!is_write_allowed(kk->kk_ikvs, os)))
        return merr(EINVAL);

    parent = kk->kk_parent;
    if (ev(parent->ikdb_rdonly))
        return merr(EROFS);

    /* puts do not stop on block deletion failures. */
    err = kvdb_health_check(
        &parent->ikdb_health, KVDB_HEALTH_FLAG_ALL & ~KVDB_HEALTH_FLAG_DELBLKFAIL);
    if (ev(err))
        return err;

    vlen = kvs_vtuple_vlen(vt);
    clen = kvs_vtuple_clen(vt);

    vbufsz = tls_vbufsz;
    vbuf = NULL;

    if (clen == 0 && vlen > kk->kk_vcompmin) {
        if (vlen > kk->kk_vcompbnd) {
            vbufsz = vlen + PAGE_SIZE * 2;
            vbuf = vlb_alloc(vbufsz);
        } else {
            vbuf = tls_vbuf;
        }

        if (vbuf) {
            err = kk->kk_vcompress(vt->vt_data, vlen, vbuf, vbufsz, &clen);

            if (!err && clen < vlen) {
                kvs_vtuple_cinit(&vtbuf, vbuf, vlen, clen);
                vt = &vtbuf;
                vlen = clen;
            }
        }
    }

    put_seqno = kvdb_kop_is_txn(os) ? 0 : HSE_SQNREF_SINGLE;

    err = ikvs_put(kk->kk_ikvs, os, kt, vt, put_seqno);

    if (vbuf && vbuf != tls_vbuf)
        vlb_free(vbuf, (vbufsz > VLB_ALLOCSZ_MAX) ? vbufsz : clen);

    if (err) {
        ev(merr_errno(err) != ECANCELED);
        return err;
    }

    if (!(kvdb_kop_is_priority(os) || parent->ikdb_rp.throttle_disable))
        ikvdb_throttle(parent, kt->kt_len + (clen ? clen : vlen));

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

    if (ev(!is_read_allowed(kk->kk_ikvs, os)))
        return merr(EINVAL);

    p = kk->kk_parent;

    if (kvdb_kop_is_txn(os)) {
        /*
         * No need to wait for ongoing commits. A transaction waited when its view was
         * being established i.e. at the time of transaction begin.
         */
        view_seqno = 0;
    } else {
        /* Establish our view before waiting on ongoing commits. */
        view_seqno = atomic64_read(&p->ikdb_seqno);
        kvdb_ctxn_set_wait_commits(p->ikdb_ctxn_set);
    }

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

    if (ev(!is_read_allowed(kk->kk_ikvs, os)))
        return merr(EINVAL);

    p = kk->kk_parent;

    if (kvdb_kop_is_txn(os)) {
        /*
         * No need to wait for ongoing commits. A transaction waited when its view was
         * being established i.e. at the time of transaction begin.
         */
        view_seqno = 0;
    } else {
        /* Establish our view before waiting on ongoing commits. */
        view_seqno = atomic64_read(&p->ikdb_seqno);
        kvdb_ctxn_set_wait_commits(p->ikdb_ctxn_set);
    }

    return ikvs_get(kk->kk_ikvs, os, kt, view_seqno, res, vbuf);
}

merr_t
ikvdb_kvs_del(
    struct hse_kvs*         handle,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent;
    u64                del_seqno;
    merr_t             err;

    if (ev(!handle))
        return merr(EINVAL);

    if (ev(!is_write_allowed(kk->kk_ikvs, os)))
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

    if (ev(!is_write_allowed(kk->kk_ikvs, os)))
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
cursor_view_release(struct hse_kvs_cursor *cursor)
{
    u64 minview;
    u32 minchg;

    if (!cursor->kc_on_list)
        return;

    viewset_remove(cursor->kc_kvs->kk_viewset, cursor->kc_viewcookie, &minchg, &minview);
    cursor->kc_on_list = false;
}

static merr_t
cursor_view_acquire(struct hse_kvs_cursor *cursor)
{
    merr_t err;

    /* Add to cursor list only if this is NOT part of a txn.
     */
    if (cursor->kc_seq != HSE_SQNREF_UNDEFINED)
        return 0;

    err = viewset_insert(cursor->kc_kvs->kk_viewset, &cursor->kc_seq,
                         &cursor->kc_viewcookie);
    if (!err)
        cursor->kc_on_list = true;

    return err;
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
        cur->kc_gen = -1;
        cur->kc_bind = 0;

        /*
         * Retain the view seqno of the current transaction if the
         * static view flag is set.
         * If the flag isn't set, a committed txn unbind sets the view
         * to commit_sn + 1 and an aborted txn unbind sets the view to
         * the current KVDB seqno.
         */
        if (!(cur->kc_flags & HSE_KVDB_KOP_FLAG_STATIC_VIEW)) {
            /*
             * Since the cursor view is refreshed to a newer one,  we need to
             * wait for ongoing commits after the view is established.
             */
            cur->kc_seq = bind->b_seq;
            kvdb_ctxn_set_wait_commits(cur->kc_kvs->kk_parent->ikdb_ctxn_set);
        }

        kvdb_ctxn_cursor_unbind(bind);
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
    u64                    vseq, tstart;
    struct perfc_set *     pkvsl_pc;

    *cursorp = NULL;

    if (ev(!is_read_allowed(kk->kk_ikvs, os)))
        return merr(EINVAL);

    if (ev(atomic_read(&ikvdb->ikdb_curcnt) > ikvdb->ikdb_curcnt_max))
        return merr(ECANCELED);

    pkvsl_pc = ikvs_perfc_pkvsl(kk->kk_ikvs);
    tstart = perfc_lat_start(pkvsl_pc);

    reverse = false;

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

    cur->kc_kvs = kk;
    cur->kc_gen = 0;
    cur->kc_bind = 0;

    /* Temporarily lock a view until this cursor gets refs on cn kvsets. */
    err = cursor_view_acquire(cur);
    if (!err) {
        u64 ts = perfc_lat_start(pkvsl_pc);
        err = ikvs_cursor_init(cur);
        perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_INIT, ts);
        if (!err) {
            if (bind) {
                /*
                 * No need to wait for ongoing commits. A transaction waited when its view was
                 * being established i.e. at the time of transaction begin.
                 */
                err = cursor_bind_txn(cur, bind);
            } else {
                /* New cursor view is established. Now wait on ongoing commits. */
                kvdb_ctxn_set_wait_commits(ikvdb->ikdb_ctxn_set);
            }
        }

        cursor_view_release(cur);
    }

    if (ev(err)) {
        ikvdb_kvs_cursor_destroy(cur);
        cur = 0;
    } else {
        perfc_inc(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURCNT);
        cur->kc_create_time = tstart;
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

    if (ev(!is_read_allowed(cur->kc_kvs->kk_ikvs, os)))
        return merr(EINVAL);

    /* Check if this call is trying to change cursor direction. */
    if (os) {
        bool os_reverse = kvdb_kop_is_reverse(os);
        bool cur_reverse = cur->kc_flags && (cur->kc_flags & HSE_KVDB_KOP_FLAG_REVERSE);

        if (ev(os_reverse != cur_reverse))
            return merr(EINVAL);
    }

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
                /* Save view seq; do not change in unbind.
                 * Since the view remains unchanged, no need to wait on commits.
                 */
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
    err = cursor_view_acquire(cur);
    if (!err) {
        cur->kc_err = ikvs_cursor_update(cur, cur->kc_seq);
        if (!ev(cur->kc_err)) {
            if (bind) {
                /*
                 * No need to wait for ongoing commits. A transaction waited when its view was
                 * being established i.e. at the time of transaction begin.
                 */
                cur->kc_err = cursor_bind_txn(cur, bind);
            } else {
                /* New cursor view is established. Now wait on ongoing commits. */
                kvdb_ctxn_set_wait_commits(cur->kc_kvs->kk_parent->ikdb_ctxn_set);
            }
        }

        cursor_view_release(cur);
    }

    cur->kc_flags = os ? os->kop_flags : 0;

    perfc_lat_record(cur->kc_pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_UPDATE, tstart);

    /* Since the update code doesn't currently allow retrying, change the error code
     * if it's an EAGAIN. Wherever possible, the code retries the cursor update call
     * internally.
     */
    if (ev(merr_errno(cur->kc_err) == EAGAIN))
        cur->kc_err = merr(ENOTRECOVERABLE);

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
    err = kvs_cursor_seek(cur, key, (u32)len, limit, (u32)limit_len, kt);

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

    err = kvs_cursor_read(cur, &kvt, eof);
    if (ev(err))
        return err;
    if (*eof)
        return 0;

    *key = kvt.kvt_key.kt_data;
    *key_len = kvt.kvt_key.kt_len;

    *val = kvt.kvt_value.vt_data;
    *val_len = kvs_vtuple_vlen(&kvt.kvt_value);

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
    u64               tstart, ctime;

    if (!cur)
        return 0;

    pkvsl_pc = cur->kc_pkvsl_pc;
    tstart = perfc_lat_start(pkvsl_pc);
    ctime = cur->kc_create_time;

    cursor_unbind_txn(cur);

    perfc_dec(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURCNT);

    ikvs_cursor_free(cur);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_DESTROY, tstart);
    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_FULL, ctime);

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
ikvdb_compact_status_get(struct ikvdb *handle, struct hse_kvdb_compact_status *status)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_rdonly))
        return;

    csched_compact_status_get(self->ikdb_csched, status);
}

merr_t
ikvdb_sync(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_rdonly))
        return merr(EROFS);

    return c0sk_sync(self->ikdb_c0sk);
}

merr_t
ikvdb_flush(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_rdonly))
        return merr(EROFS);

    return c0sk_flush(self->ikdb_c0sk);
}

u64
ikvdb_horizon(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    u64                horizon;
    u64                b, c;

    b = viewset_horizon(self->ikdb_cur_viewset);
    c = viewset_horizon(self->ikdb_txn_viewset);

    horizon = min_t(u64, b, c);

    if (HSE_UNLIKELY( perfc_ison(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_SEQNO) )) {
        u64 a;

        /* Must read a after b and c to test assertions. */
        __atomic_thread_fence(__ATOMIC_RELEASE);

        a = atomic64_read(&self->ikdb_seqno);
        assert(b == U64_MAX || a >= b);
        assert(a >= c);

        perfc_set(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_SEQNO, a);
        perfc_set(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURHORIZON, b);
        perfc_set(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_HORIZON, horizon);
    }

    return horizon;
}

static HSE_ALWAYS_INLINE struct kvdb_ctxn_bkt *
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
    if (bkt->kcb_ctxnc > 0) {
        ctxn = bkt->kcb_ctxnv[--bkt->kcb_ctxnc];
        kvdb_ctxn_reset(ctxn);
    }
    spin_unlock(&bkt->kcb_lock);

    if (ctxn)
        return &ctxn->ctxn_handle;

    ctxn = kvdb_ctxn_alloc(
        self->ikdb_keylock,
        &self->ikdb_seqno,
        self->ikdb_ctxn_set,
        self->ikdb_txn_viewset,
        self->ikdb_c0snr_set,
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
    c0sk_perfc_fini();
    kvs_perfc_fini();
    kvdb_perfc_fini();
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

    /* Need an extra byte to terminate string read from TOC file */
    buf = malloc(buflen + 1);
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

    buf[buflen] = '\0';

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
    char **                  kvsv = NULL;
    struct kvs_cparams *     kvs_cparams;
    unsigned int             count = 0;
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

#if HSE_MOCKING
#include "ikvdb_ut_impl.i"
#include "kvs_ut_impl.i"
#endif /* HSE_MOCKING */
