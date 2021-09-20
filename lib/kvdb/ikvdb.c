/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_ikvdb
#define MTF_MOCK_IMPL_kvs

#include <hse/flags.h>

#include <hse_util/hse_err.h>
#include <hse_util/invariant.h>
#include <hse_util/event_counter.h>
#include <hse_util/string.h>
#include <hse_util/page.h>
#include <hse_util/seqno.h>
#include <hse_util/darray.h>
#include <hse_util/rest_api.h>
#include <hse_util/log2.h>
#include <hse_util/atomic.h>
#include <hse_util/vlb.h>
#include <hse_util/compression_lz4.h>
#include <hse_util/token_bucket.h>
#include <hse_util/xrand.h>
#include <hse_util/bkv_collection.h>
#include <hse_util/alloc.h>

#include <hse_ikvdb/config.h>
#include <hse_ikvdb/argv.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/lc.h>
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
#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/hse_gparams.h>
#include <hse_ikvdb/wal.h>
#include <hse_ikvdb/kvdb_meta.h>
#include <hse_ikvdb/omf_version.h>
#include <hse_ikvdb/kvdb_home.h>

#include "kvdb_kvs.h"
#include "viewset.h"
#include "kvdb_keylock.h"
#include "kvdb_pfxlock.h"
#include "kvdb_ctxn_pfxlock.h"

#include <mpool/mpool.h>

#include <xxhash.h>
#include <cjson/cJSON.h>
#include <bsd/libutil.h>

#include "kvdb_rest.h"

/* clang-format off */

static_assert((sizeof(uintptr_t) == sizeof(u64)),
              "libhse relies on pointers being 64-bits in size");

/* tls_vbuf[] is a thread-local buffer used as a compression output buffer by
 * ikvdb_kvs_put() and for small to medium direct reads by kvset_lookup_val().
 */
thread_local char tls_vbuf[256 * 1024] HSE_ALIGNED(PAGE_SIZE);
const size_t      tls_vbufsz = sizeof(tls_vbuf);

struct perfc_set kvdb_pkvdbl_pc HSE_READ_MOSTLY;
struct perfc_set kvdb_pc        HSE_READ_MOSTLY;

struct perfc_set kvdb_metrics_pc HSE_READ_MOSTLY;
struct perfc_set c0_metrics_pc   HSE_READ_MOSTLY;

#define ikvdb_h2r(_ikvdb_handle) \
    container_of(_ikvdb_handle, struct ikvdb_impl, ikdb_handle)

struct ikvdb {
};

/* Max buckets in ctxn cache.
 */
#define KVDB_CTXN_BKT_MAX   (32)

/* Simple fixed-size stack for caching ctxn objects.
 */
struct kvdb_ctxn_bkt {
    spinlock_t        kcb_lock HSE_ALIGNED(SMP_CACHE_BYTES);
    uint              kcb_ctxnc;
    struct kvdb_ctxn *kcb_ctxnv[7];
};

static thread_local uint     tls_txn_idx;
static              atomic_t ikvdb_txn_idx;

/**
 * struct ikvdb_impl - private representation of a kvdb
 * @ikdb_handle:        handle for users of struct ikvdb_impl's
 * @ikdb_read_only:        bool indicating read-only mode
 * @ikdb_work_stop:     used to control maint and throttle threads
 * @ikdb_tb_dbg:        token bucket debug flags
 * @ikdb_ctxn_set:      kvdb transaction set
 * @ikdb_ctxn_op:       transaction performance counters
 * @ikdb_keylock:       handle to the KVDB keylock
 * @ikdb_c0sk:          c0sk handle
 * @ikdb_health:        used to remember health error counts
 * @ikdb_mp:            mpool handle
 * @ikdb_log:           KVDB log handle
 * @ikdb_cndb:          CNDB handle
 * @ikdb_ctxn_cache:    ctxn cache
 * @ikdb_curcnt:        number of active cursors (lazily updated)
 * @ikdb_curcnt_max:    maximum number of active cursors
 * @ikdb_seqno:         current sequence number for the struct ikvdb
 * @ikdb_maint_work:    used to schedule kvdb maint task
 * @ikdb_rp:            KVDB run time params
 * @ikdb_lock:          protects ikdb_kvs_vec/ikdb_kvs_cnt writes
 * @ikdb_kvs_cnt:       number of KVSes in ikdb_kvs_vec
 * @ikdb_kvs_vec:       vector of KVDB KVSes
 * @ikdb_home:          KVDB home
 *
 * Note:  The first group of fields are read-mostly and some of them are very
 * heavily concurrently accessed, hence they live in the first few cache lines.
 * Only add a new fields to this group if they are read-mostly.  Similarly,
 * fields such as %ikdb_seqno and %ikdb_curcnt are heavily concurrently
 * modified, hence they get their own private cache lines that are padded
 * with fields that are rarely referenced.
 */
struct ikvdb_impl {
    struct ikvdb            ikdb_handle;
    bool                    ikdb_read_only;
    bool                    ikdb_work_stop;
    u32                     ikdb_tb_dbg;
    struct kvdb_ctxn_set   *ikdb_ctxn_set;
    struct c0snr_set       *ikdb_c0snr_set;
    struct perfc_set        ikdb_ctxn_op;
    struct kvdb_keylock    *ikdb_keylock;
    struct kvdb_pfxlock    *ikdb_pfxlock;
    struct c0sk            *ikdb_c0sk;
    struct lc              *ikdb_lc;

    struct wal             *ikdb_wal;
    struct csched          *ikdb_csched;
    struct cn_kvdb         *ikdb_cn_kvdb;
    struct mpool           *ikdb_mp;
    struct cndb            *ikdb_cndb;
    struct viewset         *ikdb_txn_viewset;
    struct viewset         *ikdb_cur_viewset;

    struct kvdb_callback    ikdb_wal_cb;
    struct kvdb_health      ikdb_health;
    struct throttle         ikdb_throttle;
    struct tbkt             ikdb_tb;

    struct kvdb_ctxn_bkt    ikdb_ctxn_cache[KVDB_CTXN_BKT_MAX];

    atomic_t                ikdb_curcnt HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    u32                     ikdb_curcnt_max;

    atomic64_t              ikdb_tb_dbg_ops HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t              ikdb_tb_dbg_bytes;
    atomic64_t              ikdb_tb_dbg_sleep_ns;
    u64                     ikdb_tb_dbg_next;
    u64                     ikdb_tb_burst;
    u64                     ikdb_tb_rate;

    atomic64_t              ikdb_seqno HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct work_struct      ikdb_throttle_work;
    struct work_struct      ikdb_maint_work;

    u64                     ikdb_cndb_oid1;
    u64                     ikdb_cndb_oid2;
    u64                     ikdb_wal_oid1;
    u64                     ikdb_wal_oid2;

    struct kvdb_rparams     ikdb_rp HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct mclass_policy    ikdb_mpolicies[HSE_MPOLICY_COUNT];

    struct workqueue_struct *ikdb_workqueue;

    struct mutex     ikdb_lock;
    u32              ikdb_kvs_cnt;
    struct kvdb_kvs *ikdb_kvs_vec[HSE_KVS_COUNT_MAX];

    unsigned int     ikdb_omf_version;
    struct pidfh    *ikdb_pidfh;
    struct config   *ikdb_config;
    const char       ikdb_home[]; /* flexible array */
};

/* clang-format on */

struct ikvdb *
ikvdb_kvdb_handle(struct ikvdb_impl *self)
{
    return &self->ikdb_handle;
}

void
ikvdb_perfc_alloc(struct ikvdb_impl *self)
{
    merr_t err;

    err = perfc_ctrseti_alloc(
        COMPNAME, self->ikdb_home, ctxn_perfc_op, PERFC_EN_CTXNOP, "set", &self->ikdb_ctxn_op);
    if (err)
        hse_elog(HSE_ERR "cannot alloc ctxn op perf counters for %s: @@e", err, self->ikdb_home);
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
ikvdb_create(const char *kvdb_home, struct kvdb_cparams *params)
{
    assert(kvdb_home);
    assert(params);

    struct kvdb_meta     meta;
    merr_t               err;
    u64                  cndb_captgt;
    struct mpool *       mp = NULL;
    struct mpool_rparams mp_rparams = {};

    err = mpool_create(kvdb_home, &params->storage);
    if (ev(err))
        goto out;

    for (int i = 0; i < MP_MED_COUNT; i++) {
        if (params->storage.mclass[i].path[0] != '\0') {
            strlcpy(
                mp_rparams.mclass[i].path,
                params->storage.mclass[i].path,
                sizeof(mp_rparams.mclass[i].path));
        }
    }

    err = mpool_open(kvdb_home, &mp_rparams, O_RDWR, &mp);
    if (ev(err))
        goto mpool_cleanup;

    for (int i = 0; i < MP_MED_COUNT; i++) {
        struct mpool_mclass_props mcprops;

        err = mpool_mclass_props_get(mp, i, &mcprops);
        if (merr_errno(err) == ENOENT)
            continue;
        else if (err)
            goto mpool_cleanup;

        err = mcprops.mc_mblocksz == 32 ? 0 : merr(EINVAL);
        if (ev(err))
            goto mpool_cleanup;
    }

    meta.km_omf_version = GLOBAL_OMF_VERSION;

    cndb_captgt = 0;
    err = cndb_alloc(mp, &cndb_captgt, &meta.km_cndb.oid1, &meta.km_cndb.oid2);
    if (ev(err))
        goto mpool_cleanup;

    err = cndb_create(mp, cndb_captgt, meta.km_cndb.oid1, meta.km_cndb.oid2);
    if (ev(err))
        goto cndb_cleanup; /* XXXXXX: Is this a valid point to call cndb_drop()? */

    err = wal_create(mp, &meta.km_wal.oid1, &meta.km_wal.oid2);
    if (err)
        goto cndb_cleanup;

    kvdb_meta_from_mpool_cparams(&meta, kvdb_home, &params->storage);

    err = kvdb_meta_create(kvdb_home);
    if (ev(err))
        goto wal_cleanup;

    err = kvdb_meta_serialize(&meta, kvdb_home);
    if (ev(err))
        goto wal_cleanup;

    mpool_close(mp);

    return err;

wal_cleanup:
    wal_destroy(mp, meta.km_wal.oid1, meta.km_wal.oid2);
cndb_cleanup:
    cndb_drop(mp, meta.km_cndb.oid1, meta.km_cndb.oid2);
mpool_cleanup:
    {
        struct mpool_dparams mp_dparams;

        for (int i = 0; i < MP_MED_COUNT; i++) {
            if (params->storage.mclass[i].path[0] != '\0') {
                strlcpy(
                    mp_dparams.mclass[i].path,
                    params->storage.mclass[i].path,
                    sizeof(mp_dparams.mclass[i].path));
            }
        }
        mpool_destroy(kvdb_home, &mp_dparams);
    }
out:
    /* Failed ikvdb_create() indicates that the caller or operator should
     * destroy the kvdb: recovery is not possible.
     */

    return err;
}

merr_t
ikvdb_storage_add(const char *kvdb_home, struct kvdb_cparams *params)
{
    struct kvdb_meta  meta;
    merr_t            err;
    bool              mc_present[MP_MED_COUNT] = {0};
    int               i;

    assert(kvdb_home);
    assert(params);

    err = kvdb_meta_deserialize(&meta, kvdb_home);
    if (err)
        return err;

    if (meta.km_omf_version != GLOBAL_OMF_VERSION) {
        hse_log(HSE_ERR "Mismatched global OMF version: %u != %u", meta.km_omf_version, GLOBAL_OMF_VERSION);
        err = merr(EPROTO);
        return err;
    }

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        if (i != MP_MED_CAPACITY && params->storage.mclass[i].path[0] != '\0') {
            int j;

            if (meta.km_storage[i].path[0] != '\0') {
                err = merr(EEXIST);
                goto errout;
            }

            for (j = i - 1; j >= MP_MED_BASE; j--) {
                if (meta.km_storage[j].path[0] != '\0') {
                    char rpath1[PATH_MAX], rpath2[PATH_MAX];

                    err = kvdb_home_storage_realpath_get(
                            kvdb_home, meta.km_storage[j].path, rpath1, false);
                    if (err)
                        goto errout;

                    err = kvdb_home_storage_realpath_get(
                            kvdb_home, params->storage.mclass[i].path, rpath2, true);
                    if (err)
                        goto errout;

                    if (!strcmp(rpath1, rpath2)) {
                        err = merr(EINVAL);
                        goto errout; /* Duplicate storage path */
                    }
                }
            }

            mc_present[i] = true;

            err = mpool_mclass_add(i, &params->storage);
            if (err)
                goto errout;
        }
    }

    err = kvdb_meta_storage_add(&meta, kvdb_home, &params->storage);
    if (err)
        goto errout;

    return 0;

errout:
    {
        struct mpool_dparams dparams = {0};

        for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
            if (mc_present[i]) {
                strlcpy(dparams.mclass[i].path, params->storage.mclass[i].path,
                        sizeof(dparams.mclass[i].path));
                mpool_mclass_destroy(i, &dparams);
            }
        }
    }

    return err;
}


merr_t
ikvdb_drop(const char *const kvdb_home)
{
    struct kvdb_meta     meta;
    merr_t               err;
    struct mpool_dparams mparams;

    assert(kvdb_home);

    err = kvdb_meta_deserialize(&meta, kvdb_home);
    if (ev(err))
        return err;

    err = kvdb_meta_to_mpool_dparams(&meta, kvdb_home, &mparams);
    if (err)
        return err;

    err = mpool_destroy(kvdb_home, &mparams);
    if (err)
        return err;

    err = kvdb_meta_destroy(kvdb_home);
    if (err)
        return err;

    return err;
}

static inline void
ikvdb_tb_configure(struct ikvdb_impl *self, u64 burst, u64 rate, bool initialize)
{
    if (initialize)
        tbkt_init(&self->ikdb_tb, burst, rate);
    else
        tbkt_adjust(&self->ikdb_tb, burst, rate);
}

static void
ikvdb_rate_limit_set(struct ikvdb_impl *self, u64 rate)
{
    u64 burst = rate / 2;

    /* cache debug params from KVDB runtime params */
    self->ikdb_tb_dbg = self->ikdb_rp.throttle_debug & THROTTLE_DEBUG_TB_MASK;

    /* debug: manual control: get burst and rate from params  */
    if (HSE_UNLIKELY(self->ikdb_tb_dbg & THROTTLE_DEBUG_TB_MANUAL)) {
        burst = self->ikdb_rp.throttle_burst;
        rate = self->ikdb_rp.throttle_rate;
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
            long dbg_ops = atomic64_read(&self->ikdb_tb_dbg_ops);
            long dbg_bytes = atomic64_read(&self->ikdb_tb_dbg_bytes);
            long dbg_sleep_ns = atomic64_read(&self->ikdb_tb_dbg_sleep_ns);

            hse_log(
                HSE_NOTICE " tbkt_debug: manual %d shunt %d ops %8ld  bytes %10ld"
                           " sleep_ns %12ld burst %10lu rate %10lu raw %10u",
                (bool)(self->ikdb_tb_dbg & THROTTLE_DEBUG_TB_MANUAL),
                (bool)(self->ikdb_tb_dbg & THROTTLE_DEBUG_TB_SHUNT),
                dbg_ops,
                dbg_bytes,
                dbg_sleep_ns,
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

            uint raw = throttle_update(&self->ikdb_throttle);
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
    u64                curcnt_warn = 0;
    u64                maxdelay;

    self = container_of(work, struct ikvdb_impl, ikdb_maint_work);

    maxdelay = 10000; /* 10ms initial delay time */

    while (!self->ikdb_work_stop) {
        uint64_t vadd = 0, vsub = 0, curcnt;
        u64      tstart = get_time_ns();
        uint     i;

        /* Lazily sample the active cursor count and update ikdb_curcnt if necessary.
         * ikvdb_kvs_cursor_create() checks ikdb_curcnt to prevent the creation
         * of an excessive number of cursors.
         */
        perfc_read(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURCNT, &vadd, &vsub);

        curcnt = (vadd > vsub) ? (vadd - vsub) : 0;

        if (atomic_read(&self->ikdb_curcnt) != curcnt) {
            atomic_set(&self->ikdb_curcnt, curcnt);

            if (ev(curcnt > self->ikdb_curcnt_max && tstart > curcnt_warn)) {
                hse_log(
                    HSE_WARNING "%s: active cursors (%lu) > max allowed (%u)",
                    __func__,
                    curcnt,
                    self->ikdb_curcnt_max);

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
                kvs_maint_task(kvs->kk_ikvs, tstart);
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
    if (self->ikdb_read_only)
        return;

    /* Hand out throttle sensors */

    csched_throttle_sensor(self->ikdb_csched,
                           throttle_sensor(&self->ikdb_throttle, THROTTLE_SENSOR_CNROOT));

    c0sk_throttle_sensor(
        self->ikdb_c0sk, throttle_sensor(&self->ikdb_throttle, THROTTLE_SENSOR_C0SK));

    wal_throttle_sensor(
        self->ikdb_wal, throttle_sensor(&self->ikdb_throttle, THROTTLE_SENSOR_WAL));

}

static void
ikvdb_txn_init(struct ikvdb_impl *self)
{
    int i;

    for (i = 0; i < NELEM(self->ikdb_ctxn_cache); ++i) {
        struct kvdb_ctxn_bkt *bkt = self->ikdb_ctxn_cache + i;

        spin_lock_init(&bkt->kcb_lock);
        bkt->kcb_ctxnc = 0;
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

        bkt->kcb_ctxnc = 0;
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

static merr_t
ikvdb_alloc(
    const char                 *kvdb_home,
    const struct kvdb_rparams  *params,
    struct ikvdb_impl         **impl)
{
    struct ikvdb_impl *self;
    size_t             sz;

    assert(kvdb_home);
    assert(params);
    assert(impl);

    sz = sizeof(*self) + strlen(kvdb_home) + 1;

    self = aligned_alloc(4096, roundup(sz, 4096));
    if (!self)
        return merr(ENOMEM);

    memset(self, 0, sz);
    self->ikdb_rp = *params;
    self->ikdb_read_only = params->read_only;
    strcpy((char *)self->ikdb_home, kvdb_home);

    *impl = self;

    return 0;
}

/* ikvdb_diag_open() - open relevant media streams with minimal processing. */
merr_t
ikvdb_diag_open(
    const char *         kvdb_home,
    struct kvdb_rparams *params,
    struct ikvdb **      handle)
{
    static atomic64_t    tseqno = ATOMIC_INIT(0);
    struct ikvdb_impl   *self = NULL;
    merr_t               err;
    struct kvdb_meta     meta;
    struct mpool_rparams mparams;

    err = ikvdb_alloc(kvdb_home, params, &self);
    if (err)
        return err;

    mutex_init(&self->ikdb_lock);
    ikvdb_txn_init(self);

    err = kvdb_meta_deserialize(&meta, kvdb_home);
    if (ev(err))
        goto self_cleanup;

    if (meta.km_omf_version != GLOBAL_OMF_VERSION) {
        hse_log(HSE_ERR "Mismatched global OMF version: %u != %u", meta.km_omf_version, GLOBAL_OMF_VERSION);
        err = merr(EPROTO);
        goto self_cleanup;
    }

    err = kvdb_meta_to_mpool_rparams(&meta, kvdb_home, &mparams);
    if (ev(err))
        goto self_cleanup;

    err = mpool_open(kvdb_home, &mparams, O_RDWR, &self->ikdb_mp);
    if (ev(err))
        goto self_cleanup;

    atomic_set(&self->ikdb_curcnt, 0);

    err = viewset_create(&self->ikdb_txn_viewset, &self->ikdb_seqno, &tseqno);
    if (ev(err))
        goto mpool_cleanup;

    err = viewset_create(&self->ikdb_cur_viewset, &self->ikdb_seqno, &tseqno);
    if (ev(err))
        goto txn_viewset_cleanup;

    err = kvdb_keylock_create(&self->ikdb_keylock, params->keylock_tables);
    if (ev(err))
        goto cur_viewset_cleanup;

    err = kvdb_pfxlock_create(self->ikdb_txn_viewset, &self->ikdb_pfxlock);
    if (ev(err))
        goto kvdb_keylock_cleanup;

    self->ikdb_cndb_oid1 = meta.km_cndb.oid1;
    self->ikdb_cndb_oid2 = meta.km_cndb.oid2;

    err = cndb_open(
        self->ikdb_mp,
        self->ikdb_read_only,
        &self->ikdb_seqno,
        params->cndb_entries,
        self->ikdb_cndb_oid1,
        self->ikdb_cndb_oid2,
        &self->ikdb_health,
        &self->ikdb_rp,
        &self->ikdb_cndb);

    if (!ev(err)) {
        *handle = &self->ikdb_handle;
        return 0;
    }

    kvdb_pfxlock_destroy(self->ikdb_pfxlock);
kvdb_keylock_cleanup:
    kvdb_keylock_destroy(self->ikdb_keylock);
cur_viewset_cleanup:
    viewset_destroy(self->ikdb_cur_viewset);
txn_viewset_cleanup:
    viewset_destroy(self->ikdb_txn_viewset);
mpool_cleanup:
    mpool_close(self->ikdb_mp);
self_cleanup:
    ikvdb_txn_fini(self);
    mutex_destroy(&self->ikdb_lock);
    free(self);

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

    mutex_unlock(&self->ikdb_lock);

    viewset_destroy(self->ikdb_cur_viewset);
    viewset_destroy(self->ikdb_txn_viewset);

    kvdb_pfxlock_destroy(self->ikdb_pfxlock);
    kvdb_keylock_destroy(self->ikdb_keylock);
    ikvdb_txn_fini(self);
    mutex_destroy(&self->ikdb_lock);
    free(self);

    return ret;
}

/**
 * ikvdb_rest_register() - install rest handlers for KVSes and the kvs list
 * @self:       self
 * @handle:     ikvdb handle
 */
static void
ikvdb_rest_register(struct ikvdb_impl *self, struct ikvdb *handle)
{
    int    i;
    merr_t err;

    for (i = 0; i < self->ikdb_kvs_cnt; i++) {
        err = kvs_rest_register(self->ikdb_kvs_vec[i]->kk_name, self->ikdb_kvs_vec[i]);
        if (err)
            hse_elog(
                HSE_WARNING "%s/%s REST registration failed: @@e",
                err,
                self->ikdb_home,
                self->ikdb_kvs_vec[i]->kk_name);
    }

    err = kvdb_rest_register(handle);
    if (err)
        hse_elog(HSE_WARNING "%s REST registration failed: @@e", err, self->ikdb_home);
}

/**
 * ikvdb_maint_start() - start maintenance work queue
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
        hse_elog(HSE_ERR "%s cannot start kvdb maintenance", err, self->ikdb_home);
        return err;
    }

    INIT_WORK(&self->ikdb_maint_work, ikvdb_maint_task);
    if (!queue_work(self->ikdb_workqueue, &self->ikdb_maint_work)) {
        err = merr(EBUG);
        hse_elog(HSE_ERR "%s cannot start kvdb maintenance", err, self->ikdb_home);
        return err;
    }

    INIT_WORK(&self->ikdb_throttle_work, ikvdb_throttle_task);
    if (!queue_work(self->ikdb_workqueue, &self->ikdb_throttle_work)) {
        err = merr(EBUG);
        hse_elog(HSE_ERR "%s cannot start kvdb throttle", err, self->ikdb_home);
        return err;
    }

    return 0;
}

static struct kvdb_kvs *
kvdb_kvs_create(void)
{
    struct kvdb_kvs *kvs;

    kvs = aligned_alloc(alignof(*kvs), sizeof(*kvs));
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
        free(kvs);
    }
}

/**
 * ikvdb_cndb_open() - instantiate multi-kvs metadata
 * @self:       self
 * @seqno:      sequence number (output)
 * @ingestid:   ingest id (output)
 */
static merr_t
ikvdb_cndb_open(struct ikvdb_impl *self, u64 *seqno, u64 *ingestid, u64 *txhorizon)
{
    merr_t           err = 0;
    int              i;
    struct kvdb_kvs *kvs;

    err = cndb_open(
        self->ikdb_mp,
        self->ikdb_read_only,
        &self->ikdb_seqno,
        self->ikdb_rp.cndb_entries,
        self->ikdb_cndb_oid1,
        self->ikdb_cndb_oid2,
        &self->ikdb_health,
        &self->ikdb_rp,
        &self->ikdb_cndb);
    if (ev(err))
        goto err_exit;

    err = cndb_replay(self->ikdb_cndb, seqno, ingestid, txhorizon);
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

uint32_t
ikvdb_lowmem_scale(uint32_t memgb)
{
    return max_t(uint, 1, roundup_pow_of_two(memgb) / HSE_LOWMEM_THRESHOLD_GB_MIN);
}

/**
 * ikvdb_lowmem_adjust() - configure for constrained memory environment
 * @self:       self
 */
static void
ikvdb_lowmem_adjust(struct ikvdb_impl *self, ulong memgb)
{
    struct kvdb_rparams  rpdef = kvdb_rparams_defaults();
    struct kvdb_rparams *rp = &self->ikdb_rp;
    uint32_t scale;

    if (memgb > HSE_LOWMEM_THRESHOLD_GB_DFLT)
        return;

    hse_log(HSE_NOTICE "Configuring %s for %lu GiB memory", self->ikdb_home, memgb);

    scale = ikvdb_lowmem_scale(memgb);

    if (rp->dur_bufsz_mb == rpdef.dur_bufsz_mb)
        rp->dur_bufsz_mb =
            min_t(uint32_t, HSE_WAL_DUR_BUFSZ_MB_MIN * scale, HSE_WAL_DUR_BUFSZ_MB_MAX);

    if (rp->c0_ingest_width == rpdef.c0_ingest_width)
        rp->c0_ingest_width = HSE_C0_INGEST_WIDTH_MIN;

    hse_log(HSE_DEBUG "Low mem config settings for %s: c0kvs_cache %lu c0kvs_cheap %lu "
            "c0_width %u dur_bufsz_mb %u vlb cache %lu",
            self->ikdb_home, hse_gparams.gp_c0kvs_ccache_sz_max, hse_gparams.gp_c0kvs_cheap_sz,
            rp->c0_ingest_width, rp->dur_bufsz_mb, hse_gparams.gp_vlb_cache_sz);
}

static void
ikvdb_wal_cningest_cb(
    struct ikvdb *ikdb,
    uint64_t      seqno,
    uint64_t      gen,
    uint64_t      txhorizon,
    bool          post_ingest)
{
    struct ikvdb_impl *self = ikvdb_h2r(ikdb);

    if (self->ikdb_wal)
        wal_cningest_cb(self->ikdb_wal, seqno, gen, txhorizon, post_ingest);
}

static void
ikvdb_wal_bufrel_cb(struct ikvdb *ikdb, uint64_t gen)
{
    struct ikvdb_impl *self = ikvdb_h2r(ikdb);

    if (self->ikdb_wal)
        wal_bufrel_cb(self->ikdb_wal, gen);
}

static void
ikvdb_wal_install_callback(struct ikvdb_impl *self)
{
    struct kvdb_callback *cb = &self->ikdb_wal_cb;

    if (!self->ikdb_wal) {
        c0sk_install_callback(self->ikdb_c0sk, NULL);
        return;
    }

    cb->kc_cbarg = &self->ikdb_handle;
    cb->kc_cningest_cb = ikvdb_wal_cningest_cb;
    cb->kc_bufrel_cb = ikvdb_wal_bufrel_cb;

    c0sk_install_callback(self->ikdb_c0sk, cb);
}

static void
ikvdb_wal_replay_info_init(
    struct ikvdb_impl      *self,
    uint64_t                seqno,
    uint64_t                gen,
    uint64_t                txhorizon,
    struct wal_replay_info *rinfo)
{
    rinfo->mdcid1 = self->ikdb_wal_oid1;
    rinfo->mdcid2 = self->ikdb_wal_oid2;
    rinfo->seqno = seqno;
    rinfo->gen = gen;
    rinfo->txhorizon = txhorizon;
}

merr_t
ikvdb_open(
    const char *         kvdb_home,
    struct kvdb_rparams *params,
    struct ikvdb **      handle)
{
    merr_t                 err;
    struct ikvdb_impl *    self = NULL;
    atomic64_t *           tseqnop;
    u64                    seqno = 0; /* required by unit test */
    ulong                  mavail;
    size_t                 sz;
    int                    i;
    uint32_t               flags;
    u64                    ingestid, gen = 0, txhorizon = 0;
    struct wal_replay_info rinfo = {0};
    struct mpool_rparams   mparams;
    struct kvdb_meta       meta;

    assert(kvdb_home);
    assert(params);
    assert(handle);

    *handle = NULL;

    err = ikvdb_alloc(kvdb_home, params, &self);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        return err;
    }

    mutex_init(&self->ikdb_lock);
    ikvdb_txn_init(self);

    err = kvdb_meta_deserialize(&meta, kvdb_home);
    if (ev(err)) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    if (meta.km_omf_version != GLOBAL_OMF_VERSION) {
        hse_log(HSE_ERR "Mismatched global OMF version: %u != %u", meta.km_omf_version, GLOBAL_OMF_VERSION);
        err = merr(EPROTO);
        goto out;
    }

    err = kvdb_meta_to_mpool_rparams(&meta, kvdb_home, &mparams);
    if (ev(err))
        goto out;

    flags = params->read_only ? O_RDONLY : O_RDWR;
    err = mpool_open(kvdb_home, &mparams, flags, &self->ikdb_mp);
    if (ev(err))
        goto out;

    for (int i = 0; i < MP_MED_COUNT; i++) {
        struct mpool_mclass_props mcprops;

        err = mpool_mclass_props_get(self->ikdb_mp, i, &mcprops);
        if (merr_errno(err) == ENOENT)
            continue;
        else if (err)
            goto out;

        err = mcprops.mc_mblocksz == 32 ? 0 : merr(EINVAL);
        if (ev(err))
            goto out;
    }

    memcpy(self->ikdb_mpolicies, params->mclass_policies, sizeof(params->mclass_policies));

    hse_meminfo(NULL, &mavail, 0);
    ikvdb_lowmem_adjust(self, mavail >> 30);

    throttle_init(&self->ikdb_throttle, &self->ikdb_rp);
    throttle_init_params(&self->ikdb_throttle, &self->ikdb_rp);

    self->ikdb_tb_burst = self->ikdb_rp.throttle_burst;
    self->ikdb_tb_rate = self->ikdb_rp.throttle_rate;

    ikvdb_tb_configure(self, self->ikdb_tb_burst, self->ikdb_tb_rate, true);

    if (!self->ikdb_read_only) {
        err = csched_create(
            csched_rp_policy(&self->ikdb_rp),
            self->ikdb_mp,
            &self->ikdb_rp,
            self->ikdb_home,
            &self->ikdb_health,
            &self->ikdb_csched);
        if (err) {
            hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
            goto out;
        }
    }

    /* Set max number of active cursors per kvdb such that max
     * memory use is limited to about 10% of system memory.
     */
    sz = (mavail * HSE_CURACTIVE_SZ_PCT) / 100;
    sz = clamp_t(size_t, sz, HSE_CURACTIVE_SZ_MIN, HSE_CURACTIVE_SZ_MAX);
    self->ikdb_curcnt_max = sz / HSE_CURSOR_SZ_MIN;

    atomic_set(&self->ikdb_curcnt, 0);
    atomic64_set(&self->ikdb_seqno, 1);

    err = kvdb_ctxn_set_create(
        &self->ikdb_ctxn_set, self->ikdb_rp.txn_timeout, self->ikdb_rp.txn_wkth_delay);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    tseqnop = kvdb_ctxn_set_tseqnop_get(self->ikdb_ctxn_set);

    err = viewset_create(&self->ikdb_txn_viewset, &self->ikdb_seqno, tseqnop);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    err = viewset_create(&self->ikdb_cur_viewset, &self->ikdb_seqno, tseqnop);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    err = kvdb_keylock_create(&self->ikdb_keylock, params->keylock_tables);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    err = kvdb_pfxlock_create(self->ikdb_txn_viewset, &self->ikdb_pfxlock);
    if (ev(err))
        goto out;

    self->ikdb_cndb_oid1 = meta.km_cndb.oid1;
    self->ikdb_cndb_oid2 = meta.km_cndb.oid2;

    err = ikvdb_cndb_open(self, &seqno, &ingestid, &txhorizon);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    atomic64_set(&self->ikdb_seqno, seqno);

    kvdb_ctxn_set_tseqno_init(self->ikdb_ctxn_set, seqno);

    err = c0snr_set_create(kvdb_ctxn_abort, &self->ikdb_c0snr_set);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    err = cn_kvdb_create(&self->ikdb_cn_kvdb);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    err = lc_create(&self->ikdb_lc, &self->ikdb_health);
    if (ev(err)) {
        hse_elog(HSE_ERR "failed to create lc: @@e", err);
        goto out;
    }

    if (ingestid != CNDB_INVAL_INGESTID && ingestid != CNDB_DFLT_INGESTID && ingestid > 0)
        gen = ingestid;

    err = c0sk_open(
        &self->ikdb_rp,
        self->ikdb_mp,
        self->ikdb_home,
        &self->ikdb_health,
        self->ikdb_csched,
        &self->ikdb_seqno,
        gen,
        &self->ikdb_c0sk);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    c0sk_lc_set(self->ikdb_c0sk, self->ikdb_lc);
    c0sk_ctxn_set_set(self->ikdb_c0sk, self->ikdb_ctxn_set);

    self->ikdb_wal_oid1 = meta.km_wal.oid1;
    self->ikdb_wal_oid2 = meta.km_wal.oid2;

    ikvdb_wal_replay_info_init(self, seqno, gen, txhorizon, &rinfo);

    err = wal_open(self->ikdb_mp, &self->ikdb_rp, &rinfo, &self->ikdb_handle, &self->ikdb_health,
                   &self->ikdb_wal);
    if (err) {
        hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
        goto out;
    }

    seqno = atomic64_read(&self->ikdb_seqno);
    lc_ingest_seqno_set(self->ikdb_lc, seqno);
    c0sk_min_seqno_set(self->ikdb_c0sk, seqno);

    *handle = &self->ikdb_handle;

    if (!self->ikdb_read_only) {
        err = ikvdb_maint_start(self);
        if (err) {
            hse_elog(HSE_ERR "cannot open %s: @@e", err, kvdb_home);
            goto out;
        }
    }

    ikvdb_wal_install_callback(self);

    ikvdb_perfc_alloc(self);
    kvdb_keylock_perfc_init(self->ikdb_keylock, &self->ikdb_ctxn_op);

    ikvdb_rest_register(self, &self->ikdb_handle);

    ikvdb_init_throttle_params(self);

    *handle = &self->ikdb_handle;

out:
    if (err) {
        c0sk_close(self->ikdb_c0sk);
        lc_destroy(self->ikdb_lc);
        self->ikdb_work_stop = true;
        destroy_workqueue(self->ikdb_workqueue);
        cn_kvdb_destroy(self->ikdb_cn_kvdb);
        for (i = 0; i < self->ikdb_kvs_cnt; i++)
            kvdb_kvs_destroy(self->ikdb_kvs_vec[i]);
        c0snr_set_destroy(self->ikdb_c0snr_set);
        kvdb_ctxn_set_destroy(self->ikdb_ctxn_set);
        wal_close(self->ikdb_wal);
        cndb_close(self->ikdb_cndb);
        kvdb_pfxlock_destroy(self->ikdb_pfxlock);
        kvdb_keylock_destroy(self->ikdb_keylock);
        viewset_destroy(self->ikdb_cur_viewset);
        viewset_destroy(self->ikdb_txn_viewset);
        csched_destroy(self->ikdb_csched);
        throttle_fini(&self->ikdb_throttle);
        mpool_close(self->ikdb_mp);

        ikvdb_txn_fini(self);
        mutex_destroy(&self->ikdb_lock);
        free(self);
    }

    return err;
}

struct pidfh *
ikvdb_pidfh(struct ikvdb *kvdb)
{
    struct ikvdb_impl *self;

    assert(kvdb);

    self = ikvdb_h2r(kvdb);

    return self->ikdb_pidfh;
}

void
ikvdb_pidfh_attach(struct ikvdb *kvdb, struct pidfh *pfh)
{
    struct ikvdb_impl *self;

    assert(kvdb);

    self = ikvdb_h2r(kvdb);

    self->ikdb_pidfh = pfh;
}

const char *
ikvdb_home(struct ikvdb *kvdb)
{
    struct ikvdb_impl *self = ikvdb_h2r(kvdb);

    return self->ikdb_home;
}

struct config *
ikvdb_config(struct ikvdb *kvdb)
{
    struct ikvdb_impl *self = ikvdb_h2r(kvdb);

    return self->ikdb_config;
}

void
ikvdb_config_attach(struct ikvdb *kvdb, struct config *conf)
{
    struct ikvdb_impl *self;

    assert(kvdb);

    self = ikvdb_h2r(kvdb);

    self->ikdb_config = conf;
}

bool
ikvdb_read_only(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    return self->ikdb_read_only;
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
ikvdb_kvs_create(struct ikvdb *handle, const char *kvs_name, const struct kvs_cparams *params)
{
    assert(handle);
    assert(kvs_name);
    assert(params);

    merr_t             err = 0;
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    struct kvdb_kvs *  kvs = NULL;
    int                idx;

    if (self->ikdb_read_only)
        goto out_immediate;

    err = validate_kvs_name(kvs_name);
    if (ev(err))
        goto out_immediate;

    kvs = kvdb_kvs_create();
    if (ev(!kvs)) {
        err = merr(ENOMEM);
        goto out_immediate;
    }

    strlcpy(kvs->kk_name, kvs_name, sizeof(kvs->kk_name));

    mutex_lock(&self->ikdb_lock);

    if (self->ikdb_kvs_cnt >= HSE_KVS_COUNT_MAX) {
        err = merr(ev(EINVAL));
        goto out_unlock;
    }

    if (get_kvs_index(self->ikdb_kvs_vec, kvs_name, &idx) >= 0) {
        err = merr(ev(EEXIST));
        goto out_unlock;
    }

    assert(idx >= 0); /* assert we found an empty slot */

    kvs->kk_flags = cn_cp2cflags(params);

    err = cndb_cn_create(self->ikdb_cndb, params, &kvs->kk_cnid, kvs->kk_name);
    if (ev(err))
        goto out_unlock;

    kvs->kk_cparams = cndb_cn_cparams(self->ikdb_cndb, kvs->kk_cnid);

    if (ev(!kvs->kk_cparams)) {
        cndb_cn_drop(self->ikdb_cndb, kvs->kk_cnid);
        err = merr(EBUG);
        goto out_unlock;
    }

    assert(kvs->kk_cparams);

    self->ikdb_kvs_cnt++;
    self->ikdb_kvs_vec[idx] = kvs;

    mutex_unlock(&self->ikdb_lock);

    /* Register in kvs make instead of open so all KVSes can be queried for
     * info
     */
    err = kvs_rest_register(self->ikdb_kvs_vec[idx]->kk_name, self->ikdb_kvs_vec[idx]);
    if (ev(err))
        hse_elog(
            HSE_WARNING "rest: %s registration failed: @@e", err, self->ikdb_kvs_vec[idx]->kk_name);

    return 0;

out_unlock:
    mutex_unlock(&self->ikdb_lock);
out_immediate:
    if (err && kvs)
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

    if (self->ikdb_rp.read_only) {
        err = merr(ev(EROFS));
        goto out_immediate;
    }

    err = validate_kvs_name(kvs_name);
    if (ev(err))
        goto out_immediate;

    mutex_lock(&self->ikdb_lock);

    idx = get_kvs_index(self->ikdb_kvs_vec, kvs_name, NULL);
    if (idx < 0) {
        err = merr(ev(ENOENT));
        goto out_unlock;
    }

    kvs = self->ikdb_kvs_vec[idx];

    if (kvs->kk_ikvs) {
        err = merr(ev(EBUSY));
        goto out_unlock;
    }

    kvs_rest_deregister(kvs->kk_name);

    /* kvs_rest_deregister() waits until all active rest requests
     * have finished. Verify that the refcnt has gone down to zero
     */
    assert(atomic_read(&kvs->kk_refcnt) == 0);

    err = cndb_cn_drop(self->ikdb_cndb, kvs->kk_cnid);
    if (ev(err))
        goto out_unlock;

    drop_kvs_index(handle, idx);

out_unlock:
    mutex_unlock(&self->ikdb_lock);
out_immediate:
    return err;
}

merr_t
ikvdb_kvs_names_get(struct ikvdb *handle, size_t *namec, char ***namev)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    int                i, slot = 0;
    char **            kvsv;
    char *             name;

    kvsv = calloc(HSE_KVS_COUNT_MAX, sizeof(*kvsv) + HSE_KVS_NAME_LEN_MAX);
    if (!namev)
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

    *namev = kvsv;

    if (namec)
        *namec = self->ikdb_kvs_cnt;

    mutex_unlock(&self->ikdb_lock);
    return 0;
}

void
ikvdb_kvs_names_free(struct ikvdb *handle, char **namev)
{
    assert(namev);

    free(namev);
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
    struct ikvdb *      handle,
    const char *        kvs_name,
    struct kvs_rparams *params,
    uint                flags,
    struct hse_kvs **   kvs_out)
{
    const struct compress_ops *cops;
    struct ikvdb_impl *        self;
    struct kvdb_kvs *          kvs;
    int                        idx;
    merr_t                     err;

    assert(handle);
    assert(kvs_name);
    assert(params);
    assert(kvs_out);

    self = ikvdb_h2r(handle);

    err = config_deserialize_to_kvs_rparams(self->ikdb_config, kvs_name, params);
    if (ev(err))
        return err;

    params->read_only = self->ikdb_rp.read_only; /* inherit from kvdb */

    mutex_lock(&self->ikdb_lock);

    idx = get_kvs_index(self->ikdb_kvs_vec, kvs_name, NULL);
    if (idx < 0) {
        err = merr(ENOENT);
        goto out_unlock;
    }

    kvs = self->ikdb_kvs_vec[idx];

    if (kvs->kk_ikvs) {
        err = merr(EBUSY);
        goto out_unlock;
    }

    kvs->kk_parent = self;
    kvs->kk_seqno = &self->ikdb_seqno;
    kvs->kk_viewset = self->ikdb_cur_viewset;

    kvs->kk_vcompmin = UINT_MAX;
    assert(params->value_compression >= VCOMP_ALGO_MIN &&
        params->value_compression <= VCOMP_ALGO_MAX);
    cops = vcomp_compress_ops[params->value_compression];
    if (cops) {
        assert(cops->cop_compress && cops->cop_estimate);

        kvs->kk_vcompress = cops->cop_compress;
        kvs->kk_vcompmin = max_t(uint, CN_SMALL_VALUE_THRESHOLD, params->vcompmin);

        kvs->kk_vcompbnd = cops->cop_estimate(NULL, tls_vbufsz);
        kvs->kk_vcompbnd = tls_vbufsz - (kvs->kk_vcompbnd - tls_vbufsz);
        assert(kvs->kk_vcompbnd < tls_vbufsz);

        assert(cops->cop_estimate(NULL, HSE_KVS_VALUE_LEN_MAX) < HSE_KVS_VALUE_LEN_MAX + PAGE_SIZE * 2);
    }

    ikvdb_wal_install_callback(self); /* TODO: can this be removed? */

    /* Need a lock to prevent ikvdb_close from freeing up resources from
     * under us
     */

    err = kvs_open(
        handle,
        kvs,
        self->ikdb_mp,
        self->ikdb_cndb,
        self->ikdb_lc,
        self->ikdb_wal,
        params,
        &self->ikdb_health,
        self->ikdb_cn_kvdb,
        flags);
    if (ev(err))
        goto out_unlock;

    atomic_inc(&kvs->kk_refcnt);

    *kvs_out = (struct hse_kvs *)kvs;

out_unlock:
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

merr_t
ikvdb_storage_info_get(
    struct ikvdb *                handle,
    struct hse_kvdb_storage_info *info)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    struct mpool *     mp;
    struct mpool_stats stats = {};
    merr_t             err;
    uint64_t           allocated, used;

    mp = ikvdb_mpool_get(handle);
    err = mpool_stats_get(mp, &stats);
    if (ev(err))
        return err;

    info->total_bytes = stats.mps_total;
    info->available_bytes = stats.mps_available;

    info->allocated_bytes = stats.mps_allocated;
    info->used_bytes = stats.mps_used;

    /* Get allocated and used space for kvdb metadata. Allocated and used are
     * the same.
     */
    err = kvdb_meta_usage(self->ikdb_home, &used);
    if (ev(err))
        return err;
    info->allocated_bytes += used;
    info->used_bytes += used;

    err = cndb_usage(self->ikdb_cndb, &allocated, &used);
    if (ev(err))
        return err;
    info->allocated_bytes += allocated;
    info->used_bytes += used;

    return 0;
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

    return handle ? self->ikdb_mp : NULL;
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
    if (!self->ikdb_read_only) {
        self->ikdb_work_stop = true;
        destroy_workqueue(self->ikdb_workqueue);
    }

    /* Deregistering this url before trying to get ikdb_lock prevents
     * a deadlock between this call and an ongoing call to ikvdb_kvs_names_get()
     */
    kvdb_rest_deregister();

    mutex_lock(&self->ikdb_lock);

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        struct kvdb_kvs *kvs = self->ikdb_kvs_vec[i];

        if (!kvs)
            continue;

        if (kvs->kk_ikvs)
            atomic_dec(&kvs->kk_refcnt);

        kvs_rest_deregister(kvs->kk_name);

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

    /* Destroy LC only after c0sk has been destroyed. This ensures that the garbage collector is
     * not running.
     */
    lc_destroy(self->ikdb_lc);
    self->ikdb_lc = NULL;

    cn_kvdb_destroy(self->ikdb_cn_kvdb);

    err = cndb_close(self->ikdb_cndb);
    if (ev(err))
        ret = ret ?: err;

    mutex_unlock(&self->ikdb_lock);

    ikvdb_txn_fini(self);

    kvdb_ctxn_set_destroy(self->ikdb_ctxn_set);

    c0snr_set_destroy(self->ikdb_c0snr_set);

    kvdb_pfxlock_destroy(self->ikdb_pfxlock);
    kvdb_keylock_destroy(self->ikdb_keylock);

    viewset_destroy(self->ikdb_cur_viewset);
    viewset_destroy(self->ikdb_txn_viewset);

    wal_close(self->ikdb_wal);

    csched_destroy(self->ikdb_csched);

    mutex_destroy(&self->ikdb_lock);

    throttle_fini(&self->ikdb_throttle);

    mpool_close(self->ikdb_mp);

    ikvdb_perfc_free(self);

    free(self);

    return ret;
}

static void
ikvdb_throttle(struct ikvdb_impl *self, u64 bytes, u64 tstart)
{
    u64 sleep_ns, now;

    sleep_ns = tbkt_request(&self->ikdb_tb, bytes, &now);
    if (sleep_ns > 0) {
        u64 dly = now - tstart;

        if (sleep_ns > dly) {
            if (sleep_ns - dly > timer_slack / 2) {
                tbkt_delay(sleep_ns - dly);
            } else {
                pthread_yield();
            }
        }

        if (HSE_UNLIKELY(self->ikdb_tb_dbg)) {
            atomic64_inc(&self->ikdb_tb_dbg_ops);
            atomic64_add(bytes, &self->ikdb_tb_dbg_bytes);
            atomic64_add(sleep_ns, &self->ikdb_tb_dbg_sleep_ns);
        }
    }
}

static inline bool
is_write_allowed(struct ikvs *kvs, struct hse_kvdb_txn *const txn)
{
    const bool kvs_is_txn = kvs_txn_is_enabled(kvs);
    const bool op_is_txn = txn;

    return kvs_is_txn ^ op_is_txn ? false : true;
}

static inline bool
is_read_allowed(struct ikvs *kvs, struct hse_kvdb_txn *const txn)
{
    return txn && !kvs_txn_is_enabled(kvs) ? false : true;
}

merr_t
ikvdb_kvs_put(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt,
    struct kvs_vtuple *        vt)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent;
    struct kvs_ktuple  ktbuf;
    struct kvs_vtuple  vtbuf;
    uint64_t           seqnoref;
    merr_t             err;
    uint               vlen, clen;
    size_t             vbufsz;
    void *             vbuf;
    uint64_t           tstart;

    INVARIANT(handle && kt && vt);

    if (HSE_UNLIKELY(!is_write_allowed(kk->kk_ikvs, txn)))
        return merr(EINVAL);

    parent = kk->kk_parent;
    if (HSE_UNLIKELY(parent->ikdb_read_only))
        return merr(EROFS);

    /* puts do not stop on block deletion failures. */
    err = kvdb_health_check(
        &parent->ikdb_health, KVDB_HEALTH_FLAG_ALL & ~KVDB_HEALTH_FLAG_DELBLKFAIL);
    if (err)
        return err;

    tstart = (flags & HSE_KVS_PUT_PRIO || parent->ikdb_rp.throttle_disable) ? 0 : get_time_ns();

    ktbuf = *kt;
    vtbuf = *vt;

    kt = &ktbuf;
    vt = &vtbuf;

    vlen = kvs_vtuple_vlen(vt);
    clen = kvs_vtuple_clen(vt);

    vbufsz = tls_vbufsz;
    vbuf = NULL;

    if (clen == 0 && vlen > kk->kk_vcompmin && !(flags & HSE_KVS_PUT_VCOMP_OFF)) {
        if (vlen > kk->kk_vcompbnd) {
            vbufsz = vlen + PAGE_SIZE * 2;
            vbuf = vlb_alloc(vbufsz);
        } else {
            vbuf = tls_vbuf;
        }

        if (vbuf) {
            err = kk->kk_vcompress(vt->vt_data, vlen, vbuf, vbufsz, &clen);

            if (!err && clen < vlen) {
                kvs_vtuple_cinit(vt, vbuf, vlen, clen);
                vlen = clen;
            }
        }
    }

    seqnoref = txn ? 0 : HSE_SQNREF_SINGLE;

    err = kvs_put(kk->kk_ikvs, txn, kt, vt, seqnoref);

    if (vbuf && vbuf != tls_vbuf)
        vlb_free(vbuf, (vbufsz > VLB_ALLOCSZ_MAX) ? vbufsz : clen);

    if (tstart > 0)
        ikvdb_throttle(parent, kt->kt_len + (clen ? clen : vlen), tstart);

    return err;
}

merr_t
ikvdb_kvs_pfx_probe(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt,
    enum key_lookup_res *      res,
    struct kvs_buf *           kbuf,
    struct kvs_buf *           vbuf)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *p;
    u64                view_seqno;

    if (ev(!handle))
        return merr(EINVAL);

    if (ev(!is_read_allowed(kk->kk_ikvs, txn)))
        return merr(EINVAL);

    p = kk->kk_parent;

    if (txn) {
        /*
         * No need to wait for ongoing commits. A transaction waited when its view was
         * being established i.e. at the time of transaction begin.
         */
        view_seqno = 0;
    } else {
        /* Establish our view before waiting on ongoing commits. */
        view_seqno = atomic64_read(&p->ikdb_seqno);
        kvdb_ctxn_set_wait_commits(p->ikdb_ctxn_set, 0);
    }

    return kvs_pfx_probe(kk->kk_ikvs, txn, kt, view_seqno, res, kbuf, vbuf);
}

merr_t
ikvdb_kvs_get(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt,
    enum key_lookup_res *      res,
    struct kvs_buf *           vbuf)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *p;
    u64                view_seqno;

    if (ev(!handle))
        return merr(EINVAL);

    if (ev(!is_read_allowed(kk->kk_ikvs, txn)))
        return merr(EINVAL);

    p = kk->kk_parent;

    if (txn) {
        /*
         * No need to wait for ongoing commits. A transaction waited when its view was
         * being established i.e. at the time of transaction begin.
         */
        view_seqno = 0;
    } else {
        /* Establish our view before waiting on ongoing commits. */
        view_seqno = atomic64_read(&p->ikdb_seqno);
        kvdb_ctxn_set_wait_commits(p->ikdb_ctxn_set, 0);
    }

    return kvs_get(kk->kk_ikvs, txn, kt, view_seqno, res, vbuf);
}

merr_t
ikvdb_kvs_del(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent;
    u64                seqnoref;
    merr_t             err;

    if (ev(!handle))
        return merr(EINVAL);

    if (ev(!is_write_allowed(kk->kk_ikvs, txn)))
        return merr(EINVAL);

    parent = kk->kk_parent;
    if (ev(parent->ikdb_read_only))
        return merr(EROFS);

    /* tombstone puts do not stop on block deletion failures. */
    err = kvdb_health_check(
        &parent->ikdb_health, KVDB_HEALTH_FLAG_ALL & ~KVDB_HEALTH_FLAG_DELBLKFAIL);
    if (ev(err))
        return err;

    seqnoref = txn ? 0 : HSE_SQNREF_SINGLE;

    return kvs_del(kk->kk_ikvs, txn, kt, seqnoref);
}

merr_t
ikvdb_kvs_prefix_delete(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    struct kvs_ktuple *        kt)
{
    struct kvdb_kvs *  kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *parent;
    u32                ct_pfx_len;
    u64                seqnoref;

    if (ev(!handle))
        return merr(EINVAL);

    if (ev(!is_write_allowed(kk->kk_ikvs, txn)))
        return merr(EINVAL);

    parent = kk->kk_parent;
    if (ev(parent->ikdb_read_only))
        return merr(EROFS);

    ct_pfx_len = kk->kk_cparams->pfx_len;

    if (ev(!kt->kt_data || kt->kt_len != ct_pfx_len))
        return merr(EINVAL);
    if (ev(kt->kt_len == 0))
        return merr(ENOENT);

    seqnoref = txn ? 0 : HSE_SQNREF_SINGLE;

    /* Prefix tombstone deletes all current keys with a matching prefix -
     * those with a sequence number up to but excluding the current seqno.
     * Insert prefix tombstone with a higher seqno. Use a higher sequence
     * number to allow newer mutations (after prefix) to be distinguished.
     */
    return kvs_prefix_del(kk->kk_ikvs, txn, kt, seqnoref);
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
cursor_view_acquire(struct hse_kvs_cursor *cur, u64 *tseqnop)
{
    merr_t err;

    /* Add to cursor list only if this is NOT part of a txn.
     */
    if (cur->kc_seq != HSE_SQNREF_UNDEFINED)
        return 0;

    err = viewset_insert(cur->kc_kvs->kk_viewset, &cur->kc_seq, tseqnop, &cur->kc_viewcookie);
    if (!err)
        cur->kc_on_list = true;

    return err;
}

static merr_t
cursor_unbind_txn(struct hse_kvs_cursor *cur)
{
    struct kvdb_ctxn_bind *bind = cur->kc_bind;

    if (bind) {
        cur->kc_gen = -1;
        cur->kc_bind = 0;
        kvdb_ctxn_cursor_unbind(bind);
    }

    return 0;
}

merr_t
ikvdb_kvs_cursor_create(
    struct hse_kvs *           handle,
    const unsigned int         flags,
    struct hse_kvdb_txn *const txn,
    const void *               prefix,
    size_t                     pfx_len,
    struct hse_kvs_cursor **   cursorp)
{
    struct kvdb_kvs *      kk = (struct kvdb_kvs *)handle;
    struct ikvdb_impl *    ikvdb = kk->kk_parent;
    struct kvdb_ctxn *     ctxn = 0;
    struct hse_kvs_cursor *cur = 0;
    merr_t                 err;
    u64                    ts, vseq, tstart, tseqno;
    struct perfc_set *     pkvsl_pc;

    *cursorp = NULL;

    if (ev(!is_read_allowed(kk->kk_ikvs, txn)))
        return merr(EINVAL);

    if (ev(atomic_read(&ikvdb->ikdb_curcnt) > ikvdb->ikdb_curcnt_max))
        return merr(ECANCELED);

    pkvsl_pc = kvs_perfc_pkvsl(kk->kk_ikvs);
    tstart = perfc_lat_start(pkvsl_pc);

    vseq = HSE_SQNREF_UNDEFINED;

    if (txn) {
        ctxn = kvdb_ctxn_h2h(txn);
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
    cur = kvs_cursor_alloc(kk->kk_ikvs, prefix, pfx_len, flags & HSE_CURSOR_CREATE_REV);
    if (ev(!cur))
        return merr(ENOMEM);

    cur->kc_pkvsl_pc = pkvsl_pc;

    /* if we have a transaction at all, use its view seqno... */
    cur->kc_seq = vseq;
    cur->kc_flags = flags;

    cur->kc_kvs = kk;
    cur->kc_gen = 0;
    cur->kc_ctxn = ctxn;
    cur->kc_bind = ctxn ? kvdb_ctxn_cursor_bind(ctxn) : NULL;

    /* Temporarily lock a view until this cursor gets refs on cn kvsets. */
    err = cursor_view_acquire(cur, &tseqno);
    if (ev(err))
        goto out;

    ts = perfc_lat_start(pkvsl_pc);
    err = kvs_cursor_init(cur, ctxn);
    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_INIT, ts);
    if (ev(err))
        goto out;

    cursor_view_release(cur); /* release the view that was locked */

    /* After acquiring a view, non-txn cursors must wait for ongoing commits
     * to finish to ensure they never see partial txns.  This is not necessary
     * for txn cursors because their view is inherited from the txn.
     */
    if (!txn)
        kvdb_ctxn_set_wait_commits(ikvdb->ikdb_ctxn_set, tseqno);

    err = kvs_cursor_prepare(cur);
    if (ev(err))
        goto out;

    perfc_inc(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_CURCNT);
    cur->kc_create_time = tstart;

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_CREATE, tstart);

    *cursorp = cur;

out:
    if (err)
        ikvdb_kvs_cursor_destroy(cur);

    return err;
}

merr_t
ikvdb_kvs_cursor_update_view(struct hse_kvs_cursor *cur, unsigned int flags)
{
    u64 tstart, tseqno;
    merr_t err;

    tstart = perfc_lat_start(cur->kc_pkvsl_pc);

    /* a cursor in error cannot be updated - must be destroyed */
    if (ev(cur->kc_err))
        return cur->kc_err;

    if (ev(cur->kc_ctxn))
        return merr(EINVAL);

    cur->kc_seq = HSE_SQNREF_UNDEFINED;

    /* Temporarily reserve seqno until this cursor gets refs on
     * cn kvsets.
     */
    err = cursor_view_acquire(cur, &tseqno);
    if (ev(err))
        return err;

    cur->kc_err = kvs_cursor_update(cur, NULL, cur->kc_seq);
    if (ev(cur->kc_err))
        goto out;

    cursor_view_release(cur);

    /* After acquiring a view, non-txn cursors must wait for ongoing commits
     * to finish to ensure they never see partial txns.
     */
    kvdb_ctxn_set_wait_commits(cur->kc_kvs->kk_parent->ikdb_ctxn_set, tseqno);

    cur->kc_flags = flags;

    perfc_lat_record(cur->kc_pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_UPDATE, tstart);

out:
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
        err = kvs_cursor_update(cur, cur->kc_bind ? cur->kc_bind->b_ctxn : 0, cur->kc_seq);

    return ev(err);
}

merr_t
ikvdb_kvs_cursor_seek(
    struct hse_kvs_cursor *cur,
    const unsigned int     flags,
    const void *           key,
    size_t                 len,
    const void *           limit,
    size_t                 limit_len,
    struct kvs_ktuple *    kt)
{
    merr_t err;
    u64    tstart;

    tstart = perfc_lat_start(cur->kc_pkvsl_pc);

    if (ev(limit && (cur->kc_flags & HSE_CURSOR_CREATE_REV)))
        return merr(EINVAL);

    if (ev(cur->kc_err)) {
        if (ev(merr_errno(cur->kc_err) != EAGAIN))
            return cur->kc_err;

        cur->kc_err = kvs_cursor_update(cur, cur->kc_bind ? cur->kc_bind->b_ctxn : 0, cur->kc_seq);
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
    struct hse_kvs_cursor *cur,
    const unsigned int     flags,
    const void **          key,
    size_t *               key_len,
    const void **          val,
    size_t *               val_len,
    bool *                 eof)
{
    struct kvs_kvtuple kvt;
    merr_t             err;
    u64                tstart;

    tstart = perfc_lat_start(cur->kc_pkvsl_pc);

    if (ev(cur->kc_err)) {
        if (ev(merr_errno(cur->kc_err) != EAGAIN))
            return cur->kc_err;

        cur->kc_err = kvs_cursor_update(cur, cur->kc_bind ? cur->kc_bind->b_ctxn : 0, cur->kc_seq);
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
        cur->kc_flags & HSE_CURSOR_CREATE_REV ? PERFC_LT_PKVSL_KVS_CURSOR_READREV
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

    kvs_cursor_free(cur);

    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_DESTROY, tstart);
    perfc_lat_record(pkvsl_pc, PERFC_LT_PKVSL_KVS_CURSOR_FULL, ctime);

    return 0;
}

void
ikvdb_compact(struct ikvdb *handle, int flags)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_read_only))
        return;

    csched_compact_request(self->ikdb_csched, flags);
}

void
ikvdb_compact_status_get(struct ikvdb *handle, struct hse_kvdb_compact_status *status)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_read_only))
        return;

    csched_compact_status_get(self->ikdb_csched, status);
}

merr_t
ikvdb_sync(struct ikvdb *handle, const unsigned int flags)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    if (ev(self->ikdb_read_only))
        return merr(EROFS);

    if (self->ikdb_wal)
        return wal_sync(self->ikdb_wal);

    return c0sk_sync(self->ikdb_c0sk, flags);
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

    if (HSE_UNLIKELY(perfc_ison(&kvdb_metrics_pc, PERFC_BA_KVDBMETRICS_SEQNO))) {
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

u64
ikvdb_txn_horizon(struct ikvdb *handle)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);

    return viewset_horizon(self->ikdb_txn_viewset);
}

static HSE_ALWAYS_INLINE struct kvdb_ctxn_bkt *
ikvdb_txn_tid2bkt(struct ikvdb_impl *self)
{
    if (!tls_txn_idx)
        tls_txn_idx = atomic_inc_return(&ikvdb_txn_idx);

    return self->ikdb_ctxn_cache + (tls_txn_idx % NELEM(self->ikdb_ctxn_cache));
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

    if (ctxn) {
        kvdb_ctxn_reset(ctxn);
        return &ctxn->ctxn_handle;
    }

    ctxn = kvdb_ctxn_alloc(
        self->ikdb_keylock,
        self->ikdb_pfxlock,
        &self->ikdb_seqno,
        self->ikdb_ctxn_set,
        self->ikdb_txn_viewset,
        self->ikdb_c0snr_set,
        self->ikdb_c0sk,
        self->ikdb_wal);
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
    struct kvdb_ctxn * ctxn = kvdb_ctxn_h2h(txn);
    merr_t             err;

    perfc_inc(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);
    perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_BEGIN);

    err = kvdb_ctxn_begin(ctxn);
    if (err)
        perfc_dec(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);

    return err;
}

merr_t
ikvdb_txn_commit(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    struct kvdb_ctxn * ctxn = kvdb_ctxn_h2h(txn);
    merr_t             err;
    u64                lstart;

    lstart = perfc_lat_startu(&self->ikdb_ctxn_op, PERFC_LT_CTXNOP_COMMIT);
    perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_COMMIT);

    err = kvdb_ctxn_commit(ctxn);

    perfc_dec(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);
    perfc_lat_record(&self->ikdb_ctxn_op, PERFC_LT_CTXNOP_COMMIT, lstart);

    return err;
}

merr_t
ikvdb_txn_abort(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    struct ikvdb_impl *self = ikvdb_h2r(handle);
    struct kvdb_ctxn * ctxn = kvdb_ctxn_h2h(txn);

    perfc_inc(&self->ikdb_ctxn_op, PERFC_RA_CTXNOP_ABORT);

    kvdb_ctxn_abort(ctxn);

    perfc_dec(&self->ikdb_ctxn_op, PERFC_BA_CTXNOP_ACTIVE);

    return 0;
}

enum kvdb_ctxn_state
ikvdb_txn_state(struct ikvdb *handle, struct hse_kvdb_txn *txn)
{
    return kvdb_ctxn_get_state(kvdb_ctxn_h2h(txn));
}

/* ------------------  WAL replay ikvdb interfaces ---------------- */

struct ikvdb_kvs_hdl {
    struct kvdb_kvs *kk_prev;
    uint64_t cnid_prev;
    size_t   cache_sz;
    size_t   cheap_sz;
    bool     needs_reset;
    uint32_t kvshc;
    struct hse_kvs *kvshv[];
};

merr_t
ikvdb_wal_replay_open(struct ikvdb *ikvdb, struct ikvdb_kvs_hdl **ikvsh_out)
{
    struct ikvdb_kvs_hdl  *ikvsh;
    struct hse_kvs       **kvshv;
    struct kvs_rparams params = kvs_rparams_defaults();
    merr_t  err;
    int     i;
    size_t  sz;
    size_t  kvshc;
    char  **knamev = NULL;

    err = ikvdb_kvs_names_get(ikvdb, &kvshc, &knamev);
    if (err)
        return err;

    sz = sizeof(*ikvsh) + kvshc * sizeof(kvshv[0]);
    ikvsh = calloc(1, sz);
    if (!ikvsh) {
        ikvdb_kvs_names_free(ikvdb, knamev);
        return merr(ENOMEM);
    }

    kvshv = ikvsh->kvshv;
    for (i = 0; i < kvshc; i++) {
        err = ikvdb_kvs_open(ikvdb, knamev[i], &params, IKVS_OFLAG_REPLAY, &kvshv[i]);
        if (err) {
            hse_elog(HSE_WARNING "ikvdb_kvs_open %s: @@e", err, knamev[i]);
            break;
        }
    }

    ikvdb_kvs_names_free(ikvdb, knamev);

    if (err) {
        while (i-- > 0)
            ikvdb_kvs_close(kvshv[i]);
        free(ikvsh);
        return err;
    }

    ikvsh->kvshc = kvshc;

    assert(ikvsh_out);
    *ikvsh_out = ikvsh;

    return 0;
}

void
ikvdb_wal_replay_close(struct ikvdb *ikvdb, struct ikvdb_kvs_hdl *ikvsh)
{
    int i;

    assert(ikvsh);

    for (i = 0; i < ikvsh->kvshc; i++)
        ikvdb_kvs_close(ikvsh->kvshv[i]);

    free(ikvsh);
}

static struct kvdb_kvs *
ikvdb_wal_replay_kvs_get(struct ikvdb_kvs_hdl *ikvsh, u64 cnid)
{
    int i;

    if (ikvsh->cnid_prev == cnid)
        return ikvsh->kk_prev;

    for (i = 0; i < ikvsh->kvshc; i++) {
        struct kvdb_kvs *kk = (struct kvdb_kvs *)ikvsh->kvshv[i];
        if (kk->kk_cnid == cnid) {
            ikvsh->cnid_prev = cnid;
            ikvsh->kk_prev = kk;
            return kk;
        }
    }

    return NULL;
}

merr_t
ikvdb_wal_replay_put(
    struct ikvdb         *ikvdb,
    struct ikvdb_kvs_hdl *ikvsh,
    u64                   cnid,
    u64                   seqno,
    struct kvs_ktuple    *kt,
    struct kvs_vtuple    *vt)
{
    struct kvdb_kvs *kk;
    merr_t err;

    assert(ikvdb && ikvsh);

    kk = ikvdb_wal_replay_kvs_get(ikvsh, cnid);
    if (ev(!kk))
        return 0; /* Possible that the kvs is dropped just prior to crash */

    err = kvs_put(kk->kk_ikvs, NULL, kt, vt, HSE_ORDNL_TO_SQNREF(seqno));
    if (!err) /* Update ikdb_seqno if it's lower than "seqno", called from the replay thread */
        ikvdb_wal_replay_seqno_set(ikvdb, seqno);

    return err;
}

merr_t
ikvdb_wal_replay_del(
    struct ikvdb         *ikvdb,
    struct ikvdb_kvs_hdl *ikvsh,
    u64                   cnid,
    u64                   seqno,
    struct kvs_ktuple    *kt)
{
    struct kvdb_kvs *kk;
    merr_t err;

    assert(ikvdb && ikvsh);

    kk = ikvdb_wal_replay_kvs_get(ikvsh, cnid);
    if (ev(!kk))
        return 0; /* Possible that the kvs is dropped just prior to crash */

    err = kvs_del(kk->kk_ikvs, NULL, kt, HSE_ORDNL_TO_SQNREF(seqno));
    if (!err)
        ikvdb_wal_replay_seqno_set(ikvdb, seqno);

    return err;
}

merr_t
ikvdb_wal_replay_prefix_del(
    struct ikvdb         *ikvdb,
    struct ikvdb_kvs_hdl *ikvsh,
    u64                   cnid,
    u64                   seqno,
    struct kvs_ktuple    *kt)
{
    struct kvdb_kvs *kk;
    merr_t err;

    assert(ikvdb && ikvsh);

    kk = ikvdb_wal_replay_kvs_get(ikvsh, cnid);
    if (ev(!kk))
        return 0; /* Possible that the kvs is dropped just prior to crash */

    err = kvs_prefix_del(kk->kk_ikvs, NULL, kt, HSE_ORDNL_TO_SQNREF(seqno));
    if (!err)
        ikvdb_wal_replay_seqno_set(ikvdb, seqno);

    return err;
}

void
ikvdb_wal_replay_seqno_set(struct ikvdb *ikvdb, uint64_t seqno)
{
    struct ikvdb_impl *self;

    assert(ikvdb);

    self = ikvdb_h2r(ikvdb);

    /* This is called only in a single-threaded replay context */
    if (seqno > atomic64_read(&self->ikdb_seqno))
        atomic64_set(&self->ikdb_seqno, seqno);
}

void
ikvdb_wal_replay_gen_set(struct ikvdb *ikvdb, u64 gen)
{
    struct ikvdb_impl *self;

    assert(ikvdb);

    self = ikvdb_h2r(ikvdb);

    c0sk_gen_set(self->ikdb_c0sk, gen);
}

void
ikvdb_wal_replay_enable(struct ikvdb *ikvdb)
{
    struct ikvdb_impl *self;

    assert(ikvdb);

    self = ikvdb_h2r(ikvdb);

    c0sk_replaying_enable(self->ikdb_c0sk);
}

void
ikvdb_wal_replay_disable(struct ikvdb *ikvdb)
{
    struct ikvdb_impl *self;

    assert(ikvdb);

    self = ikvdb_h2r(ikvdb);

    c0sk_replaying_disable(self->ikdb_c0sk);
}

bool
ikvdb_wal_replay_size_set(struct ikvdb *ikvdb, struct ikvdb_kvs_hdl *ikvsh, uint64_t mem_sz)
{
    struct ikvdb_impl *self;
    size_t             cheap_sz;
    uint32_t           width;

    assert(ikvdb && ikvsh);

    if (mem_sz == 0)
        return false;

    self = ikvdb_h2r(ikvdb);

    /* Save a copy of the globals to restore post replay */
    ikvsh->cache_sz = ikvsh->cache_sz ? : c0kvs_cache_sz_get();
    ikvsh->cheap_sz = ikvsh->cheap_sz ? : c0kvs_cheap_sz_get();

    width = c0sk_ingest_width_get(self->ikdb_c0sk);
    assert(width);

    cheap_sz = ((mem_sz * 14) / 10) / (width - 1);
    if (cheap_sz <= ikvsh->cheap_sz)
        return false;

    cheap_sz = roundup_pow_of_two(cheap_sz);
    cheap_sz = max_t(size_t, cheap_sz, HSE_C0_CHEAP_SZ_MAX);

    hse_log(HSE_NOTICE "WAL replay: Setting c0kvms cheap size from %lu to %lu",
            ikvsh->cheap_sz, cheap_sz);
    c0kvs_reinit_force(0, cheap_sz);

    ikvsh->needs_reset = true;

    return true;
}

void
ikvdb_wal_replay_size_reset(struct ikvdb_kvs_hdl *ikvsh)
{
    assert(ikvsh);

    if (ikvsh->needs_reset) {
        hse_log(HSE_NOTICE "WAL replay: Resetting c0kvms cheap size back to %lu", ikvsh->cheap_sz);
        c0kvs_reinit_force(ikvsh->cache_sz, ikvsh->cheap_sz);
    }

    ikvsh->needs_reset = false;
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

    err = c0_init(hse_gparams.gp_c0kvs_ccache_sz, hse_gparams.gp_c0kvs_cheap_sz);
    if (err)
        goto errout1;

    err = kvdb_ctxn_pfxlock_init();
    if (err)
        goto errout2;

    err = lc_init();
    if (err)
        goto errout3;

    err = cn_init();
    if (err)
        goto errout4;

    err = bkv_collection_init();
    if (err)
        goto errout5;

    return 0;

errout5:
    cn_fini();

errout4:
    lc_fini();

errout3:
    kvdb_ctxn_pfxlock_fini();

errout2:
    c0_fini();

errout1:
    kvs_fini();
    kvdb_perfc_finish();

    return err;
}

/* Called once by unload() at program termination or module unload time.
 */
void
ikvdb_fini(void)
{
    bkv_collection_fini();
    cn_fini();
    lc_fini();
    kvdb_ctxn_pfxlock_fini();
    c0_fini();
    kvs_fini();
    kvdb_perfc_finish();
}

#if HSE_MOCKING
#include "ikvdb_ut_impl.i"
#include "kvs_ut_impl.i"
#endif /* HSE_MOCKING */
