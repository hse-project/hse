/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_KVDB_LOG_H
#define HSE_KVDB_KVDB_LOG_H

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include <hse/hse.h>

#include <hse_ikvdb/../../kvdb/kvdb_omf.h>

/* MTF_MOCK_DECL(kvdb_log) */

#define KVDB_LOG_TABLE_DEFAULT   8192
#define KVDB_LOG_HIGH_WATER(log) (log->kl_captgt * 3 / 4)

struct kvdb_kvs;
struct mpool;
struct mpool_mdc;

struct kvdb_log {
    struct mpool_mdc *kl_mdc; /* our MDC */
    struct mpool *    kl_ds;  /* dataset operating upon */
    struct table *    kl_work;
    struct table *    kl_work_old;
    u64               kl_captgt;
    u64               kl_highwater;
    u64               kl_serial;
    u64               kl_cndb_oid1;
    u64               kl_cndb_oid2;
    u64               kl_c1_oid1;
    u64               kl_c1_oid2;
    bool              kl_rdonly;

    /* buffering MDC I/O -- NB: cannot mix reads and writes */
    unsigned char kl_buf[KVDB_OMF_REC_MAX];
};

struct kvdb_mdh {
    u32 mdh_type;
    u32 mdh_serial; /* order in which records appeared in log */
};

struct kvdb_mdv {
    struct kvdb_mdh mdv_hdr;
    u32             mdv_magic;
    u32             mdv_version;
    u64             mdv_captgt;
};

struct kvdb_mdc {
    struct kvdb_mdh mdc_hdr;
    u32             mdc_disp;
    u32             mdc_id;
    u64             mdc_new_oid1;
    u64             mdc_new_oid2;
    u64             mdc_old_oid1;
    u64             mdc_old_oid2;
};

union kvdb_mdu {
    struct kvdb_mdh h;
    struct kvdb_mdv v;
    struct kvdb_mdc c;
};

struct kvdb_log_tx;

/* MTF_MOCK */
merr_t
kvdb_log_replay(
    struct kvdb_log *log,
    u64 *            cndblog_oid1,
    u64 *            cndblog_oid2,
    u64 *            c1_oid1,
    u64 *            c1_oid2);

/* MTF_MOCK */
merr_t
kvdb_log_open(struct mpool *ds, struct kvdb_log **handle, int mode);

/* MTF_MOCK */
merr_t
kvdb_log_close(struct kvdb_log *log);

/*----------------------------------------------------------------
 * Quasi-external kvdb_log API - probably not best to call directly
 *
 * These methods define actions that could be called independently,
 * but the above open/replay/save/close should be complete.
 */

/* MTF_MOCK */
merr_t
kvdb_log_make(struct kvdb_log *log, u64 captgt);

/* MTF_MOCK */
merr_t
kvdb_log_rollover(struct kvdb_log *log);

/* MTF_MOCK */
merr_t
kvdb_log_compact(struct kvdb_log *log);

/* MTF_MOCK */
merr_t
kvdb_log_mdc_create(
    struct kvdb_log *    log,
    enum kvdb_log_mdc_id mdcid,
    u64                  oid1,
    u64                  oid2,
    struct kvdb_log_tx **tx);

/* MTF_MOCK */
merr_t
kvdb_log_abort(struct kvdb_log *log, struct kvdb_log_tx *tx);

/* MTF_MOCK */
merr_t
kvdb_log_done(struct kvdb_log *log, struct kvdb_log_tx *tx);

/* PRIVATE */
bool
kvdb_log_finished(union kvdb_mdu *mdp);

/* PRIVATE */
merr_t
kvdb_log_disp_set(union kvdb_mdu *mdp, enum kvdb_log_disp disp);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "kvdb_log_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
