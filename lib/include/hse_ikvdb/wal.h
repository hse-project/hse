/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */
#ifndef HSE_WAL_H
#define HSE_WAL_H

#include <hse/hse.h>
#include <mpool/mpool.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/tuple.h>

#define HSE_WAL_DUR_MS_DFLT    (100)
#define HSE_WAL_DUR_MS_MIN     (25)
#define HSE_WAL_DUR_MS_MAX     (1000)

#define HSE_WAL_DUR_BYTES_DFLT (35 << 20)
#define HSE_WAL_DUR_BYTES_MIN  (8 << 20)
#define HSE_WAL_DUR_BYTES_MAX  (64 << 20)

struct wal;
struct kvdb_log;
struct kvdb_log_tx;

/* MTF_MOCK_DECL(wal) */

struct wal_record {
    void   *recbuf;
    u64     offset;
    uint    wbidx;
    size_t  len;
};

struct wal_replay_info {
    u64  mdcid1;
    u64  mdcid2;
    u64  gen;
    u64  seqno;
    u64  txhorizon;
    bool clean;
};

/* MTF_MOCK */
merr_t
wal_create(struct mpool *mp, struct kvdb_cparams *cp, uint64_t *mdcid1, uint64_t *mdcid2);

/* MTF_MOCK */
void
wal_destroy(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2);

/* MTF_MOCK */
merr_t
wal_open(
    struct mpool           *mp,
    struct kvdb_rparams    *rp,
    struct wal_replay_info *rinfo,
    struct ikvdb           *ikdb,
    struct kvdb_health     *health,
    struct wal            **wal_out);

/* MTF_MOCK */
void
wal_close(struct wal *wal);

/* MTF_MOCK */
merr_t
wal_put(
    struct wal *wal,
    struct ikvs *kvs,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    uint64_t txid,
    struct wal_record *recout);

/* MTF_MOCK */
merr_t
wal_del(
    struct wal *wal,
    struct ikvs *kvs,
    struct kvs_ktuple *kt,
    uint64_t txid,
    struct wal_record *recout);

/* MTF_MOCK */
merr_t
wal_del_pfx(
    struct wal *wal,
    struct ikvs *kvs,
    struct kvs_ktuple *kt,
    uint64_t txid,
    struct wal_record *recout);

/* MTF_MOCK */
merr_t
wal_txn_begin(struct wal *wal, uint64_t txid);

/* MTF_MOCK */
merr_t
wal_txn_abort(struct wal *wal, uint64_t txid);

/* MTF_MOCK */
merr_t
wal_txn_commit(struct wal *wal, uint64_t txid, uint64_t seqno);

void
wal_op_finish(struct wal *wal, struct wal_record *rec, uint64_t seqno, uint64_t gen, int rc);

void
wal_cningest_cb(struct wal *wal, u64 seqno, u64 gen, u64 txhorizon, bool post_ingest);

merr_t
wal_sync(struct wal *wal);

void
wal_throttle_sensor(struct wal *wal, struct throttle_sensor *sensor);

#if HSE_MOCKING
#include "wal_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_WAL_H */
