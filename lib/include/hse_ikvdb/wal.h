/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */
#ifndef HSE_WAL_H
#define HSE_WAL_H

#include <mpool/mpool.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/tuple.h>

#define HSE_WAL_DUR_MS_MIN         (25)
#define HSE_WAL_DUR_MS_DFLT        (100)
#define HSE_WAL_DUR_MS_MAX         (1000)

/* Per wal buffer size */
#define HSE_WAL_DUR_BUFSZ_MB_MIN   (256ul)
#define HSE_WAL_DUR_BUFSZ_MB_DFLT  (4096ul)
#define HSE_WAL_DUR_BUFSZ_MB_MAX   (8192ul)

struct wal;
struct throttle_sensor;

/* MTF_MOCK_DECL(wal) */

struct wal_record {
    void    *recbuf;
    uint64_t offset;
    uint     wbidx;
    size_t   len;
    int64_t  cookie;
};

struct wal_replay_info {
    uint64_t  mdcid1;
    uint64_t  mdcid2;
    uint64_t  gen;
    uint64_t  seqno;
    uint64_t  txhorizon;
    bool      clean;
};

/* MTF_MOCK */
merr_t
wal_create(struct mpool *mp, uint64_t *mdcid1, uint64_t *mdcid2);

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
wal_txn_begin(struct wal *wal, uint64_t txid, int64_t *cookie);

/* MTF_MOCK */
merr_t
wal_txn_abort(struct wal *wal, uint64_t txid, int64_t cookie);

/* MTF_MOCK */
merr_t
wal_txn_commit(struct wal *wal, uint64_t txid, uint64_t seqno, uint64_t cid, int64_t cookie);

void
wal_op_finish(struct wal *wal, struct wal_record *rec, uint64_t seqno, uint64_t gen, int rc);

void
wal_cningest_cb(
    struct wal *wal,
    uint64_t    seqno,
    uint64_t    gen,
    uint64_t    txhorizon,
    bool        post_ingest);

void
wal_bufrel_cb(struct wal *wal, uint64_t gen);

merr_t
wal_sync(struct wal *wal);

void
wal_throttle_sensor(struct wal *wal, struct throttle_sensor *sensor);

#if HSE_MOCKING
#include "wal_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_WAL_H */
