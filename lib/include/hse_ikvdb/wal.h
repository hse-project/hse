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

struct wal;
struct kvdb_log;
struct kvdb_log_tx;

/* MTF_MOCK_DECL(wal) */

struct wal_record {
    void   *recbuf;
    size_t  len;
    u64     offset;
};

/* MTF_MOCK */
merr_t
wal_create(struct mpool *mp, uint64_t *mdcid1, uint64_t *mdcid2);

/* MTF_MOCK */
merr_t
wal_destroy(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2);

/* MTF_MOCK */
merr_t
wal_open(struct mpool *mp, bool rdonly, uint64_t mdcid1, uint64_t mdcid2, struct wal **wal_out);

/* MTF_MOCK */
merr_t
wal_close(struct wal *wal);

/* MTF_MOCK */
merr_t
wal_put(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    struct wal_record *recout);

/* MTF_MOCK */
merr_t
wal_del(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct wal_record *recout);

/* MTF_MOCK */
merr_t
wal_del_pfx(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
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
wal_op_finish(struct wal *wal, struct wal_record *rec, uint64_t seqno, uint64_t gen);

void
wal_cningest_cb(struct wal *wal, u64 seqno, u64 gen);

#if HSE_MOCKING
#include "wal_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_WAL_H */
