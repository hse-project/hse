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

merr_t
wal_create(struct mpool *mp, uint64_t *mdcid1, uint64_t *mdcid2);

merr_t
wal_destroy(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2);

merr_t
wal_open(struct mpool *mp, bool rdonly, uint64_t mdcid1, uint64_t mdcid2, struct wal **wal_out);

merr_t
wal_close(struct wal *wal);

merr_t
wal_put(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    u64 seqno);

#endif /* HSE_WAL_H */
