/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CNDB_H
#define HSE_CNDB_H

#include <hse_util/platform.h>
#include <hse_util/inttypes.h>
#include <hse/error/merr.h>
#include <hse_util/atomic.h>

struct mpool;
struct kvset_meta;
struct kvdb_rparams;
struct kvs_cparams;
struct kvdb_health;

struct cndb;
struct cndb_txn;

#define CNDB_DEFAULT_SIZE (128 * 1024 * 1024)

#define CNDB_INVAL_INGESTID U64_MAX
#define CNDB_DFLT_INGESTID (U64_MAX - 1)

#define CNDB_INVAL_HORIZON  CNDB_INVAL_INGESTID

#define CNDB_INVAL_KVSETID 0

/* MTF_MOCK_DECL(cndb) */

/* MTF_MOCK */
merr_t
cndb_create(struct mpool *mp, size_t size, uint64_t *oid1_out, uint64_t *oid2_out);

/* MTF_MOCK */
merr_t
cndb_destroy(struct mpool *mp, uint64_t oid1, uint64_t oid2);

/* MTF_MOCK */
merr_t
cndb_open(struct mpool *mp, u64 oid1, u64 oid2, struct kvdb_rparams *rp, struct cndb **cndb_out);

/* MTF_MOCK */
merr_t
cndb_close(struct cndb *cndb);

/* MTF_MOCK */
merr_t
cndb_replay(struct cndb *cndb, u64 *seqno, u64 *ingestid, u64 *txhorizon);

/* MTF_MOCK */
merr_t
cndb_compact(struct cndb *cndb);

/* MTF_MOCK */
uint64_t
cndb_kvsetid_mint(struct cndb *cndb);

/* MTF_MOCK */
uint64_t
cndb_nodeid_mint(struct cndb *cndb);

/* MTF_MOCK */
merr_t
cndb_record_kvs_add(
    struct cndb              *cndb,
    const struct kvs_cparams *cp,
    uint64_t                 *cnid_out,
    const char               *name);

/* MTF_MOCK */
merr_t
cndb_record_kvs_del(struct cndb *cndb, uint64_t cnid);

/* MTF_MOCK */
merr_t
cndb_record_txstart(
    struct cndb      *cndb,
    uint64_t          seqno,
    uint64_t          ingestid,
    uint64_t          txhorizon,
    uint32_t          add_cnt,
    uint32_t          del_cnt,
    struct cndb_txn **tx_out);

/* MTF_MOCK */
merr_t
cndb_record_kvset_add(
    struct cndb       *cndb,
    struct cndb_txn   *tx,
    uint64_t           cnid,
    uint64_t           nodeid,
    struct kvset_meta *km,
    uint64_t           kvsetid,
    uint64_t           hblkid,
    unsigned int       kblkc,
    uint64_t          *kblkv,
    unsigned int       vblkc,
    uint64_t          *vblkv,
    void             **cookie);

/* MTF_MOCK */
merr_t
cndb_record_kvset_del(
    struct cndb     *cndb,
    struct cndb_txn *tx,
    uint64_t         cnid,
    uint64_t         kvsetid,
    void           **cookie);

/* MTF_MOCK */
merr_t
cndb_record_kvset_move(
    struct cndb    *cndb,
    uint64_t        cnid,
    uint64_t        src_nodeid,
    uint64_t        tgt_nodeid,
    uint32_t        kvset_idc,
    const uint64_t *kvset_idv);

/* MTF_MOCK */
merr_t
cndb_record_kvset_add_ack(struct cndb *cndb, struct cndb_txn *tx, void *cookie);

/* MTF_MOCK */
merr_t
cndb_record_kvset_del_ack(struct cndb *cndb, struct cndb_txn *tx, void *cookie);

/* MTF_MOCK */
merr_t
cndb_record_nak(struct cndb *cndb, struct cndb_txn *tx);

/* MTF_MOCK */
uint
cndb_kvs_count(struct cndb *cndb);

typedef merr_t
cndb_kvs_callback(uint64_t, struct kvs_cparams *, const char *, void *);

/* MTF_MOCK */
merr_t
cndb_kvs_info(
    struct cndb         *cndb,
    void                *cb_ctx,
    cndb_kvs_callback   *cb);

typedef merr_t
cn_init_callback(void *, struct kvset_meta *, u64);

/* MTF_MOCK */
merr_t
cndb_cn_instantiate(struct cndb *cndb, u64 cnid, void *ctx, cn_init_callback *cb);

merr_t
cndb_kvset_delete(struct cndb *cndb, uint64_t cnid, uint64_t kvsetid);

/* MTF_MOCK */
struct kvs_cparams *
cndb_kvs_cparams(struct cndb *cndb, u64 cnid);

struct mpool_mdc *
cndb_mdc_get(struct cndb *cndb);

#if HSE_MOCKING
#include "cndb_ut.h"
#endif /* HSE_MOCKING */

#endif
