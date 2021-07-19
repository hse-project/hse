/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CNDB_H
#define HSE_CNDB_H

#include <hse_util/platform.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>

#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cn.h>

struct mpool;
struct cndb;
struct cndb_tx_hdl;
struct kvset_meta;
struct kvdb_rparams;

/* Invalid ingest id. */
#define CNDB_INVAL_INGESTID U64_MAX
#define CNDB_INVAL_HORIZON  CNDB_INVAL_INGESTID

/* Default ingest id. */
#define CNDB_DFLT_INGESTID (U64_MAX - 1)

/* MTF_MOCK_DECL(cndb) */

/**
 * cndb_alloc() - allocate a new cndb
 * @ds:       dataset
 * @captgt:   (input/output)capacity target for the cndb
 * @oid1_out: new cndb MDC mlog id
 * @oid2_out: new cndb MDC mlog id
 *
 * If @captgt is not specified, CNDB_CAPTGT_DEFAULT is used.  If specified,
 * the argument is updated with the allocated capacity, which may be higher
 * than requested.
 */
/* MTF_MOCK */
merr_t
cndb_alloc(struct mpool *ds, u64 *captgt, u64 *oid1_out, u64 *oid2_out);

/**
 * cndb_create() - initialize a new cndb with no cn KVSes.
 * @ds:       dataset
 * @captgt:   capacity target for the cndb
 * @oid1:     new cndb MDC mlog id
 * @oid2:     new cndb MDC mlog id
 *
 */
/* MTF_MOCK */
merr_t
cndb_create(struct mpool *ds, u64 captgt, u64 oid1, u64 oid2);

/**
 * cndb_drop() - Delete a cndb and its constituent cn KVSes.
 * @ds:   dataset
 * @oid1: cndb MDC mlog id #1
 * @oid2: cndb MDC mlog id #2
 *
 * This is currently a NO-OP
 */
merr_t
cndb_drop(struct mpool *ds, u64 oid1, u64 oid2);

/**
 * cndb_open() - Open a cndb
 * @ds:   dataset
 * @rdonly: readonly flag
 * @cndb_entries: max number of entries in a CNDB's in memory representation.
 * @oid1: mlog id #1 of the cndb MDC
 * @oid2: mlog id #2 of the cndb MDC
 * @health: reference to the container kvdb's health struct
 * @cndb_out: cndb handle
 *
 * Implementation notes:
 *   - Cndb MDC processing will occur as part of cndb_open, rolling MDC
 *     transactions forward or backward as appropriate.
 *   - Diagnostic tools such as cn_metrics, and cn_kbdump will use
 *     cn secret sauce APIs to interact with cn trees w/o fully
 *     activating them.
 */
/* MTF_MOCK */
merr_t
cndb_open(
    struct mpool *      ds,
    bool                rdonly,
    atomic64_t *        ikvdb_seqno,
    size_t              cndb_entries,
    u64                 oid1,
    u64                 oid2,
    struct kvdb_health *health,
    struct kvdb_rparams *rp,
    struct cndb **      cndb_out);

/**
 * cndb_cn_close() - Release a reference on a specific cn
 * @cndb:         cndb handle
 * @cnid:         cnid to release
 */
/* MTF_MOCK */
merr_t
cndb_cn_close(struct cndb *cndb, u64 cnid);

/**
 * cndb_getref() - gain a reference to cndb
 * @cndb:         cndb handle
 */
/* MTF_MOCK */
void
cndb_getref(struct cndb *cndb);

/**
 * cndb_putref() - release a reference to cndb
 * @cndb:         cndb handle
 */
/* MTF_MOCK */
void
cndb_putref(struct cndb *cndb);

/**
 * cndb_replay() - read and compact cndb MDC in memory
 *
 * Only function that reads the cndb mdc.
 * Called in the context of a kvdb open.
 *
 * @cndb:       cndb handle
 * @seqno:      highest in-use seqno
 * @ingestid:   ingestid of the latest successful ingest
 *      If no successul ingest is found, CNDB_INVAL_INGESTID is returned.
 */
/* MTF_MOCK */
merr_t
cndb_replay(struct cndb *cndb, u64 *seqno, u64 *ingestid, u64 *txhorizon);

typedef merr_t
cn_init_callback(void *, struct kvset_meta *, u64);

/**
 * cndb_cn_instantiate() - create/instantiate a cn tree when a KVS is opened.
 *
 * Does not read the cndb mdc to get KVS information, instead get information
 * from memory (cndb->cndb_tagv).
 * Iterate through C/M records corresponding to kvsets
 *
 * @cndb:         cndb handle
 * @cnid:         target cnid
 * @ctx:          caller's context, passed to cb()
 * @cb:           callback routine to be invoked for each matching C/M tuple
 *                create kvsets in the new cn tree of the KVS
 */
/* MTF_MOCK */
merr_t
cndb_cn_instantiate(struct cndb *cndb, u64 cnid, void *ctx, cn_init_callback *cb);

/**
 * cndb_cn_count() - retrieve count of known cn's
 * @cndb:         cndb handle
 * @count:        count of cn's
 */
/* MTF_MOCK */
merr_t
cndb_cn_count(struct cndb *cndb, u32 *cnt);

/**
 * cndb_cn_blob_get() - retrieve cn metadata for given cnid
 * @cndb:  cndb handle
 * @cnid:  target cnid
 * @blobsz: (output) size of the metadata
 * @blob:  (output) a buffer containing the blob, CALLER FREES
 */
/* MTF_MOCK */
merr_t
cndb_cn_blob_get(struct cndb *cndb, u64 cnid, size_t *blobsz, void **blob);

/**
 * cndb_cn_blob_set() - update cn metadata for given cnid
 * @cndb:  cndb handle
 * @cnid:  target cnid
 * @blobsz: size of the metadata
 * @blob:  a buffer containing the blob
 *
 * Upon success, the metadata is persisted on media.
 * Upon failure, the caller must not proceed without retrying, but may exit.
 */
/* MTF_MOCK */
merr_t
cndb_cn_blob_set(struct cndb *cndb, u64 cnid, size_t blobsz, void *blob);

/**
 * cndb_cn_info() - retrieve parameters from a single cn by index
 * @cndb:         cndb handle
 * @idx:          target index
 * @cnid:         cnid
 * @flags:        cn flags
 * @fanout_bits:  fanout bits
 * @pfx_len:       prefix length
 * @name:         KVS name
 * @namelen:      size of buffer backing @name
 */
/* MTF_MOCK */
merr_t
cndb_cn_info_idx(
    struct cndb *        cndb,
    u32                  idx,
    u64 *                cnid,
    u32 *                flags,
    struct kvs_cparams **cp,
    char *               name,
    size_t               namelen);

/**
 * cndb_seqno() - retrieve cndb seqno
 * @cndb:         cndb handle
 */
/* MTF_MOCK */
u64
cndb_seqno(struct cndb *cndb);

/**
 * cndb_journal() - write-through cache a message to the MDC.
 * @cndb:         cndb handle
 * @data:         the message.
 * @sz:           the size of the message.
 *
 * This function is only exposed for mocking in unit tests.  Do not call it
 * directly.
 */
/* MTF_MOCK */
merr_t
cndb_journal(struct cndb *cndb, void *data, size_t sz);

/**
 * cndb_close() - Close a cndb.
 * @cndb: cndb handle
 *
 * Close a cndb that was open with cndb_open().
 */
/* MTF_MOCK */
merr_t
cndb_close(struct cndb *cndb);

/**
 * cndb_usage() - Get cndb space usage
 *
 * @cndb:      cndb handle
 * @allocated: allocated space
 * @used:      used space
 */
merr_t
cndb_usage(struct cndb *cndb, uint64_t *allocated, uint64_t *used);

/**
 * cndb_cn_create() - add a cn KVS to a cndb.
 * @cndb:     admin mode cndb handle
 * @cparams:  cn kvs create parameters
 * @cnid_out: persistent identifier for new KVS
 * @name:     KVS name
 *
 * Cn KVSes can only be created in the open/admin state.
 *
 * Implementation notes:
 *   - This will require cndb compaction if the cndb is near full capacity.
 *     Internal cn APIs will need to be developed to support cndb compaction
 *     in admin mode.
 */
/* MTF_MOCK */
merr_t
cndb_cn_create(struct cndb *cndb, const struct kvs_cparams *cparams, u64 *cnid_out, char *name);

/**
 * cndb_cn_cparams() - Get a pointer to the cn cparams
 * @cndb: cndb handle
 * @cnid: cn id
 */
/* MTF_MOCK */
struct kvs_cparams *
cndb_cn_cparams(struct cndb *cndb, u64 cnid);

/**
 * cndb_cn_drop() - delete a cn KVS
 * @log:   admin mode clog handle
 * @cnid:  persistent identifier for new KVS
 *
 * The cn kvs must not be open, and cndb must be open read/write.
 */
/* MTF_MOCK */
merr_t
cndb_cn_drop(struct cndb *cndb, u64 cnid);

/**
 * cndb_txn_start() - begin a cndb transaction
 * @cndb:     a cndb handle obtained from cndb_open()
 * @txid:     (output) unique identifier for this txn
 * @ingestid: if not CNDB_INVAL_INGESTID,
 *      - this transaction start is the start of an ingest with C1 enabled.
 *      - it is the ingest id.
 * @nc:       maximum count of TXC records in this txn
 * @nd:       actual count of TXD records in this txn
 * @seqno:    max sequence number of any kvset taking part in this txn
 *
 * @nc is an upper bound on the number of kvsets to be created in this
 * transaction. The actual number of kvsets will be determined by the number of
 * TXC records, which must be less than or equal to @nc.
 *
 * NOTE: the next txid will be @txid + @nc.  Inflated values of @nc will
 * prematurely exhaust the @txid space.
 */
/* MTF_MOCK */
merr_t
cndb_txn_start(
    struct cndb *cndb,
    u64         *txid,
    int          nc,
    int          nd,
    u64          seqno,
    u64          ingestid,
    u64          txhorizon);

/**
 * cndb_txn_txc() - Add a kvset to a transaction
 * @cndb:     a cndb handle obtained from cndb_open()
 * @txid:     an identifier obtained from cndb_txn_start()
 * @cnid:     a cN identifier minted by ikvdb_kvs_create()
 * @tag:      (input/output) must be zero for the first TXC in a txn
 * @mblocks:  list of involved blkids
 * @keepvbc:  count of vblocks to keep (not delete) when the CN mutation is
 *      rolled back during cndb replay. The oids of vblocks to keep are the
 *      first in the vblocks oids list.
 *
 * @tag is a unique iterator for this @txid.  It is owned by the caller, but
 * maintained by cndb.  It must be initialized to zero when the txid is minted.
 * On return from cndb_txn_txc(), @tag is @txid for the first C record in a txn
 * and monotonically increases for every subsequent TXC.
 */
/* MTF_MOCK */
merr_t
cndb_txn_txc(
    struct cndb *         cndb,
    u64                   txid,
    u64                   cnid,
    u64 *                 tag,
    struct kvset_mblocks *mblocks,
    u32                   keepvbc);

/**
 * cndb_txn_txd() - Add a kvset deletion to a transaction
 * @cndb:     a cndb handle obtained from cndb_open()
 * @txid:     an identifier obtained from cndb_txn_start()
 * @cnid:     a cN identifier minted by ikvdb_kvs_create()
 * @tag:      kvset to delete, indicated by tag minted by cndb_txn_txc()
 * @n_oids:   count of blkids for deletion
 * @oidv:     list of blkids for deletion
 */
/* MTF_MOCK */
merr_t
cndb_txn_txd(struct cndb *cndb, u64 txid, u64 cnid, u64 tag, int n_oids, u64 *oidv);

/**
 * cndb_txn_meta() - Add a kvset metadata to a transaction
 * @cndb:     a cndb handle obtained from cndb_open()
 * @txid:     an identifier obtained from cndb_txn_start()
 * @cnid:     a cN identifier minted by ikvdb_kvs_create()
 * @tag:      kvset described by metadata, minted by cndb_txn_txc()
 * @meta:     metadata describing the kvset
 */
/* MTF_MOCK */
merr_t
cndb_txn_meta(struct cndb *cndb, u64 txid, u64 cnid, u64 tag, struct kvset_meta *meta);

/**
 * cndb_txn_ack_c() - Acknowledge complete description of transaction
 * @cndb:     a cndb handle obtained from cndb_open()
 * @txid:     an identifier obtained from cndb_txn_start()
 *
 * ACK-C indicates that all metadata describing a transaction is on-media
 * and that all blkids indicated in constituent TXC records are committed.
 * It is an error for any ACK-D to exist for any txid lacking an ACK-C.
 */
/* MTF_MOCK */
merr_t
cndb_txn_ack_c(struct cndb *cndb, u64 txid);

/**
 * cndb_txn_ack_d() - Acknowledge deletion of a kvset
 * @cndb:     a cndb handle obtained from cndb_open()
 * @txid:     an identifier obtained from cndb_txn_start()
 * @tag:      tag of deleted kvset, minted by cndb_txn_txc())
 * @cnid:     the cnid to which the kvset belongs
 */
/* MTF_MOCK */
merr_t
cndb_txn_ack_d(struct cndb *cndb, u64 txid, u64 tag, u64 cnid);

/**
 * cndb_txn_nak() - Abort a transaction
 * @cndb:     a cndb handle obtained from cndb_open()
 * @txid:     an identifier obtained from cndb_txn_start()
 *
 * NAK and ACK-C are mutually exclusive.
 */
/* MTF_MOCK */
merr_t
cndb_txn_nak(struct cndb *cndb, u64 txid);

#if HSE_MOCKING
#include "cndb_ut.h"
#endif /* HSE_MOCKING */

#endif
