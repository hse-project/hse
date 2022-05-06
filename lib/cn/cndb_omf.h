/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CNDB_OMF_H
#define HSE_KVS_CNDB_OMF_H

#include <hse_util/omf.h>
#include <hse/limits.h>

/*****************************************************************
 *
 * CNDB on media format
 *
 ****************************************************************/

/**
 * Type of records in the cndb mdc
 *
 * @CNDB_TYPE_VERSION: version record
 *      Version 5 adds the ingest id in CNDB_TYPE_TX and
 *      replaces the flags field with keepvbc in CNDB_TYPE_TXC
 * The code is backward compatible for cndb mdc down to version 4 included.
 *
 * @CNDB_TYPE_INFO:    appended when a KVS is created
 * @CNDB_TYPE_INFOD:   appended when a KVS is deleted
 * @CNDB_TYPE_TX:      appended when a CN node is mutated
 * @CNDB_TYPE_ACK:
 * @CNDB_TYPE_NAK:
 * @CNDB_TYPE_TXC:
 * @CNDB_TYPE_TXM:
 * @CNDB_TYPE_TXD:
 */
enum {
    CNDB_MAGIC = 0x32313132,

    /* the algorithm in cndb_compact() is sensitive to CNDB_TYPE_ enums.
     * they are used by cndb_cmp() to order records during collation.
     *
     * VERSION must be first
     * INFO must be second
     * INFOD is grouped immediately after INFO for consistency
     * TX must be enumerated next
     * ACK must immediately follows TX and must precedes TXC
     * TXC must precede TXM
     * TXD is grouped after TXM because TXC and TXM form a tuple
     *
     * Deep understanding of cndb_compact() and friends is required before
     * changing these constants.
     */
    CNDB_TYPE_VERSION = 1,
    CNDB_TYPE_INFO = 2,
    CNDB_TYPE_INFOD = 3,
    CNDB_TYPE_TX = 4,
    CNDB_TYPE_ACK = 5,
    CNDB_TYPE_NAK = 6,
    CNDB_TYPE_TXC = 7,
    CNDB_TYPE_TXM = 8,
    CNDB_TYPE_TXD = 9,
    CNDB_TYPE_META = 10,

    CNDB_CN_NAME_MAX = 32,
};

_Static_assert(CNDB_CN_NAME_MAX == HSE_KVS_NAME_LEN_MAX, "kvs name len mismatch");

/**
 * struct cndb_oid_omf
 */
struct cndb_oid_omf {
    uint64_t cndb_oid;
} HSE_PACKED;

OMF_SETGET(struct cndb_oid_omf, cndb_oid, 64);


/**
 * struct cndb_hdr_omf
 */
struct cndb_hdr_omf {
    uint32_t cnhdr_type;
    uint32_t cnhdr_len;
} HSE_PACKED;

OMF_SETGET(struct cndb_hdr_omf, cnhdr_type, 32);
OMF_SETGET(struct cndb_hdr_omf, cnhdr_len, 32);


/**
 * struct cndb_ver_omf
 */
struct cndb_ver_omf {
    struct cndb_hdr_omf hdr;
    uint32_t            cnver_magic;
    uint32_t            cnver_version;
    uint64_t            cnver_captgt;
} HSE_PACKED;

OMF_SETGET(struct cndb_ver_omf, cnver_magic, 32);
OMF_SETGET(struct cndb_ver_omf, cnver_version, 32);
OMF_SETGET(struct cndb_ver_omf, cnver_captgt, 64);


/**
 * struct cndb_info_omf
 *
 * Record a KVStore information.
 * If type is CNDB_TYPE_INFO:
 *      appended when the KVS is created.
 * If type is CNDB_TYPE_INFOD:
 *      appended when the KVS is deleted.
 *
 * @cninfo_fanout:     cn tree fanout
 * @cninfo_prefix_len: kvs prefix length
 * @cninfo_flags: flags (eg, capped kvs)
 * @cninfo_cnid: uniquely identify the KVS in the KVDB.
 * @cninfo_metasz: size of opaque metadata following @cninfo_name.
 * @cninfo_name: the name of the kvs
 * @cninfo_meta: opaque data
 */
struct cndb_info_omf {
    struct cndb_hdr_omf hdr;
    uint32_t            cninfo_fanout;
    uint32_t            cninfo_prefix_len;
    uint32_t            cninfo_sfx_len;
    uint32_t            cninfo_unused;
    uint32_t            cninfo_flags;
    uint32_t            cninfo_metasz;
    uint64_t            cninfo_cnid;
    char                cninfo_name[CNDB_CN_NAME_MAX];
    char                cninfo_meta[];
} HSE_PACKED;

OMF_SETGET(struct cndb_info_omf, cninfo_fanout, 32);
OMF_SETGET(struct cndb_info_omf, cninfo_prefix_len, 32);
OMF_SETGET(struct cndb_info_omf, cninfo_sfx_len, 32);
OMF_SETGET(struct cndb_info_omf, cninfo_flags, 32);
OMF_SETGET(struct cndb_info_omf, cninfo_metasz, 32);
OMF_SETGET(struct cndb_info_omf, cninfo_cnid, 64);
OMF_SETGET_CHBUF(struct cndb_info_omf, cninfo_name);


/**
 * struct cndb_meta_omf - Metadata concerning the cndb
 *
 * @cnmeta_seqno_max: max seqno encountered during the last rollover.
 */
struct cndb_meta_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            cnmeta_seqno_max;
} HSE_PACKED;

OMF_SETGET(struct cndb_meta_omf, cnmeta_seqno_max, 64);


/**
 * struct cndb_tx_omf_v10
 */
struct cndb_tx_omf_v10 {
    struct cndb_hdr_omf hdr;
    uint64_t            tx_id;
    uint64_t            tx_seqno;
    uint64_t            tx_ingestid;
    uint32_t            tx_nc;
    uint32_t            tx_nd;
} HSE_PACKED;

OMF_GET_VER(struct cndb_tx_omf_v10, tx_id, 64, v10);
OMF_GET_VER(struct cndb_tx_omf_v10, tx_seqno, 64, v10);
OMF_GET_VER(struct cndb_tx_omf_v10, tx_ingestid, 64, v10);
OMF_GET_VER(struct cndb_tx_omf_v10, tx_nc, 32, v10);
OMF_GET_VER(struct cndb_tx_omf_v10, tx_nd, 32, v10);


/**
 * struct cndb_tx_omf
 *
 * Record type CNDB_TYPE_TX.
 * One record per CN ingest or CN compaction or CN spill.
 * Is the first record of a transaction containing mutiple records (with
 * same tx_id).
 * The whole transaction describing the new output kvsets and old ones deleted.
 * This record is followed by a number of records CNDB_TYPE_TXC,
 * CNDB_TYPE_TXD, CNDB_TYPE_TXM, CNDB_TYPE_ACK
 *
 * @tx_id:    transaction id associated with this CN mutation.
 * @tx_nc:    number of kvsets created during the CN mutation.
 *            Also number of records CNDB_TYPE_TXC following this record
 *            in the same transaction.
 *            The number of records CNDB_TYPE_TXM following this record
 *            in the same transaction is the number of CNDB_TYPE_TXC records
 *            containing at least one kblock or vblock.
 * @tx_nd:    number of kvsets deleted during the CN mutation.
 *            Also number of records CNDB_TYPE_TXD following this record
 *            in the same transaction.
 * @tx_seqno: KVDB sequence number at the time the transaction started.
 * @tx_ingestid: if different from CNDB_INVAL_INGESTID:
 *      - it is the ingest id of a CN ingest
 *      When the transaction is not an ingest, the value is CNDB_INVAL_INGESTID.
 * @tx_horizon: transaction horizon for a cN ingest
 *      When the transaction is not an ingest, the value is CNDB_INVAL_HORIZON.
 */
struct cndb_tx_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            tx_id;
    uint32_t            tx_nc;
    uint32_t            tx_nd;
    uint64_t            tx_seqno;
    uint64_t            tx_ingestid;
    uint64_t            tx_txhorizon;
} HSE_PACKED;

OMF_SETGET(struct cndb_tx_omf, tx_id, 64);
OMF_SETGET(struct cndb_tx_omf, tx_nc, 32);
OMF_SETGET(struct cndb_tx_omf, tx_nd, 32);
OMF_SETGET(struct cndb_tx_omf, tx_seqno, 64);
OMF_SETGET(struct cndb_tx_omf, tx_ingestid, 64);
OMF_SETGET(struct cndb_tx_omf, tx_txhorizon, 64);


/*
 * struct cndb_txc_omf
 *
 * The "c" stands for mblock commit.
 * Record type CNDB_TYPE_TXC.
 * One record per new CN kvset created during the CN mutation.
 * This record is appended just before the kvset mblocks are committed.
 *
 * @txc_cnid:
 * @txc_id:
 * @txc_tag: the first such record of the transaction/CN mutation has its
 *      tag equal to the transaction id. Subsequent such records in the
 *      transaction have their tag incremented by 1 for each record.
 *      This tag can be seen as a kvset unique id.
 *      This same tag will also be placed later in the record CNDB_TYPE_ACK
 *      (with CNDB_ACK_TYPE_D type) when the kvset will be deleted.
 *      It allows to correlate CNDB_TYPE_TXC and CNDB_TYPE_ACK records applying
 *      to a same kvset.
 * @txc_keepvbc: count of vblocks to keep (do not delete them when rolling back
 *      a CN mutation). The oids of the vblocks to keep are at beginning of
 *      the array vblocks oids.
 * @txc_kcnt:
 * @txc_vcnt:
 * @txc_mcnt:
 * an array of txc_kcnt mblock OIDs appears here
 * an array of txc_vcnt mblock OIDs appears here
 * an array of txc_mcnt mblock OIDs appears here
 */
struct cndb_txc_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            txc_cnid;
    uint64_t            txc_id;
    uint64_t            txc_tag;
    uint32_t            txc_keepvbc;
    uint32_t            txc_kcnt;
    uint32_t            txc_vcnt;
    uint32_t            txc_mcnt;
} HSE_PACKED;

OMF_SETGET(struct cndb_txc_omf, txc_cnid, 64);
OMF_SETGET(struct cndb_txc_omf, txc_id, 64);
OMF_SETGET(struct cndb_txc_omf, txc_tag, 64);
OMF_SETGET(struct cndb_txc_omf, txc_keepvbc, 32);
OMF_SETGET(struct cndb_txc_omf, txc_kcnt, 32);
OMF_SETGET(struct cndb_txc_omf, txc_vcnt, 32);
OMF_SETGET(struct cndb_txc_omf, txc_mcnt, 32);


/**
 * struct cndb_txm_omf
 *
 * Record type CNDB_TYPE_TXM.
 * One record per new kvset in a transaction/CN mutation.
 * Record the position of the new kvset in the CN tree.
 *
 * @txm_cnid:
 * @txm_id:
 * @txm_tag: kvset tag (tag in kvset record cndb_txc_omf appended when the
 *      kvset was committed).
 * @txm_level:
 * @txm_offset:
 * @txm_dgen:
 * @txm_vused:
 * @txm_compc:
 * @txm_scatter:
 */
struct cndb_txm_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            txm_cnid;
    uint64_t            txm_id;
    uint64_t            txm_tag;
    uint32_t            txm_level;
    uint32_t            txm_offset;
    uint64_t            txm_dgen;
    uint64_t            txm_vused;
    uint32_t            txm_compc;
    uint32_t            txm_scatter;
} HSE_PACKED;

OMF_SETGET(struct cndb_txm_omf, txm_cnid, 64);
OMF_SETGET(struct cndb_txm_omf, txm_id, 64);
OMF_SETGET(struct cndb_txm_omf, txm_tag, 64);
OMF_SETGET(struct cndb_txm_omf, txm_level, 32);
OMF_SETGET(struct cndb_txm_omf, txm_offset, 32);
OMF_SETGET(struct cndb_txm_omf, txm_dgen, 64);
OMF_SETGET(struct cndb_txm_omf, txm_vused, 64);
OMF_SETGET(struct cndb_txm_omf, txm_compc, 32);
OMF_SETGET(struct cndb_txm_omf, txm_scatter, 32);


/*
 * struct cndb_txd_omf
 *
 * Record type CNDB_TYPE_TXD.
 * One such record per kvset deleted as part of a transaction/CN mutation
 * State that the mblocks of the kvset are not needed anymore (they can be
 * deleted).
 * This record is appended before the kvset mblocks are deleted.
 *
 * @txd_cnid:
 * @txd_id:
 * @txd_tag: same tag as the one used in the record cndb_txc_omf when this
 *      kvset was created. Aka kvset tag. This tag is older/smaller that the
 *      tags used for the new kvsets in this transaction/CN mutation.
 * @txd_n_oids: number of mblocks in the kvset.
 * @pad_do_not_use:
 */
struct cndb_txd_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            txd_cnid;
    uint64_t            txd_id;
    uint64_t            txd_tag;
    uint32_t            txd_n_oids;
    uint32_t            pad_do_not_use;
    /* an array of txd_n_oids mblock OIDs appears here */
} HSE_PACKED;

OMF_SETGET(struct cndb_txd_omf, txd_cnid, 64);
OMF_SETGET(struct cndb_txd_omf, txd_id, 64);
OMF_SETGET(struct cndb_txd_omf, txd_tag, 64);
OMF_SETGET(struct cndb_txd_omf, txd_n_oids, 32);


enum { CNDB_ACK_TYPE_C = 1, CNDB_ACK_TYPE_D = 2 };

/**
 * struct cndb_ack_omf
 *
 * If type is CNDB_ACK_TYPE_C:
 * Record that all the mblocks of all the new kvsets of the CN mutation have
 * been committed.
 * If type is CNDB_ACK_TYPE_D:
 * Records that all mblocks of one old and deleted kvset [of a CN mutation]
 * have been deleted. The kvset is identified by its tag "ack_tag".
 *
 * @ack_txid:
 * @ack_tag: unused for CNDB_ACK_TYPE_C. For CNDB_ACK_TYPE_D, tag of the kvset
 *      whose mblocks have been deleted.
 * @ack_cnid: unused for CNDB_ACK_TYPE_C. For CNDB_ACK_TYPE_D, identify the
 *      KVS containing the kvset.
 * @ack_type: CNDB_ACK_TYPE_C or CNDB_ACK_TYPE_D
 */
struct cndb_ack_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            ack_txid;
    uint64_t            ack_tag;
    uint64_t            ack_cnid;
    uint32_t            ack_type;
    uint32_t            pad_do_not_use;
} HSE_PACKED;

OMF_SETGET(struct cndb_ack_omf, ack_txid, 64);
OMF_SETGET(struct cndb_ack_omf, ack_type, 32);
OMF_SETGET(struct cndb_ack_omf, ack_tag, 64);
OMF_SETGET(struct cndb_ack_omf, ack_cnid, 64);


/**
 * struct cndb_nak_omf
 */
struct cndb_nak_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            nak_txid;
} HSE_PACKED;

OMF_SETGET(struct cndb_nak_omf, nak_txid, 64);

#endif /* HSE_KVS_CNDB_OMF_H */
