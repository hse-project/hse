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

#define CNDB_MAGIC 0x32313132

/**
 * Type of records in the cndb mdc
 *
 * CNDB_TYPE_VERSION:   Cndb version.
 * CNDB_TYPE_META:      Metadata for cndb/kvdb.
 * CNDB_TYPE_TXSTART:   CNDB transaction begins.
 * CNDB_TYPE_KVS_ADD:   Add a new KVS.
 * CNDB_TYPE_KVS_DEL:   Drop a KVS.
 * CNDB_TYPE_KVSET_ADD: Add a new kvset.
 * CNDB_TYPE_KVSET_DEL: Delete a kvset.
 * CNDB_TYPE_ACK:       Acknowledge a CNDB_TYPE_KVSET_ADD or a CNDB_TYPE_KVSET_DEL record.
 * CNDB_TYPE_NAK:       Abort transaction.
 */
enum cndb_rec_type {
    CNDB_TYPE_VERSION = 1,
    CNDB_TYPE_META = 2,
    CNDB_TYPE_TXSTART = 3,
    CNDB_TYPE_KVS_ADD = 4,
    CNDB_TYPE_KVS_DEL = 5,
    CNDB_TYPE_KVSET_ADD = 6,
    CNDB_TYPE_KVSET_DEL = 7,
    CNDB_TYPE_KVSET_MOVE = 8,
    CNDB_TYPE_ACK = 9,
    CNDB_TYPE_NAK = 10,

    CNDB_TYPE_CNT = 10,
};

/**
 * struct cndb_oid_omf - Used to write object IDs.
 */
struct cndb_oid_omf {
    uint64_t cndb_oid;
} HSE_PACKED;

OMF_SETGET(struct cndb_oid_omf, cndb_oid, 64);

/**
 * struct cndb_kvsetid_omf - Used to write kvset IDs.
 */
struct cndb_kvsetid_omf {
    uint64_t cndb_kvsetid;
} HSE_PACKED;

OMF_SETGET(struct cndb_kvsetid_omf, cndb_kvsetid, 64);


/**
 * struct cndb_hdr_omf - Identify the type and length of a record.
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


struct cndb_kvs_add_omf {
    struct cndb_hdr_omf hdr;
    uint32_t            kvs_add_pfxlen;
    uint32_t            kvs_add_flags;
    uint64_t            kvs_add_cnid;
    uint8_t             kvs_add_name[HSE_KVS_NAME_LEN_MAX];
} HSE_PACKED;

OMF_SETGET(struct cndb_kvs_add_omf, kvs_add_pfxlen, 32);
OMF_SETGET(struct cndb_kvs_add_omf, kvs_add_flags, 32);
OMF_SETGET(struct cndb_kvs_add_omf, kvs_add_cnid, 64);
OMF_SETGET_CHBUF(struct cndb_kvs_add_omf, kvs_add_name);

struct cndb_kvs_del_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            kvs_del_cnid;
} HSE_PACKED;

OMF_SETGET(struct cndb_kvs_del_omf, kvs_del_cnid, 64);

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


struct cndb_txstart_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            txstart_id;
    uint64_t            txstart_seqno;
    uint64_t            txstart_ingestid;
    uint64_t            txstart_txhorizon;
    uint16_t            txstart_add_cnt;
    uint16_t            txstart_del_cnt;
    uint32_t            txstart_del_pad;
} HSE_PACKED;

OMF_SETGET(struct cndb_txstart_omf, txstart_id, 64);
OMF_SETGET(struct cndb_txstart_omf, txstart_seqno, 64);
OMF_SETGET(struct cndb_txstart_omf, txstart_ingestid, 64);
OMF_SETGET(struct cndb_txstart_omf, txstart_txhorizon, 64);
OMF_SETGET(struct cndb_txstart_omf, txstart_add_cnt, 16);
OMF_SETGET(struct cndb_txstart_omf, txstart_del_cnt, 16);

/*
 * struct cndb_kvset_add_omf
 *
 * The "c" stands for mblock commit.
 * Record type CNDB_TYPE_TXC.
 * One record per new CN kvset created during the CN mutation.
 * This record is appended just before the kvset mblocks are committed.
 *
 * @kvset_add_cnid:
 * @kvset_add_txid:
 * @kvset_add_kvsetid:
 *      The first such record of the transaction/CN mutation has its
 *      kvsetid equal to the transaction id. Subsequent such records in the
 *      transaction have their kvsetid incremented by 1 for each record.
 *      This kvsetid can be seen as a kvset unique id.
 *      This same kvsetid will also be placed later in the record CNDB_TYPE_ACK
 *      (with CNDB_ACK_TYPE_D type) when the kvset will be deleted.
 *      It allows to correlate CNDB_TYPE_TXC and CNDB_TYPE_ACK records applying
 *      to a same kvset.
 */
struct cndb_kvset_add_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            kvset_add_cnid;
    uint64_t            kvset_add_txid;
    uint64_t            kvset_add_kvsetid;
    uint64_t            kvset_add_nodeid;
    uint64_t            kvset_add_dgen_hi;
    uint64_t            kvset_add_dgen_lo;
    uint64_t            kvset_add_vused;
    uint32_t            kvset_add_compc;
    uint16_t            kvset_add_rule;
    uint16_t            kvset_add_pad;
    uint64_t            kvset_add_hblkid;
    uint32_t            kvset_add_kblk_cnt;
    uint32_t            kvset_add_vblk_cnt;
} HSE_PACKED;

OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_cnid, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_txid, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_kvsetid, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_nodeid, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_dgen_hi, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_dgen_lo, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_vused, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_compc, 32);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_rule, 16);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_hblkid, 64);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_kblk_cnt, 32);
OMF_SETGET(struct cndb_kvset_add_omf, kvset_add_vblk_cnt, 32);

/*
 * struct cndb_blk_del_omf
 *
 * Record type CNDB_TYPE_TXD.
 * One such record per kvset deleted as part of a transaction/CN mutation
 * State that the mblocks of the kvset are not needed anymore (they can be
 * deleted).
 * This record is appended before the kvset mblocks are deleted.
 *
 * @blk_del_cnid:
 * @blk_del_txid:
 * @blk_del_kvsetid: same kvsetid as the one used in the record cndb_txc_omf when this
 *      kvset was created. Aka kvset kvsetid. This kvsetid is older/smaller that the
 *      kvsetid used for the new kvsets in this transaction/CN mutation.
 * @blk_del_id_cnt: number of mblocks in the kvset.
 * @pad_do_not_use:
 */
struct cndb_kvset_del_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            kvset_del_txid;
    uint64_t            kvset_del_cnid;
    uint64_t            kvset_del_kvsetid;
    /* an array of kvset_del_id_cnt mblock OIDs appears here */
} HSE_PACKED;

OMF_SETGET(struct cndb_kvset_del_omf, kvset_del_txid, 64);
OMF_SETGET(struct cndb_kvset_del_omf, kvset_del_cnid, 64);
OMF_SETGET(struct cndb_kvset_del_omf, kvset_del_kvsetid, 64);

/**
 * struct cndb_kvset_move_omf
 *
 * A KVSET_MOVE record persists the intent to move one or more kvsets from
 * a source node to a target node
 */
struct cndb_kvset_move_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            kvset_move_cnid;
    uint64_t            kvset_move_src_nodeid;
    uint64_t            kvset_move_tgt_nodeid;
    uint32_t            kvset_move_pad;
    uint32_t            kvset_move_kvset_idc;
    uint64_t            kvset_move_kvset_idv[];
} HSE_PACKED;

OMF_SETGET(struct cndb_kvset_move_omf, kvset_move_cnid, 64);
OMF_SETGET(struct cndb_kvset_move_omf, kvset_move_src_nodeid, 64);
OMF_SETGET(struct cndb_kvset_move_omf, kvset_move_tgt_nodeid, 64);
OMF_SETGET(struct cndb_kvset_move_omf, kvset_move_kvset_idc, 32);

enum {
    CNDB_ACK_TYPE_ADD = 1, /* Ack kvset create records */
    CNDB_ACK_TYPE_DEL = 2, /* Ack kvset delete records */
};

/**
 * struct cndb_ack_omf
 *
 * If type is CNDB_ACK_TYPE_C:
 * Record that all the mblocks of all the new kvsets of the CN mutation have
 * been committed.
 * If type is CNDB_ACK_TYPE_D:
 * Records that all mblocks of one old and deleted kvset [of a CN mutation]
 * have been deleted. The kvset is identified by its kvsetid "ack_kvsetid".
 *
 * @ack_txid:
 * @ack_kvsetid: unused for CNDB_ACK_TYPE_C. For CNDB_ACK_TYPE_D, kvsetid of the kvset
 *      whose mblocks have been deleted.
 * @ack_cnid: unused for CNDB_ACK_TYPE_C. For CNDB_ACK_TYPE_D, identify the
 *      KVS containing the kvset.
 * @ack_type: CNDB_ACK_TYPE_C or CNDB_ACK_TYPE_D
 */
struct cndb_ack_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            ack_txid;
    uint64_t            ack_cnid;
    uint64_t            ack_kvsetid;
    uint32_t            ack_type;
    uint32_t            ack_pad;
} HSE_PACKED;

OMF_SETGET(struct cndb_ack_omf, ack_txid, 64);
OMF_SETGET(struct cndb_ack_omf, ack_type, 32);
OMF_SETGET(struct cndb_ack_omf, ack_kvsetid, 64);
OMF_SETGET(struct cndb_ack_omf, ack_cnid, 64);


/**
 * struct cndb_nak_omf
 */
struct cndb_nak_omf {
    struct cndb_hdr_omf hdr;
    uint64_t            nak_txid;
} HSE_PACKED;

OMF_SETGET(struct cndb_nak_omf, nak_txid, 64);

/*
 * OMF Write functions
 */

merr_t
cndb_omf_ver_write(struct mpool_mdc *mdc, size_t captgt);

merr_t
cndb_omf_meta_write(struct mpool_mdc *mdc, uint64_t seqno_max);

merr_t
cndb_omf_kvs_add_write(
    struct mpool_mdc    *mdc,
    uint64_t             cnid,
    struct kvs_cparams  *cp,
    const char          *name);

merr_t
cndb_omf_kvs_del_write(struct mpool_mdc *mdc, uint64_t cnid);

merr_t
cndb_omf_txstart_write(
    struct mpool_mdc *mdc,
    uint64_t          txid,
    uint64_t          seqno,
    uint64_t          ingestid,
    uint64_t          txhorizon,
    uint16_t          add_cnt,
    uint16_t          del_cnt);

merr_t
cndb_omf_kvset_add_write(
    struct mpool_mdc *mdc,
    uint64_t          txid,
    uint64_t          cnid,
    uint64_t          kvsetid,
    uint64_t          nodeid,
    uint64_t          dgen_hi,
    uint64_t          dgen_lo,
    uint64_t          vused,
    uint32_t          compc,
    uint16_t          rule,
    uint64_t          hblkid,
    uint32_t          kblkc,
    uint64_t         *kblkv,
    uint32_t          vblkc,
    uint64_t         *vblkv);

merr_t
cndb_omf_kvset_del_write(
    struct mpool_mdc *mdc,
    uint64_t          txid,
    uint64_t          cnid,
    uint64_t          kvsetid);

merr_t
cndb_omf_kvset_move_write(
    struct mpool_mdc *mdc,
    uint64_t          cnid,
    uint64_t          src_nodeid,
    uint64_t          tgt_nodeid,
    uint32_t          kvset_idc,
    const uint64_t   *kvset_idv);

merr_t
cndb_omf_ack_write(
    struct mpool_mdc *mdc,
    uint64_t          txid,
    uint64_t          cnid,
    unsigned int      type,
    uint64_t          kvsetid);

merr_t
cndb_omf_nak_write(struct mpool_mdc *mdc, uint64_t txid);

/*
 * OMF Read functions
 */

struct kvset_meta;

void
cndb_omf_ver_read(
    struct cndb_ver_omf *omf,
    uint32_t            *magic,
    uint16_t            *version,
    size_t              *size);

void
cndb_omf_meta_read(
    struct cndb_meta_omf *omf,
    uint64_t            *seqno_max);

void
cndb_omf_kvs_add_read(
    struct cndb_kvs_add_omf *omf,
    struct kvs_cparams      *cp,
    uint64_t                *cnid,
    char                    *namebuf,
    size_t                   namebufsz);

void
cndb_omf_kvs_del_read(
    struct cndb_kvs_del_omf *omf,
    uint64_t                *cnid);

void
cndb_omf_kvset_move_read(
    struct cndb_kvset_move_omf *omf,
    uint64_t                   *cnid,
    uint64_t                   *src_nodeid,
    uint64_t                   *tgt_nodeid,
    uint32_t                   *kvset_idc,
    uint64_t                  **kvset_idv);

void
cndb_omf_txstart_read(
    struct cndb_txstart_omf *omf,
    uint64_t                *txid,
    uint64_t                *seqno,
    uint64_t                *ingestid,
    uint64_t                *txhorizon,
    uint16_t                *add_cnt,
    uint16_t                *del_cnt);

/* This function modifies the input buffer (omf).
 */
void
cndb_omf_kvset_add_read(
    struct cndb_kvset_add_omf *omf,
    uint64_t                  *txid,
    uint64_t                  *cnid,
    uint64_t                  *kvsetid,
    uint64_t                  *nodeid,
    uint64_t                  *hblkid,
    unsigned int              *kblkc,
    uint64_t                 **kblkv,
    unsigned int              *vblkc,
    uint64_t                 **vblkv,
    struct kvset_meta         *km);

void
cndb_omf_kvset_del_read(
    struct cndb_kvset_del_omf *omf,
    uint64_t                  *txid,
    uint64_t                  *cnid,
    uint64_t                  *kvsetid);

void
cndb_omf_ack_read(
    struct cndb_ack_omf *omf,
    uint64_t            *txid,
    uint64_t            *cnid,
    unsigned int        *type,
    uint64_t            *kvsetid);

void
cndb_omf_nak_read(
    struct cndb_nak_omf *omf,
    uint64_t            *txid);

#endif /* HSE_KVS_CNDB_OMF_H */
