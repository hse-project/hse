/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_OMF_H
#define WAL_OMF_H

#include <hse_util/omf.h>

enum wal_rec_type {
    WAL_RT_INVALID = 0,

    WAL_VERSION1 = 1,
    WAL_VERSION = WAL_VERSION1,

    WAL_RT_VERSION = 100,
    WAL_RT_CONFIG = 101,
    WAL_RT_RECLAIM = 102,
    WAL_RT_CLOSE = 103,

    WAL_RT_NONTX = 200,
    WAL_RT_TX = 201,
    WAL_RT_TXBEGIN = 202,
    WAL_RT_TXCOMMIT = 203,
    WAL_RT_TXABORT = 204,
};

enum wal_op {
    WAL_OP_PUT = 500,
    WAL_OP_DEL = 501,
    WAL_OP_PDEL = 502,
};


/*
 * WAL MDC OMF
 */

struct wal_mdchdr_omf {
    __le32 mh_rtype;
    __le32 mh_rsvd;
} HSE_PACKED;

OMF_SETGET(struct wal_mdchdr_omf, mh_rtype, 32);
OMF_SETGET(struct wal_mdchdr_omf, mh_rsvd, 32);


struct wal_version_omf {
    struct wal_mdchdr_omf ver_hdr;
    __le32 ver_version;
    __le32 ver_magic;
} HSE_PACKED;

/* Define set/get methods for wal_version_omf */
OMF_SETGET(struct wal_version_omf, ver_version, 32);
OMF_SETGET(struct wal_version_omf, ver_magic, 32);


struct wal_config_omf {
    struct wal_mdchdr_omf cfg_hdr;
    __le32 cfg_dintvl;
    __le32 cfg_dsize;
} HSE_PACKED;

/* Define set/get methods for wal_config_omf */
OMF_SETGET(struct wal_config_omf, cfg_dintvl, 32);
OMF_SETGET(struct wal_config_omf, cfg_dsize, 32);


struct wal_reclaim_omf {
    struct wal_mdchdr_omf rcm_hdr;
    __le64 rcm_dgen;
} HSE_PACKED;

/* Define set/get methods for wal_reclaim_omf */
OMF_SETGET(struct wal_reclaim_omf, rcm_dgen, 64);


struct wal_close_omf {
    struct wal_mdchdr_omf cls_hdr;
} HSE_PACKED;


/*
 * WAL File OMF
 */

struct wal_filehdr_omf {
    __le32 fh_magic;
    __le32 fh_version;
    __le64 fh_dgen;
    __le32 fh_rsvd;
    __le32 fh_cksum;
} HSE_PACKED;

/* Define set/get methods for wal_filehdr_omf */
OMF_SETGET(struct wal_filehdr_omf, fh_magic, 32);
OMF_SETGET(struct wal_filehdr_omf, fh_version, 32);
OMF_SETGET(struct wal_filehdr_omf, fh_dgen, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_rsvd, 32);
OMF_SETGET(struct wal_filehdr_omf, fh_cksum, 32);


struct wal_rechdr_omf {
    __le32 rh_cksum;
    __le32 rh_type;
    __le64 rh_rid;
    __le64 rh_len;
} HSE_PACKED;

/* Define set/get methods for wal_rechdr_omf */
OMF_SETGET(struct wal_rechdr_omf, rh_cksum, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_type, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_rid, 64);
OMF_SETGET(struct wal_rechdr_omf, rh_len, 64);


struct wal_rec_omf {
    struct wal_rechdr_omf r_hdr;
    __le32                r_op;
    __le32                r_klen;
    __le64                r_cnid;
    __le64                r_txid;
    __le64                r_dgen;
    __le64                r_seqno;
    __le64                r_vxlen;
    __u8                  r_data[0];
} HSE_PACKED;

/* Define set/get methods for wal_oprec_omf */
OMF_SETGET(struct wal_rec_omf, r_op, 32);
OMF_SETGET(struct wal_rec_omf, r_klen, 32);
OMF_SETGET(struct wal_rec_omf, r_cnid, 64);
OMF_SETGET(struct wal_rec_omf, r_txid, 64);
OMF_SETGET(struct wal_rec_omf, r_dgen, 64);
OMF_SETGET(struct wal_rec_omf, r_seqno, 64);
OMF_SETGET(struct wal_rec_omf, r_vxlen, 64);


struct wal_txnrec_omf {
    struct wal_rechdr_omf tr_hdr;
    __le64                tr_txid;
    __le64                tr_seqno;
} HSE_PACKED;

/* Define set/get methods for wal_txrec_omf */
OMF_SETGET(struct wal_txnrec_omf, tr_txid, 64);
OMF_SETGET(struct wal_txnrec_omf, tr_seqno, 64);


/* WAL OMF interfaces */

void
wal_rechdr_pack(enum wal_rec_type rtype, u64 rid, size_t kvlen, void *outbuf);

uint
wal_rechdr_len(void);

void
wal_rec_finish(struct wal_record *rec, u64 seqno, u64 dgen);

void
wal_rec_pack(enum wal_op op, u64 cnid, u64 txid, uint klen, size_t vxlen, void *outbuf);

uint
wal_rec_len(void);

void
wal_txn_rechdr_pack(enum wal_rec_type rtype, u64 rid, void *outbuf);

void
wal_txn_rec_pack(u64 txid, u64 seqno, void *outbuf);

void
wal_txn_rechdr_crc_pack(void *recbuf, size_t len);

uint
wal_txn_rec_len(void);

#endif /* WAL_OMF_H */
