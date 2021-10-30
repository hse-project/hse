/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_OMF_H
#define WAL_OMF_H

#include <hse_util/omf.h>

#include "wal.h"

struct wal_rec;
struct wal_txmeta_rec;

enum wal_rec_type {
    WAL_RT_INVALID = 0,

    WAL_RT_VERSION = 100,
    WAL_RT_CONFIG = 101,
    WAL_RT_RECLAIM = 102,
    WAL_RT_CLOSE = 103,

    WAL_RT_NONTX = 200,
    WAL_RT_TX = 201,
    WAL_RT_TXBEGIN = 202,
    WAL_RT_TXCOMMIT = 203,
    WAL_RT_TXABORT = 204,

    WAL_RT_TYPE_MAX = 512,
};

enum wal_op {
    WAL_OP_PUT = 500,
    WAL_OP_DEL = 501,
    WAL_OP_PDEL = 502,
};

enum wal_flags {
    WAL_FLAGS_BORG = (1 << 0),
    WAL_FLAGS_MORG = (1 << 1),
    WAL_FLAGS_EORG = (1 << 2),
};

#define WAL_FLAGS_ALL   (WAL_FLAGS_BORG | WAL_FLAGS_MORG | WAL_FLAGS_EORG)
#define WAL_FLAGS_MASK ~(WAL_FLAGS_ALL)


/*
 * WAL MDC OMF
 */

struct wal_mdchdr_omf {
    uint32_t mh_rtype;
    uint32_t mh_rsvd;
} HSE_PACKED;

OMF_SETGET(struct wal_mdchdr_omf, mh_rtype, 32);
OMF_SETGET(struct wal_mdchdr_omf, mh_rsvd, 32);


struct wal_version_omf {
    struct wal_mdchdr_omf ver_hdr;
    uint32_t ver_version;
    uint32_t ver_magic;
} HSE_PACKED;

/* Define set/get methods for wal_version_omf */
OMF_SETGET(struct wal_version_omf, ver_version, 32);
OMF_SETGET(struct wal_version_omf, ver_magic, 32);


struct wal_config_omf {
    struct wal_mdchdr_omf cfg_hdr;
    uint8_t cfg_mclass;
    uint8_t cfg_rsvd1;
    uint16_t  cfg_rsvd2;
    uint32_t  cfg_rsvd3;
} HSE_PACKED;

/* Define set/get methods for wal_config_omf */
OMF_SETGET(struct wal_config_omf, cfg_mclass, 8);
OMF_SETGET(struct wal_config_omf, cfg_rsvd1, 8);
OMF_SETGET(struct wal_config_omf, cfg_rsvd2, 16);
OMF_SETGET(struct wal_config_omf, cfg_rsvd3, 32);


struct wal_close_omf {
    struct wal_mdchdr_omf cls_hdr;
} HSE_PACKED;


/*
 * WAL File OMF
 */

struct wal_filehdr_omf {
    uint32_t fh_cksum;
    uint32_t fh_magic;
    uint32_t fh_version;
    uint32_t fh_close;
    uint64_t fh_mingen;
    uint64_t fh_maxgen;
    uint64_t fh_minseqno;
    uint64_t fh_maxseqno;
    uint64_t fh_mintxid;
    uint64_t fh_maxtxid;
    uint64_t fh_startoff;
    uint64_t fh_endoff;
} HSE_PACKED;

/* Define set/get methods for wal_filehdr_omf */
OMF_SETGET(struct wal_filehdr_omf, fh_cksum, 32);
OMF_SETGET(struct wal_filehdr_omf, fh_magic, 32);
OMF_SETGET(struct wal_filehdr_omf, fh_version, 32);
OMF_SETGET(struct wal_filehdr_omf, fh_close, 32);
OMF_SETGET(struct wal_filehdr_omf, fh_mingen, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_maxgen, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_minseqno, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_maxseqno, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_mintxid, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_maxtxid, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_startoff, 64);
OMF_SETGET(struct wal_filehdr_omf, fh_endoff, 64);


struct wal_rechdr_omf {
    uint64_t rh_off;
    uint32_t rh_flags;
    uint32_t rh_cksum;
    uint64_t rh_rid;
    uint64_t rh_gen;
    uint32_t rh_type;
    uint32_t rh_len;
    uint64_t rh_rsvd;
} __attribute__((packed,aligned(__alignof__(uint64_t))));

/* Define set/get methods for wal_rechdr_omf */
OMF_SETGET(struct wal_rechdr_omf, rh_off, 64);
OMF_SETGET(struct wal_rechdr_omf, rh_flags, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_cksum, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_rid, 64);
OMF_SETGET(struct wal_rechdr_omf, rh_gen, 64);
OMF_SETGET(struct wal_rechdr_omf, rh_type, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_len, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_rsvd, 64);


struct wal_rec_omf {
    struct wal_rechdr_omf r_hdr;
    uint32_t                r_op;
    uint32_t                r_klen;
    uint64_t                r_cnid;
    uint64_t                r_txid;
    uint64_t                r_seqno;
    uint64_t                r_vxlen;
    uint8_t               r_data[0];
} __attribute__((packed,aligned(__alignof__(uint64_t))));

/* Define set/get methods for wal_oprec_omf */
OMF_SETGET(struct wal_rec_omf, r_op, 32);
OMF_SETGET(struct wal_rec_omf, r_klen, 32);
OMF_SETGET(struct wal_rec_omf, r_cnid, 64);
OMF_SETGET(struct wal_rec_omf, r_txid, 64);
OMF_SETGET(struct wal_rec_omf, r_seqno, 64);
OMF_SETGET(struct wal_rec_omf, r_vxlen, 64);


struct wal_txnrec_omf {
    struct wal_rechdr_omf tr_hdr;
    uint64_t              tr_txid;
    uint64_t              tr_seqno;
    uint64_t              tr_cid;
} __attribute__((packed,aligned(__alignof__(uint64_t))));

/* Define set/get methods for wal_txrec_omf */
OMF_SETGET(struct wal_txnrec_omf, tr_txid, 64);
OMF_SETGET(struct wal_txnrec_omf, tr_seqno, 64);
OMF_SETGET(struct wal_txnrec_omf, tr_cid, 64);


/* WAL OMF interfaces */

static inline bool
wal_rectype_txn(enum wal_rec_type rtype)
{
    return rtype == WAL_RT_TX;
}

static inline bool
wal_rectype_txnmeta(enum wal_rec_type rtype)
{
    return rtype == WAL_RT_TXBEGIN || rtype == WAL_RT_TXCOMMIT || rtype == WAL_RT_TXABORT;
}

static inline bool
wal_rectype_txncommit(enum wal_rec_type rtype)
{
    return rtype == WAL_RT_TXCOMMIT;
}

static inline bool
wal_rectype_nontxn(enum wal_rec_type rtype)
{
    return rtype == WAL_RT_NONTX;
}

void
wal_rechdr_pack(enum wal_rec_type rtype, uint64_t rid, size_t tlen, uint64_t gen, void *outbuf);

uint32_t
wal_rechdr_len(void);

void
wal_rec_finish(struct wal_record *rec, uint64_t seqno, uint64_t gen);

void
wal_rec_pack(
    enum wal_op op,
    uint64_t    cnid,
    uint64_t    txid,
    uint32_t    klen,
    size_t      vxlen,
    void       *outbuf);

uint32_t
wal_reclen(void);

uint64_t
wal_reclen_total(const void *inbuf);

bool
wal_rec_is_eorg(const void *inbuf);

bool
wal_rec_is_txnmeta(const void *inbuf);

bool
wal_rec_is_txncommit(const void *inbuf);

bool
wal_rec_is_valid(
    const void             *inbuf,
    off_t                   foff,
    size_t                  fsize,
    uint64_t               *recoff,
    uint64_t                gen,
    struct wal_minmax_info *info,
    bool                   *eorg);

bool
wal_rec_skip(const void *inbuf);

void
wal_rec_unpack(const char *inbuf, struct wal_rec *rec);

void
wal_txn_rec_pack(uint64_t txid, uint64_t seqno, uint64_t cid, void *outbuf);

void
wal_txn_rec_unpack(const void *inbuf, struct wal_txmeta_rec *trec);

void
wal_txn_rechdr_finish(void *recbuf, size_t len, uint64_t offset);

uint32_t
wal_txn_reclen(void);

void
wal_update_minmax_seqno(const void *buf, struct wal_minmax_info *info);

void
wal_update_minmax_txid(const void *buf, struct wal_minmax_info *info);

void
wal_filehdr_pack(
    uint32_t                magic,
    uint32_t                version,
    struct wal_minmax_info *info,
    off_t                   soff,
    off_t                   eoff,
    bool                    close,
    void                   *outbuf);

merr_t
wal_filehdr_unpack(
    const void             *inbuf,
    uint32_t                magic,
    uint32_t                version,
    bool                   *close,
    off_t                  *soff,
    off_t                  *eoff,
    struct wal_minmax_info *info);

#endif /* WAL_OMF_H */
