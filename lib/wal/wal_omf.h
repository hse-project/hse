/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef WAL_OMF_H
#define WAL_OMF_H

#include <hse_util/omf.h>

#include "wal.h"

struct wal_rec;

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
    __le32 cfg_durms;
    __le32 cfg_durbytes;
        u8 cfg_mclass;
        u8 cfg_rsvd1;
    __le16 cfg_rsvd2;
    __le32 cfg_rsvd3;
} HSE_PACKED;

/* Define set/get methods for wal_config_omf */
OMF_SETGET(struct wal_config_omf, cfg_durms, 32);
OMF_SETGET(struct wal_config_omf, cfg_durbytes, 32);
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
    __le32 fh_cksum;
    __le32 fh_magic;
    __le32 fh_version;
    __le32 fh_close;
    __le64 fh_mingen;
    __le64 fh_maxgen;
    __le64 fh_minseqno;
    __le64 fh_maxseqno;
    __le64 fh_mintxid;
    __le64 fh_maxtxid;
    __le64 fh_startoff;
    __le64 fh_endoff;
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
    __le64 rh_off;
    __le32 rh_flags;
    __le32 rh_cksum;
    __le64 rh_rid;
    __le64 rh_gen;
    __le32 rh_type;
    __le32 rh_len;
} __attribute__((packed,aligned(__alignof__(uint64_t))));

/* Define set/get methods for wal_rechdr_omf */
OMF_SETGET(struct wal_rechdr_omf, rh_off, 64);
OMF_SETGET(struct wal_rechdr_omf, rh_flags, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_cksum, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_rid, 64);
OMF_SETGET(struct wal_rechdr_omf, rh_gen, 64);
OMF_SETGET(struct wal_rechdr_omf, rh_type, 32);
OMF_SETGET(struct wal_rechdr_omf, rh_len, 32);


struct wal_rec_omf {
    struct wal_rechdr_omf r_hdr;
    __le32                r_op;
    __le32                r_klen;
    __le64                r_cnid;
    __le64                r_txid;
    __le64                r_seqno;
    __le64                r_vxlen;
    __u8                  r_data[0];
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
    __le64                tr_txid;
    __le64                tr_seqno;
} __attribute__((packed,aligned(__alignof__(uint64_t))));

/* Define set/get methods for wal_txrec_omf */
OMF_SETGET(struct wal_txnrec_omf, tr_txid, 64);
OMF_SETGET(struct wal_txnrec_omf, tr_seqno, 64);


/* WAL OMF interfaces */

static inline bool
wal_rectype_txnmeta(enum wal_rec_type rtype)
{
    return rtype == WAL_RT_TXBEGIN || rtype == WAL_RT_TXCOMMIT || rtype == WAL_RT_TXABORT;
}

static inline bool
wal_rectype_txcommit(enum wal_rec_type rtype)
{
    return rtype == WAL_RT_TXCOMMIT;
}

static inline bool
wal_rectype_nontx(enum wal_rec_type rtype)
{
    return rtype == WAL_RT_NONTX;
}

void
wal_rechdr_pack(enum wal_rec_type rtype, u64 rid, size_t kvlen, void *outbuf);

uint
wal_rechdr_len(void);

void
wal_rec_finish(struct wal_record *rec, u64 seqno, u64 gen);

void
wal_rec_pack(enum wal_op op, u64 cnid, u64 txid, uint klen, size_t vxlen, void *outbuf);

uint
wal_rec_len(void);

u64
wal_rec_total_len(const char *inbuf);

bool
wal_rec_is_borg(const char *inbuf);

bool
wal_rec_is_eorg(const char *inbuf);

bool
wal_rec_is_morg(const char *inbuf);

bool
wal_rec_is_valid(const char *inbuf, off_t *offset, u64 gen);

bool
wal_rec_skip(const char *inbuf);

void
wal_rec_unpack(const char *inbuf, struct wal_rec *rec);

void
wal_txn_rechdr_pack(enum wal_rec_type rtype, u64 rid, u64 gen, void *outbuf);

void
wal_txn_rec_pack(u64 txid, u64 seqno, void *outbuf);

void
wal_txn_rechdr_finish(void *recbuf, size_t len, u64 offset);

uint
wal_txn_rec_len(void);

void
wal_filehdr_pack(
    u32                     magic,
    u32                     version,
    struct wal_minmax_info *info,
    off_t                   soff,
    off_t                   eoff,
    bool                    close,
    void                   *outbuf);

merr_t
wal_filehdr_unpack(
    const void             *inbuf,
    u32                    *magic,
    u32                    *version,
    bool                   *close,
    off_t                  *soff,
    off_t                  *eoff,
    struct wal_minmax_info *info);

#endif /* WAL_OMF_H */
