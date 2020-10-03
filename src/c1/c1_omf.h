/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_OMF_H
#define HSE_C1_OMF_H

#include <hse_util/omf.h>

/*
 * c1 on media format
 *
 * There are two types of on-media entries - metadata and data.
 */
enum {
    C1_MAGIC = 0x11223344,
    C1_KEY_MAGIC = 0x11223355,
    C1_VAL_MAGIC = 0x11223366,
    C1_INVALID_SEQNO = 0,
    C1_INITIAL_SEQNO = 1,
    C1_VERSION1 = 1,
    C1_VERSION = C1_VERSION1,
    C1_TYPE_BASE = 10,
    C1_TYPE_VERSION = C1_TYPE_BASE,
    C1_TYPE_INFO = 11,
    C1_TYPE_DESC = 12,
    C1_TYPE_INGEST = 13,
    C1_TYPE_KVLOG = 14,
    C1_TYPE_KVB = 15,
    C1_TYPE_KVT = 16,
    C1_TYPE_COMPLETE = 17,
    C1_TYPE_RESET = 18,
    C1_TYPE_TXN = 19,
    C1_TYPE_TXN_BEGIN = 20,
    C1_TYPE_TXN_COMMIT = 21,
    C1_TYPE_TXN_ABORT = 22,
    C1_TYPE_CLOSE = 23,
    C1_TYPE_VT = 24,
    C1_TYPE_MBLK = 25,
    C1_TYPE_END = 26,
};

enum {
    C1_DESC_INIT = 0,
    C1_DESC_COMPLETE = 1,
    C1_DESC_CLEAN = 2,
};

struct c1_hdr_omf {
    __le32 c1hdr_type;
    __le32 c1hdr_len;
} __packed;

struct c1_ver_omf {
    struct c1_hdr_omf hdr;
    __le32            c1ver_magic;
    __le32            c1ver_version;
} __packed;

/*
 * A single record in the journal MDC describing c1 configuration
 */
struct c1_info_omf {
    struct c1_hdr_omf hdr;
    __le64            c1info_seqno;
    __le32            c1info_gen;
    __le32            c1info_filler;
    __le64            c1info_capacity;
} __packed;

/*
 * One or more records in the journal pointing to a MDC each
 * contining c1 Tree.
 */
struct c1_desc_omf {
    struct c1_hdr_omf hdr;
    __le64            c1desc_oid;
    __le64            c1desc_seqno;
    __le32            c1desc_state;
    __le32            c1desc_gen;
} __packed;

/*
 * Close record
 */
struct c1_close_omf {
    struct c1_hdr_omf hdr;
    __le64            c1close_filler[3];
};

/*
 * One or more cN ingest status records ithe journal descringing
 * if the contetions of a c1 tree is ingested into cN.
 */
struct c1_ingest_omf {
    struct c1_hdr_omf hdr;
    __le64            c1ingest_seqno;
    __le64            c1ingest_cnid;
    __le64            c1ingest_cntgen;
    __le64            c1ingest_status;
} __packed;

/*
 * c1 tree is full
 */
struct c1_complete_omf {
    struct c1_hdr_omf hdr;
    __le64            c1comp_seqno;
    __le32            c1comp_gen;
    __le32            c1comp_filler;
    __le64            c1comp_kvseqno;
    __le64            c1comp_filler2;
} __packed;

/*
 * A reset record indicates the the c1 tree with given seqno is no more
 * valid since it is reused.
 */
struct c1_reset_omf {
    struct c1_hdr_omf hdr;
    __le64            c1reset_seqno;
    __le64            c1reset_newseqno;
    __le32            c1reset_gen;
    __le32            c1reset_newgen;
    __le64            c1reset_filler2;
} __packed;

/*
 * One or more records in the c1 Tree  describing every mlog
 * which is part of a c1 Tree.
 */
struct c1_kvlog_omf {
    struct c1_hdr_omf hdr;
    __le64            c1kvlog_mdcoid1;
    __le64            c1kvlog_mdcoid2;
    __le64            c1kvlog_oid;
    __le64            c1kvlog_size;
    __le64            c1kvlog_seqno;
    __le32            c1kvlog_gen;
    __le32            c1kvlog_filler;
} __packed;

/*
 * One or more records in the c1 Tree describing every bundle
 * containing one or more {opcode/key and and if needed value}.
 * If tuple {c1tree_kvb_seqno, c1tree_kvb_gen} determines the age
 * or freshess of a bundle across c1 Tree.
 */
struct c1_kvbundle_omf {
    struct c1_hdr_omf hdr;
    __le64            c1kvb_seqno;
    __le64            c1kvb_txnid;
    __le32            c1kvb_gen;
    __le32            c1kvb_keycount;
    __le64            c1kvb_mutation;
    __le64            c1kvb_size;
    __le64            c1kvb_minkey;
    __le64            c1kvb_maxkey;
    __le64            c1kvb_minseqno;
    __le64            c1kvb_maxseqno;
    __le64            c1kvb_ckeycount;
    __le64            c1kvb_oid;
    __le64            c1kvb_oid_offset;
    __le64            c1kvb_ingestid;
} __packed;

struct c1_treetxn_omf {
    struct c1_hdr_omf hdr;
    __le64            c1ttxn_seqno;
    __le64            c1ttxn_gen;
    __le64            c1ttxn_id;
    __le64            c1ttxn_kvseqno;
    __le64            c1ttxn_mutation;
    __le32            c1ttxn_cmd;
    __le32            c1ttxn_flag;
    __le64            c1ttxn_filler[7];
} __packed;

_Static_assert(
    sizeof(struct c1_treetxn_omf) == sizeof(struct c1_kvbundle_omf),
    "c1_treetxn_omf and c1_kvbundle_omf size mismatch");

struct c1_vtuple_omf {
    __le64 c1vt_sign;
    __le64 c1vt_seqno;
    __le64 c1vt_xlen;
    __le32 c1vt_tomb;
    __le32 c1vt_logtype;
    u8     c1vt_data[0];
} __packed;

struct c1_mblk_omf {
    __le64 c1mblk_id;
    __le32 c1mblk_off;
    __le32 c1mblk_filler;
} __packed;

/*
 * One or more records in the c1 Tree mlogs describing opcode/key
 * and if required value.
 */
struct c1_kvtuple_omf {
    __le64 c1kvt_sign;
    __le64 c1kvt_klen;
    __le64 c1kvt_cnid;
    __le64 c1kvt_xlen;
    __le64 c1kvt_vcount;
    u8     c1kvt_data[0];
} __packed;

OMF_SETGET(struct c1_hdr_omf, c1hdr_type, 32);
OMF_SETGET(struct c1_hdr_omf, c1hdr_len, 32)

OMF_SETGET(struct c1_ver_omf, c1ver_magic, 32)
OMF_SETGET(struct c1_ver_omf, c1ver_version, 32)

OMF_SETGET(struct c1_info_omf, c1info_seqno, 64)
OMF_SETGET(struct c1_info_omf, c1info_gen, 32)
OMF_SETGET(struct c1_info_omf, c1info_capacity, 64)

OMF_SETGET(struct c1_desc_omf, c1desc_oid, 64)
OMF_SETGET(struct c1_desc_omf, c1desc_seqno, 64)
OMF_SETGET(struct c1_desc_omf, c1desc_state, 32)
OMF_SETGET(struct c1_desc_omf, c1desc_gen, 32)

OMF_SETGET(struct c1_kvlog_omf, c1kvlog_mdcoid1, 64)
OMF_SETGET(struct c1_kvlog_omf, c1kvlog_mdcoid2, 64)
OMF_SETGET(struct c1_kvlog_omf, c1kvlog_seqno, 64)
OMF_SETGET(struct c1_kvlog_omf, c1kvlog_gen, 32)
OMF_SETGET(struct c1_kvlog_omf, c1kvlog_oid, 64)
OMF_SETGET(struct c1_kvlog_omf, c1kvlog_size, 64)

OMF_SETGET(struct c1_kvbundle_omf, c1kvb_seqno, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_txnid, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_gen, 32);
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_keycount, 32)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_mutation, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_size, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_minkey, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_maxkey, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_minseqno, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_maxseqno, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_ckeycount, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_oid, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_oid_offset, 64)
OMF_SETGET(struct c1_kvbundle_omf, c1kvb_ingestid, 64)

OMF_SETGET(struct c1_ingest_omf, c1ingest_seqno, 64)
OMF_SETGET(struct c1_ingest_omf, c1ingest_cnid, 64)
OMF_SETGET(struct c1_ingest_omf, c1ingest_cntgen, 64)
OMF_SETGET(struct c1_ingest_omf, c1ingest_status, 64)

OMF_SETGET(struct c1_reset_omf, c1reset_seqno, 64)
OMF_SETGET(struct c1_reset_omf, c1reset_gen, 32);
OMF_SETGET(struct c1_reset_omf, c1reset_newseqno, 64)
OMF_SETGET(struct c1_reset_omf, c1reset_newgen, 32)

OMF_SETGET(struct c1_complete_omf, c1comp_seqno, 64)
OMF_SETGET(struct c1_complete_omf, c1comp_gen, 32);
OMF_SETGET(struct c1_complete_omf, c1comp_kvseqno, 64)

OMF_SETGET(struct c1_vtuple_omf, c1vt_sign, 64)
OMF_SETGET(struct c1_vtuple_omf, c1vt_seqno, 64)
OMF_SETGET(struct c1_vtuple_omf, c1vt_xlen, 64)
OMF_SETGET(struct c1_vtuple_omf, c1vt_tomb, 32)
OMF_SETGET(struct c1_vtuple_omf, c1vt_logtype, 32)

OMF_SETGET(struct c1_mblk_omf, c1mblk_id, 64)
OMF_SETGET(struct c1_mblk_omf, c1mblk_off, 32)

OMF_SETGET(struct c1_treetxn_omf, c1ttxn_seqno, 64)
OMF_SETGET(struct c1_treetxn_omf, c1ttxn_gen, 64)
OMF_SETGET(struct c1_treetxn_omf, c1ttxn_kvseqno, 64)
OMF_SETGET(struct c1_treetxn_omf, c1ttxn_mutation, 64)
OMF_SETGET(struct c1_treetxn_omf, c1ttxn_id, 64)
OMF_SETGET(struct c1_treetxn_omf, c1ttxn_cmd, 32)
OMF_SETGET(struct c1_treetxn_omf, c1ttxn_flag, 32)

OMF_SETGET(struct c1_kvtuple_omf, c1kvt_sign, 64)
OMF_SETGET(struct c1_kvtuple_omf, c1kvt_klen, 64)
OMF_SETGET(struct c1_kvtuple_omf, c1kvt_cnid, 64)
OMF_SETGET(struct c1_kvtuple_omf, c1kvt_xlen, 64)
OMF_SETGET(struct c1_kvtuple_omf, c1kvt_vcount, 64)

#endif /* HSE_C1_OMF_H */
