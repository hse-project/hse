/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_LOG_H
#define HSE_C1_LOG_H

struct c1_kvset_builder_elem;
struct c1_bonsai_vbldr;

#define HSE_C1_KEY_IOVS (1 + 1) /* 1 each for kvt, key*/
#define HSE_C1_VAL_IOVS (1 + 1) /* 1 each for vallen & val) */

#define HSE_C1_LOG_USEABLE_CAPACITY(space) ((space * 60) / 100)
#define HSE_C1_LOG_VBLDR_HEAPSZ (1024 * MB)
#define HSE_C1_SMALL_VALUE_THRESHOLD 16

enum {
    C1_LOG_MLOG,
    C1_LOG_MBLOCK,
};

struct c1_log_desc {
    u64 c1_oid;
};

struct c1_log {
    struct mutex       c1l_ingest_mtx;
    u64                c1l_mdcoid1;
    u64                c1l_mdcoid2;
    u64                c1l_oid;
    u64                c1l_seqno;
    u32                c1l_gen;
    bool               c1l_empty;
    u64                c1l_space; /* Available space */
    u64                c1l_maxkv_seqno;
    void *             c1l_repbuf;
    u32                c1l_repbuflen;
    u32                c1l_reptype;
    atomic_t           c1l_mb_lowutil;
    u64                c1l_repseek;
    u64                c1l_repoffset;
    atomic64_t         c1l_rsvdspace;
    atomic64_t         c1l_kcount;
    atomic64_t         c1l_ckcount;
    atomic64_t         c1l_cvcount;
    struct mpool *     c1l_mp;
    struct mpool_mlog *c1l_mlh;
    struct cheap *     c1l_cheap[HSE_C1_DEFAULT_STRIPE_WIDTH];
    struct list_head   c1l_kvb_list;
    struct list_head   c1l_txn_list;
};

struct c1_kvb {
    struct list_head c1kvb_list;
    struct c1_log *  c1kvb_log;
    u64              c1kvb_seqno;
    u32              c1kvb_gen;
    u32              c1kvb_keycount;
    u32              c1kvb_ckeycount;
    u64              c1kvb_mutation;
    u64              c1kvb_txnid;
    u64              c1kvb_size;
    u64              c1kvb_minkey;
    u64              c1kvb_maxkey;
    u64              c1kvb_minseqno;
    u64              c1kvb_maxseqno;
    u64              c1kvb_offset;
    u64              c1kvb_ingestid;
    void *           c1kvb_data;
};

struct c1_ktuple {
    u64   c1kt_klen;
    void *c1kt_data;
};

struct c1_vtuple {
    struct s_list_head       c1vt_next;
    u64                      c1vt_vlen;
    u64                      c1vt_seqno;
    void *                   c1vt_data;
    struct c1_bonsai_vbldr **c1vt_vbuilder;
    bool                     c1vt_tomb;
};

struct c1_vtuple_array {
    struct s_list_head c1vt_vth;
    u64                c1vt_vlen;
    u64                c1vt_vcount;
};

struct c1_kvtuple {
    struct s_list_head     c1kvt_next;
    struct c1_ktuple       c1kvt_kt;
    struct c1_vtuple_array c1kvt_vt;
    struct bonsai_kv *     c1kvt_bkv;
    u64                    c1kvt_cnid;
    u32                    c1kvt_skidx;
};

struct c1_kvbundle {
    struct s_list_head c1kvb_kvth;
    u64                c1kvb_minseqno;
    u64                c1kvb_maxseqno;
    u64                c1kvb_size;
    u32                c1kvb_ktcount;
    u32                c1kvb_vtcount;
    u64                c1kvb_minkey; /* For future use */
    u64                c1kvb_maxkey; /* For future use */
};

struct c1_log_stats {
    u32 c1log_mlwrites;
    u32 c1log_mbwrites;
    u64 c1log_mllatency;
    u64 c1log_mblatency;
    u64 c1log_vsize;
};

static inline u64
c1_log_kvseqno(struct c1_log *log)
{
    return log->c1l_maxkv_seqno;
}

merr_t
c1_log_create(struct mpool *mp, u64 capacity, int *mclass, struct c1_log_desc *desc);

merr_t
c1_log_abort(struct mpool *mp, struct c1_log_desc *desc);

merr_t
c1_log_destroy(struct mpool *mp, struct c1_log_desc *desc);

merr_t
c1_log_open(
    struct mpool *      mp,
    u64                 seqno,
    u32                 gen,
    u64                 mdcoid1,
    u64                 mdcoid2,
    struct c1_log_desc *desc,
    u64                 capacity,
    struct c1_log **    out);

merr_t
c1_log_close(struct c1_log *log);

void
c1_log_set_capacity(struct c1_log *log, u64 size);

u64
c1_log_get_capacity(struct c1_log *log);

struct c1_kvbundle;
struct c1_ttxn;

merr_t
c1_log_issue_kvb(
    struct c1_log *               log,
    struct c1_kvset_builder_elem *vbldr,
    u64                           ingestid,
    u64                           vsize,
    struct c1_kvbundle *          kvb,
    u64                           seqno,
    u64                           txnid,
    u32                           gen,
    u64                           mutation,
    int                           sync,
    u8                            tidx,
    struct c1_log_stats *         statsp);

merr_t
c1_log_issue_txn(
    struct c1_log * log,
    struct c1_ttxn *txn,
    u64             seqno,
    u32             gen,
    u64             mutation,
    int             sync);

merr_t
c1_log_reserve_space(struct c1_log *log, u64 space);

merr_t
c1_log_make(
    struct mpool *      mp,
    u64                 seqno,
    u32                 gen,
    u64                 mdcoid1,
    u64                 mdcoid2,
    struct c1_log_desc *desc,
    u64                 capacity);

merr_t
c1_log_reset(struct c1_log *log, u64 newseqno, u64 newgen);

merr_t
c1_log_flush(struct c1_log *log);

#endif /* HSE_C1_LOG_H */
