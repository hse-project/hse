/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_JOURNAL_H
#define HSE_C1_JOURNAL_H

#define HSE_C1_JOURNAL_SIZE (1 * GB)

#define C1_JOURNAL_START_PERF(_jrnl, _start) ((_start) = perfc_lat_start(&(_jrnl)->c1j_pcset))

/* MTF_MOCK_DECL(c1_journal) */

struct c1_journal {
    u64               c1j_dtime;    /* Durability time */
    u64               c1j_dsize;    /* Durability size */
    u64               c1j_capacity; /* c1 overall size */
    u64               c1j_jrnlsize; /* Journal size */
    int               c1j_mediaclass;
    int               c1j_rdonly;
    u64               c1j_seqno;
    u32               c1j_gen;
    atomic_t          c1j_treecnt;
    u64               c1j_oid1;
    u64               c1j_oid2;
    u64               c1j_resetseqno;
    struct mpool *    c1j_mp;
    struct mpool_mdc *c1j_mdc;
    struct perfc_set  c1j_pcset;
};

static inline void
c1_journal_set_seqno(struct c1_journal *jrnl, u64 seqno, u64 gen)
{
    assert(jrnl);

    if ((jrnl->c1j_seqno == C1_INVALID_SEQNO) || (seqno > jrnl->c1j_seqno)) {
        jrnl->c1j_seqno = seqno;
        jrnl->c1j_gen = gen;
    }
}

static inline void
c1_journal_inc_seqno(struct c1_journal *jrnl)
{
    assert(jrnl);

    jrnl->c1j_seqno++;
    jrnl->c1j_gen = 0;
}

static inline struct mpool *
c1_journal_get_mp(struct c1_journal *jrnl)
{
    assert(jrnl);

    return jrnl->c1j_mp;
}

merr_t
c1_journal_alloc(struct mpool *mp, int mediaclass, u64 capacity, struct c1_journal **out);

merr_t
c1_journal_make(
    struct mpool *      mp,
    u64                 oid1,
    u64                 oid2,
    int                 mediaclass,
    u64                 capacity,
    struct c1_journal **out);

merr_t
c1_journal_destroy(struct c1_journal *jrnl);

merr_t
c1_journal_open(
    int                 rdonly,
    struct mpool *      mp,
    int                 mclass,
    const char *        mpname,
    u64                 oid1,
    u64                 oid2,
    struct c1_journal **out);

merr_t
c1_journal_close(struct c1_journal *jrnl);

merr_t
c1_journal_flush(struct c1_journal *jrnl);

/* MTF_MOCK */
merr_t
c1_journal_replay(struct c1 *c1, struct c1_journal *jrnl, c1_journal_replay_cb *cb);

void
c1_journal_set_info(struct c1_journal *jrnl, u64 dtime, u64 dsize);

void
c1_journal_get_info(struct c1_journal *jrnl, u64 *dtime, u64 *dsize, u64 *dcapacity);

merr_t
c1_journal_write_desc(struct c1_journal *jrnl, u32 state, u64 oid, u64 seqno, u64 gen);

merr_t
c1_journal_reset_tree(struct c1_journal *jrnl, u64 seqno, u32 gen, u64 newseqno, u64 newgen);

merr_t
c1_journal_complete_tree(struct c1_journal *jrnl, u64 seqno, u32 gen, u64 kvseqno);

bool
c1_journal_reaching_capacity(struct c1_journal *jrnl);

/* MTF_MOCK */
merr_t
c1_journal_format(struct c1_journal *jrnl);

/* MTF_MOCK */
merr_t
c1_journal_compact_begin(struct c1_journal *jrnl);

/* MTF_MOCK */
merr_t
c1_journal_compact_end(struct c1_journal *jrnl);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_journal_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_C1_JOURNAL_H */
