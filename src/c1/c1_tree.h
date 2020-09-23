/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_TREE_H
#define HSE_C1_TREE_H

/* MTF_MOCK_DECL(c1_tree) */

#define HSE_C1_MAX_LOG_SIZE (4 * GB)
#define HSE_C1_MIN_LOG_SIZE (1 * GB)
#define HSE_C1_TREE_USEABLE_CAPACITY(space) ((space * 80) / 100)

struct c1_log;
struct c1_complete;
struct c1_mblk;

struct c1_tree {
    struct list_head    c1t_list;     /* c1 tree list */
    u64                 c1t_capacity; /* c1 overall size */
    atomic64_t          c1t_rsvdspace;
    u64                 c1t_seqno;
    u32                 c1t_gen;
    atomic_t            c1t_nextlog;
    atomic64_t          c1t_mutation;
    u64                 c1t_mdcoid1;
    u64                 c1t_mdcoid2;
    int                 c1t_mclass;
    u32                 c1t_strip_size;
    u32                 c1t_stripe_width;
    atomic64_t          c1t_numkeys;
    atomic64_t          c1t_numvals;
    struct list_head    c1t_kvb_list;
    struct list_head    c1t_txn_list;
    struct mpool *      c1t_ds;
    struct c1_log **    c1t_log;
    struct c1_log_desc *c1t_desc;
};

static inline void
c1_tree_mark_empty(struct c1_tree *tree)
{
    int numlogs = tree->c1t_stripe_width;
    int i;

    for (i = 0; i < numlogs; i++)
        tree->c1t_log[i]->c1l_empty = true;
}

merr_t
c1_tree_alloc(
    struct mpool *   ds,
    u64              seqno,
    u32              gen,
    u64              mdcoid1,
    u64              mdcoid2,
    int *            mclass,
    u32              stripsize,
    u32              stripewidth,
    u64              capacity,
    struct c1_tree **out);

merr_t
c1_tree_make(struct c1_tree *tree);

merr_t
c1_tree_get_complete(struct c1_tree *tree, struct c1_complete *cmp);

merr_t
c1_tree_destroy(struct mpool *ds, struct c1_log_desc *desc, int numlogs);

merr_t
c1_tree_open(struct c1_tree *tree, bool replay);

merr_t
c1_tree_close(struct c1_tree *tree);

/* MTF_MOCK */
merr_t
c1_tree_get_desc(struct c1_tree *tree, struct c1_log_desc **desc, int *numdesc);

merr_t
c1_tree_reset(struct c1_tree *tree, u64 newseqno, u32 newgen);

merr_t
c1_tree_flush(struct c1_tree *tree);

merr_t
c1_tree_create(
    struct mpool *      ds,
    u64                 seqno,
    u32                 gen,
    struct c1_log_desc *desc,
    u64                 mdcoid1,
    u64                 mdcoid2,
    int                 mclass,
    u32                 strip_size,
    u32                 stripe_width,
    u64                 capacity,
    struct c1_tree **   out);

/* MTF_MOCK */
merr_t
c1_tree_reserve_space_txn(struct c1_tree *tree, u64 size);

/* MTF_MOCK */
merr_t
c1_tree_reserve_space(struct c1_tree *tree, u64 size, int *idx, u64 *mutation, bool spare);

merr_t
c1_tree_reserve_space_iter(
    struct c1_tree *    tree,
    u32                 kmetasz,
    u32                 vmetasz,
    u32                 kvbmetasz,
    u64                 stripsz,
    struct c1_iterinfo *ci);

void
c1_tree_refresh_space(struct c1_tree *tree);

u64
c1_tree_space_threshold(struct c1_tree *tree);

merr_t
c1_tree_issue_kvb(
    struct c1_tree *              tree,
    u64                           ingestid,
    u64                           vsize,
    int                           idx,
    u64                           txnid,
    u64                           mutation,
    struct c1_kvbundle *          kvb,
    int                           sync,
    u8                            tidx);

merr_t
c1_tree_issue_txn(struct c1_tree *tree, int idx, u64 mutation, struct c1_ttxn *txn, int sync);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_tree_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif /* HSE_C1_TREE_H */
