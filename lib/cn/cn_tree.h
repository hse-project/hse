/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_H
#define HSE_KVDB_CN_CN_TREE_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

#include "cn_metrics.h"
#include "kcompact.h"

/* MTF_MOCK_DECL(cn_tree) */

struct cn_tree;
struct cn_cache;
enum cn_action;
enum key_lookup_res;
struct kvs_buf;
struct kvs_ktuple;
struct perfc_set;
struct query_ctx;

struct cn_tstate_omf;
typedef merr_t
cn_tstate_prepare_t(struct cn_tstate_omf *omf, void *arg);
typedef void
cn_tstate_commit_t(const struct cn_tstate_omf *omf, void *arg);
typedef void
cn_tstate_abort_t(struct cn_tstate_omf *omf, void *arg);

struct cn_tstate {
    merr_t (*ts_update)(
        struct cn_tstate *   tstate,
        cn_tstate_prepare_t *ts_prepare,
        cn_tstate_commit_t * ts_commit,
        cn_tstate_abort_t *  ts_abort,
        void *               arg);

    void (*ts_get)(struct cn_tstate *tstate, u32 *genp, u16 *mapv);
};

uint
cn_tree_route_lookup(struct cn_tree *tree, const void *pfx, uint pfxlen, u64 hash, uint level);

/* MTF_MOCK */
uint
cn_tree_route_create(struct cn_tree *tree, const void *pfx, uint pfxlen, u64 hash, uint level);

/* MTF_MOCK */
merr_t
cn_tree_lookup(
    struct cn_tree *     tree,
    struct perfc_set *   pc,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct query_ctx *   qctx,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf);

/**
 * cn_tree_initial_dgen() - return most current dgen in tree
 * @tree: tree to query
 *
 * The dgen returned is the largest dgen value seen during MDC replay.
 */
/* MTF_MOCK */
u64
cn_tree_initial_dgen(const struct cn_tree *tree);

/* Return true if the cn_tree is capped. */
bool
cn_tree_is_capped(const struct cn_tree *tree);

/* MTF_MOCK */
struct cn *
cn_tree_get_cn(const struct cn_tree *tree);

/* MTF_MOCK */
struct cn_khashmap *
cn_tree_get_khashmap(const struct cn_tree *tree);

struct cn_cache *
cn_tree_get_cache(const struct cn_tree *tree);

struct cn_kvdb *
cn_tree_get_cnkvdb(const struct cn_tree *tree);

struct mpool *
cn_tree_get_ds(const struct cn_tree *tree);

struct kvs_rparams *
cn_tree_get_rp(const struct cn_tree *tree);

struct cndb *
cn_tree_get_cndb(const struct cn_tree *tree);

u64
cn_tree_get_cnid(const struct cn_tree *tree);

struct kvs_cparams *
cn_tree_get_cparams(const struct cn_tree *tree);

uint
cn_tree_get_fanout(const struct cn_tree *tree);

uint
cn_tree_get_pfx_len(const struct cn_tree *tree);

bool
cn_tree_is_replay(const struct cn_tree *tree);

uint
cn_tree_get_pfx_pivot(struct cn_tree *tree);

/* MTF_MOCK */
void
cn_tree_samp(const struct cn_tree *tree, struct cn_samp_stats *s_out);

merr_t
cn_tree_init(void);

void
cn_tree_fini(void);

#if HSE_MOCKING
#include "cn_tree_ut.h"
#endif /* HSE_MOCKING */

#endif
