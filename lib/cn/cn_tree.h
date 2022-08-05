/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_H
#define HSE_KVDB_CN_CN_TREE_H

#include <error/merr.h>
#include <hse_util/inttypes.h>

#include "cn_metrics.h"
#include "kcompact.h"

/* MTF_MOCK_DECL(cn_tree) */

struct cn_tree;
struct cn_tree_node;
enum key_lookup_res;
struct kvs_buf;
struct kvs_ktuple;
struct perfc_set;
struct query_ctx;

struct cn_tree_node *
cn_tree_node_lookup(struct cn_tree *tree, const void *key, uint keylen);

struct route_node *
cn_tree_route_get(struct cn_tree *tree, const void *key, uint keylen);

void
cn_tree_route_put(struct cn_tree *tree, struct route_node *node);

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

struct cn_kvdb *
cn_tree_get_cnkvdb(const struct cn_tree *tree);

struct mpool *
cn_tree_get_mp(const struct cn_tree *tree);

struct kvs_rparams *
cn_tree_get_rp(const struct cn_tree *tree);

/* MTF_MOCK */
struct cndb *
cn_tree_get_cndb(const struct cn_tree *tree);

u64
cn_tree_get_cnid(const struct cn_tree *tree);

struct kvs_cparams *
cn_tree_get_cparams(const struct cn_tree *tree);

uint
cn_tree_get_pfx_len(const struct cn_tree *tree);

bool
cn_tree_is_replay(const struct cn_tree *tree);

/* MTF_MOCK */
void
cn_tree_samp(const struct cn_tree *tree, struct cn_samp_stats *s_out);

/**
 * cn_tree_node_get_min_key() - Get the smallest key in a cN node
 *
 * @tn:       cn_tree_node handle
 * @kbuf:     (output) copy out buffer for storing the min key
 * @kbuf_sz:  size of kbuf
 * @min_klen: (output) length of min key
 */
void
cn_tree_node_get_min_key(struct cn_tree_node *tn, void *kbuf, size_t kbuf_sz, uint *min_klen);

/**
 * cn_tree_node_get_max_key() - Get the largest key in a cN node
 *
 * @tn:       cn_tree_node handle
 * @kbuf:     (output) copy out buffer for storing the max key
 * @kbuf_sz:  size of kbuf
 * @min_klen: (output) length of max key
 */
void
cn_tree_node_get_max_key(struct cn_tree_node *tn, void *kbuf, size_t kbuf_sz, uint *max_klen);

struct cn_tree_node *
cn_node_alloc(struct cn_tree *tree, uint64_t nodeid);

void
cn_node_free(struct cn_tree_node *tn);

merr_t
cn_tree_init(void);

void
cn_tree_fini(void);

#if HSE_MOCKING
#include "cn_tree_ut.h"
#endif /* HSE_MOCKING */

#endif
