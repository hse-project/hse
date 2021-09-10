/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_QCTX_H
#define HSE_KVS_QCTX_H

#include <hse_util/hse_err.h>

#include <rbtree.h>

#include <pthread.h>

extern pthread_key_t tomb_thread_key;

enum query_type {
    QUERY_GET = 0,
    QUERY_PROBE_PFX,
};

/**
 * struct tomb_elem - an element in the rb tree.
 * @node: rb node
 * @hash: sfx hash
 */
struct tomb_elem {
    struct rb_node node;
    u64            hash;
};

/**
 * struct query_ctx - context for queries (get, probe etc.)
 * @qtype:     type of query
 * @tomb_tree: shrub for tombstones
 * @pos:       current position in the memory region backing tomb elems
 * @ntombs:    number of tombstones encountered in current query
 * @seen:      number of unique keys seen
 */
struct query_ctx {
    enum query_type qtype;

    /* prefix probe specific context */
    int            pos;
    uint           ntombs;
    int            seen;
    struct rb_root tomb_tree;
};

merr_t
qctx_tomb_insert(struct query_ctx *qctx, const void *sfx, size_t sfx_len);

bool
qctx_tomb_seen(struct query_ctx *qctx, const void *sfx, size_t sfx_len);

void
qctx_te_mem_reset(void);

merr_t
qctx_te_mem_init(void);

#endif /* HSE_KVS_QCTX_H */
