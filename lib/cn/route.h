/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_ROUTE_H
#define HSE_ROUTE_H

struct cn_tree;
struct route_map;
struct kvs_cparams;

#include <hse_util/inttypes.h>
#include <hse_util/minmax.h>
#include <hse_util/keycmp.h>
#include <hse/error/merr.h>

#include <stdatomic.h>
#include <rbtree.h>

/* MTF_MOCK_DECL(route) */

/**
 * struct route_node - tracks an edge key in the routing table
 * @rtn_node:     rb tree linkage
 * @rtn_keylen:   edge key length
 * @rtn_tnode:    cn_tree_node pointer
 * @rtn_next:     ptr to the next route_node with larger edge key
 * @rtn_keybufp:  ptr to the inline or an allocated edge key
 * @rtn_keybufsz: size of the allocated edge key
 * @rtn_keybuf:   the edge key
 *
 * Notes;
 *   0) A route_node instance fits in two cache lines (on architectures with 64B cache lines)
 *   1) rtn_tnode is currently used only to optimize tree-node lookups
 *   2) rtn_next will be NULL for the last route node (i.e., the rightmost edge)
 *   3) rtn_next is used for free list linkage when node is not in rb tree
 */
struct route_node {
    union {
        struct rb_node     rtn_node;
        struct route_node *rtn_next;
    };
    uint16_t           rtn_keylen;
    bool               rtn_isfirst;
    bool               rtn_islast;
    uint32_t           rtn_keybufsz;
    void              *rtn_tnode;
    uint8_t           *rtn_keybufp;
    uint8_t            rtn_keybuf[72];
};

struct route_node *
route_map_insert(
    struct route_map *map,
    void             *tnode,
    const void       *edge_key,
    uint              edge_klen);

struct route_node *
route_map_insert_by_node(struct route_map *map, struct route_node *node);

/* MTF_MOCK */
void
route_map_delete(struct route_map *map, struct route_node *node);

struct route_node *
route_node_alloc(struct route_map *map, void *tnode, const void *edge_key, uint edge_klen);

void
route_node_free(struct route_map *map, struct route_node *node);

/**
 * route_map_lookup() - Return a node for which its edge key is greater than or equal to %key
 *
 * @map:    Route map handle
 * @key:    Key being looked up
 * @keylen: Length of %key
 */
struct route_node *
route_map_lookup(struct route_map *map, const void *key, uint keylen);

/**
 * route_map_lookupGT() - Return a node for which its edge key is strictly greater than %key
 *
 * @map:    Route map handle
 * @key:    Key being looked up
 * @keylen: Length of %key
 */
struct route_node *
route_map_lookupGT(struct route_map *map, const void *key, uint keylen);

struct route_node *
route_map_last_node(struct route_map *map);

struct route_node *
route_map_first_node(struct route_map *map);

struct route_map *
route_map_create(uint nodec);

void
route_map_destroy(struct route_map *map);

struct route_node *
route_node_next(struct route_node *node);

struct route_node *
route_node_prev(struct route_node *node);

static HSE_ALWAYS_INLINE bool
route_node_isfirst(const struct route_node *node)
{
    return node->rtn_isfirst;
}

static HSE_ALWAYS_INLINE bool
route_node_islast(const struct route_node *node)
{
    return node->rtn_islast;
}

static HSE_ALWAYS_INLINE void *
route_node_tnode(struct route_node *node)
{
    return node->rtn_tnode;
}

static HSE_ALWAYS_INLINE void
route_node_keycpy(struct route_node *node, void *kbuf, size_t kbuf_sz, uint *klen)
{
    *klen = node->rtn_keylen;
    memcpy(kbuf, node->rtn_keybufp, min_t(size_t, kbuf_sz, node->rtn_keylen));
}

merr_t
route_node_key_modify(
    struct route_map  *map,
    struct route_node *node,
    const void        *edge_key,
    uint               edge_klen);

static HSE_ALWAYS_INLINE int
route_node_keycmp(const struct route_node *node, const void *key, uint klen)
{
    return keycmp(node->rtn_keybufp, node->rtn_keylen, key, klen);
}

#if HSE_MOCKING
#include "route_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_ROUTE_H */
