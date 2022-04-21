/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_ROUTE_H
#define HSE_ROUTE_H

/* MTF_MOCK_DECL(route) */

struct cn_tree;
struct route_map;
struct kvs_cparams;

#include <hse_util/inttypes.h>
#include <hse_util/minmax.h>

#include <stdatomic.h>
#include <rbtree.h>

/**
 * struct route_node - tracks an edge key in the routing table
 * @rtn_node:   rb tree linkage
 * @rtn_refcnt: reference count
 * @rtn_keylen: edge key length
 * @rtn_child:  index into tn_childv[]
 * @rtn_tnode:  cn_tree_node pointer
 * @rtn_next:   ptr to the next route_node with larger edge key
 * @rtn_keybuf: the edge key
 *
 * Notes;
 *   1) rtn_child will go away after we convert the tree-node array to a list
 *   2) rtn_tnode is currently used only to optimize tree-node lookups
 *   3) rtn_next will be NULL for the last route node (i.e., the rightmost edge)
 *   4) rtn_next is used for free list linkage when node is not in rb tree
 */
struct route_node {
    union {
        struct rb_node     rtn_node;
        struct route_node *rtn_next;
    };
    atomic_uint        rtn_refcnt;
    uint16_t           rtn_keylen;
    uint16_t           rtn_child;
    bool               rtn_isfirst;
    bool               rtn_islast;
    void              *rtn_tnode;
    uint8_t            rtn_keybuf[72];
};


struct route_node *
route_map_lookup(struct route_map *map, const void *pfx, uint pfxlen);

struct route_node *
route_map_lookupGT(struct route_map *map, const void *pfx, uint pfxlen);

struct route_node *
route_map_get(struct route_map *map, const void *pfx, uint pfxlen);

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
    memcpy(kbuf, node->rtn_keybuf, min_t(size_t, kbuf_sz, node->rtn_keylen));
}

void
route_map_put(struct route_map *map, struct route_node *node);

struct route_node *
route_map_insert(struct route_map *map, struct route_node *node);

/* MTF_MOCK */
struct route_map *
route_map_create(const struct kvs_cparams *cp, const char *kvsname, struct cn_tree *tree);

/* MTF_MOCK */
void
route_map_destroy(struct route_map *map);

#if HSE_MOCKING
#include "route_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_ROUTE_H */
