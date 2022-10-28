/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_BONSAI_TREE_PVT_H
#define HSE_BONSAI_TREE_PVT_H

#include <hse/util/arch.h>
#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/bonsai_tree.h>
#include <hse/util/assert.h>

enum bonsai_match_type {
    B_MATCH_EQ = 0,
    B_MATCH_GE = 1,
    B_MATCH_LE = 2,
    B_MATCH_GT = 3,
    B_MATCH_LT = 4,
};

struct bonsai_slab *
bn_slab_init(struct bonsai_slab *slab, struct bonsai_slabinfo *slabinfo, bool canfree);

void bn_slab_free(struct bonsai_slab *slab);

uint bn_gc_reclaim(struct bonsai_root *tree, struct bonsai_slab *slab);

/**
 * bn_node_alloc() - allocate and initialize a node plus key and value
 * @tree:    bonsai tree instance
 * @skey:
 * @sval:
 *
 * Return: new node at height 1 with nil left/right child ptrs
 */
struct bonsai_node *
bn_kvnode_alloc(
    struct bonsai_root       *tree,
    const struct bonsai_skey *skey,
    const struct bonsai_sval *sval);

void bn_kv_free(struct bonsai_kv *freekeys);

/**
 * bn_val_alloc() - allocate and initialize a value
 * @tree:       bonsai tree instance
 * @sval:
 * @deepcopy:   value must be copied into bonsai tree if true
 *
 * Return:
 */
struct bonsai_val *
bn_val_alloc(struct bonsai_root *tree, const struct bonsai_sval *sval, bool deepcopy);

/**
 * bn_node_dup() - allocate and initialize a new node copied from src
 * @tree: bonsai tree instance
 * @src:  bonsai_node to be dup'ed
 *
 * Return: new node (duplicated from 'node') at height of src node
 */
struct bonsai_node *
bn_node_dup(struct bonsai_root *tree, struct bonsai_node *src);

/**
 * bn_node_dup_ext() - allocate and initialize a new node copied from src
 * @tree:  bonsai tree instance
 * @node:  bonsai_node to be dup'ed
 * @left:  left child
 * @right: right child
 *
 * Similar to bn_node_dup() but installs new left and right children.
 *
 * Return: new node (duplicated from 'node') at max height of left/right
 */
struct bonsai_node *
bn_node_dup_ext(
    struct bonsai_root *tree,
    struct bonsai_node *src,
    struct bonsai_node *left,
    struct bonsai_node *right);

/**
 * bn_node_rcufree() - mark a node for delayed free
 * @tree:    bonsai tree instance
 * @dnode:   node to delay free
 *
 * %dnode will remain intact and visible until end of next rcu epoch
 * after which it can be reclaimed.  Typically called shortly after
 * duplicating a node with bn_node_dup() or bn_node_dup_ext().
 */
static HSE_ALWAYS_INLINE void
bn_node_rcufree(struct bonsai_root *tree, struct bonsai_node *dnode)
{
    dnode->bn_rcugen = atomic_read(&tree->br_gc_rcugen_start);
}

/**
 * bn_kv_rcufree() - mark a kv for delayed free
 * @tree:    bonsai tree instance
 * @dkv:     kv to delay free
 *
 * %dkv will remain intact and visible until end of next rcu epoch
 * after which it can be reclaimed.
 */
static HSE_ALWAYS_INLINE void
bn_kv_rcufree(struct bonsai_root *tree, struct bonsai_kv *dkv)
{
    dkv->bkv_free = tree->br_vfkeys;
    tree->br_vfkeys = dkv;
}


/**
 * bn_balance() - balance subtree given by %node
 * @tree:    bonsai tree instance
 * @node:    root of the subtree to balance
 * @left:    left child
 * @right:   right child
 *
 * Return: %node if balancing not needed, otherwise a new balanced
 * subtree root node that is not yet visible to rcu readers
 */
struct bonsai_node *
bn_balance(
    struct bonsai_root *tree,
    struct bonsai_node *node,
    struct bonsai_node *left,
    struct bonsai_node *right);

/**
 * bn_height_max() -
 * @a:
 * @b:
 *
 * Return:
 */
static HSE_ALWAYS_INLINE int
bn_height_max(int a, int b)
{
    return (a > b) ? a : b;
}

/**
 * bn_height_get() -
 * @node:
 *
 * Return:
 */
static HSE_ALWAYS_INLINE int
bn_height_get(const struct bonsai_node *node)
{
    return node ? node->bn_height : 0;
}

/**
 * bn_height_update() -
 * @node:
 *
 * Return:
 */
static HSE_ALWAYS_INLINE void
bn_height_update(struct bonsai_node *node)
{
    node->bn_height = bn_height_max(bn_height_get(node->bn_left), bn_height_get(node->bn_right));

    node->bn_height++;
}

#endif /* HSE_BONSAI_TREE_PVT_H */
