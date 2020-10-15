/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_BONSAI_TREE_PVT_H
#define HSE_BONSAI_TREE_PVT_H

#include <hse_util/string.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/barrier.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/assert.h>

#pragma GCC visibility push(hidden)

enum bonsai_update_lr {
    B_UPDATE_L = 0,
    B_UPDATE_R = 1,
};

enum bonsai_match_type {
    B_MATCH_EQ = 0,
    B_MATCH_GE = 1,
    B_MATCH_LE = 2,
};

/**
 * bn_node_alloc() -
 * @tree:    bonsai tree instance
 * @key_imm:
 * @key:
 * @sval:
 *
 * Return:
 */
struct bonsai_node *
bn_node_alloc(
    struct bonsai_root *        tree,
    const struct key_immediate *key_imm,
    const void *                key,
    const struct bonsai_sval *  sval);

/**
 * bn_val_alloc() -
 * @tree:    bonsai tree instance
 * @sval:
 *
 * Return:
 */
struct bonsai_val *
bn_val_alloc(struct bonsai_root *tree, const struct bonsai_sval *sval);

/**
 * bn_node_dup() -
 * @tree: bonsai tree instance
 * @node: bonsai_node to be dup'ed
 *
 * Return: new bonsai_node (duplicated from 'node')
 */
struct bonsai_node *
bn_node_dup(struct bonsai_root *tree, struct bonsai_node *node);

/**
 * bn_node_dup_ext() -
 * @tree:  bonsai tree instance
 * @node:  bonsai_node to be dup'ed
 * @left:  left child
 * @right: right child
 *
 * Return: new bonsai_node (duplicated from 'node')
 */
struct bonsai_node *
bn_node_dup_ext(
    struct bonsai_root *tree,
    struct bonsai_node *node,
    struct bonsai_node *left,
    struct bonsai_node *right);

/**
 * bn_balance_tree() -
 * @tree:    bonsai tree instance
 * @node:
 * @left:    left child
 * @right:   right child
 * @key_imm: key immediate
 * @key:
 *
 * Return:
 */
struct bonsai_node *
bn_balance_tree(
    struct bonsai_root *        tree,
    struct bonsai_node *        node,
    struct bonsai_node *        left,
    struct bonsai_node *        right,
    const struct key_immediate *key_imm,
    const void *                key,
    enum bonsai_update_lr       lr);

/**
 * bn_height_max() -
 * @a:
 * @b:
 *
 * Return:
 */
static inline int
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
static __always_inline int
bn_height_get(struct bonsai_node *node)
{
    if (!node)
        return 0;

    assert(node->bn_height >= 0);

    return node->bn_height;
}

/**
 * bn_height_update() -
 * @node:
 *
 * Return:
 */
static __always_inline void
bn_height_update(struct bonsai_node *node)
{
    node->bn_height = bn_height_max(bn_height_get(node->bn_left), bn_height_get(node->bn_right));

    node->bn_height++;
}

#pragma GCC visibility pop

#endif /* HSE_BONSAI_TREE_PVT_H */
