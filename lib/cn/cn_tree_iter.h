/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_ITER_H
#define HSE_KVDB_CN_CN_TREE_ITER_H

#include <hse_util/inttypes.h>

#include <hse_ikvdb/cn_tree_view.h>

/* MTF_MOCK_DECL(cn_tree_iter) */

struct cn_tree;
struct cn_tree_node;
struct kvset;
struct cn_node_loc;

typedef int
cn_tree_walk_callback_fn(
    void *               rock,
    struct cn_tree *     tree,
    struct cn_tree_node *node,
    struct cn_node_loc * loc,
    struct kvset *       kvset);

struct tree_iter {
    struct cn_tree_node *prev;
    struct cn_tree_node *next;
    struct cn_tree_node *end;
    bool                 topdown;
};

/* TOPDOWN:  Pre-order traversal, visit parents before children.
 * BOTTOMUP: Post-order traversal, visit children before parents.
 */
#define TRAVERSE_TOPDOWN 0
#define TRAVERSE_BOTTOMUP 1

void
tree_iter_init_node(
    struct cn_tree *     tree,
    struct tree_iter *   iter,
    int                  traverse_order,
    struct cn_tree_node *node);

void
tree_iter_init(struct cn_tree *tree, struct tree_iter *iter, int traverse_order);

struct cn_tree_node *
tree_iter_next(struct cn_tree *tree, struct tree_iter *iter);

/**
 * cn_tree_preorder_walk() - Perform preorder traversal of tree.
 * @tree: tree to traverse
 * @order: callback order for kvsets
 * @callback: function invoked on each kvset of the tree
 * @rock: context passed to callback function
 *
 * Callback sequence:
 *
 *   for each node:
 *     - invoke callback with kvset==NULL;
 *     - for each kvset K in node:
 *          invoke callback with kvset==K;
 */
/* MTF_MOCK */
void
cn_tree_preorder_walk(
    struct cn_tree *          tree,
    enum kvset_order          order,
    cn_tree_walk_callback_fn *callback,
    void *                    rock);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_tree_iter_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
