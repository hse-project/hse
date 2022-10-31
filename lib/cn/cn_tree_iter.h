/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_ITER_H
#define HSE_KVDB_CN_CN_TREE_ITER_H

#include <hse/util/inttypes.h>

#include <hse/ikvdb/cn_tree_view.h>

/* MTF_MOCK_DECL(cn_tree_iter) */

struct cn_tree;
struct cn_tree_node;
struct kvset;

typedef int
cn_tree_walk_callback_fn(
    void *               rock,
    struct cn_tree *     tree,
    struct cn_tree_node *node,
    struct kvset *       kvset);

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

#if HSE_MOCKING
#include "cn_tree_iter_ut.h"
#endif /* HSE_MOCKING */

#endif
