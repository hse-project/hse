/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_KVS_CN_MOVE_H
#define HSE_KVS_CN_MOVE_H

#include <hse/error/merr.h>

struct cn_tree;
struct cn_tree_node;
struct kvset_list_entry;

/**
 * cn_move() - move kvsets between two nodes
 *
 * @w:        compaction work
 * @src_node: source node for the move operation
 * @src_list: first kvset list entry to move from tn_kvset_list
 * @src_cnt:  number of kvset list entries to move
 * @src_del:  can the source node be deleted after a successful move operation
 * @tgt_node: target node for the move operation
 *
 * NOTE:
 * - src_del is true for node-join, where we move all kvsets from the source node
 * - src_del is false for z-spill, where we move a subset of kvsets from the source
 *   node and cannot delete the root node
 * - cn_move() updates both cNDB and the in-memory kvset list
 * - If src_del is true, then the route node is destroyed and the tn_route_node is set
 *   to NULL. The deletion of the cn_tree_node happens later in csched.
 */
merr_t
cn_move(
    struct cn_compaction_work *w,
    struct cn_tree_node       *src_node,
    struct kvset_list_entry   *src_list,
    uint32_t                   src_cnt,
    bool                       src_del,
    struct cn_tree_node       *tgt_node);

/**
 * cn_join() - join w->cw_join and w->cw_node
 *
 * @w: compaction work
 *
 * NOTE:
 * - The join operation moves all the kvsets from w->cw_join to w->cw_node
 * - The join direction is always from left to right: w->cw_join -> w->cw_node
 * - The edge key of w->cw_node is untouched after a join
 * - w->cw_node is always intact after a successful join operation, i.e., only
 *   w->cw_join can be marked for deletion after a successful join.
 * - The edge key of w->cw_join is removed from the route map after a successful join
 */
merr_t
cn_join(struct cn_compaction_work *w);

#endif /* HSE_KVS_CN_MOVE_H */
