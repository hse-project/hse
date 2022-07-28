/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CN_OTHER_ITERATOR_H
#define HSE_CN_OTHER_ITERATOR_H

#include <stddef.h>

#include <hse_util/compiler.h>
#include <error/merr.h>

struct cn_tree_node;

/**
 * Return an optimal key to split a node on.
 *
 * When a node grows to large, it must be split into two ideally equal size
 * nodes. This function will look for a key that has equal amounts of data on
 * either side of it.
 *
 * @param node: Tree node.
 * @param key_buf: Key buffer in which to copy out the split key.
 * @param key_buf_sz: Size of @p key_buf.
 *
 * @remark Caller must take the cN tree read lock before calling this function.
 *
 * @returns Error status.
 */
merr_t
cn_tree_node_get_split_key(
    const struct cn_tree_node *node,
    void *key_buf,
    size_t key_buf_sz,
    unsigned int *key_len) HSE_NONNULL(1);

/**
 * cn_split() - Build kvsets as part of a node split operation
 * @w: compaction work struct
 *
 * NOTES:
 *
 * Here are some important fields used from @w during a node split operation:
 *
 * Let N be the number of kvsets in the source node.
 *
 * - cw_outv, cw_outc = 2N
 *   [0, N - 1] : kvset_mblocks belonging to the left node after a node-split
 *   [N, 2N - 1]; kvset_mblocks belonging to the right node after a node-split
 *
 *   For instance:
 *      Input Node w/ 4 kvsets:
 *          Ns = (s1, s2, s3, s4)
 *      Output Nodes:
 *          Nleft =  (s1left, s2left, s3left, s4left)
 *          Nright = (s1right, s2right, NULL, s4right)
 *
 *      s3right is NULL as the kvset-split(s3) moved all the keys to the left side
 *
 * - cw_vgmap[2N]: vgroup map of all the valid output kvsets generated from a node split
 *
 * - cw_kvsetidv[2N]: kvset ID of all the valid output kvsets generated from a node split
 *
 * - cw_split: described in struct cn_compaction_work
 */
merr_t
cn_split(struct cn_compaction_work *w) HSE_NONNULL(1);

#endif
