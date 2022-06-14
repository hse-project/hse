/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CN_OTHER_ITERATOR_H
#define HSE_CN_OTHER_ITERATOR_H

#include <stddef.h>

#include <hse_util/compiler.h>
#include <hse_util/hse_err.h>

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

#endif
