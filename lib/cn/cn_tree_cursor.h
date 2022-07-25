/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_CN_TREE_CURSOR_H
#define HSE_KVDB_CN_CN_TREE_CURSOR_H

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/cursor.h>
#include <hse/ikvdb/kvs.h>
#include <hse/util/table.h>

struct cn_cursor;
struct cn_tree;
struct cn_tree_node;
struct kvs_ktuple;

struct kvref {
    struct kvset *kvset;
};

/**
 * cn_tree_cursor_create() - Initialize a cn cursor object.
 *
 * @cur: Cursor handle.
 */
merr_t
cn_tree_cursor_create(struct cn_cursor *cur) HSE_MOCK;

/**
 * cn_tree_cursor_update() - Update a cursor's view
 *
 * @cur:
 */
merr_t
cn_tree_cursor_update(struct cn_cursor *cur) HSE_MOCK;

/**
 * cn_tree_cursor_seek() - Position a cursor to a key.
 *
 * @cur:    Cursor handle.
 * @key:    The seek key.
 * @len:    Length of %key.
 * @filter: Filter keys in the cursor's view.
 */
merr_t
cn_tree_cursor_seek(struct cn_cursor *cur, const void *key, uint32_t len, struct kc_filter *filter)
    HSE_MOCK;

/**
 * cn_tree_cursor_read() - Read the next kv-pair according to the cursor's iteration order.
 *
 * @cur:  Cursor handle
 * @elem: (output) The kv-pair that was read.
 * @eof:  (output) Whether or not the cursor is at EOF.
 */
merr_t
cn_tree_cursor_read(struct cn_cursor *cur, struct kvs_cursor_element *elem, bool *eof) HSE_MOCK;

/**
 * cn_tree_cursor_destroy() - Destroy the resources associated with the cursor.
 *
 * @cur:
 */
void
cn_tree_cursor_destroy(struct cn_cursor *cur) HSE_MOCK;

/**
 * cn_tree_cursor_active_kvsets() - Retrieve information about the kvsets participating in the
 *                                  cursor.
 *
 * @cur:    Cursor handle.
 * @active: Number of kvsets feeding into in the cursor's binheap.
 * @total:  Total number of kvsets in the participating nodes.
 */
merr_t
cn_tree_cursor_active_kvsets(struct cn_cursor *cur, uint32_t *active, uint32_t *total) HSE_MOCK;

#if HSE_MOCKING
#include "cn_tree_cursor_ut.h"
#endif /* HSE_MOCKING */

#endif
