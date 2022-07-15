/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_CURSOR_H
#define HSE_KVDB_CN_CN_TREE_CURSOR_H

#include <hse_util/inttypes.h>
#include <error/merr.h>
#include <hse_util/table.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/cursor.h>

/* MTF_MOCK_DECL(cn_tree_cursor) */

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
/* MTF_MOCK */
merr_t
cn_tree_cursor_create(struct cn_cursor *cur);

/**
 * cn_tree_cursor_update() - Update a cursor's view
 *
 * @cur:
 */
/* MTF_MOCK */
merr_t
cn_tree_cursor_update(struct cn_cursor *cur);

/**
 * cn_tree_cursor_seek() - Position a cursor to a key.
 *
 * @cur:    Cursor handle.
 * @key:    The seek key.
 * @len:    Length of %key.
 * @filter: Filter keys in the cursor's view.
 */
/* MTF_MOCK */
merr_t
cn_tree_cursor_seek(
    struct cn_cursor * cur,
    const void *       key,
    u32                len,
    struct kc_filter * filter);

/**
 * cn_tree_cursor_read() - Read the next kv-pair according to the cursor's iteration order.
 *
 * @cur:  Cursor handle
 * @elem: (output) The kv-pair that was read.
 * @eof:  (output) Whether or not the cursor is at EOF.
 */
/* MTF_MOCK */
merr_t
cn_tree_cursor_read(struct cn_cursor *cur, struct kvs_cursor_element *elem, bool *eof);

/**
 * cn_tree_cursor_destroy() - Destroy the resources associated with the cursor.
 *
 * @cur:
 */
/* MTF_MOCK */
void
cn_tree_cursor_destroy(struct cn_cursor *cur);

/**
 * cn_tree_cursor_active_kvsets() - Retrieve information about the kvsets participating in the
 *                                  cursor.
 *
 * @cur:    Cursor handle.
 * @active: Number of kvsets feeding into in the cursor's binheap.
 * @total:  Total number of kvsets in the participating nodes.
 */
/* MTF_MOCK */
merr_t
cn_tree_cursor_active_kvsets(struct cn_cursor *cur, u32 *active, u32 *total);

#if HSE_MOCKING
#include "cn_tree_cursor_ut.h"
#endif /* HSE_MOCKING */

#endif
