/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_CURSOR_H
#define HSE_KVDB_CN_CN_TREE_CURSOR_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
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

/* MTF_MOCK */
merr_t
cn_tree_cursor_create(struct cn_cursor *cur);

/* MTF_MOCK */
merr_t
cn_tree_cursor_update(struct cn_cursor *cur, struct cn_tree *tree);

/* MTF_MOCK */
merr_t
cn_tree_cursor_seek(
    struct cn_cursor * cur,
    const void *       key,
    u32                len,
    struct kc_filter * filter);

/* MTF_MOCK */
merr_t
cn_tree_cursor_read(struct cn_cursor *cur, struct kvs_cursor_element *elem, bool *eof);

/* MTF_MOCK */
void
cn_tree_cursor_destroy(struct cn_cursor *cur);

/* MTF_MOCK */
merr_t
cn_tree_cursor_active_kvsets(struct cn_cursor *cur, u32 *active, u32 *total);

#if HSE_MOCKING
#include "cn_tree_cursor_ut.h"
#endif /* HSE_MOCKING */

#endif
