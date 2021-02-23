/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_CURSOR_H
#define HSE_KVDB_CN_CN_TREE_CURSOR_H

/* MTF_MOCK_DECL(cn_tree_cursor) */

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>

struct pscan;
struct cn_tree;
struct kvs_ktuple;

/* MTF_MOCK */
merr_t
cn_tree_cursor_create(struct pscan *cur, struct cn_tree *tree);

/* MTF_MOCK */
merr_t
cn_tree_cursor_update(struct pscan *cur, struct cn_tree *tree);

/* MTF_MOCK */
merr_t
cn_tree_cursor_seek(
    struct pscan *     cur,
    const void *       key,
    u32                len,
    struct kc_filter * filter,
    struct kvs_ktuple *kt);

/* MTF_MOCK */
merr_t
cn_tree_cursor_read(struct pscan *cur, struct kvs_kvtuple *kvt, bool *eof);

/* MTF_MOCK */
void
cn_tree_cursor_destroy(struct pscan *cur);

/* MTF_MOCK */
merr_t
cn_tree_cursor_active_kvsets(struct pscan *cur, u32 *active, u32 *total);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_tree_cursor_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
