/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_VIEW_H
#define HSE_KVDB_CN_CN_TREE_VIEW_H

#include <hse_util/table.h>
#include <hse/error/merr.h>

/* MTF_MOCK_DECL(ct_view) */

enum kvset_order {
    KVSET_ORDER_NEWEST_FIRST = 0,
    KVSET_ORDER_OLDEST_FIRST = 1,
};

struct cn;

/* MTF_MOCK */
merr_t
cn_tree_view_create(struct cn *cn, struct table **view_out);

/* MTF_MOCK */
void
cn_tree_view_destroy(struct table *view);

#if HSE_MOCKING
#include "cn_tree_view_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_KVS_CN_CN_TREE_VIEW_H */
