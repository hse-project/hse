/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_VIEW_H
#define HSE_KVDB_CN_CN_TREE_VIEW_H

#include <hse/util/table.h>
#include <hse/error/merr.h>

/* MTF_MOCK_DECL(ct_view) */

enum kvset_order {
    KVSET_ORDER_NEWEST_FIRST = 0,
    KVSET_ORDER_OLDEST_FIRST = 1,
};

#if HSE_MOCKING
#include "cn_tree_view_ut.h"
#endif /* HSE_MOCKING */

#endif /* HSE_KVS_CN_CN_TREE_VIEW_H */
