/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_CN_CN_TREE_STATS_H
#define HSE_KVDB_CN_CN_TREE_STATS_H

#include <hse/util/perfc.h>
#include <hse/util/platform.h>

/* MTF_MOCK_DECL(cn_tree_stats) */

struct cn_tree;

/* MTF_MOCK */
void
cn_tree_perfc_shape_report(struct cn_tree *tree, struct perfc_set *rnode, struct perfc_set *lnode);

#if HSE_MOCKING
#include "cn_tree_stats.h"
#endif /* HSE_MOCKING */

#endif
