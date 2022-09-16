/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
  */

#ifndef HSE_KVS_CN_MOVE_H
#define HSE_KVS_CN_MOVE_H

#include <hse/error/merr.h>

struct cn_tree;
struct cn_tree_node;
struct kvset_list_entry;

merr_t
cn_join(struct cn_compaction_work *w);

#endif /* HSE_KVS_CN_MOVE_H */
