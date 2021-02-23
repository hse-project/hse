/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_VIEWSET_SOS_H
#define HSE_KVDB_VIEWSET_SOS_H

struct viewset_tree;

merr_t
viewset_tree_create(u32 max_elts, u32 index, struct viewset_tree **tree);

void
viewset_tree_destroy(struct viewset_tree *self);

#endif
