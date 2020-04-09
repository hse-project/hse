/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_ACTIVE_CTXN_SOS_H
#define HSE_KVDB_ACTIVE_CTXN_SOS_H

struct active_ctxn_tree;
struct active_ctxn_entry;

merr_t
active_ctxn_tree_create(u32 max_elts, u32 index, struct active_ctxn_tree **tree);

void
active_ctxn_tree_destroy(struct active_ctxn_tree *self);

struct active_ctxn_entry *
active_ctxn_entry_alloc(struct active_ctxn_entry **entry_listp);

void
active_ctxn_entry_free(struct active_ctxn_entry **entry_listp, struct active_ctxn_entry *entry);

#endif
