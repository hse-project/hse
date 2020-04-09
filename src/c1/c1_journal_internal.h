/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_JOURNAL_INTERNAL_H
#define HSE_C1_JOURNAL_INTERNAL_H

merr_t
c1_journal_alloc_mdc(struct c1_journal *jrnl);

merr_t
c1_journal_commit_mdc(struct c1_journal *jrnl);

merr_t
c1_journal_destroy_mdc(struct mpool *ds, u64 oid1, u64 oid2);

merr_t
c1_journal_open_mdc(struct c1_journal *jrnl);

merr_t
c1_journal_close_mdc(struct c1_journal *jrnl);

void
c1_journal_rec_perf(struct c1_journal *jrnl, u64 start, merr_t err);

merr_t
c1_journal_write_version(struct c1_journal *jrnl);

merr_t
c1_journal_write_info(struct c1_journal *jrnl);

merr_t
c1_journal_write_close(struct c1_journal *jrnl);

merr_t
c1_tree_replay_process_txn(struct c1 *c1, struct c1_tree *tree);

merr_t
c1_tree_replay_process_kvb(struct c1 *c1, struct c1_tree *tree);

#endif /* HSE_C1_JOURNAL_INTERNAL_H */
