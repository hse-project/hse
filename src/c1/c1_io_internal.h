/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_IO_INTERNAL_H
#define HSE_C1_IO_INTERNAL_H

void
c1_io_thread_master(void *arg);

void
c1_io_thread_slave(void *arg);

void
c1_io_shutdown_threads(struct c1_io *io);

merr_t
c1_io_get_tree(struct c1 *c1, u64 size, bool txn, struct c1_tree **out, int *idx, u64 *mutation);

merr_t
c1_io_get_tree_txn(struct c1 *c1, u64 size, struct c1_tree **out, int *idx, u64 *mutation);

void
c1_io_iter_kvbtxn(struct c1_io *io, struct c1_io_queue *q, u8 tidx);

void
c1_io_rec_perf(struct c1_io *io, struct c1_io_queue *q, u64 start, merr_t err);

void
ci_io_iter_update_stats(struct c1_io *io, struct c1_log_stats *statsp, u64 size);

bool
c1_sync_or_flush_command(struct kvb_builder_iter *iter);

merr_t
c1_issue_sync(struct c1 *c1, int sync);

merr_t
c1_issue_iter(struct c1 *c1, struct kvb_builder_iter *iter, u64 txnid, u64 size, int sync);

merr_t
c1_io_txn_begin(struct c1 *c1, u64 txnid, u64 size, int sync);

merr_t
c1_io_txn_commit(struct c1 *c1, u64 txnid, u64 seqno, int sync);

merr_t
c1_io_txn_abort(struct c1 *c1, u64 txnid);

#endif /* HSE_C1_IO_INTERNAL_H */
