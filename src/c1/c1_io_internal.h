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

merr_t
c1_io_get_tree(struct c1 *c1, struct c1_kvinfo *cki, struct c1_tree **out, int *idx, u64 *mutation);

merr_t
c1_io_get_tree_txn(
    struct c1 *         c1,
    struct c1_iterinfo *ci,
    struct c1_tree **   out,
    int *               idx,
    u64 *               mutation);

void
c1_io_iter_kvbtxn(struct c1_io *io, struct c1_io_queue *q, u8 tidx);

void
c1_io_rec_perf(struct c1_io *io, struct c1_io_queue *q, u64 start, merr_t err);

bool
c1_sync_or_flush_command(struct kvb_builder_iter *iter);

merr_t
c1_issue_sync(struct c1 *c1, int sync, bool skip_flush);

merr_t
c1_issue_iter(
    struct c1 *              c1,
    struct kvb_builder_iter *iter,
    u64                      txnid,
    struct c1_kvinfo *       cki,
    int                      sync);

#endif /* HSE_C1_IO_INTERNAL_H */
