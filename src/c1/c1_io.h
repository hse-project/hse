/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_IO_H
#define HSE_C1_IO_H

struct c1_io;
struct c1_io_queue;

merr_t
c1_io_create(struct c1 *c1, u64 dtime, const char *mpname, int threads);

void
c1_io_destroy(struct c1 *c1);

merr_t
c1_io_txn_begin(struct c1 *c1, u64 txnid, struct c1_kvinfo *cki, int flag);

merr_t
c1_io_txn_commit(struct c1 *c1, u64 txnid, u64 seqno, int flag);

merr_t
c1_io_txn_abort(struct c1 *c1, u64 txnid);

merr_t
c1_io_kvset_builder_get(struct c1 *c1, u64 gen, struct kvset_builder ***c1bldrout);

void
c1_io_kvset_builder_put(struct c1 *c1, u64 gen);

void
c1_io_kvset_builder_release(struct c1 *c1, struct c1_kvset_builder_elem *elem);

merr_t
c1_issue_iter(
    struct c1 *              c1,
    struct kvb_builder_iter *iter,
    u64                      txnid,
    struct c1_kvinfo *       cki,
    int                      sync);

#endif /* HSE_C1_IO_H */
