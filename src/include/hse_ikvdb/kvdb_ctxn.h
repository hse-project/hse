/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CTXN_H
#define HSE_KVDB_CTXN_H

#include <hse_ikvdb/ikvdb.h>

#include <hse_util/hse_err.h>
#include <hse_util/keylock.h>

struct c0;
struct cn;
struct ikvs;
struct mutex;
struct hse_kvs_cursor;
struct kvs_ktuple;
struct kvs_vtuple;
struct kvs_buf;
struct kvdb_keylock;
struct kvdb_ctxn_set;
struct active_ctxn_set;
struct query_ctx;

enum key_lookup_res;

enum kvdb_ctxn_state {
    KVDB_CTXN_ACTIVE = 11,
    KVDB_CTXN_COMMITTED = 12,
    KVDB_CTXN_ABORTED = 13,
    KVDB_CTXN_INVALID = 14,
};

#define kvdb_ctxn_h2h(handle) container_of(handle, struct kvdb_ctxn, ctxn_handle)

struct kvdb_ctxn {
    struct hse_kvdb_txn ctxn_handle;
};

/**
 * struct kvdb_ctxn_bind - used to bind cursors and transactions
 * @b_ctxn:     pointer to originating transaction; invalid when null
 * @b_seq:      seqno if committed
 * @b_gen:      generation count; if mismatch, must update
 * @b_ref:      reference counts; last one in frees
 * @b_update:   updated by cursor when it changes the tombspan
 * @b_preserve: updated by transaction when it ends
 *              committed transactions preserve the tombspan
 *              aborted transactions don't preserve it, if there were puts/dels
 *              (potentially uncommitted tombstones)
 */
struct kvdb_ctxn_bind {
    struct kvdb_ctxn *b_ctxn;
    u64               b_seq;
    atomic64_t        b_gen;
    atomic64_t        b_ref;
    bool              b_update;
    bool              b_preserve;
};

struct kvdb_ctxn *
kvdb_ctxn_alloc(
    struct kvdb_keylock *   kvdb_keylock,
    atomic64_t *            kvdb_seqno_addr,
    struct kvdb_ctxn_set *  kvdb_ctxn_set,
    struct active_ctxn_set *active_txn_set,
    struct c0sk *           c0sk);

void
kvdb_ctxn_free(struct kvdb_ctxn *txn);

merr_t
kvdb_ctxn_begin(struct kvdb_ctxn *txn);

merr_t
kvdb_ctxn_commit(struct kvdb_ctxn *txn);

void
kvdb_ctxn_abort(struct kvdb_ctxn *txn);

enum kvdb_ctxn_state
kvdb_ctxn_get_state(struct kvdb_ctxn *txn);

void
kvdb_ctxn_set_seqref(struct kvdb_ctxn *txn, uintptr_t seqref);

merr_t
kvdb_ctxn_get_view_seqno(struct kvdb_ctxn *txn, u64 *view_seqno);

bool
kvdb_ctxn_lock_inherit(
    u64                      start_seq,
    struct keylock_cb_rock * old_rock,
    struct keylock_cb_rock **new_rock);

merr_t
kvdb_ctxn_put(
    struct kvdb_ctxn *       txn,
    struct c0 *              c0,
    const struct kvs_ktuple *kt,
    const struct kvs_vtuple *vt);

merr_t
kvdb_ctxn_get(
    struct kvdb_ctxn *       txn,
    struct c0 *              c0,
    struct cn *              cn,
    const struct kvs_ktuple *kt,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf);

merr_t
kvdb_ctxn_del(struct kvdb_ctxn *txn, struct c0 *c0, const struct kvs_ktuple *kt);

merr_t
kvdb_ctxn_pfx_probe(
    struct kvdb_ctxn *       handle,
    struct c0 *              c0,
    struct cn *              cn,
    const struct kvs_ktuple *kt,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf);

merr_t
kvdb_ctxn_prefix_del(struct kvdb_ctxn *txn, struct c0 *c0, const struct kvs_ktuple *kt);

/* -- c0 cursor w/ txn support ------------ */

struct c0_kvmultiset *
kvdb_ctxn_get_kvms(struct kvdb_ctxn *txn);

uintptr_t
kvdb_ctxn_get_seqnoref(struct kvdb_ctxn *txn);

struct kvdb_ctxn_bind *
kvdb_ctxn_cursor_bind(struct kvdb_ctxn *txn);

void
kvdb_ctxn_cursor_unbind(struct kvdb_ctxn_bind *bind);

void
kvdb_ctxn_locks_fini(void);

void
kvdb_ctxn_locks_init(void);

/* -- list of allocated transactions -- */
merr_t
kvdb_ctxn_set_create(struct kvdb_ctxn_set **handle_out, u64 txn_timeout, u64 msecs);

void
kvdb_ctxn_set_wait_commits(struct kvdb_ctxn_set *handle);

void
kvdb_ctxn_set_destroy(struct kvdb_ctxn_set *handle);

#endif
