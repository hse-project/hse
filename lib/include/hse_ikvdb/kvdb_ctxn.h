/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CTXN_H
#define HSE_KVDB_CTXN_H

#include <hse_util/hse_err.h>
#include <hse_util/keylock.h>

#include <hse_ikvdb/ikvdb.h>

/* MTF_MOCK_DECL(kvdb_ctxn) */

struct c0;
struct kvs_ktuple;
struct kvs_buf;
struct kvdb_keylock;
struct kvdb_ctxn_set;
struct viewset;
struct c0snr_set;
struct query_ctx;
struct wal;

enum kvdb_ctxn_state {
    KVDB_CTXN_ACTIVE = 11,
    KVDB_CTXN_COMMITTED = 12,
    KVDB_CTXN_ABORTED = 13,
    KVDB_CTXN_INVALID = 14,
};

struct kvdb_ctxn {
    struct hse_kvdb_txn ctxn_handle;
};

#define kvdb_ctxn_h2h(handle) container_of(handle, struct kvdb_ctxn, ctxn_handle)

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

/* MTF_MOCK */
struct kvdb_ctxn *
kvdb_ctxn_alloc(
    struct kvdb_keylock *   kvdb_keylock,
    atomic64_t *            kvdb_seqno_addr,
    struct kvdb_ctxn_set *  kvdb_ctxn_set,
    struct viewset         *active_txn_set,
    struct c0snr_set       *c0snrset,
    struct c0sk *           c0sk,
    struct wal             *wal);

/* MTF_MOCK */
void
kvdb_ctxn_free(struct kvdb_ctxn *txn);

/* MTF_MOCK */
merr_t
kvdb_ctxn_begin(struct kvdb_ctxn *txn);

/* MTF_MOCK */
merr_t
kvdb_ctxn_commit(struct kvdb_ctxn *txn);

/* MTF_MOCK */
void
kvdb_ctxn_abort(struct kvdb_ctxn *txn);

/* MTF_MOCK */
enum kvdb_ctxn_state
kvdb_ctxn_get_state(struct kvdb_ctxn *txn);

/* MTF_MOCK */
void
kvdb_ctxn_reset(struct kvdb_ctxn *txn);

/* MTF_MOCK */
merr_t
kvdb_ctxn_get_view_seqno(struct kvdb_ctxn *txn, u64 *view_seqno);

/* MTF_MOCK */
bool
kvdb_ctxn_lock_inherit(u64 start_seq, uint old_rock, uint *new_rock);

/* Exclusively lock a txn for reading (e.g., get, prefix probe)  */
/* MTF_MOCK */
merr_t
kvdb_ctxn_trylock_read(struct kvdb_ctxn *handle, uintptr_t *seqref, u64 *view_seqno);

/* Exclusively lock a txn for write (e.g., put, delete)  */
/* MTF_MOCK */
merr_t
kvdb_ctxn_trylock_write(
    struct kvdb_ctxn *handle,
    uintptr_t        *seqref,
    u64              *view_seqno,
    bool              needkeylock,
    u64               hash);

/* MTF_MOCK */
void
kvdb_ctxn_unlock(
    struct kvdb_ctxn *handle);

int64_t
kvdb_ctxn_wal_cookie_get(struct kvdb_ctxn *handle);

/* -- c0 cursor w/ txn support ------------ */

/* MTF_MOCK */
uintptr_t
kvdb_ctxn_get_seqnoref(struct kvdb_ctxn *txn);

/* MTF_MOCK */
struct kvdb_ctxn_bind *
kvdb_ctxn_cursor_bind(struct kvdb_ctxn *txn);

/* MTF_MOCK */
void
kvdb_ctxn_cursor_unbind(struct kvdb_ctxn_bind *bind);

/* -- list of allocated transactions -- */
/* MTF_MOCK */
merr_t
kvdb_ctxn_set_create(struct kvdb_ctxn_set **handle_out, u64 txn_timeout, u64 msecs);

/* MTF_MOCK */
void
kvdb_ctxn_set_wait_commits(struct kvdb_ctxn_set *handle);

/* MTF_MOCK */
void
kvdb_ctxn_set_destroy(struct kvdb_ctxn_set *handle);

#if HSE_MOCKING
#include "kvdb_ctxn_ut.h"
#endif /* HSE_MOCKING */

#endif
