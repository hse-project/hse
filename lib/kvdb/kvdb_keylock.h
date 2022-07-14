/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_KEYLOCK_H
#define HSE_KVDB_KEYLOCK_H

#include <error/merr.h>

struct mutex;
struct kvdb_keylock;
struct kvdb_ctxn;
struct kvdb_ctxn_locks;
struct perfc_set;

/* MTF_MOCK_DECL(kvdb_keylock) */

merr_t
kvdb_keylock_create(struct kvdb_keylock **handle_out, u32 num_tables);

void
kvdb_keylock_destroy(struct kvdb_keylock *handle);

/* MTF_MOCK */
void
kvdb_keylock_list_lock(struct kvdb_keylock *handle, void **cookiep);

/* MTF_MOCK */
void
kvdb_keylock_list_unlock(void *cookie);

void
kvdb_keylock_perfc_init(struct kvdb_keylock *handle_out, struct perfc_set *perfc_set);

/* MTF_MOCK */
merr_t
kvdb_keylock_lock(
    struct kvdb_keylock *   hklock,
    struct kvdb_ctxn_locks *hlocks,
    u64                     hash,
    u64                     start_seq);

merr_t
kvdb_ctxn_locks_init(void) HSE_COLD;

void
kvdb_ctxn_locks_fini(void) HSE_COLD;

/* MTF_MOCK */
u64
kvdb_ctxn_locks_count(struct kvdb_ctxn_locks *ctxn_locks_handle);

/* MTF_MOCK */
merr_t
kvdb_ctxn_locks_create(struct kvdb_ctxn_locks **handle);

/* MTF_MOCK */
void
kvdb_ctxn_locks_destroy(struct kvdb_ctxn_locks *ctxn_locks_handle);

/* MTF_MOCK */
u64
kvdb_ctxn_locks_end_seqno(uint32_t desc);

/* MTF_MOCK */
struct kvdb_ctxn_locks *
kvdb_ctxn_locks_desc2locks(uint32_t desc);

/* MTF_MOCK */
void
kvdb_keylock_release_locks(struct kvdb_keylock *klock_handle, struct kvdb_ctxn_locks *locks_handle);

/**
 * kvdb_keylock_enqueue_locks() - Add locks to the deferred list at the right
 *                               position (as determined by end_seqno).
 * @handle:    handle to transaction's write locks.
 * @end_seqno: end seqno of transaction.
 * @cookie:    identifies dlock from the per-cpu buckets.
 */
/* MTF_MOCK */
void
kvdb_keylock_enqueue_locks(struct kvdb_ctxn_locks *handle, u64 end_seqno, void *cookie);

void
kvdb_keylock_prune_own_locks(struct kvdb_keylock *kl_handle, struct kvdb_ctxn_locks *locks_handle);

/* MTF_MOCK */
void
kvdb_keylock_expire(struct kvdb_keylock *klock, u64 min_view_seqno, u64 spin);

#if HSE_MOCKING
#include "kvdb_keylock_ut.h"
#endif /* HSE_MOCKING */

#endif
