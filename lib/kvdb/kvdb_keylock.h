/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_KEYLOCK_H
#define HSE_KVDB_KEYLOCK_H

#include <stdint.h>

#include <hse/error/merr.h>

struct mutex;
struct kvdb_keylock;
struct kvdb_ctxn;
struct kvdb_ctxn_locks;
struct perfc_set;

merr_t
kvdb_keylock_create(struct kvdb_keylock **handle_out, uint32_t num_tables);

void
kvdb_keylock_destroy(struct kvdb_keylock *handle);

void
kvdb_keylock_list_lock(struct kvdb_keylock *handle, void **cookiep) HSE_MOCK;

void
kvdb_keylock_list_unlock(void *cookie) HSE_MOCK;

void
kvdb_keylock_perfc_init(struct kvdb_keylock *handle_out, struct perfc_set *perfc_set);

merr_t
kvdb_keylock_lock(
    struct kvdb_keylock *hklock,
    struct kvdb_ctxn_locks *hlocks,
    uint64_t hash,
    uint64_t start_seq) HSE_MOCK;

merr_t
kvdb_ctxn_locks_init(void) HSE_COLD;

void
kvdb_ctxn_locks_fini(void) HSE_COLD;

uint64_t
kvdb_ctxn_locks_count(struct kvdb_ctxn_locks *ctxn_locks_handle) HSE_MOCK;

merr_t
kvdb_ctxn_locks_create(struct kvdb_ctxn_locks **handle) HSE_MOCK;

void
kvdb_ctxn_locks_destroy(struct kvdb_ctxn_locks *ctxn_locks_handle) HSE_MOCK;

uint64_t
kvdb_ctxn_locks_end_seqno(uint32_t desc) HSE_MOCK;

struct kvdb_ctxn_locks *
kvdb_ctxn_locks_desc2locks(uint32_t desc) HSE_MOCK;

void
kvdb_keylock_release_locks(struct kvdb_keylock *klock_handle, struct kvdb_ctxn_locks *locks_handle)
    HSE_MOCK;

/**
 * kvdb_keylock_enqueue_locks() - Add locks to the deferred list at the right
 *                               position (as determined by end_seqno).
 * @handle:    handle to transaction's write locks.
 * @end_seqno: end seqno of transaction.
 * @cookie:    identifies dlock from the per-cpu buckets.
 */
void
kvdb_keylock_enqueue_locks(struct kvdb_ctxn_locks *handle, uint64_t end_seqno, void *cookie)
    HSE_MOCK;

void
kvdb_keylock_prune_own_locks(struct kvdb_keylock *kl_handle, struct kvdb_ctxn_locks *locks_handle);

void
kvdb_keylock_expire(struct kvdb_keylock *klock, uint64_t min_view_seqno, uint64_t spin) HSE_MOCK;

#if HSE_MOCKING
#include "kvdb_keylock_ut.h"
#endif /* HSE_MOCKING */

#endif
