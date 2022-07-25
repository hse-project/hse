/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_PFX_RMLOCK_H
#define HSE_KVDB_PFX_RMLOCK_H

#include <stdint.h>

#include <hse/error/merr.h>

struct kvdb_pfxlock;
struct kvdb_pfxlock_entry;

struct viewset;

/**
 * kvdb_pfxlock_create() - Create a new kvdb_pfxlock instance
 *
 * @txn_viewset: txn viewset of the kvdb
 * @pfxlock_out: (output) created kvdb_pfxlock instance
 */
merr_t
kvdb_pfxlock_create(struct viewset *txn_viewset, struct kvdb_pfxlock **pfxlock_out) HSE_MOCK;

/**
 * kvdb_pfxlock_destroy() - Destroy kvdb_pfxlock
 *
 * @pfx_lock:
 */
void
kvdb_pfxlock_destroy(struct kvdb_pfxlock *pfx_lock) HSE_MOCK;

/**
 * kvdb_pfxlock_shared() - Acquire a shared lock on pfx
 *
 * @pfx_lock:    kvdb_pfxlock object
 * @hash:        hash of prefix
 * @start_seqno: view_seqno of calling txn
 * @cookie:      (output) lock handle
 */
merr_t
kvdb_pfxlock_shared(
    struct kvdb_pfxlock *pfx_lock,
    uint64_t hash,
    uint64_t start_seqno,
    void **cookie) HSE_MOCK;

/**
 * kvdb_pfxlock_excl() - Acquire an exclusive lock on pfx
 *
 * @pfx_lock:    kvdb_pfxlock object
 * @hash:        hash of pfx
 * @start_seqno: view_seqno of calling txn
 * @cookie:      (input/output) lock handle. If the caller holds a shared lock, it must set
 *               *cookie to a non-NULL value.
 */
merr_t
kvdb_pfxlock_excl(struct kvdb_pfxlock *pfx_lock, uint64_t hash, uint64_t start_seqno, void **cookie)
    HSE_MOCK;

/**
 * kvdb_pfxlock_seqno_pub() - Publish end seqno to all entries of a pfx
 *
 * @pfx_lock:  kvdb_pfxlock object
 * @end_seqno: end seqno to which  all entries with pfx will be set.
 * @cookie:    lock handle
 */
void
kvdb_pfxlock_seqno_pub(struct kvdb_pfxlock *pfx_lock, uint64_t end_seqno, void *cookie) HSE_MOCK;

#if HSE_MOCKING
#include "kvdb_pfxlock_ut.h"
#endif /* HSE_MOCKING */

#endif
