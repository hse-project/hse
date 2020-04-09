/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_KEYLOCK_H
#define HSE_CORE_KEYLOCK_H

#include <hse_util/hse_err.h>

#define KLE_PLEN_MAX (1u << 16)

struct keylock;
struct keylock_stats {
    u32 kls_num_occupied;
    u32 kls_max_occupied;
    u32 kls_max_probe_len;
    u64 kls_collisions;
    u64 kls_table_full;
};

struct keylock_cb_rock;

typedef bool
keylock_cb_fn(u64 start_seq, struct keylock_cb_rock *rock1, struct keylock_cb_rock **new_rock);

merr_t
keylock_create(u64 num_ents, keylock_cb_fn *cb_fun, struct keylock **handle_out);

/**
 * keylock_lock() - obtain an exclusive lock based on %hash
 * @handle:     handle from keylock_create()
 * @hash:       48-bit hash to uniquely identify the lock
 * @start_seq:  provided to keylock_cb_fn()
 * @rock:       provided to keylock_cb_fn()
 * @inherited:  %true if keylock_cb_fn() allowed inheritance
 *
 * Note:  Only the least significant 48 bits of %hash are used
 * to uniquely identify the lock.
 */
merr_t
keylock_lock(
    struct keylock *        handle,
    u64                     hash,
    u64                     start_seq,
    struct keylock_cb_rock *rock,
    bool *                  inherited);

void
keylock_unlock(struct keylock *handle, u64 hash, struct keylock_cb_rock *rock);

void
keylock_search(struct keylock *handle, u64 hash, u64 *index);

void
keylock_destroy(struct keylock *handle);

void
keylock_query_stats(struct keylock *handle, struct keylock_stats *stats);

#endif
