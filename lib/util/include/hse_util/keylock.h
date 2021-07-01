/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_KEYLOCK_H
#define HSE_CORE_KEYLOCK_H

/* MTF_MOCK_DECL(keylock) */

#include <hse_util/hse_err.h>

#define KLE_PLEN_MAX ((1u << 15) - 1)

struct keylock;
struct keylock_cb_rock;

typedef bool
keylock_cb_fn(u64 start_seq, struct keylock_cb_rock *rock1, struct keylock_cb_rock **new_rock);

/* MTF_MOCK */
merr_t
keylock_create(uint maxbkts, keylock_cb_fn *cb_fun, struct keylock **handle_out);

void
keylock_destroy(struct keylock *handle);

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

#if HSE_MOCKING
void
keylock_search(struct keylock *handle, u64 hash, uint *index);

#include "keylock_ut.h"
#endif

#endif
