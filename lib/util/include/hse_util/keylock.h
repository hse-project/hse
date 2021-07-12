/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_KEYLOCK_H
#define HSE_CORE_KEYLOCK_H

/* MTF_MOCK_DECL(keylock) */

#include <hse_util/hse_err.h>

/* clang-format off */

#define KLE_PSL_MAX     (1u << 15)

struct keylock;

typedef bool keylock_cb_fn(u64 start_seq, uint rock1, uint *new_rock);

/* MTF_MOCK */
merr_t
keylock_create(keylock_cb_fn *cb_fun, struct keylock **handle_out);

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
    struct keylock *handle,
    u64             hash,
    u64             start_seq,
    uint            rock,
    bool           *inherited);

/* clang-format on */

void
keylock_unlock(struct keylock *handle, u64 hash, uint rock);

#if HSE_MOCKING
void
keylock_search(struct keylock *handle, u64 hash, uint *index);

#include "keylock_ut.h"
#endif

#endif
