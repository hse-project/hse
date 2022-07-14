/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_KEYLOCK_H
#define HSE_CORE_KEYLOCK_H

/* MTF_MOCK_DECL(keylock) */

#include <stdbool.h>
#include <stdint.h>

#include <error/merr.h>

/* clang-format off */

#define KLE_PSL_MAX     (1u << 15)

struct keylock;

typedef bool keylock_cb_fn(uint32_t owner, uint64_t start_seq);

/* MTF_MOCK */
merr_t
keylock_create(keylock_cb_fn *cb_fun, struct keylock **handle_out);

void
keylock_destroy(struct keylock *handle);

/**
 * keylock_lock() - obtain an exclusive lock based on %hash
 * @handle:     handle from keylock_create()
 * @hash:       64-bit key to identify the lock
 * @owner:      keylock owner ID provided to keylock_cb_fn()
 * @start_seq:  (view seqno) provided to keylock_cb_fn()
 * @inherited:  %true if keylock_cb_fn() allowed inheritance
 *
 * The owner ID parameter is used to uniquely identify the holder
 * of the keylock should it be acquired outright or inherited.
 * Threads wishing to share ownership of a keylock should use
 * the same owner ID.
 *
 * For HSE, the owner is a unique descriptor used to locate the
 * lock collection object which contains all the keylocks held
 * by a transaction.
 */
merr_t
keylock_lock(
    struct keylock *handle,
    uint64_t        hash,
    uint32_t        owner,
    uint64_t        start_seq,
    bool           *inherited);

/* clang-format on */

void
keylock_unlock(struct keylock *handle, uint64_t hash, uint32_t owner);

#if HSE_MOCKING
void
keylock_search(struct keylock *handle, uint64_t hash, unsigned int *index);

#include "keylock_ut.h"
#endif

#endif
