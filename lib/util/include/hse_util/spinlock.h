/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_SPINLOCK_H
#define HSE_PLATFORM_SPINLOCK_H

#include <pthread.h>

#include <hse_util/assert.h>
#include <hse_util/compiler.h>

typedef struct {
    pthread_spinlock_t lock;
} spinlock_t;

static inline void
spin_lock_init(spinlock_t *lock)
{
    int rc HSE_MAYBE_UNUSED;

    rc = pthread_spin_init(&lock->lock, PTHREAD_PROCESS_PRIVATE);
    assert(rc == 0);
}

static inline void
spin_lock(spinlock_t *lock)
{
    int rc HSE_MAYBE_UNUSED;

    rc = pthread_spin_lock(&lock->lock);
    assert(rc == 0);
}

static inline int
spin_trylock(spinlock_t *lock)
{
    int rc;

    rc = pthread_spin_trylock(&lock->lock);

    return rc ? 0 : 1;
}

static inline void
spin_unlock(spinlock_t *lock)
{
    int rc HSE_MAYBE_UNUSED;

    rc = pthread_spin_unlock(&lock->lock);
    assert(rc == 0);
}

#endif
