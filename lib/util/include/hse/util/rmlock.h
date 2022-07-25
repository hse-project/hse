/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_RMLOCK_H
#define HSE_RMLOCK_H

/* MTF_MOCK_DECL(rmlock) */

#include <pthread.h>
#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/util/arch.h>
#include <hse/util/atomic.h>
#include <hse/util/compiler.h>

/* clang-format off */

/**
 * A "read-mostly" lock.
 */
struct rmlock;

struct rmlock_bkt {
    atomic_uint_fast64_t  rm_rwcnt HSE_ACP_ALIGNED;
    struct rmlock        *rm_lockp;
};

struct rmlock {
    struct rmlock_bkt  *rm_bktv;
    uint32_t            rm_bktmax;

    atomic_int          rm_writer HSE_ALIGNED(64);
    pthread_rwlock_t    rm_rwlock;

    struct rmlock_bkt   rm_bkt;
};

merr_t rmlock_init(struct rmlock *lock) HSE_COLD HSE_MOCK;

void rmlock_destroy(struct rmlock *lock) HSE_COLD HSE_MOCK;

void rmlock_rlock(struct rmlock *lock, void **cookiep) HSE_MOCK;

void rmlock_runlock(void *cookie) HSE_MOCK;

void rmlock_yield(struct rmlock *lock, void **cookiep) HSE_MOCK;

void rmlock_wlock(struct rmlock *lock) HSE_MOCK;

void rmlock_wunlock(struct rmlock *lock) HSE_MOCK;

/* clang-format on */

#if HSE_MOCKING
#include "rmlock_ut.h"
#endif /* HSE_MOCKING */

#endif
