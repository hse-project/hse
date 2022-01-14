/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_RMLOCK_H
#define HSE_RMLOCK_H

#include <hse_util/atomic.h>

#include <pthread.h>

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
    u32                 rm_bktmax;

    atomic_int          rm_writer HSE_ALIGNED(64);
    pthread_rwlock_t    rm_rwlock;

    struct rmlock_bkt   rm_bkt;
};

merr_t rmlock_init(struct rmlock *lock) HSE_COLD;
void rmlock_destroy(struct rmlock *lock) HSE_COLD;
void rmlock_rlock(struct rmlock *lock, void **cookiep);
void rmlock_runlock(void *cookie);
void rmlock_yield(struct rmlock *lock, void **cookiep);
void rmlock_wlock(struct rmlock *lock);
void rmlock_wunlock(struct rmlock *lock);

/* clang-format on */

#endif
