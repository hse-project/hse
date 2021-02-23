/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_RMLOCK_H
#define HSE_RMLOCK_H

#include <hse_util/atomic.h>
#include <hse_util/rwsem.h>

/**
 * A "read-mostly" lock.
 */
struct rmlock;

struct rmlock_bkt {
    u64            rm_rwcnt;
    struct rmlock *rm_lockp;
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

struct rmlock {
    atomic_t            rm_writer;
    u32                 rm_bktmax;
    struct rw_semaphore rm_sema;
    struct rmlock_bkt   rm_bkt;
    struct rmlock_bkt * rm_bktv;
};

merr_t
rmlock_init(struct rmlock *lock) HSE_COLD;
void
rmlock_destroy(struct rmlock *lock) HSE_COLD;
void
rmlock_rlock(struct rmlock *lock, void **cookiep);
void
rmlock_runlock(void *cookie);
void
rmlock_yield(struct rmlock *lock, void **cookiep);
void
rmlock_wlock(struct rmlock *lock);
void
rmlock_wunlock(struct rmlock *lock);

#endif
