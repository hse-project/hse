/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_RWSEM_H
#define HSE_PLATFORM_RWSEM_H

/*
 * Summary:
 *
 *   init_rwsem -- intialize to unlocked state
 *
 *   down_read/down_write -- acquire lock for reading/writing
 *
 *   down_read_tryock/down_write_trylock
 *     -- try to acquire lock for reading/writing.
 *        returns !0 on success, 0 on fail.
 *
 *   up_read/up_write -- release lcok for reading/writing
 *
 * NOTES:
 *  - This implementation uses classic read/write locks and
 *    allows (1) one writer with no readers, or (2) no writers with
 *    multiple readers.
 */

#include <hse_util/assert.h>
#include <hse_util/logging.h>

#include <pthread.h>

struct rw_semaphore {
    pthread_rwlock_t rwsemlock;
};

#define __RWSEM_INITIALIZER(name)               \
    {                                           \
        .rwsemlock = PTHREAD_RWLOCK_INITIALIZER \
    }

#define DECLARE_RWSEM(name) struct rw_semaphore name = __RWSEM_INITIALIZER(name)

static inline void
init_rwsem(struct rw_semaphore *sem)
{
    struct rw_semaphore  tmp;
    pthread_rwlockattr_t attr;
    int                  rc;

    rc = pthread_rwlockattr_init(&attr);
    if (rc)
        hse_log(HSE_INFO "pthread_rwlockattr_init() failed: %d", rc);

    rc = pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NP);
    if (rc)
        hse_log(HSE_INFO "pthread_rwlockattr_setkind_np() failed: %d", rc);

    rc = pthread_rwlock_init(&tmp.rwsemlock, &attr);
    if (rc)
        hse_log(HSE_INFO "pthread_rwlock_init() failed: %d", rc);

    rc = pthread_rwlockattr_destroy(&attr);
    if (rc)
        hse_log(HSE_INFO "pthread_rwlockattr_destroy() failed: %d", rc);

    *sem = tmp;
}

static inline void
init_rwsem_reader(struct rw_semaphore *sem)
{
    int rc;

    rc = pthread_rwlock_init(&sem->rwsemlock, NULL);
    if (rc)
        hse_log(HSE_INFO "pthread_rwlock_init() failed: %d", rc);
}

static __always_inline void
down_read(struct rw_semaphore *sem)
{
    int rc __maybe_unused;

    rc = pthread_rwlock_rdlock(&sem->rwsemlock);
    assert(rc == 0);
}

static __always_inline void
down_write(struct rw_semaphore *sem)
{
    int rc __maybe_unused;

    rc = pthread_rwlock_wrlock(&sem->rwsemlock);
    assert(rc == 0);
}

/* The trylock variants are not currently in use, so they're
 * ifdef'd out to appease Bullseye...
 */
#if 0
/* Return nonzero on success, zero on fail */
static __always_inline
int
down_read_trylock(struct rw_semaphore *sem)
{
    int rc;

    rc = pthread_rwlock_tryrdlock(&sem->rwsemlock);

    assert(rc == 0 || rc == EBUSY);

    return rc == 0;
}

/* Return nonzero on success, zero on fail */
static __always_inline
int
down_write_trylock(struct rw_semaphore *sem)
{
    int rc;

    rc = pthread_rwlock_trywrlock(&sem->rwsemlock);

    assert(rc == 0 || rc == EBUSY);

    return rc == 0;
}
#endif

static __always_inline void
up_read(struct rw_semaphore *sem)
{
    int rc __maybe_unused;

    rc = pthread_rwlock_unlock(&sem->rwsemlock);
    assert(rc == 0);
}

static __always_inline void
up_write(struct rw_semaphore *sem)
{
    int rc __maybe_unused;

    rc = pthread_rwlock_unlock(&sem->rwsemlock);
    assert(rc == 0);
}

#define down_read_nested(sem, subclass) down_read(sem)
#define down_write_nested(sem, subclass) down_write(sem)

#endif
