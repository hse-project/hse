/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_rmlock

#include <stdint.h>

#include <hse/util/alloc.h>
#include <hse/util/minmax.h>
#include <hse/util/platform.h>
#include <hse/util/rmlock.h>

#define RMLOCK_MAX (128)

#define rmlock_cmpxchg(_ptr, _oldp, _new) atomic_cmpxchg((_ptr), (_oldp), (_new))

static HSE_ALWAYS_INLINE uint
rmlock_bktidx(struct rmlock *lock)
{
    return hse_getcpu(NULL) % RMLOCK_MAX;
}

merr_t
rmlock_init(struct rmlock *lock)
{
    size_t sz;
    int rc, i;

    if (!lock)
        return merr(EINVAL);

    atomic_set(&lock->rm_writer, 0);

    lock->rm_bktmax = min_t(uint32_t, get_nprocs_conf(), RMLOCK_MAX);
    if (lock->rm_bktmax < 2)
        lock->rm_bktmax = RMLOCK_MAX;

    sz = sizeof(*lock->rm_bktv) * RMLOCK_MAX;

    lock->rm_bktv = aligned_alloc(__alignof__(*lock->rm_bktv), sz);
    if (!lock->rm_bktv)
        return merr(ENOMEM);

    for (i = 0; i < RMLOCK_MAX; ++i) {
        lock->rm_bktv[i].rm_rwcnt = 0;
        lock->rm_bktv[i].rm_lockp = lock;
    }

    /* rm_rwlock is used to serialize writers.  Readers acquire it only if
     * a writer is active.  By making it prefer readers, we ensure that
     * all readers waiting on an active writer will be allowed to proceed
     * without interruption by a waiting writer.
     * Note that this will not starve writers, as the next writer will be
     * permitted to acquire the write lock only after all readers waiting
     * on rm_rwlock have released their read locks.
     */
    rc = pthread_rwlock_init(&lock->rm_rwlock, NULL);
    if (rc) {
        free(lock->rm_bktv);
        return merr(rc);
    }

    lock->rm_bkt.rm_rwcnt = UINT64_MAX;
    lock->rm_bkt.rm_lockp = lock;

    return 0;
}

void
rmlock_destroy(struct rmlock *lock)
{
    int rc;

    if (!lock)
        return;

    rc = pthread_rwlock_destroy(&lock->rm_rwlock);
    if (rc)
        abort();

    free(lock->rm_bktv);
}

void
rmlock_rlock(struct rmlock *lock, void **cookiep)
{
    struct rmlock_bkt *bkt;
    uint64_t val;
    int rc;

    bkt = lock->rm_bktv + rmlock_bktidx(lock);
    val = bkt->rm_rwcnt & ~(1ul << 63);

    while (!rmlock_cmpxchg(&bkt->rm_rwcnt, &val, val + 1)) {
        if (val & (1ul << 63)) {
            bkt = &lock->rm_bkt;

            rc = pthread_rwlock_rdlock(&lock->rm_rwlock);
            if (rc)
                abort();
            break;
        }

        cpu_relax();
        val &= ~(1ul << 63);
    }

    *cookiep = bkt;
}

void
rmlock_runlock(void *cookie)
{
    struct rmlock_bkt *bkt = cookie;
    uint64_t val;
    int rc;

    val = bkt->rm_rwcnt;

    if (val == UINT64_MAX) {
        rc = pthread_rwlock_unlock(&bkt->rm_lockp->rm_rwlock);
        if (rc)
            abort();
        return;
    }

    while (!rmlock_cmpxchg(&bkt->rm_rwcnt, &val, val - 1))
        continue;
}

void
rmlock_yield(struct rmlock *lock, void **cookiep)
{
    struct rmlock_bkt *bkt;
    int rc;

    if (atomic_read(&lock->rm_writer)) {
        rmlock_runlock(*cookiep);

        rc = pthread_rwlock_rdlock(&lock->rm_rwlock);
        if (rc)
            abort();

        bkt = &lock->rm_bkt;
        *cookiep = bkt;
    }
}

void
rmlock_wlock(struct rmlock *lock)
{
    struct rmlock_bkt *bkt;

    uint8_t busy[RMLOCK_MAX];
    uint i, n, x;
    uint64_t val;
    int rc;

    /* Serialize all writers on rm_rwlock, then set the write bit in
     * each reader lock to prevent new readers getting in.  Finally,
     * repeatedly check all the reader locks until all the readers
     * have either left or yielded.
     */
    rc = pthread_rwlock_wrlock(&lock->rm_rwlock);
    if (rc)
        abort();

    atomic_set(&lock->rm_writer, 1);
    bkt = lock->rm_bktv;

    for (i = n = 0; i < lock->rm_bktmax; ++i, ++bkt) {
        val = bkt->rm_rwcnt;

        while (!rmlock_cmpxchg(&bkt->rm_rwcnt, &val, val | (1ul << 63))) {
            cpu_relax();
            val = bkt->rm_rwcnt;
        }

        if (val)
            busy[n++] = i;
    }

    while (n > 0) {
        for (i = x = 0; i < n; ++i) {
            bkt = lock->rm_bktv + busy[i];

            if (bkt->rm_rwcnt != 1ul << 63) {
                busy[x++] = busy[i];
                cpu_relax();
            }
        }

        n = x;
    }
}

void
rmlock_wunlock(struct rmlock *lock)
{
    struct rmlock_bkt *bkt = lock->rm_bktv;
    uint64_t val;
    int rc, i;

    for (i = 0; i < lock->rm_bktmax; ++i, ++bkt) {
        val = 1ul << 63;

        while (!rmlock_cmpxchg(&bkt->rm_rwcnt, &val, 0)) {
            cpu_relax();
            val = 1ul << 63;
        }
    }

    atomic_set(&lock->rm_writer, 0);

    rc = pthread_rwlock_unlock(&lock->rm_rwlock);
    if (rc)
        abort();
}

#if HSE_MOCKING
#include "rmlock_ut_impl.i"
#endif
