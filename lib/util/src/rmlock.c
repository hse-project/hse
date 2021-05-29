/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/minmax.h>
#include <hse_util/rmlock.h>

#define RMLOCK_MAX      (128)

#define rmlock_cmpxchg(_ptr, _oldp, _new) \
    __atomic_compare_exchange_n((_ptr), (_oldp), (_new), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)


static HSE_ALWAYS_INLINE uint
rmlock_bktidx(struct rmlock *lock)
{
    return raw_smp_processor_id() % RMLOCK_MAX;
}

merr_t
rmlock_init(struct rmlock *lock)
{
    size_t sz;
    int i;

    if (!lock)
        return merr(EINVAL);

    atomic_set(&lock->rm_writer, 0);

    lock->rm_bktmax = min_t(u32, get_nprocs_conf(), RMLOCK_MAX);
    if (lock->rm_bktmax < 2)
        lock->rm_bktmax = RMLOCK_MAX;

    sz = sizeof(*lock->rm_bktv) * RMLOCK_MAX;

    lock->rm_bktv = alloc_aligned(sz, alignof(*lock->rm_bktv));
    if (!lock->rm_bktv)
        return merr(ENOMEM);

    /* Note:  Unlike pthread r/w locks, linux rw_semaphore prefers
     * writers to readers.
     */
    for (i = 0; i < RMLOCK_MAX; ++i) {
        lock->rm_bktv[i].rm_rwcnt = 0;
        lock->rm_bktv[i].rm_lockp = lock;
    }

    /* rm_sema is used to serialize writers.  Readers acquire it only if
     * a writer is active.  By making it prefer readers, we ensure that
     * all readers waiting on an active writer will be allowed to proceed
     * without interruption by a waiting writer.
     * Note that this will not starve writers, as the next writer will
     * be permitted to acquire the write only after all readers waiting
     * on rm_sema have released their read locks.
     */
    init_rwsem_reader(&lock->rm_sema);
    lock->rm_bkt.rm_rwcnt = U64_MAX;
    lock->rm_bkt.rm_lockp = lock;

    return 0;
}

void
rmlock_destroy(struct rmlock *lock)
{
    if (lock)
        free_aligned(lock->rm_bktv);
}

void
rmlock_rlock(struct rmlock *lock, void **cookiep)
{
    struct rmlock_bkt *bkt;
    u64                val;

    bkt = lock->rm_bktv + rmlock_bktidx(lock);
    val = bkt->rm_rwcnt & ~(1ul << 63);

    while (!rmlock_cmpxchg(&bkt->rm_rwcnt, &val, val + 1)) {
        if (val & (1ul << 63)) {
            bkt = &lock->rm_bkt;
            down_read(&lock->rm_sema);
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
    u64                val;

    val = bkt->rm_rwcnt;

    if (val == U64_MAX) {
        up_read(&bkt->rm_lockp->rm_sema);
        return;
    }

    while (!rmlock_cmpxchg(&bkt->rm_rwcnt, &val, val - 1))
        ;
}

void
rmlock_yield(struct rmlock *lock, void **cookiep)
{
    struct rmlock_bkt *bkt;

    if (atomic_read(&lock->rm_writer)) {
        rmlock_runlock(*cookiep);

        bkt = &lock->rm_bkt;

        down_read(&lock->rm_sema);
        *cookiep = bkt;
    }
}

void
rmlock_wlock(struct rmlock *lock)
{
    struct rmlock_bkt *bkt;

    u8   busy[RMLOCK_MAX];
    uint i, n, x;
    u64  val;

    /* Serialize all writers on rm_sema, then set the write bit in
     * each reader lock to prevent new readers getting in.  Finally,
     * repeatedly check all the reader locks until all the readers
     * have either left or yielded.
     */
    down_write(&lock->rm_sema);
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
    u64                val;
    int                i;

    for (i = 0; i < lock->rm_bktmax; ++i, ++bkt) {
        val = 1ul << 63;

        while (!rmlock_cmpxchg(&bkt->rm_rwcnt, &val, 0)) {
            cpu_relax();
            val = 1ul << 63;
        }
    }

    atomic_set(&lock->rm_writer, 0);
    up_write(&lock->rm_sema);
}
