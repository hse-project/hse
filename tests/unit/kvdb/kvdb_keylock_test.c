/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/hse_err.h>
#include <hse_util/atomic.h>
#include <hse_util/keylock.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_ctxn.h>

#include <kvdb/kvdb_keylock.h>

#define MOCK_SET(group, func) mtfm_##group##func##_set(func)

atomic64_t kvdb_seq;

int
mapi_pre(struct mtf_test_info *ti)
{
    srand(time(NULL));

    mapi_inject_clear();

    return 0;
}

int
mapi_post(struct mtf_test_info *ti)
{
    mapi_inject_clear();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(kvdb_keylock_test)

MTF_DEFINE_UTEST_PREPOST(kvdb_keylock_test, kvdb_keylock_alloc, mapi_pre, mapi_post)
{
    struct kvdb_keylock *handle;
    merr_t               err = 0;

    ASSERT_EQ(0, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    err = kvdb_keylock_create(&handle, 16);

    ASSERT_EQ(err, 0);
    ASSERT_NE(0, handle);
    ASSERT_NE(0, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    kvdb_keylock_destroy(handle);
    ASSERT_EQ(mapi_calls(mapi_idx_malloc), mapi_calls(mapi_idx_free));

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);

    err = kvdb_keylock_create(&handle, 16);

    ASSERT_EQ(0, handle);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    mapi_inject_once_ptr(mapi_idx_malloc, 2, NULL);

    err = kvdb_keylock_create(&handle, 16);

    ASSERT_EQ(0, handle);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    kvdb_keylock_destroy(handle);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_keylock_test, kvdb_ctxn_locks_alloc, mapi_pre, mapi_post)
{
    struct kvdb_keylock *   klock_handle;
    struct kvdb_ctxn_locks *locks_handle;
    merr_t                  err = 0;

    ASSERT_EQ(0, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    err = kvdb_keylock_create(&klock_handle, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, klock_handle);
    ASSERT_GE(mapi_calls(mapi_idx_malloc), 16);

    err = kvdb_ctxn_locks_create(&locks_handle);
    ASSERT_EQ(err, 0);
    ASSERT_NE(NULL, locks_handle);
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    kvdb_ctxn_locks_destroy(locks_handle);
    kvdb_keylock_destroy(klock_handle);

    ASSERT_LE(mapi_calls(mapi_idx_malloc), mapi_calls(mapi_idx_free));
}

MTF_DEFINE_UTEST_PREPOST(kvdb_keylock_test, keylock_lock_one_ctxn, mapi_pre, mapi_post)
{
    int                     i = 0;
    const int               num_keys = 500;
    struct kvdb_keylock *   klock_handle;
    struct kvdb_ctxn_locks *locks_handle;
    merr_t                  err = 0;
    u64                     magic = 0x12345678UL << 32;
    u64                     hash = magic;

    err = kvdb_keylock_create(&klock_handle, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock_handle);

    err = kvdb_ctxn_locks_create(&locks_handle);
    ASSERT_EQ(err, 0);
    ASSERT_NE(0, locks_handle);

    /* Insert unique keys. */
    for (i = 0; i < num_keys; i++) {
        err = kvdb_keylock_lock(klock_handle, locks_handle, magic | i, 0);
        ASSERT_EQ(err, 0);
    }

    kvdb_keylock_release_locks(klock_handle, locks_handle);
    kvdb_ctxn_locks_destroy(locks_handle);

    err = kvdb_ctxn_locks_create(&locks_handle);
    ASSERT_EQ(err, 0);
    ASSERT_NE(0, locks_handle);

    /* Lock and unlock unique keys. */
    for (i = 0; i < num_keys; i++) {
        err = kvdb_keylock_lock(klock_handle, locks_handle, magic | i, 0);
        ASSERT_EQ(err, 0);
    }

    kvdb_keylock_release_locks(klock_handle, locks_handle);
    kvdb_ctxn_locks_destroy(locks_handle);

    err = kvdb_ctxn_locks_create(&locks_handle);
    ASSERT_EQ(err, 0);
    ASSERT_NE(0, locks_handle);

    for (i = 0; i < num_keys; i++) {
        /* Insert hash values that collide every 7th iteration (within
         * same transaction), this shouldn't fail. */
        if (i % 7)
            hash = rand();

        err = kvdb_keylock_lock(klock_handle, locks_handle, hash, 0);
        ASSERT_EQ(err, 0);
    }

    kvdb_keylock_release_locks(klock_handle, locks_handle);
    kvdb_ctxn_locks_destroy(locks_handle);

    err = kvdb_ctxn_locks_create(&locks_handle);
    ASSERT_EQ(err, 0);
    ASSERT_NE(0, locks_handle);

    for (i = 0; i < num_keys; i++) {
        const int entrymax = 600; /* larger than ctxn_lock_entrymax */

        /* Fail RB tree node allocation every 13th iteration. This
         * attempt to lock the key must fail. */
        hash = magic | i;

        if (i % 13 == 0 && i > entrymax)
            mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);

        err = kvdb_keylock_lock(klock_handle, locks_handle, hash, 0);

        if (i % 13 || entrymax > i) {
            ASSERT_EQ(err, 0);
        } else {
            ASSERT_EQ(ENOMEM, merr_errno(err));

            /* Validate that the key was unlocked and the
             * second attempt to lock it succeeds.
             */
            err = kvdb_keylock_lock(klock_handle, locks_handle, hash, 0);
            ASSERT_EQ(err, 0);
        }
    }

    kvdb_keylock_release_locks(klock_handle, locks_handle);
    kvdb_ctxn_locks_destroy(locks_handle);
    kvdb_keylock_destroy(klock_handle);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_keylock_test, keylock_lock_ctxn_max, mapi_pre, mapi_post)
{
    int                     i = 0;
    int                     num_keys;
    struct kvdb_keylock *   klock_handle;
    struct kvdb_ctxn_locks *locks_handle;
    merr_t                  err = 0;

    err = kvdb_keylock_create(&klock_handle, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock_handle);

    err = kvdb_ctxn_locks_create(&locks_handle);
    ASSERT_EQ(err, 0);
    ASSERT_NE(0, locks_handle);

    num_keys = (KLE_PSL_MAX * 16) / 4;

    /* Insert unique keys. */
    for (i = 0; i < num_keys + 100; i++) {
        err = kvdb_keylock_lock(klock_handle, locks_handle, i, 0);
        if (i > num_keys)
            ASSERT_EQ(E2BIG, merr_errno(err));
        else
            ASSERT_EQ(err, 0);
    }

    kvdb_keylock_release_locks(klock_handle, locks_handle);
    kvdb_ctxn_locks_destroy(locks_handle);
    kvdb_keylock_destroy(klock_handle);
}

struct parallel_lock_arg {
    struct kvdb_keylock *   klock_handle;
    struct kvdb_ctxn_locks *locks_handle;
    pthread_barrier_t *     lock_barrier;
    int                     num_hash;
    atomic_t *              owner_thread;
    int                     num;
};

void *
parallel_lock_helper(void *arg)
{
    struct parallel_lock_arg *p = (struct parallel_lock_arg *)arg;
    struct kvdb_keylock *     klock_handle = p->klock_handle;
    struct kvdb_ctxn_locks *  locks_handle = p->locks_handle;
    pthread_barrier_t *       barrier = p->lock_barrier;
    int                       num_hash = p->num_hash;
    int                       num = p->num;
    atomic_t *                owner_thread = p->owner_thread;
    merr_t                    err = 0;
    int                       i;
    u64                       hash = 0x12345678UL << 32;

    for (i = 0; i < num_hash; i++) {
        err = kvdb_keylock_lock(klock_handle, locks_handle, hash | i, 0);

        if (err == 0) {
            /* Only one transaction can successfully lock a key.
             * Note the owner thread.
             */
            VERIFY_EQ_RET(atomic_cmpxchg(owner_thread + i, 0, num), 0, 0);
        } else {
            VERIFY_EQ_RET(merr_errno(err), ECANCELED, 0);
        }

        VERIFY_EQ_RET(atomic_read(owner_thread + i) == num, err == 0, 0);

        err = kvdb_keylock_lock(klock_handle, locks_handle, hash | i, 0);

        if (atomic_read(owner_thread + i) == num) {
            VERIFY_EQ_RET(err, 0, 0);
            usleep(rand() % 256);
        } else {
            VERIFY_EQ_RET(merr_errno(err), ECANCELED, 0);
        }
    }

    pthread_barrier_wait(barrier);

    kvdb_keylock_release_locks(klock_handle, locks_handle);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(kvdb_keylock_test, keylock_lock_multiple_ctxn, mapi_pre, mapi_post)
{
    const int                num_threads = 32;
    const int                num_hash = 10000;
    pthread_t                thread_idv[num_threads];
    pthread_barrier_t        lock_barrier;
    struct parallel_lock_arg argstruct[num_threads];
    struct kvdb_keylock *    klock_handle;
    struct kvdb_ctxn_locks * locks_handle[num_threads];
    atomic_t                 owner_thread[10000] = {};
    merr_t                   err;
    int                      i, rc;

    err = kvdb_keylock_create(&klock_handle, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock_handle);

    pthread_barrier_init(&lock_barrier, NULL, num_threads);

    for (i = 0; i < num_threads; i++) {
        err = kvdb_ctxn_locks_create(&locks_handle[i]);
        ASSERT_EQ(err, 0);
        ASSERT_NE(0, locks_handle[i]);

        argstruct[i].klock_handle = klock_handle;
        argstruct[i].num_hash = num_hash;
        argstruct[i].lock_barrier = &lock_barrier;
        argstruct[i].owner_thread = owner_thread;
        argstruct[i].locks_handle = locks_handle[i];
        argstruct[i].num = i + 1;

        rc = pthread_create(thread_idv + i, 0, parallel_lock_helper, &argstruct[i]);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; i++) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    kvdb_keylock_destroy(klock_handle);
}

void
begin_ctxn(u64 *view_seqno)
{
    *view_seqno = atomic64_fetch_add(1, &kvdb_seq);
}

void
end_ctxn(bool commit, u64 *end_seqno)
{
    u64 inc = commit ? 2 : 1;
    *end_seqno = atomic64_fetch_add(inc, &kvdb_seq);
}

struct parallel_ctxn_arg {
    struct kvdb_keylock *   klock_handle;
    struct kvdb_ctxn_locks *locks_handle;
    pthread_barrier_t *     lock_barrier;
    u64                     view_seqno;
    int                     num;
};

void *
parallel_ctxn_helper(void *arg)
{
    struct parallel_ctxn_arg *p = (struct parallel_ctxn_arg *)arg;
    struct kvdb_keylock *     klock_handle = p->klock_handle;
    struct kvdb_ctxn_locks *  locks_handle = p->locks_handle;
    u64                       end_seqno, view_seqno, lockcnt = 0;
    u64                       num_hash = 100;
    bool                      commit = true;
    void *                    cookie;
    int                       i;

    usleep(rand() % 256);
    begin_ctxn(&view_seqno);

    for (i = 0; i < num_hash; i++)
        kvdb_keylock_lock(klock_handle, locks_handle, i + 1, 0);

    if (rand() % 50 > 48)
        commit = false;

    usleep(rand() % 512);

    if (!commit)
        kvdb_keylock_prune_own_locks(klock_handle, locks_handle);

    kvdb_keylock_list_lock(klock_handle, &cookie);
    lockcnt = kvdb_ctxn_locks_count(locks_handle);

    end_ctxn(commit, &end_seqno);
    if (lockcnt)
        kvdb_keylock_queue_locks(locks_handle, end_seqno, cookie);

    kvdb_keylock_list_unlock(cookie);

    if (!lockcnt) {
        kvdb_keylock_release_locks(klock_handle, locks_handle);
        kvdb_ctxn_locks_destroy(locks_handle);
    }

    kvdb_keylock_expire(klock_handle, view_seqno);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(kvdb_keylock_test, multiple_ctxn_end, mapi_pre, mapi_post)
{
    const int                num_threads = 96;
    struct kvdb_keylock *    klock_handle;
    pthread_t                thread_idv[num_threads];
    struct parallel_ctxn_arg argstruct[num_threads];
    struct kvdb_ctxn_locks * locks_handle[num_threads];
    merr_t                   err;
    int                      i, rc;

    atomic64_set(&kvdb_seq, 3234UL);

    err = kvdb_keylock_create(&klock_handle, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock_handle);

    for (i = 0; i < num_threads; i++) {
        err = kvdb_ctxn_locks_create(&locks_handle[i]);
        ASSERT_EQ(err, 0);
        ASSERT_NE(0, locks_handle[i]);

        argstruct[i].klock_handle = klock_handle;
        argstruct[i].locks_handle = locks_handle[i];
        argstruct[i].num = i + 1;

        rc = pthread_create(thread_idv + i, 0, parallel_ctxn_helper, &argstruct[i]);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; i++) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    kvdb_keylock_destroy(klock_handle);
}

MTF_END_UTEST_COLLECTION(kvdb_keylock_test);
