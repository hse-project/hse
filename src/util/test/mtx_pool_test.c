/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/platform.h>
#include <hse_util/atomic.h>
#include <hse_util/mtx_pool.h>

#include <pthread.h>

static int
mtx_pool_test_pre(struct mtf_test_info *ti)
{
    return 0;
}

static int
mtx_pool_test_post(struct mtf_test_info *ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(mtx_pool_test);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(mtx_pool_test, mtx_pool_test_pre, mtx_pool_test_post);

/* Create and delete various sized mutex pools..
 */
MTF_DEFINE_UTEST(mtx_pool_test, mtx_pool_test_mtx_pool_create)
{
    struct mtx_pool *pool;
    int              i;

    for (i = 0; i < 1000; ++i) {
        pool = mtx_pool_create(i);
        ASSERT_NE(NULL, pool);

        mtx_pool_destroy(pool);
    }

    mtx_pool_destroy(NULL);
}

/* Create a mutex pool and exercise locking..
 */
MTF_DEFINE_UTEST(mtx_pool_test, mtx_pool_test_mtx_pool_lock)
{
    struct mtx_pool *pool;
    struct mtx_node *node;
    int              i, j;

    for (i = 0; i < 100; ++i) {
        pool = mtx_pool_create(i);
        ASSERT_NE(NULL, pool);

        for (j = 0; j < 1000; ++j) {
            node = mtx_pool_lock(pool, j);
            ASSERT_NE(NULL, node);
            ASSERT_EQ(NULL, mtx_pool_trylock(pool, j));

            mtx_pool_unlock(node);

            node = mtx_pool_trylock(pool, j);
            ASSERT_NE(NULL, node);

            mtx_pool_unlock(node);
        }

        mtx_pool_destroy(pool);
    }
}

/* Create a mutex pool and exercise "lockall" locking..
 */
MTF_DEFINE_UTEST(mtx_pool_test, mtx_pool_test_mtx_pool_lockall)
{
    struct mtx_pool *pool;
    struct mtx_node *node;
    size_t           poolsz;
    int              i, j;

    poolsz = 777;

    pool = mtx_pool_create(poolsz);
    ASSERT_NE(NULL, pool);

    for (i = 0; i < 100; ++i) {
        mtx_pool_lock_all(pool);

        for (j = 0; j < poolsz; ++j) {
            node = mtx_pool_trylock(pool, j);
            ASSERT_EQ(NULL, node);
        }

        mtx_pool_unlock_all(pool, (i & 1) == 0);
    }

    mtx_pool_destroy(pool);
}

struct td_args {
    pthread_t        td;
    int              idx;
    struct mtx_pool *pool;
    atomic_t *       awake;
    atomic_t *       asleep;
};

static void *
mtx_pool_test_wait(void *arg)
{
    struct td_args * ta = arg;
    struct mtx_node *node;

    node = mtx_pool_lock(ta->pool, pthread_self() >> 12);

    atomic_inc(ta->asleep);
    atomic_dec(ta->awake);

    mtx_pool_wait(node);

    atomic_dec(ta->asleep);
    atomic_inc(ta->awake);

    mtx_pool_unlock(node);

    return NULL;
}

/* Create a mutex pool and exercise sleep/wakeup..
 */
MTF_DEFINE_UTEST(mtx_pool_test, mtx_pool_test_mtx_pool_wait)
{
    struct td_args * ta_base;
    struct mtx_pool *pool;
    int              tdmax;
    atomic_t         awake;
    atomic_t         asleep;
    int              rc;
    int              i;

    tdmax = 257;
    atomic_set(&awake, tdmax);
    atomic_set(&asleep, 0);

    pool = mtx_pool_create(59);
    ASSERT_NE(NULL, pool);

    ta_base = calloc(tdmax, sizeof(*ta_base));
    ASSERT_NE(NULL, ta_base);

    mtx_pool_lock_all(pool);

    for (i = 0; i < tdmax; ++i) {
        struct td_args *ta = ta_base + i;

        ta->idx = i;
        ta->pool = pool;
        ta->awake = &awake;
        ta->asleep = &asleep;

        rc = pthread_create(&ta->td, NULL, mtx_pool_test_wait, ta);

        if (rc && errno == EAGAIN) {
            ASSERT_GT(tdmax, 32);
            tdmax = i;
            break;
        }
    }

    mtx_pool_unlock_all(pool, false);

    /* Wreak havoc on the mutex pool..
     */
    while (atomic_read(&awake) > 0) {
        mtx_pool_lock_all(pool);
        mtx_pool_unlock_all(pool, false);
    }

    while (atomic_read(&asleep) < tdmax) {
        mtx_pool_lock_all(pool);
        mtx_pool_unlock_all(pool, false);
    }

    /* Lock/unlock entire pool, all threads should stay asleep...
     */
    mtx_pool_lock_all(pool);
    ASSERT_EQ(atomic_read(&asleep), tdmax);
    ASSERT_EQ(atomic_read(&awake), 0);
    mtx_pool_unlock_all(pool, false);

    ASSERT_EQ(atomic_read(&asleep), tdmax);
    ASSERT_EQ(atomic_read(&awake), 0);

    /* Lock/unlock-wakeup the entire pool, all threads
     * should awaken and exit..
     */
    mtx_pool_lock_all(pool);
    ASSERT_EQ(atomic_read(&asleep), tdmax);
    ASSERT_EQ(atomic_read(&awake), 0);
    mtx_pool_unlock_all(pool, true);

    for (i = 0; i < tdmax; ++i) {
        void *rval;

        rc = pthread_join(ta_base[i].td, &rval);
        ASSERT_EQ(0, rc);
    }

    ASSERT_EQ(atomic_read(&asleep), 0);
    ASSERT_EQ(atomic_read(&awake), tdmax);

    free(ta_base);

    mtx_pool_destroy(pool);
}

MTF_END_UTEST_COLLECTION(mtx_pool_test);
