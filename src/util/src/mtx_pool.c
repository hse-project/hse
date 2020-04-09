/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/slab.h>

#include <hse_util/mtx_pool.h>

struct mtx_node {
    __aligned(64) struct mutex sn_mtx;
    struct cv sn_cv;
};

struct mtx_pool {
    int             sp_nodec;
    struct mtx_node sp_nodev[];
};

struct mtx_pool *
mtx_pool_create(size_t nodes)
{
    struct mtx_pool *pool;
    size_t           max;
    int              i;

    max = (PAGE_SIZE - sizeof(*pool)) / sizeof(struct mtx_node);

    nodes = min_t(size_t, nodes, max);
    nodes = max_t(size_t, nodes, 1);

    pool = (void *)__get_free_page(GFP_KERNEL);
    if (pool) {
        int rc __maybe_unused;

        pool->sp_nodec = nodes;

        for (i = 0; i < nodes; ++i) {
            mutex_init_adaptive(&pool->sp_nodev[i].sn_mtx);
            cv_init(&pool->sp_nodev[i].sn_cv, "mtx_pool");
        }
    }

    return pool;
}

void
mtx_pool_destroy(struct mtx_pool *pool)
{
    int rc __maybe_unused;
    int    i;

    if (ev(!pool))
        return;

    for (i = 0; i < pool->sp_nodec; ++i) {
        mutex_destroy(&pool->sp_nodev[i].sn_mtx);
        cv_destroy(&pool->sp_nodev[i].sn_cv);
    }

    free_page((ulong)pool);
}

struct mtx_node *
mtx_pool_lock(struct mtx_pool *pool, uintptr_t hash)
{
    struct mtx_node *node;

    node = pool->sp_nodev + (hash % pool->sp_nodec);

    mutex_lock(&node->sn_mtx);

    return node;
}

struct mtx_node *
mtx_pool_trylock(struct mtx_pool *pool, uintptr_t hash)
{
    struct mtx_node *node;

    node = pool->sp_nodev + (hash % pool->sp_nodec);

    if (mutex_trylock(&node->sn_mtx))
        return node;

    return NULL;
}

void
mtx_pool_unlock(struct mtx_node *node)
{
    mutex_unlock(&node->sn_mtx);
}

void
mtx_pool_lock_all(struct mtx_pool *pool)
{
    struct mtx_node *node = pool->sp_nodev;

    while (node < pool->sp_nodev + pool->sp_nodec) {
        mutex_lock(&node->sn_mtx);
        ++node;
    }
}

void
mtx_pool_unlock_all(struct mtx_pool *pool, bool wakeup)
{
    struct mtx_node *node = pool->sp_nodev;

    while (node < pool->sp_nodev + pool->sp_nodec) {
        if (wakeup)
            cv_broadcast(&node->sn_cv);
        mutex_unlock(&node->sn_mtx);
        ++node;
    }
}

void
mtx_pool_wait(struct mtx_node *node)
{
    cv_wait(&node->sn_cv, &node->sn_mtx);
}
