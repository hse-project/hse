/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_MTX_POOL_H
#define HSE_MTX_POOL_H

#include <hse_util/platform.h>
#include <hse_util/mutex.h>
#include <hse_util/condvar.h>

struct mtx_node;
struct mtx_pool;

/**
 * mtx_pool_create() - create a mutex pool
 * @nodes: maximum number of locks in the pool
 *
 * Return:  Pointer to a mutex pool on success, NULL on failure
 */
struct mtx_pool *
mtx_pool_create(size_t nodes);

/**
 * mtx_pool_create() - destroy the given mutex pool
 * @pool:   ptr to the mutex pool to destroy
 *
 */
void
mtx_pool_destroy(struct mtx_pool *pool);

/**
 * mtx_pool_lock() - lock one lock in the pool
 * @pool:   ptr to a mutex pool
 * @hash:   hash used to choose a lock from the pool
 *
 * Return: ptr to a mutex pool node which contains the locked mutex
 */
struct mtx_node *
mtx_pool_lock(struct mtx_pool *pool, uintptr_t hash);

/**
 * mtx_pool_trylock() - try to lock one lock in the pool
 * @pool:   ptr to a mutex pool
 * @hash:   hash used to choose a lock from the pool
 *
 * Return: ptr to a mutex pool node which contains the locked mutex
 * or NULL if the lock was busy.
 */
struct mtx_node *
mtx_pool_trylock(struct mtx_pool *pool, uintptr_t hash);

/**
 * mtx_pool_unlock() - unlock the specified mutex pool node lock
 * @pool:   ptr to a mutex pool
 * @node:   ptr to a mutex pool node returned by mtx_pool_lock()
 *
 */
void
mtx_pool_unlock(struct mtx_node *node);

/**
 * mtx_pool_lock_all() - lock all the locks in the given mutex pool
 * @pool:   ptr to a mutex pool
 *
 * Iterates through the lock pool and locks each node's mutex.
 */
void
mtx_pool_lock_all(struct mtx_pool *pool);

/**
 * mtx_pool_unlock_all() - unlock all the locks in the given mutex pool
 * @pool:   the mutex pool
 * @wakeup: wakeup waiters if true
 *
 * Iterates through the lock pool and unlocks each nodes' mutex.  If %wakeup
 * is true, wakes up all waiters waiting on each mutex node.
 */
void
mtx_pool_unlock_all(struct mtx_pool *pool, bool wakeup);

/**
 * mtx_pool_wait() - wait on an event associated with the given mutex node
 * @node:   ptr to a mutex pool node on which to wait
 *
 */
void
mtx_pool_wait(struct mtx_node *node);

#endif /* HSE_MTX_POOL_H */
