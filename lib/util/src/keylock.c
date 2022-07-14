/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_keylock

#include <hse_util/alloc.h>
#include <hse_util/arch.h>
#include <hse_util/slab.h>
#include <hse_util/atomic.h>
#include <error/merr.h>
#include <hse_util/page.h>
#include <hse_util/minmax.h>
#include <hse_util/mutex.h>
#include <hse_util/logging.h>
#include <hse_util/keylock.h>

/* clang-format off */

struct keylock {
};

#define keylock_h2r(handle) \
    container_of(handle, struct keylock_impl, kli_handle)

struct keylock_entry {
    uint64_t kle_hash;
    uint32_t kle_owner;
    uint32_t kle_plen : 31;
    uint32_t kle_busy : 1;
};

struct keylock_impl {
    struct keylock kli_handle HSE_ACP_ALIGNED;
    uint           kli_fullhwm;
    keylock_cb_fn *kli_cb_func;
    void          *kli_mem;

    struct mutex   kli_kmutex HSE_L1D_ALIGNED;
    uint           kli_num_occupied;
    uint           kli_max_occupied;
    uint           kli_max_psl;
    uint           kli_table_full;
    ulong          kli_collisions;

    struct keylock_entry kli_bucketv[] HSE_ALIGNED(16);
};

/* clang-format on */

static bool
keylock_cb_func(uint32_t owner, uint64_t start_seq)
{
    return false;
}

merr_t
keylock_create(keylock_cb_fn *cb_func, struct keylock **handle_out)
{
    struct keylock_impl *table;
    size_t               sz;
    void                *mem;

    *handle_out = 0;

    sz = sizeof(struct keylock_impl);
    sz += sizeof(struct keylock_entry) * KLE_PSL_MAX;
    sz = roundup(sz + __alignof__(*table), __alignof__(*table));

    mem = calloc(1, sz);
    if (!mem)
        return merr(ENOMEM);

    table = PTR_ALIGN(mem, __alignof__(*table));
    table->kli_fullhwm = KLE_PSL_MAX * 90 / 100;
    table->kli_cb_func = cb_func ? cb_func : keylock_cb_func;
    table->kli_mem = mem;
    mutex_init_adaptive(&table->kli_kmutex);

    *handle_out = &table->kli_handle;

    return 0;
}

void
keylock_destroy(struct keylock *handle)
{
    struct keylock_impl *table;

    if (!handle)
        return;

    table = keylock_h2r(handle);

    mutex_destroy(&table->kli_kmutex);

    free(table->kli_mem);
}

merr_t
keylock_lock(
    struct keylock *handle,
    uint64_t        hash,
    uint32_t        owner,
    uint64_t        start_seq,
    bool *          inherited)
{
    struct keylock_impl * table = keylock_h2r(handle);
    struct keylock_entry  entry, *curr;
    bool                  displaced, almostfull;

    curr = table->kli_bucketv + (hash % KLE_PSL_MAX);
    __builtin_prefetch(curr);

    entry.kle_busy = 1;
    entry.kle_plen = 0;
    entry.kle_hash = hash;
    entry.kle_owner = owner;

    displaced = false;

    mutex_lock(&table->kli_kmutex);
    almostfull = table->kli_num_occupied >= table->kli_fullhwm;

    /* Insert will succeed unless probing requires that we move a key
     * and the load factor is too high (i.e., num_occupied > fullhwm).
     */
    while (curr->kle_busy) {
        if (!displaced && hash == curr->kle_hash) {
            uint32_t old = curr->kle_owner;
            uint32_t new = owner;

            /* Should only be considering this for the 1st hash */
            assert(hash == entry.kle_hash);

            /* Does the caller already hold the lock? */
            if (old == owner) {
                mutex_unlock(&table->kli_kmutex);
                *inherited = false;
                return 0;
            }

            /* Can the caller inherit the lock? */
            if (table->kli_cb_func(old, start_seq)) {
                curr->kle_owner = new;
                mutex_unlock(&table->kli_kmutex);
                *inherited = true;
                return 0;
            }

            /* Lock held by another transaction, cannot inherit */
            table->kli_collisions++;
            mutex_unlock(&table->kli_kmutex);

            return merr(ECANCELED);
        }

        /* If the probe len of the current entry is higher, swap it
         * with the current key. Robin Hood hashing reduces variance
         * of searches.
         */
        if (curr->kle_plen < entry.kle_plen) {
            struct keylock_entry tmp;

            /* The lock doesn't exist in the table. If the table is
             * full, exit. No room to insert a new entry.
             */
            if (HSE_UNLIKELY(almostfull)) {
                table->kli_table_full++;
                mutex_unlock(&table->kli_kmutex);

                return merr(ECANCELED);
            }

            tmp = *curr;
            *curr = entry;
            entry = tmp;

            displaced = true;
        }

        assert(entry.kle_plen < KLE_PSL_MAX);
        entry.kle_plen += 1;
        curr = table->kli_bucketv + ((entry.kle_hash + entry.kle_plen) % KLE_PSL_MAX);
    }

    /* Insert a new entry in the hash table */
    assert(!curr->kle_busy);

    *curr = entry;

    assert(table->kli_num_occupied < KLE_PSL_MAX);
    table->kli_num_occupied++;

    if (entry.kle_plen > table->kli_max_psl)
        table->kli_max_psl = entry.kle_plen;
    if (table->kli_num_occupied > table->kli_max_occupied)
        table->kli_max_occupied = table->kli_num_occupied;

    mutex_unlock(&table->kli_kmutex);

    *inherited = false;

    return 0;
}

void
keylock_unlock(struct keylock *handle, uint64_t hash, uint32_t owner)
{
    struct keylock_impl *table = keylock_h2r(handle);
    uint                 plen = 0, index, free;

    index = (hash + plen) % KLE_PSL_MAX;

    mutex_lock(&table->kli_kmutex);

    while (table->kli_bucketv[index].kle_busy &&
           table->kli_bucketv[index].kle_hash != hash &&
           table->kli_bucketv[index].kle_plen >= plen) {
        plen++;
        index = (index + 1) % KLE_PSL_MAX;
    }

    /* Check that the caller really holds the lock. If the lock was
     * inherited before the deferred lock set's ref count reaches 0,
     * then the lock isn't really held by the caller so we just return.
     * Verify that the hash is the same i.e. has not been removed previously
     * by another thread that owns the lock.
     */
    if (!table->kli_bucketv[index].kle_busy ||
        table->kli_bucketv[index].kle_hash != hash ||
        table->kli_bucketv[index].kle_owner != owner) {

        mutex_unlock(&table->kli_kmutex);

        return;
    }

    table->kli_bucketv[index].kle_busy = 0;
    table->kli_num_occupied--;

    free = index;
    index = (index + 1) % KLE_PSL_MAX;
    plen = 1;

    while (table->kli_bucketv[index].kle_plen) {
        if (table->kli_bucketv[index].kle_plen >= plen) {
            table->kli_bucketv[free] = table->kli_bucketv[index];
            table->kli_bucketv[free].kle_plen -= plen;
            table->kli_bucketv[index].kle_busy = 0;
            free = index;
            plen = 0;
        }

        plen++;
        index = (index + 1) % KLE_PSL_MAX;
    }

    mutex_unlock(&table->kli_kmutex);
}

#if HSE_MOCKING
void
keylock_search(struct keylock *handle, uint64_t hash, uint *pos)
{
    struct keylock_impl *table = keylock_h2r(handle);
    uint                 plen = 0, index;

    index = (hash + plen) % KLE_PSL_MAX;
    *pos = KLE_PSL_MAX;

    mutex_lock(&table->kli_kmutex);

    while (table->kli_bucketv[index].kle_busy &&
           table->kli_bucketv[index].kle_plen >= plen) {

        if (table->kli_bucketv[index].kle_hash == hash) {
            *pos = index;
            break;
        }

        plen++;
        index = (index + 1) % KLE_PSL_MAX;
    }

    mutex_unlock(&table->kli_kmutex);
}

#include "keylock_ut_impl.i"
#endif
