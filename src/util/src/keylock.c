/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>
#include <hse_util/platform.h>
#include <hse_util/hash.h>
#include <hse_util/slab.h>
#include <hse_util/keylock.h>

struct keylock {
};

#define keylock_h2r(handle) container_of(handle, struct keylock_impl, kli_handle)

struct keylock_entry {
    u64                     kle_hash : 48;
    u64                     kle_plen : 16;
    struct keylock_cb_rock *kle_rock;
};

struct keylock_impl {
    struct keylock kli_handle;
    u64            kli_num_entries;
    keylock_cb_fn *kli_cb_func;

    __aligned(SMP_CACHE_BYTES) struct mutex kli_kmutex;
    struct keylock_stats kli_stats;
    struct keylock_entry kli_entries[];
};

static const struct keylock_entry EMPTY_ENTRY = {.kle_rock = (void *)-1 };

#define NONEMPTY_ENTRY(_entry) ((_entry)->kle_rock != (void *)-1)

static bool
keylock_cb_func(u64 start_seq, struct keylock_cb_rock *rock1, struct keylock_cb_rock **new_rock)
{
    return false;
}

merr_t
keylock_create(u64 num_ents, keylock_cb_fn *cb_func, struct keylock **handle_out)
{
    struct keylock_impl *table;
    size_t               sz;
    u64                  i;

    *handle_out = 0;

    num_ents = clamp_t(u64, num_ents, 1, KLE_PLEN_MAX);

    sz = sizeof(struct keylock_impl);              /* size of base structure elements */
    sz += num_ents * sizeof(struct keylock_entry); /* space for entries */

    table = alloc_aligned(sz, __alignof(*table), GFP_KERNEL);
    if (!table)
        return merr(ev(ENOMEM));

    memset(table, 0, sz);
    table->kli_num_entries = num_ents;

    for (i = 0; i < num_ents; ++i)
        table->kli_entries[i] = EMPTY_ENTRY;

    table->kli_cb_func = cb_func ? cb_func : keylock_cb_func;
    mutex_init_adaptive(&table->kli_kmutex);

    *handle_out = &table->kli_handle;

    return 0;
}

void
keylock_destroy(struct keylock *handle)
{
    struct keylock_impl *table;

    if (ev(!handle))
        return;

    table = keylock_h2r(handle);

    mutex_destroy(&table->kli_kmutex);

    free_aligned(table);
}

merr_t
keylock_lock(
    struct keylock *        handle,
    u64                     hash,
    u64                     start_seq,
    struct keylock_cb_rock *rock,
    bool *                  inherited)
{
    struct keylock_impl * table = keylock_h2r(handle);
    struct keylock_entry  entry, *curr;
    struct keylock_stats *stats;
    u32                   max_entries;
    bool                  displaced, full;

    max_entries = table->kli_num_entries;

    hash = (hash << 16) >> 16;
    curr = table->kli_entries + (hash % max_entries);
    __builtin_prefetch(curr);

    entry.kle_plen = 0;
    entry.kle_hash = hash;
    entry.kle_rock = rock;

    stats = &table->kli_stats;
    displaced = false;

    mutex_lock(&table->kli_kmutex);

    full = stats->kls_num_occupied == max_entries;

    while (NONEMPTY_ENTRY(curr)) {
        if (!displaced && hash == curr->kle_hash) {
            struct keylock_cb_rock *old = curr->kle_rock;
            struct keylock_cb_rock *new = rock;

            /* Should only be considering this for the 1st hash */
            assert(hash == entry.kle_hash);

            /* Does the caller already hold the lock? */
            if (old == rock) {
                mutex_unlock(&table->kli_kmutex);
                *inherited = false;
                return 0;
            }

            /* Can the caller inherit the lock? */
            if (table->kli_cb_func(start_seq, old, &new)) {
                curr->kle_rock = new;
                mutex_unlock(&table->kli_kmutex);
                *inherited = true;
                return 0;
            }

            /* Lock held by another transaction, cannot inherit */
            stats->kls_collisions++;
            mutex_unlock(&table->kli_kmutex);

            return merr_once(ECANCELED);
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
            if (unlikely(full)) {
                stats->kls_table_full++;
                mutex_unlock(&table->kli_kmutex);

                return merr(ev(ECANCELED));
            }

            tmp = *curr;
            *curr = entry;
            entry = tmp;

            displaced = true;
        }

        entry.kle_plen += 1;
        curr = table->kli_entries + ((entry.kle_hash + entry.kle_plen) % max_entries);
    }

    /* Insert a new entry in the hash table */
    assert(!NONEMPTY_ENTRY(curr) && !full);
    assert(curr->kle_plen == 0);
    assert(entry.kle_plen < table->kli_num_entries);

    *curr = entry;

    assert(stats->kls_num_occupied < table->kli_num_entries);
    stats->kls_num_occupied++;

    if (entry.kle_plen > stats->kls_max_probe_len)
        stats->kls_max_probe_len = entry.kle_plen;
    if (stats->kls_num_occupied > stats->kls_max_occupied)
        stats->kls_max_occupied = stats->kls_num_occupied;

    mutex_unlock(&table->kli_kmutex);

    *inherited = false;

    return 0;
}

void
keylock_unlock(struct keylock *handle, u64 hash, struct keylock_cb_rock *rock)
{
    struct keylock_impl *table = keylock_h2r(handle);
    u64                  plen = 0, index, free;

    hash = (hash << 16) >> 16;
    index = (hash + plen) % table->kli_num_entries;

    mutex_lock(&table->kli_kmutex);

    while (table->kli_entries[index].kle_hash != hash &&
           table->kli_entries[index].kle_plen >= plen) {
        plen++;
        index++;
        if (index == table->kli_num_entries)
            index = 0;
    }

    /* Check that the caller really holds the lock. If the lock was
     * inherited before the deferred lock set's ref count reaches 0,
     * then the lock isn't really held by the caller so we just return.
     * Verify that the hash is the same i.e. has not been removed previously
     * by another thread that owns the lock.
     */
    if (table->kli_entries[index].kle_rock != rock || table->kli_entries[index].kle_hash != hash) {
        mutex_unlock(&table->kli_kmutex);

        return;
    }

    table->kli_entries[index] = EMPTY_ENTRY;
    table->kli_stats.kls_num_occupied--;

    free = index;
    index++;
    if (index == table->kli_num_entries)
        index = 0;
    plen = 1;

    while (table->kli_entries[index].kle_plen) {
        if (table->kli_entries[index].kle_plen >= plen) {
            table->kli_entries[free] = table->kli_entries[index];
            table->kli_entries[free].kle_plen -= plen;
            table->kli_entries[index] = EMPTY_ENTRY;
            free = index;
            plen = 0;
        }

        plen++;
        index++;
        if (index == table->kli_num_entries)
            index = 0;
    }

    mutex_unlock(&table->kli_kmutex);
}

void
keylock_search(struct keylock *handle, u64 hash, u64 *pos)
{
    struct keylock_impl *table = keylock_h2r(handle);
    u64                  plen = 0, index;

    hash = (hash << 16) >> 16;
    index = (hash + plen) % table->kli_num_entries;
    *pos = table->kli_num_entries;

    mutex_lock(&table->kli_kmutex);

    while (NONEMPTY_ENTRY(&table->kli_entries[index]) &&
           table->kli_entries[index].kle_plen >= plen) {
        if (table->kli_entries[index].kle_hash == hash) {
            *pos = index;
            break;
        }

        plen++;
        index++;
        if (index == table->kli_num_entries)
            index = 0;
    }

    mutex_unlock(&table->kli_kmutex);
}

void
keylock_query_stats(struct keylock *handle, struct keylock_stats *stats)
{
    memcpy(stats, &(keylock_h2r(handle)->kli_stats), sizeof(*stats));
}
