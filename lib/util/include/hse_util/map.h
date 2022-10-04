/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 *
 * A map library to store key-value pairs. This is not a thread safe library.
 */

#include <inttypes.h>
#include <stdbool.h>

#include <hse/error/merr.h>

#include <hse_util/compiler.h>

#ifndef HSE_UTIL_MAP_H
#define HSE_UTIL_MAP_H

struct map;

struct map *
map_create(size_t initial_cnt);

void
map_destroy(struct map *map);

merr_t
map_insert(struct map *map, uint64_t key, uintptr_t value);

static HSE_ALWAYS_INLINE merr_t
map_insert_ptr(struct map *map, uint64_t key, void *val)
{
    return map_insert(map, key, (uintptr_t)val);
}

bool
map_lookup(struct map *map, uint64_t key, uintptr_t *val);

bool
map_lookup_ref(struct map *map, uint64_t key, uintptr_t **val);

static HSE_ALWAYS_INLINE void *
map_lookup_ptr(struct map *map, uint64_t key)
{
    uintptr_t val;
    bool found = map_lookup(map, key, &val);

    return found ? (void *)val : NULL;
}

bool
map_remove(struct map *map, uint64_t key, uintptr_t *val);

static HSE_ALWAYS_INLINE void *
map_remove_ptr(struct map *map, uint64_t key)
{
    uintptr_t v;
    bool found = map_remove(map, key, &v);

    return found ? (void *)v : NULL;
}

void
map_reset(struct map *map);

unsigned int
map_count_get(struct map *map);

struct map_iter {
    struct map     *map;
    struct rb_node *curr;
};

void
map_iter_init(struct map_iter *iter, struct map *map);

bool
map_iter_next(struct map_iter *iter, uint64_t *key, uintptr_t *val);

static HSE_ALWAYS_INLINE bool
map_iter_next_val(struct map_iter *iter, void *val)
{
    return map_iter_next(iter, NULL, (uintptr_t *)(val));
}

void
map_apply(struct map *map, void (*cb)(uint64_t key, uintptr_t val));

#endif /* HSE_UTIL_MAP_H */
