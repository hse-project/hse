/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/util/list.h>
#include <hse/util/event_counter.h>
#include <hse/util/map.h>

#include <rbtree.h>

#define BLOCKCNT_DEFAULT 4096

struct map_node {
    struct rb_node rb_node;
    uint64_t       key;
    uintptr_t      blob;
};

struct map_mem_block {
    struct list_head link;
    struct map_node  mem[];
} HSE_ALIGNED(64);

/* A dictionary with uint64_t keys and uintptr_t values.
 * Memory is allocated in blocks to amortize the allocation overhead of
 * individual insert.  The memory is not freed until the map is destroyed, so
 * maps that grow large and then shrink consume more memory than necessary.
 */
struct map {
    struct rb_root    root;
    struct list_head  memlist;
    size_t            map_mem_blockcnt;
    uint              elem_cnt;
    uintptr_t         map_node_freelist;
};

/* Return a map element to the map's free list */
static void
map_mem_free(struct map *map, struct map_node *m)
{
    *(uintptr_t *)m = map->map_node_freelist;
    map->map_node_freelist = (uintptr_t)m;
}

/* Allocate a block of elements and add each element to the maps's free list */
static merr_t
map_mem_extend(struct map *map)
{
    struct map_mem_block *mem;
    int i;

    mem = malloc(sizeof(*mem) + sizeof(struct map_node) * map->map_mem_blockcnt);
    if (ev(!mem))
        return merr(ENOMEM);

    list_add_tail(&mem->link, &map->memlist);
    for (i = 0; i < map->map_mem_blockcnt; i++)
        map_mem_free(map, &mem->mem[i]);

    return 0;
}

/* Get an unused map element, extending the free list if necessary. */
static struct map_node *
map_mem_alloc(struct map *map)
{
    struct map_node *m;
    merr_t err;

    if (!map->map_node_freelist) {
        err = map_mem_extend(map);
        if (ev(err))
            return NULL;
    }

    assert(map->map_node_freelist);
    if (ev(!map->map_node_freelist))
        return NULL;

    m = (struct map_node *)map->map_node_freelist;
    map->map_node_freelist = *(uintptr_t *)map->map_node_freelist;

    return m;
}

struct map *
map_create(size_t initial_cnt)
{
    struct map *map;

    map = malloc(sizeof(*map));
    if (ev(!map))
        return NULL;

    map->map_mem_blockcnt = initial_cnt ?: BLOCKCNT_DEFAULT;
    map->root = RB_ROOT;
    map->elem_cnt = 0;

    INIT_LIST_HEAD(&map->memlist);

    map->map_node_freelist = 0;
    if (map_mem_extend(map)) {
        free(map);
        return NULL;
    }

    return map;
}

void
map_destroy(struct map *map)
{
    struct map_mem_block *p, *next;

    if (!map)
        return;

    list_for_each_entry_safe(p, next, &map->memlist, link) {
        free(p);
    }

    free(map);
}

/* Insert/update map entry.
 * - If key does not exist in map, insert (key, value) pair.
 * - If key exists in map and update is true, update existing entry with new value.
 * - If key exists in map and update is false, return merr(EEXIST).
 */
static merr_t
map_insert_cmn(struct map *map, uint64_t key, uintptr_t value, bool allow_dups)
{
    struct map_node *mn;
    struct rb_node **link;
    struct rb_node  *parent;

    link = &map->root.rb_node;
    parent = 0;

    while (*link) {
        struct map_node *this = rb_entry(*link, typeof(*this), rb_node);

        parent = *link;
        if (key < this->key)
            link = &(*link)->rb_left;
        else if (key > this->key)
            link = &(*link)->rb_right;
        else {
            if (allow_dups) {
                this->blob = value;
                return 0;
            }

            return merr(EEXIST);
        }
    }

    mn = map_mem_alloc(map);
    if (ev(!mn))
        return merr(ENOMEM);

    mn->key = key;
    mn->blob = value;

    rb_link_node(&mn->rb_node, parent, link);
    rb_insert_color(&mn->rb_node, &map->root);

    ++map->elem_cnt;

    return 0;
}

/* Insert/update map entry
 * - If key does not exist in map, insert (key, value) pair.
 * - If key exists in map, update existing entry with new value.
 */
merr_t
map_insert(struct map *map, uint64_t key, uintptr_t value)
{
    return map_insert_cmn(map, key, value, true);
}

/* Find address of value associated with key in map
 * Return:
 *   false : key not found
 *   true  : key found, address of value returned in val_out
 */
bool
map_lookup_ref(struct map *map, uint64_t key, uintptr_t **val)
{
    struct rb_node **link = &map->root.rb_node;

    while (*link) {
        struct map_node *this = rb_entry(*link, typeof(*this), rb_node);

        if (key < this->key) {
            link = &(*link)->rb_left;
        } else if (key > this->key) {
            link = &(*link)->rb_right;
        } else {
            *val = &this->blob;
            return true;
        }
    }

    return false;
}

/* Find value associated with key in map
 * Return:
 *   false : key not found
 *   true  : key found, value returned in val_out
 */
bool
map_lookup(struct map *map, uint64_t key, uintptr_t *val_out)
{
    bool found;
    uintptr_t *val;

    found = map_lookup_ref(map, key, &val);
    if (found && val_out)
        *val_out = *val;

    return found;
}

/* Remove a key from a map and optionally return its value
 * Return:
 *   true : key found and removed, value returned in val if val!=NULL
 *   false : key not found
 */
bool
map_remove(struct map *map, uint64_t key, uintptr_t *val)
{
    struct rb_node **link = &map->root.rb_node;

    while (*link) {
        struct map_node *this = rb_entry(*link, typeof(*this), rb_node);

        if (key < this->key)
            link = &(*link)->rb_left;
        else if (key > this->key)
            link = &(*link)->rb_right;
        else {
            --map->elem_cnt;
            rb_erase(&this->rb_node, &map->root);
            if (val)
                *val = this->blob;

            map_mem_free(map, this);
            return true;
        }

    }

    return false;
}

void
map_reset(struct map *map)
{
    struct map_node *entry, *next;

    rbtree_postorder_for_each_entry_safe(entry, next, &map->root, rb_node) {
        map_mem_free(map, entry);
    }

    map->elem_cnt = 0;
}

uint
map_count_get(struct map *map)
{
    return map->elem_cnt;
}

void
map_iter_init(struct map_iter *iter, struct map *map)
{
    iter->map = map;
    iter->curr = rb_first(&map->root);
}

bool
map_iter_next(struct map_iter *iter, uint64_t *key, uintptr_t *val)
{
    struct map_node *mnode;

    if (!iter->curr)
        return false;

    mnode = rb_entry(iter->curr, typeof(*mnode), rb_node);

    if (key)
        *key = mnode->key;

    if (val)
        *val = mnode->blob;

    iter->curr = rb_next(iter->curr);
    return true;
}

void
map_apply(struct map *map, void (*cb)(uint64_t key, uintptr_t val))
{
    struct map_iter it;
    uint64_t key;
    uintptr_t p;

    map_iter_init(&it, map);
    while (map_iter_next(&it, &key, &p))
        cb(key, p);
}
