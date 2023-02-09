/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <hse/error/merr.h>

#include "options_map.h"

struct options_map {
    size_t len;
    size_t cap;
    const char **keys;
    const char **values;
};

struct options_map *
options_map_create(const size_t initial_size)
{
    struct options_map *map;

    map = calloc(1, sizeof(*map));
    if (!map)
        return NULL;

    map->cap = initial_size;
    map->len = 0;

    map->keys = malloc(map->cap * sizeof(*map->keys));
    if (!map->keys)
        goto err;

    map->values = malloc(map->cap * sizeof(*map->values));
    if (!map->values)
        goto err;

    return map;

err:
    free(map->keys);
    free(map->values);
    free(map);

    return NULL;
}

void
options_map_destroy(struct options_map * const map)
{
    if (!map)
        return;

    free(map->keys);
    free(map->values);
    free(map);
}

const char *
options_map_get(struct options_map * const map, const char * const key)
{
    for (size_t i = 0; i < map->len; i++) {
        if (strcmp(map->keys[i], key) == 0)
            return map->values[i];
    }

    return NULL;
}

merr_t
options_map_put(struct options_map * const map, const char * const key, const char * const value)
{
    size_t idx = map->len;

    if (map->len >= map->cap) {
        void *buf;

        buf = realloc(map->keys, 2 * map->cap);
        if (!buf)
            return merr(ENOMEM);
        map->keys = buf;

        buf = realloc(map->values, 2 * map->cap);
        if (!buf)
            return merr(ENOMEM);
        map->values = buf;
    }

    for (size_t i = 0; i < map->len; i++) {
        if (strcmp(map->keys[i], key) == 0) {
            idx = i;
            break;
        }
    }

    map->len++;

    map->keys[idx] = key;
    map->values[idx] = value;

    return 0;
}
