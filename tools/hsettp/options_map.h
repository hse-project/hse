/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_TOOLS_HSETTP_OPTIONS_MAP_H
#define HSE_TOOLS_HSETTP_OPTIONS_MAP_H

#include <hse/error/merr.h>
#include <hse/util/compiler.h>

struct options_map;

struct options_map *
options_map_create(size_t initial_size) HSE_WARN_UNUSED_RESULT;

merr_t
options_map_put(struct options_map *map, const char *key, const char *value);

const char *
options_map_get(struct options_map *map, const char *key);

void
options_map_destroy(struct options_map *map);

#endif
