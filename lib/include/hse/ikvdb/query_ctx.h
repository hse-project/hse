/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVS_QCTX_H
#define HSE_KVS_QCTX_H

#include <stdbool.h>

#include <hse/error/merr.h>

/**
 * struct query_ctx - context for special queries (pfx probe)
 * @tomb_map: map for tombstones
 * @pos:      current position in the memory region backing tomb elems
 * @seen:     number of unique keys seen
 */
struct query_ctx {
    int pos;
    int seen;
    struct map *tomb_map;
};

merr_t
qctx_tomb_insert(struct query_ctx *qctx, const void *key, size_t klen);

bool
qctx_tomb_seen(struct query_ctx *qctx, const void *key, size_t klen);

#endif /* HSE_KVS_QCTX_H */
