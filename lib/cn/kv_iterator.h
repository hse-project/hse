/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CN_KV_ITERATOR_H
#define HSE_CN_KV_ITERATOR_H

#include <hse_util/inttypes.h>
#include <hse/error/merr.h>
#include <hse_util/bin_heap.h>

#include <hse_ikvdb/tuple.h>

/*
 *  The struct kv_iterator_ops definition specifies a generic interface for
 *  iterators over key/value collections, whether they are in c0 or in
 *  cN. There will be at least two different implementation of this interface,
 *  one for c0 and the other for cN.
 */

struct kv_iterator;

#define kvset_cursor_es_h2r(handle) container_of(handle, struct kv_iterator, kvi_es)

struct kv_iterator_ops {
    void (*kvi_release)(struct kv_iterator *kvi);
};

/* Context for iterating over values associated with a key.
 * "vctx" is short for "value context".
 */
struct kvset_iter_vctx {
    const void *kmd;
    size_t      off;
    uint        nvals;
    uint        next;
    bool        is_ptomb;
};

struct cn_kv_item {
    struct key_obj         kobj;
    struct kvset_iter_vctx vctx;
    struct element_source *src;
};

struct kv_iterator {
    struct kv_iterator_ops *kvi_ops;
    struct kvs_rparams *    kvi_rparams;
    bool                    kvi_eof;
    struct element_source   kvi_es;
    struct cn_kv_item       kvi_kv;
};

static inline void
kv_iterator_release(struct kv_iterator **kvi)
{
    if (*kvi) {
        if ((*kvi)->kvi_ops->kvi_release)
            (*kvi)->kvi_ops->kvi_release(*kvi);
        *kvi = NULL;
    }
}

#endif
