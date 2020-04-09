/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_CACHE_H
#define HSE_C1_CACHE_H

#include <hse_util/platform.h>

#define HSE_C1_CACHE_SIZE (1024 * 1024 * 1024L)

#define c1_kvcache_lock(cc) mutex_lock(&((cc)->c1kvc_lock))
#define c1_kvcache_unlock(cc) mutex_unlock(&((cc)->c1kvc_lock))

/*
 * struct c1_kvcache - c1 kv cache for objects, managed by c1.
 * @c1kvc_lock:  mutex protecting this struct
 * @c1kvc_cheap: cheap to allocate objects from
 * @c1kvc_free:  is this kvcache instance available?
 */
struct c1_kvcache {
    struct mutex  c1kvc_lock;
    struct cheap *c1kvc_cheap;
    bool          c1kvc_free;
};

/*
 * c1_kvcache_alloc - alloc object from c1 kvcache
 * @cc:        kv cache handle
 * @alignment: object alignment to use
 * @size:      size of allocation
 *
 * The total number of c1 kvcache instances == stripe width == total number
 * of c1 io threads. Before starting work on an iterator, a c1 io thread
 * picks an available c1 kvcache instance using c1_get_kvcache(). KV bundle
 * objects are then allocated from this kvcache and written to c1 mlogs.
 * After ingesting a kvbundle, the objects associated with it (kvtuple and
 * vtuple) are not referenced anymore. After all kvbundles in an iterator
 * are exhausted, the c1 kvcache instance is marked as available.
 *
 * Please note that the size of a c1 kvcache instance is large enough to
 * accommodate atleast a single KV bundle object. As a result, the cheap can
 * be reset safely once it is full.
 */
static inline void *
c1_kvcache_alloc(struct c1_kvcache *cc, size_t alignment, size_t size)
{
    void *ptr;

    ptr = cheap_memalign(cc->c1kvc_cheap, alignment, size);

    if (unlikely(!ptr)) {
        cheap_reset(cc->c1kvc_cheap, 0);
        ptr = cheap_memalign(cc->c1kvc_cheap, alignment, size);
    }

    return ptr;
}

#endif /* HSE_C1_CACHE_H */
