/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/ikvdb/c0_kvset_iterator.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/tuple.h>
#include <hse/util/event_counter.h>
#include <hse/util/platform.h>
#include <hse/util/slab.h>

#define c0_kvset_iterator_es_h2r(handle) container_of(handle, struct c0_kvset_iterator, c0it_handle)

/* [HSE_REVISIT]
 *
 * Below we issue a prefetch for the next element of this c0_kvset.
 * This is both simple and from modest experiments has the greatest
 * benefit of any of the simple prefetching strategies tried.
 *
 * Note that the c0_kvset_iterator has complete knowledge of not only
 * what is next, it can also have precomputed what is after that. It
 * would be worthwhile to experiment with computing what the next N
 * elements would be for N > 1.
 */
bool
c0_kvset_iterator_next(struct element_source *source, void **element)
{
    struct c0_kvset_iterator *iter = c0_kvset_iterator_es_h2r(source);
    struct bonsai_kv *bkv;

    bkv = iter->c0it_next;

    if (bkv == &iter->c0it_root->br_kv ||
        ((iter->c0it_flags & C0_KVSET_ITER_FLAG_INDEX) &&
         key_immediate_index(&bkv->bkv_key_imm) > iter->c0it_index))
    {
        source->es_eof = true;
        return false;
    }

    if (iter->c0it_flags & C0_KVSET_ITER_FLAG_PTOMB)
        bkv->bkv_flags |= BKV_FLAG_PTOMB;

    iter->c0it_prev = bkv;
    iter->c0it_next = bkv->bkv_next;

    __builtin_prefetch(bkv->bkv_next);
    __builtin_prefetch(bkv->bkv_values);

    bkv->bkv_es = source;
    *element = bkv;

    return true;
}

bool
c0_kvset_iterator_rnext(struct element_source *source, void **element)
{
    struct c0_kvset_iterator *iter = c0_kvset_iterator_es_h2r(source);
    struct bonsai_kv *bkv;

    bkv = iter->c0it_next;

    if (bkv == &iter->c0it_root->br_kv ||
        ((iter->c0it_flags & C0_KVSET_ITER_FLAG_INDEX) &&
         key_immediate_index(&bkv->bkv_key_imm) < iter->c0it_index))
    {
        source->es_eof = true;
        return false;
    }

    if (iter->c0it_flags & C0_KVSET_ITER_FLAG_PTOMB)
        bkv->bkv_flags |= BKV_FLAG_PTOMB;

    iter->c0it_prev = bkv;
    iter->c0it_next = bkv->bkv_prev;

    __builtin_prefetch(bkv->bkv_prev);
    __builtin_prefetch(bkv->bkv_values);

    bkv->bkv_es = source;
    *element = bkv;

    return true;
}

bool
c0_kvset_iterator_unget(struct element_source *source)
{
    struct c0_kvset_iterator *iter = c0_kvset_iterator_es_h2r(source);
    struct bonsai_kv *bkv;

    source->es_eof = false;

    bkv = iter->c0it_prev;

    if (bkv == &iter->c0it_root->br_kv ||
        ((iter->c0it_flags & C0_KVSET_ITER_FLAG_INDEX) &&
         key_immediate_index(&bkv->bkv_key_imm) > iter->c0it_index))
    {
        source->es_eof = true;
        return false;
    }

    iter->c0it_prev = bkv->bkv_prev;
    iter->c0it_next = bkv;

    return true;
}

bool
c0_kvset_iterator_runget(struct element_source *source)
{
    struct c0_kvset_iterator *iter = c0_kvset_iterator_es_h2r(source);
    struct bonsai_kv *bkv;

    source->es_eof = false;

    bkv = iter->c0it_prev;

    if (bkv == &iter->c0it_root->br_kv ||
        ((iter->c0it_flags & C0_KVSET_ITER_FLAG_INDEX) &&
         key_immediate_index(&bkv->bkv_key_imm) < iter->c0it_index))
    {
        source->es_eof = true;
        return false;
    }

    iter->c0it_prev = bkv->bkv_next;
    iter->c0it_next = bkv;

    return true;
}

/*
 * On the RCU nature of iterator linked-lists on a live Bonsai tree:
 * These lists are circular, as in no special conditions.  Therefore,
 * by careful ordering of update operations, it is always okay to
 * traverse the linked list in either order.
 *
 * There is no guarantee that reversing direction without calling these
 * initializers will produce consistent results.
 * Assume the list is presently A-C-E, there is a concurrent add of D,
 * and the last key seen was A.  If you call next-next, it is possible
 * to see C-E-eof, or C-D-E.  Assuming C-D-E, if you immediately called
 * prev, there is a race on updating the list in the opposite direction,
 * so you might see prev as either D or C.
 */
void
c0_kvset_iterator_init(
    struct c0_kvset_iterator *iter,
    struct bonsai_root *root,
    uint flags,
    int index)
{
    iter->c0it_root = root;
    iter->c0it_flags = flags;
    iter->c0it_index = index;

    if (!(flags & C0_KVSET_ITER_FLAG_REVERSE)) {
        iter->c0it_handle = es_make(c0_kvset_iterator_next, c0_kvset_iterator_unget, 0);
        iter->c0it_next = root->br_kv.bkv_next;
        iter->c0it_prev = root->br_kv.bkv_prev;
    } else {
        iter->c0it_handle = es_make(c0_kvset_iterator_rnext, c0_kvset_iterator_runget, 0);
        iter->c0it_next = root->br_kv.bkv_prev;
        iter->c0it_prev = root->br_kv.bkv_next;
    }
}

void
c0_kvset_iterator_seek(
    struct c0_kvset_iterator *iter,
    const void *seek,
    uint32_t seeklen,
    struct kvs_ktuple *kt)
{
    struct bonsai_skey skey;
    struct bonsai_kv *kv = NULL;

    bool found;

    assert(iter->c0it_flags & C0_KVSET_ITER_FLAG_INDEX);
    bn_skey_init(seek, seeklen, 0, iter->c0it_index, &skey);

    rcu_read_lock();

    if (!(iter->c0it_flags & C0_KVSET_ITER_FLAG_REVERSE))
        found = bn_findGE(iter->c0it_root, &skey, &kv);
    else
        found = bn_findLE(iter->c0it_root, &skey, &kv);

    if (!found)
        kv = &iter->c0it_root->br_kv;

    if (kt) {
        kvs_ktuple_init_nohash(kt, kv->bkv_key, key_imm_klen(&kv->bkv_key_imm));
    }

    if (!(iter->c0it_flags & C0_KVSET_ITER_FLAG_REVERSE))
        iter->c0it_prev = kv->bkv_prev;
    else
        iter->c0it_prev = kv->bkv_next;

    iter->c0it_handle.es_eof = false;
    iter->c0it_next = kv;

    __builtin_prefetch(kv->bkv_values);

    rcu_read_unlock();
}

bool
c0_kvset_iterator_empty(struct c0_kvset_iterator *iter)
{
    struct bonsai_kv *next = iter->c0it_next;

    if (next == &iter->c0it_root->br_kv)
        return true;

    if (iter->c0it_flags & C0_KVSET_ITER_FLAG_INDEX) {
        int index = key_immediate_index(&next->bkv_key_imm);

        if (!(iter->c0it_flags & C0_KVSET_ITER_FLAG_REVERSE))
            return index > iter->c0it_index;
        else
            return index < iter->c0it_index;
    }

    return false;
}

bool
c0_kvset_iterator_eof(struct c0_kvset_iterator *iter)
{
    struct bonsai_kv *next = iter->c0it_next;
    struct bonsai_kv *prev = iter->c0it_prev;
    bool empty = c0_kvset_iterator_empty(iter);

    if (!(iter->c0it_flags & C0_KVSET_ITER_FLAG_REVERSE))
        return empty && prev->bkv_next == next;
    else
        return empty && prev->bkv_prev == next;
}

struct element_source *
c0_kvset_iterator_get_es(struct c0_kvset_iterator *iter)
{
    return &iter->c0it_handle;
}
