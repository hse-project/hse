/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#define MTF_MOCK_IMPL_bonsai_iter

#include <stdint.h>

#include <hse/ikvdb/c0_kvset.h>
#include <hse/ikvdb/cursor.h>
#include <hse/ikvdb/kvdb_ctxn.h>
#include <hse/util/bonsai_tree.h>
#include <hse/util/element_source.h>
#include <hse/util/key_util.h>

#include "bonsai_iter.h"

void
bonsai_iter_init(
    struct bonsai_iter *iter,
    struct bonsai_root **root,
    int skidx,
    uint64_t view_seq,
    uint64_t horizon_seq,
    uintptr_t seqnoref,
    bool reverse,
    bool ptomb_tree)
{
    iter->bi_root = root;
    iter->bi_kv = NULL; /* Set at first read */
    iter->bi_index = skidx;
    iter->bi_seq_view = view_seq;
    iter->bi_seq_horizon = horizon_seq;
    iter->bi_seqref = seqnoref;
    iter->bi_reverse = reverse ? 1 : 0;
    iter->bi_is_ptomb = ptomb_tree ? 1 : 0;
}

void
bonsai_iter_update(struct bonsai_iter *iter, uint64_t view_seq, uint64_t horizon_seq)
{
    iter->bi_seq_view = view_seq;
    iter->bi_seq_horizon = horizon_seq;
}

void
bonsai_iter_seek(struct bonsai_iter *iter, const void *key, size_t klen)
{
    struct bonsai_skey skey;
    struct bonsai_kv *kv = NULL;
    struct bonsai_root *root;
    bool found;

    assert(rcu_read_ongoing());

    bn_skey_init(key, klen, 0, iter->bi_index, &skey);
    root = rcu_dereference(*iter->bi_root);
    if (iter->bi_reverse)
        found = bn_findLE(root, &skey, &kv);
    else
        found = bn_findGE(root, &skey, &kv);

    iter->bi_es.es_eof = !found;
    iter->bi_kv = found ? kv : &root->br_kv;
}

void
bonsai_iter_position(struct bonsai_iter *iter, const void *key, size_t klen)
{
    struct bonsai_skey skey;
    struct bonsai_kv *kv = NULL;
    struct bonsai_root *root;
    bool found;

    assert(rcu_read_ongoing());

    bn_skey_init(key, klen, 0, iter->bi_index, &skey);
    root = rcu_dereference(*iter->bi_root);

    if (iter->bi_reverse)
        found = bn_findLE(root, &skey, &kv);
    else
        found = bn_findGE(root, &skey, &kv);

    iter->bi_es.es_eof = !found;
    iter->bi_kv = found ? kv : &root->br_kv;
}

static struct bonsai_kv *
get_next(struct bonsai_iter *iter)
{
    struct bonsai_kv *bkv;
    struct bonsai_root *root;

    if (!iter->bi_kv)
        return NULL;

    bkv = iter->bi_kv;
    root = rcu_dereference(*iter->bi_root);

    if (iter->bi_reverse) {
        if (bkv == &root->br_kv || key_immediate_index(&bkv->bkv_key_imm) < iter->bi_index)
            return NULL;

        iter->bi_kv = rcu_dereference(bkv->bkv_prev);
    } else {
        if (bkv == &root->br_kv || key_immediate_index(&bkv->bkv_key_imm) > iter->bi_index)
            return NULL;

        iter->bi_kv = rcu_dereference(bkv->bkv_next);
    }

    return bkv;
}

static bool
bonsai_iter_next(struct element_source *es, void **element)
{
    struct bonsai_iter *iter = container_of(es, struct bonsai_iter, bi_es);
    struct bonsai_kv *bkv;
    struct bonsai_val *val;
    struct kvs_cursor_element *elem;

    if (es->es_eof)
        return false;

    /* At the end of this loop, iter->bi_kv must point to a node that is within this
     * cursor's view. This ensures that the node won't be garbage collected before the next
     * cursor read call.
     */
    rcu_read_lock();

    do {
        enum hse_seqno_state state;
        uint64_t seqno;

        bkv = get_next(iter);
        if (!bkv) {
            es->es_eof = true;
            rcu_read_unlock();
            return false;
        }

        val = c0kvs_findval(bkv, iter->bi_seq_view, iter->bi_seqref);
        if (!val)
            continue;

        /* val will be non-NULL when there's a value with
         *   (1) an ordinal seqno less than the cursor's view seqno, or
         *   (2) a seqref that matches the txn's seqref
         *
         * If val is set (non-NULL), check if seqno is larger than the horizon.
         */
        state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);
        if (state == HSE_SQNREF_STATE_DEFINED && seqno < iter->bi_seq_horizon)
            val = NULL;

    } while (!val);
    rcu_read_unlock();

    elem = &iter->bi_elem;
    key2kobj(&elem->kce_kobj, bkv->bkv_key, key_imm_klen(&bkv->bkv_key_imm));
    kvs_vtuple_init(&elem->kce_vt, val->bv_value, bonsai_val_ulen(val));
    elem->kce_source = KCE_SOURCE_LC;
    elem->kce_seqnoref = val->bv_seqnoref;
    elem->kce_complen = bonsai_val_clen(val);
    elem->kce_is_ptomb = iter->bi_is_ptomb;

    *element = &iter->bi_elem;

    return true;
}

struct element_source *
bonsai_iter_es_make(struct bonsai_iter *iter)
{
    iter->bi_es = es_make(bonsai_iter_next, 0, 0);
    return &iter->bi_es;
}

static bool
bonsai_ingest_iter_next(struct element_source *es, void **element)
{
    struct bonsai_ingest_iter *iter = container_of(es, struct bonsai_ingest_iter, bii_es);
    struct bonsai_root *root;

    rcu_read_lock();

    root = rcu_dereference(*iter->bii_rootp);

    if (!iter->bii_kv)
        iter->bii_kv = &root->br_kv;

    while (!es->es_eof) {
        struct bonsai_kv *bkv;
        struct bonsai_val *val;

        iter->bii_kv = bkv = rcu_dereference(iter->bii_kv->bkv_next);
        if (bkv == &root->br_kv)
            break;

        /* Similar to a a cursor read, this function should return only when the bkv is "valid"
         * or the iteration has reached eof. A bkv is valid if it lies in the ingest's view i.e.
         * horizon <= seqno <= view.
         *
         * But we can go a step further and treat entries from aborted and active txns as invalid
         * lc_ingest_seqno_get (invalid for ingest) too. This will save some work for the ingest
         * thread.
         */
        for (val = rcu_dereference(bkv->bkv_values); val; val = rcu_dereference(val->bv_next)) {
            uint64_t seqno;
            enum hse_seqno_state state;

            state = seqnoref_to_seqno(val->bv_seqnoref, &seqno);
            if (state != HSE_SQNREF_STATE_DEFINED)
                continue;

            if (seqno < iter->bii_min_seqno || seqno > iter->bii_max_seqno)
                continue;

            bkv->bkv_es = es;
            *element = iter->bii_kv;
            rcu_read_unlock();
            return true;
        }
    }

    rcu_read_unlock();
    es->es_eof = true;
    return false;
}

struct element_source *
bonsai_ingest_iter_init(
    struct bonsai_ingest_iter *iter,
    uint64_t min_seqno,
    uint64_t max_seqno,
    struct bonsai_root **rootp)
{
    iter->bii_rootp = rootp;
    iter->bii_es = es_make(bonsai_ingest_iter_next, 0, 0);
    iter->bii_kv = NULL;
    iter->bii_min_seqno = min_seqno;
    iter->bii_max_seqno = max_seqno;

    return &iter->bii_es;
}

#if HSE_MOCKING
#include "bonsai_iter_ut_impl.i"
#endif
