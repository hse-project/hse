/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 *
 * The cn cursor provides all keys that match the cursor's filters (prefix, view seqno etc.) in
 * lexicographical order - forward or reverse.
 *
 * At any given time, a cursor only needs to merge keys across the root node and one leaf node.
 * When enough keys are read and all keys from the leaf node are exhausted, the cursor needs to
 * swap out the leaf node for the next leaf node in the iteration order. This is achieved using
 * two layers of bin heaps.
 *
 * Each node (root node and the one leaf node) uses a binheap to merge keys across all its kvsets.
 * These two binheaps feed into a top level binheap that forms the cn cursor.
 *
 * Each node uses a struct cn_level_cursor to iterate over its kvsets.
 */

#include <stdint.h>

#include <hse/util/event_counter.h>
#include <hse/util/page.h>
#include <hse/logging/logging.h>
#include <hse/util/assert.h>
#include <hse/util/table.h>
#include <hse/util/key_util.h>
#include <hse/util/keycmp.h>
#include <hse/util/bin_heap.h>

#include <hse/ikvdb/cn.h>

#include "cn/cn_cursor.h"

#include "route.h"

#define MTF_MOCK_IMPL_cn_tree_cursor

#include "cn_tree_internal.h"
#include "cn_tree_cursor.h"
#include "kvset_internal.h"
#include "kvset.h"
#include "kv_iterator.h"

/*
 * Min heap comparator for forward iteration.
 *
 * Returns:
 *   < 0 : a_blob < b_blob
 *   > 0 : a_blob > b_blob
 *  == 0 : a_blob == b_blob
 */
static int
cn_kv_cmp(const void *a_blob, const void *b_blob)
{
    const struct cn_kv_item *a = a_blob;
    const struct cn_kv_item *b = b_blob;

    return key_obj_cmp(&a->kobj, &b->kobj);
}

/*
 * Max heap comparator for reverse iteration.
 * with a caveat: A ptomb sorts before all keys w/ matching
 * prefix.
 *
 * Returns:
 *   < 0 : a_blob > b_blob
 *   > 0 : a_blob < b_blob
 *  == 0 : a_blob == b_blob
 */
static int
cn_kv_cmp_rev(const void *a_blob, const void *b_blob)
{
    const struct cn_kv_item *a = a_blob;
    const struct cn_kv_item *b = b_blob;
    size_t                   a_klen = a->kobj.ko_pfx_len + a->kobj.ko_sfx_len;
    size_t                   b_klen = b->kobj.ko_pfx_len + b->kobj.ko_sfx_len;

    int rc;

    if (!(a->vctx.is_ptomb ^ b->vctx.is_ptomb))
        return key_obj_cmp(&b->kobj, &a->kobj);

    /* Exactly one of a and b is a ptomb. */
    if (a->vctx.is_ptomb && a_klen <= b_klen) {
        rc = key_obj_ncmp(&b->kobj, &a->kobj, a_klen);
        if (rc == 0)
            return -1; /* a wins */
    } else if (b->vctx.is_ptomb && b_klen <= a_klen) {
        rc = key_obj_ncmp(&b->kobj, &a->kobj, b_klen);
        if (rc == 0)
            return 1; /* b wins */
    }

    /* Non-ptomb key is shorter than ptomb. Full key compare. */
    return key_obj_cmp(&b->kobj, &a->kobj);
}

MTF_STATIC merr_t
cn_tree_kvset_refs(struct cn_tree_node *node, struct cn_level_cursor *lcur)
{
    struct table *tab = lcur->cnlc_kvref_tab;
    struct kvset_list_entry *le;

    if (!atomic_read(&node->tn_readers))
        atomic_inc(&node->tn_readers);

    lcur->cnlc_dgen_hi = lcur->cnlc_dgen_lo = 0;
    table_reset(tab);

    list_for_each_entry (le, &node->tn_kvset_list, le_link) {
        struct kvset *kvset = le->le_kvset;
        struct kvref *k;
        uint64_t dgen = kvset_get_dgen(kvset);

        if (!lcur->cnlc_dgen_hi)
            lcur->cnlc_dgen_hi = dgen;

        k = table_append(tab);
        if (ev(!k))
            return merr(ENOMEM);

        kvset_get_ref(kvset);
        k->kvset = kvset;

        lcur->cnlc_dgen_lo = dgen;
    }

    return 0;
}

static void
kvref_tab_putref(void *arg)
{
    struct kvref *k = arg;

    if (k->kvset) {
        kvset_put_ref(k->kvset);
        k->kvset = 0;
    }
}

static bool
cn_lcur_read(struct element_source *, void **);

MTF_STATIC merr_t
cn_lcur_init(
    struct cn_level_cursor *lcur)
{
    struct cn_cursor       *cncur = lcur->cnlc_cncur;
    struct table           *tab = lcur->cnlc_kvref_tab;
    struct element_source **esrc;

    struct workqueue_struct *maint_wq = cn_get_maint_wq(cncur->cncur_cn);

    uint iterc = table_len(tab);
    uint i, bh_align = 16;
    size_t bh_max_cnt;
    merr_t err;

    lcur->cnlc_iterc = 0;
    lcur->cnlc_es = es_make(cn_lcur_read, 0, 0);

    /* Grow element source array if necessary.
     */
    if (iterc > lcur->cnlc_esrcc) {
        size_t cnt = ALIGN(iterc, 32);
        void *p = realloc(lcur->cnlc_esrcv, cnt * sizeof(*lcur->cnlc_esrcv));

        if (ev(!p))
            return merr(ENOMEM);

        lcur->cnlc_esrcc = cnt;
        lcur->cnlc_esrcv = p;
    }

    esrc = lcur->cnlc_esrcv;

    for (i = 0; i < iterc; i++) {
        struct kvref *k = table_at(tab, i);
        struct kv_iterator *it;

        err = kvset_iter_create(k->kvset, NULL, maint_wq, NULL, cncur->cncur_flags, &it);
        if (ev(err))
            return err;

        *esrc++ = kvset_iter_es_get(it);
        ++lcur->cnlc_iterc;
    }

    if (!lcur->cnlc_iterc)
        return 0;

    /* Grow binheap if necessary
     */
    bh_max_cnt = ALIGN(lcur->cnlc_iterc, bh_align);
    if (bh_max_cnt > lcur->cnlc_bh_max_cnt) {
        bin_heap_destroy(lcur->cnlc_bh);
        lcur->cnlc_bh = 0;

        lcur->cnlc_bh_max_cnt = bh_max_cnt;
        err = bin_heap_create(lcur->cnlc_bh_max_cnt,
                              cncur->cncur_reverse ? cn_kv_cmp_rev : cn_kv_cmp,
                              &lcur->cnlc_bh);
        if (ev(err))
            return err;
    }

    return 0;
}

static void
cn_lcur_kvset_release(struct cn_level_cursor *lcur)
{
    int i;

    for (i = 0; i < lcur->cnlc_iterc; i++)
        kvset_iter_release(kvset_cursor_es_h2r(lcur->cnlc_esrcv[i]));

    lcur->cnlc_iterc = 0;

    table_apply(lcur->cnlc_kvref_tab, kvref_tab_putref);
    table_reset(lcur->cnlc_kvref_tab);
}

merr_t
cn_tree_cursor_create(struct cn_cursor *cur)
{
    int i;
    merr_t err = 0;
    void *lock;
    struct cn_level_cursor *lcur;
    struct cn_tree *tree = cn_get_tree(cur->cncur_cn);

    for (i = 0; i < NUM_LEVELS; i++) {
        size_t kvref_tab_cnt = 1024 / sizeof(struct kvref);

        lcur = &cur->cncur_lcur[i];
        lcur->cnlc_cncur = cur;
        lcur->cnlc_level = i;
        lcur->cnlc_iterc = 0;
        if (!lcur->cnlc_kvref_tab)
            lcur->cnlc_kvref_tab = table_create(kvref_tab_cnt, sizeof(struct kvref), false);

        lcur->cnlc_esrcc = 64;
        lcur->cnlc_esrcv = malloc(lcur->cnlc_esrcc * sizeof(*lcur->cnlc_esrcv));

        if (!lcur->cnlc_kvref_tab || !lcur->cnlc_esrcv) {
            err = merr(ENOMEM);
            goto out;
        }
    }

    cur->cncur_flags = kvset_iter_flag_mmap;
    if (cur->cncur_reverse)
        cur->cncur_flags |= kvset_iter_flag_reverse;

    lcur = &cur->cncur_lcur[0];

    rmlock_rlock(&tree->ct_lock, &lock);
    err = cn_tree_kvset_refs(tree->ct_root, lcur);
    rmlock_runlock(lock);

    if (ev(err))
        goto out;

    err = cn_lcur_init(lcur);
    if (ev(err))
        goto out;

    cur->cncur_first_read = 1;

    cur->cncur_dgen = lcur->cnlc_dgen_hi;
    err = bin_heap_create(NUM_LEVELS, cur->cncur_reverse ? cn_kv_cmp_rev : cn_kv_cmp, &cur->cncur_bh);

out:
    if (err) {
        for (; i >= 0; i--) {
            struct cn_level_cursor *lcur = &cur->cncur_lcur[i];

            cn_lcur_kvset_release(lcur);
            table_destroy(lcur->cnlc_kvref_tab);
            free(lcur->cnlc_esrcv);
        }
    }

    return err;
}

void
cn_tree_cursor_destroy(struct cn_cursor *cur)
{
    int i;

    for (i = 0; i < NUM_LEVELS; i++) {
        struct cn_level_cursor *lcur = &cur->cncur_lcur[i];

        cn_lcur_kvset_release(lcur);

        table_destroy(lcur->cnlc_kvref_tab);
        bin_heap_destroy(lcur->cnlc_bh);
        free(lcur->cnlc_esrcv);
    }

    bin_heap_destroy(cur->cncur_bh);
}

MTF_STATIC merr_t
cn_lcur_seek(
    struct cn_level_cursor *lcur,
    const void             *key,
    uint32_t                len)
{
    merr_t err;
    int i;

    for (i = 0; i < lcur->cnlc_iterc; i++) {
        struct kv_iterator *it = kvset_cursor_es_h2r(lcur->cnlc_esrcv[i]);
        bool eof = false;

        err = kvset_iter_seek(it, key, len, &eof);
        if (ev(err))
            return err;
    }

    err = bin_heap_prepare(lcur->cnlc_bh, lcur->cnlc_iterc, lcur->cnlc_esrcv);

    return err;
}

static void
cn_lcur_advance(struct cn_level_cursor *lcur)
{
    struct cn_cursor *cncur = lcur->cnlc_cncur;
    struct cn_tree *tree = cn_get_tree(cncur->cncur_cn);
    struct route_node *rtn_curr, *rtn_ekey;
    void *lock;
    bool first_pass = true;

    if (lcur->cnlc_islast)
        return;

    /* Invalidate ptomb if it's a level 1 ptomb. If the next node also contains keys with the
     * ptomb's prefix, it will also have a copy of the ptomb.
     */
    if (cncur->cncur_pt_set && cncur->cncur_pt_level == 1)
        cncur->cncur_pt_set = 0;

    cn_lcur_kvset_release(lcur);

    rmlock_rlock(&tree->ct_lock, &lock);

    rtn_curr = cncur->cncur_reverse ?
               route_map_lookup(tree->ct_route_map, lcur->cnlc_next_ekey, lcur->cnlc_next_eklen) :
               route_map_lookupGT(tree->ct_route_map, lcur->cnlc_next_ekey, lcur->cnlc_next_eklen);

    do {
        if (cncur->cncur_reverse) {
            if (!first_pass)
                rtn_curr = route_node_prev(rtn_curr);

            lcur->cnlc_islast = route_node_isfirst(rtn_curr);
            rtn_ekey = route_node_prev(rtn_curr);
        } else {
            if (!first_pass)
                rtn_curr = route_node_next(rtn_curr);

            lcur->cnlc_islast = route_node_islast(rtn_curr);
            rtn_ekey = rtn_curr;
        }

        first_pass = false;
        cncur->cncur_merr = cn_tree_kvset_refs(route_node_tnode(rtn_curr), lcur);
        if (ev(cncur->cncur_merr))
            break;

    } while (!lcur->cnlc_islast && !table_len(lcur->cnlc_kvref_tab));

    rmlock_runlock(lock);

    if (ev(cncur->cncur_merr))
        return;

    cncur->cncur_merr = cn_lcur_init(lcur);
    if (ev(cncur->cncur_merr))
        return;

    if (lcur->cnlc_iterc) {
        cncur->cncur_merr = cn_lcur_seek(lcur, lcur->cnlc_next_ekey, lcur->cnlc_next_eklen);
        if (ev(cncur->cncur_merr))
            return;
    }

    if (lcur->cnlc_islast)
        return;

    route_node_keycpy(rtn_ekey, lcur->cnlc_next_ekey,
                      sizeof(lcur->cnlc_next_ekey),
                      &lcur->cnlc_next_eklen);
}

static bool
cn_lcur_read(struct element_source *es, void **element)
{
    struct cn_level_cursor *lcur = container_of(es, struct cn_level_cursor, cnlc_es);
    struct cn_kv_item      *popme;
    bool                    more;

    more = bin_heap_peek(lcur->cnlc_bh, (void **)&popme);

    while (!more) {
        if (lcur->cnlc_level == 0 || lcur->cnlc_islast)
            return false;

        cn_lcur_advance(lcur);
        if (ev(lcur->cnlc_cncur->cncur_merr))
            return false;

        more = bin_heap_peek(lcur->cnlc_bh, (void **)&popme);
    }

    lcur->cnlc_item = *popme;
    *element = &lcur->cnlc_item;

    bin_heap_pop(lcur->cnlc_bh, (void **)&popme);
    return true;
}

merr_t
cn_tree_cursor_seek(
    struct cn_cursor * cur,
    const void *       key,
    uint32_t           len,
    struct kc_filter * filter)
{
    struct cn_tree *tree = cn_get_tree(cur->cncur_cn);
    struct cn_level_cursor *lcur = &cur->cncur_lcur[1];
    void *lock;
    struct element_source **esrc;
    struct route_node *rtn_curr, *rtn_ekey;
    merr_t err = 0;
    bool first_pass = true;
    int i;

    cn_lcur_kvset_release(lcur);

    rmlock_rlock(&tree->ct_lock, &lock);

    rtn_curr = route_map_lookup(tree->ct_route_map, key, len);

    do {
        if (cur->cncur_reverse) {
            if (!first_pass)
                rtn_curr = route_node_prev(rtn_curr);

            lcur->cnlc_islast = route_node_isfirst(rtn_curr);
            rtn_ekey = route_node_prev(rtn_curr);

        } else {
            if (!first_pass)
                rtn_curr = route_node_next(rtn_curr);

            lcur->cnlc_islast = route_node_islast(rtn_curr);
            rtn_ekey = rtn_curr;
        }

        first_pass = false;
        err = cn_tree_kvset_refs(route_node_tnode(rtn_curr), lcur);
        if (ev(err))
            break;

    } while (!lcur->cnlc_islast && !table_len(lcur->cnlc_kvref_tab));

    if (!lcur->cnlc_islast)
        route_node_keycpy(rtn_ekey, lcur->cnlc_next_ekey,
                          sizeof(lcur->cnlc_next_ekey), &lcur->cnlc_next_eklen);

    rmlock_runlock(lock);

    if (ev(err))
        return err;

    err = cn_lcur_init(lcur);
    if (ev(err))
        return err;

    /* Prepare iters and binheaps.
     */
    cur->cncur_iterc = 0;
    esrc = cur->cncur_esrcv;

    for (i = 0; i < NUM_LEVELS; i++) {
        lcur = &cur->cncur_lcur[i];

        if (!lcur->cnlc_iterc)
            continue;

        err = cn_lcur_seek(lcur, key, len);
        if (ev(err))
            return err;

        ++cur->cncur_iterc;
        *esrc = &lcur->cnlc_es;
        ++esrc;
    }

    cur->cncur_first_read = 1;
    cur->cncur_eof = cur->cncur_iterc ? false : true;
    cur->cncur_pt_set = 0;

    return bin_heap_prepare(cur->cncur_bh, cur->cncur_iterc, cur->cncur_esrcv);
}

merr_t
cn_tree_cursor_active_kvsets(struct cn_cursor *cur, uint32_t *active, uint32_t *total)
{
    int i;

    if (ev(!active || !total))
        return merr(EINVAL);

    *active = *total = 0;

    for (i = 0; i < NUM_LEVELS; i++) {
        struct cn_level_cursor *lcur = &cur->cncur_lcur[i];

        *active += bin_heap_width(lcur->cnlc_bh);
        *total  += table_len(lcur->cnlc_kvref_tab);
    }

    return 0;
}

merr_t
cn_tree_cursor_update(struct cn_cursor *cur)
{
    struct cn_tree *tree = cn_get_tree(cur->cncur_cn);
    struct cn_level_cursor *lcur;
    void *lock;
    int i;
    merr_t err;

    /* Release resources.
     */
    for (i = 0; i < NUM_LEVELS; i++)
        cn_lcur_kvset_release(&cur->cncur_lcur[i]);

    /* Re-acquire Level 0 resources.
     */
    cur->cncur_first_read = 1;
    lcur = &cur->cncur_lcur[0];

    rmlock_rlock(&tree->ct_lock, &lock);
    err = cn_tree_kvset_refs(tree->ct_root, lcur);
    rmlock_runlock(lock);

    if (ev(err))
        return err;

    err = cn_lcur_init(lcur);
    if (ev(err))
        return err;

    cur->cncur_dgen = lcur->cnlc_dgen_hi;

    return err;
}

static void
drop_dups(struct cn_cursor *cur, struct key_obj *kobj)
{
    struct cn_kv_item *dup;

    while (bin_heap_peek(cur->cncur_bh, (void **)&dup)) {

        if (key_obj_cmp(&dup->kobj, kobj))
            return;

        /* If dup is ptomb and kobj isn't, leave dup be so it can hide
         * the appropriate keys.
         */
        if (dup->vctx.is_ptomb)
            return;

        bin_heap_pop(cur->cncur_bh, (void **)&dup);
    }
}

/*
 * compare item's prefix to cursor's prefix.
 *
 * rc <  0 : itempfx < cursor's pfx
 * rc >  0 : itempfx > cursor's pfx
 * rc == 0 : itempfx == cursor's pfx
 */
static int
cur_item_pfx_cmp(struct cn_cursor *cur, struct cn_kv_item *item)
{
    int            rc;
    struct key_obj ko_pfx;

    key2kobj(&ko_pfx, cur->cncur_pfx, cur->cncur_pfxlen);

    /* When cursor's pfx_len is larger than tree's pfx_len, allow ptombs to
     * pass through. To correctly compare ptomb w/ cursor's pfx in this
     * case, invert the order of args to keycmp_prefix() and then invert
     * signedness of rc.
     */
    if (item->vctx.is_ptomb && cur->cncur_pfxlen > cur->cncur_tree_pfxlen) {
        rc = key_obj_cmp_prefix(&item->kobj, &ko_pfx);
        rc = -rc;
    } else {
        rc = key_obj_cmp_prefix(&ko_pfx, &item->kobj);
    }

    if (cur->cncur_reverse)
        rc = -rc;

    return rc;
}

/* When bin_heap_pop() is called, it moves the underlying iterators forward. This could cause the
 * level 1 iterator to cross nodes, which involves releasing its resources and acquiring new ones
 * for the new node. This crossover must happen before cn_tree_cursor_read() uses an item from
 * the binheap.
 *
 * This ensures that the pointers in item will remain valid until the next call to
 * cn_tree_cursor_read().
 *
 * This function ensures that the pointers in item do not become invalid due to a crossover while
 * duplicate keys are being dropped. This function must be called at the beginning of the merge loop.
 */
static void
cn_tree_cursor_advance_safe(struct cn_cursor *cur)
{
    struct kvset *ks;
    struct cn_kv_item item, *popme = NULL;

    bin_heap_peek(cur->cncur_bh, (void **)&popme);
    assert(popme); /* This is the key read at the last cursor read. */

    item = *popme;

    /* Make sure the memory backing item's pointers is safe by acquiring a kvset ref before
     * advancing the cursor.
     */
    ks = kvset_iter_kvset_get(kvset_cursor_es_h2r(popme->src));
    kvset_get_ref(ks);

    bin_heap_pop(cur->cncur_bh, (void **)&popme); /* advance the cursor */
    if (!cur->cncur_merr)
        drop_dups(cur, &item.kobj); /* push on past the duplicates */

    kvset_put_ref(ks);
}

merr_t
cn_tree_cursor_read(struct cn_cursor *cur, struct kvs_cursor_element *elem, bool *eof)
{
    struct cn_kv_item  *item;
    uint64_t            seq;
    bool                found;
    const void *        vdata;
    uint                vlen;
    uint                complen;
    int                 rc;
    struct kv_iterator *kv_iter = 0;
    struct key_obj      filter_ko = { 0 };

    if (ev(cur->cncur_merr))
        return cur->cncur_merr;

    if (cur->cncur_eof) {
        *eof = cur->cncur_eof;
        return 0;
    }

    if (HSE_UNLIKELY(cur->cncur_filter))
        key2kobj(&filter_ko, cur->cncur_filter->kcf_maxkey, cur->cncur_filter->kcf_maxklen);

    do {
        enum kmd_vtype vtype;
        uint32_t       vbidx;
        uint32_t       vboff;
        bool           more;

        if (!cur->cncur_first_read) {
            cn_tree_cursor_advance_safe(cur);
            if (ev(cur->cncur_merr))
                return cur->cncur_merr;
        }

        cur->cncur_first_read = 0;

        more = bin_heap_peek(cur->cncur_bh, (void **)&item);
        if (!more) {
            *eof = (cur->cncur_eof = 1);
            return 0;
        }

        rc = cur_item_pfx_cmp(cur, item);
        if (rc < 0) {
            *eof = (cur->cncur_eof = 1);
            return 0;
        }

        assert(rc <= 0);

        if (HSE_UNLIKELY(cur->cncur_filter && key_obj_cmp(&item->kobj, &filter_ko) > 0)) {
            *eof = (cur->cncur_eof = 1);
            return 0;
        }

        kv_iter = kvset_cursor_es_h2r(item->src);

        do {
            found = kvset_iter_next_vref(kv_iter, &item->vctx, &seq, &vtype, &vbidx,
                                         &vboff, &vdata, &vlen, &complen);
        } while (found && seq > cur->cncur_seqno);

        if (!found)
            continue; /* Key doesn't have a value in the cursor's view. */

        cur->cncur_merr = kvset_iter_val_get(kv_iter, &item->vctx, vtype, vbidx,
                                       vboff, &vdata, &vlen, &complen);
        if (ev(cur->cncur_merr))
            return cur->cncur_merr;

        if (cur->cncur_pt_set) {
            if (key_obj_cmp_prefix(&cur->cncur_pt_kobj, &item->kobj) == 0) {
                if (seq < cur->cncur_pt_seq)
                    found = false; /* Key is hidden by a ptomb. */
            } else {
                cur->cncur_pt_set = 0;
                cur->cncur_pt_seq = 0;
            }
        }

        if (vtype == VTYPE_PTOMB) {
            found = false;

            /* In case of duplicate ptombs, we need just the first (newest) ptomb in the cursor's
             * view.
             */
            if (!cur->cncur_pt_set) {
                struct cn_level_cursor *pt_lcur;
                assert(cur->cncur_tree_pfxlen > 0);

                cur->cncur_pt_kobj = item->kobj;
                cur->cncur_pt_seq = seq;
                cur->cncur_pt_set = 1;

                pt_lcur = container_of(item, typeof(struct cn_level_cursor), cnlc_item);
                cur->cncur_pt_level = pt_lcur->cnlc_level;
            }
        }

    } while (!found);


    elem->kce_kobj = item->kobj;
    kvs_vtuple_init(&elem->kce_vt, (void *)vdata, vlen);
    elem->kce_complen = complen;
    elem->kce_is_ptomb = false; /* cn never returns a ptomb */
    elem->kce_seqnoref = HSE_ORDNL_TO_SQNREF(seq);

    cur->cncur_stats.ms_keys_out++;
    cur->cncur_stats.ms_key_bytes_out += key_obj_len(&item->kobj);
    cur->cncur_stats.ms_val_bytes_out += vlen;

    *eof = 0;
    return 0;
}

#if HSE_MOCKING
#include "cn_tree_cursor_ut_impl.i"
#endif /* HSE_MOCKING */
