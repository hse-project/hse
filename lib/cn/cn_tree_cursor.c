/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_util/mutex.h>
#include <hse_util/list.h>
#include <hse_util/logging.h>
#include <hse_util/assert.h>
#include <hse_util/atomic.h>
#include <hse_util/table.h>
#include <hse_util/key_util.h>
#include <hse_util/keycmp.h>
#include <hse_util/bin_heap.h>

#include <hse_ikvdb/cn.h>

#include <cn/cn_cursor.h>

#define MTF_MOCK_IMPL_cn_tree_cursor

#include "route.h"
#include "cn_tree_internal.h"
#include "cn_tree_cursor.h"
#include "kvset_internal.h"
#include "kvset.h"
#include "kv_iterator.h"

/* Temporary route map stubs - START
 * ==================================
 */

struct route_map *map;

struct route_node {
};

struct route_node *
rmap_lookup(struct route_map *map, const void *pfx, uint pfxlen)
{
    return 0;
}

struct route_node *
rmap_lookupGT(struct route_map *map, const void *pfx, uint pfxlen)
{
    return 0;
}

struct route_node *
rmap_get(struct route_map *map, struct route_node *rtn)
{
    return 0;
}

void
rmap_put(struct route_map *map, struct route_node *node)
{
}

static HSE_ALWAYS_INLINE bool
rnode_isfirst(const struct route_node *node)
{
    return true;
}

static HSE_ALWAYS_INLINE bool
rnode_islast(const struct route_node *node)
{
    return true;
}

static HSE_ALWAYS_INLINE void *
rnode_tnode(struct route_node *node)
{
    return 0;
}

static HSE_ALWAYS_INLINE void
rnode_keycpy(struct route_node *node, void *kbuf, size_t kbuf_sz, uint *klen)
{
}

struct route_node *
rnode_next(const struct route_node *node)
{
    return 0;
}

struct route_node *
rnode_prev(const struct route_node *node)
{
    return 0;
}

struct route_map *
rmap_create(const struct kvs_cparams *cp, const char *kvsname, struct cn_tree *tree)
{
    return 0;
}

void
rmap_destroy(struct route_map *map)
{
}

/* Temporary route map stubs - END
 * ==================================
 */

/*
 * Min heap comparator.
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
 * Max heap comparator with a caveat: A ptomb sorts before all keys w/ matching
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
    struct table *tab = lcur->kvref_tab;
    struct kvset_list_entry *le;

    lcur->dgen_hi = lcur->dgen_lo = 0;
    table_reset(tab);

    list_for_each_entry (le, &node->tn_kvset_list, le_link) {
        struct kvset *kvset = le->le_kvset;
        struct kvref *k;
        u64 dgen = kvset_get_dgen(kvset);

        if (!lcur->dgen_hi)
            lcur->dgen_hi = dgen;

        k = table_append(tab);
        if (ev(!k))
            return merr(ENOMEM);

        kvset_get_ref(kvset);
        k->kvset = kvset;

        lcur->dgen_lo = dgen;
    }

    return 0;
}

// TODO Gaurav: rename to init
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
        lcur->cncur = cur;
        lcur->level = i;
        if (!lcur->kvref_tab)
            lcur->kvref_tab = table_create(kvref_tab_cnt, sizeof(struct kvref), false);

        // TODO Gaurav: magic number alert! Store into cncur_lcur->iterv_sz and grow as needed.
        lcur->esrcv = malloc(100 * sizeof(lcur->esrcv));

        if (!lcur->kvref_tab || !lcur->esrcv) {
            err = merr(ENOMEM);
            goto out;
        }
    }

    cur->kvset_putref_tab = table_create(64, sizeof(struct kvref), false);

    lcur = &cur->cncur_lcur[0];

    rmlock_rlock(&tree->ct_lock, &lock);
    err = cn_tree_kvset_refs(tree->ct_root, lcur);
    rmlock_runlock(lock);

    if (ev(err))
        goto out;

    err = bin_heap2_create(NUM_LEVELS, cur->reverse ? cn_kv_cmp_rev : cn_kv_cmp, &cur->cncur_bh);

out:
    if (err) {
        for (i = 0; i < NUM_LEVELS; i++) {
            struct cn_level_cursor *lcur = &cur->cncur_lcur[i];

            table_destroy(lcur->kvref_tab);
            free(lcur->esrcv);
        }
    }

    return err;
}

void
kvref_tab_putref(void *arg)
{
    struct kvref *k = arg;

    if (k->kvset) {
        kvset_put_ref(k->kvset);
        k->kvset = 0;
    }
}

void
cn_tree_cursor_destroy(struct cn_cursor *cur)
{
    int i;

    table_apply(cur->kvset_putref_tab, kvref_tab_putref);
    table_destroy(cur->kvset_putref_tab);

    for (i = 0; i < NUM_LEVELS; i++) {
        table_destroy(cur->cncur_lcur[i].kvref_tab);
        free(cur->cncur_lcur[i].esrcv);
    }
}

static bool
cn_tree_lcur_read(struct element_source *, void **);

MTF_STATIC merr_t
cn_tree_lcur_seek(
    struct cn_level_cursor *lcur,
    const void             *key,
    u32                     len,
    bool                   *added)
{
    struct cn_cursor       *cncur = lcur->cncur;
    struct table           *tab = lcur->kvref_tab;
    struct element_source **esrc;

    struct workqueue_struct *maint_wq = cn_get_maint_wq(cncur->cncur_cn);

    uint old_iterc, iterc = table_len(tab);
    uint i, bh_align = 16;
    size_t bh_sz;
    merr_t err;

    old_iterc = lcur->iterc;
    lcur->iterc = 0;
    esrc = lcur->esrcv;

    for (i = 0; i < iterc; i++) {
        struct kvref *k = table_at(tab, i);
        struct kv_iterator *it;
        bool eof = false;

        // TODO Gaurav: (1) handle error. (2) Split create into alloc+reset. Then reuse kvset iters cached in cn_cursor.
        err = kvset_iter_create(k->kvset, NULL, maint_wq, NULL, cncur->cncur_flags, &it);
        if (ev(err))
            return err;

        err = kvset_iter_seek(it, key, len, &eof);
        if (ev(err))
            return err;

        if (eof)
            continue;

        *esrc++ = kvset_iter_es_get(it);
        ++lcur->iterc;
    }

    if (!lcur->iterc) {
        bin_heap2_destroy(lcur->bh);
        *added = false;
        return 0;
    }

    *added = true;

    bh_sz = ALIGN(lcur->iterc, bh_align);
    if (bh_sz > ALIGN(old_iterc, bh_align)) {
        bin_heap2_destroy(lcur->bh);
        err = bin_heap2_create(bh_sz, cncur->reverse ? cn_kv_cmp_rev : cn_kv_cmp, &lcur->bh);
        if (err)
            return err;
    }

    err = bin_heap2_prepare(lcur->bh, lcur->iterc, lcur->esrcv);
    lcur->es = es_make(cn_tree_lcur_read, 0, 0);

    return err;
}

static bool
cn_tree_lcur_advance(struct cn_level_cursor *lcur)
{
        struct cn_cursor *cncur = lcur->cncur;
        struct cn_tree *tree = cn_get_tree(cncur->cncur_cn);
        struct route_node *rtn_curr, *rtn_next;
        merr_t err;
        bool added;
        void *lock;

        for (int i = 0; i < lcur->iterc; i++)
            kvset_iter_release(kvset_cursor_es_h2r(lcur->esrcv[i]));

        for (int i = 0; i < table_len(lcur->kvref_tab); i++) {
            struct kvref *from = table_at(lcur->kvref_tab, i);
            struct kvref *to = table_append(cncur->kvset_putref_tab);

            to->kvset = from->kvset;
        }

        rmlock_rlock(&tree->ct_lock, &lock);
        rtn_curr = rmap_lookup(map, lcur->next_ekey, lcur->next_eklen);
        rtn_next = cncur->reverse ? rmap_lookup(map, lcur->next_ekey, lcur->next_eklen) :
                                    rmap_lookupGT(map, lcur->next_ekey, lcur->next_eklen);

        rnode_keycpy(rtn_next, &lcur->next_ekey, sizeof(lcur->next_ekey), &lcur->next_eklen);

        err = cn_tree_kvset_refs(rnode_tnode(rtn_curr), lcur);
        rmlock_runlock(&lock);

        if (ev(err)) {
            cncur->merr = err;
            return false;
        }

        err = cn_tree_lcur_seek(lcur, 0, 0, &added);
        if (ev(err)) {
            cncur->merr = err;
            return false;
        }

        return added;
}

static bool
cn_tree_lcur_read(struct element_source *es, void **element)
{
    struct cn_level_cursor *lcur = container_of(es, struct cn_level_cursor, es);
    struct cn_kv_item      *popme;
    bool                    more;

again:
    more = bin_heap2_peek(lcur->bh, (void **)&popme);
    if (!more) {
        bool l1_eof;

        if (lcur->level == 0)
            return false;

        l1_eof = lcur->cncur->reverse ? rnode_isfirst(lcur->route_node) : rnode_islast(lcur->route_node);
        if (l1_eof)
            return false;

        if (cn_tree_lcur_advance(lcur))
            goto again;

        // TODO Gaurav: check cur->merr and short-circuit
    }

    lcur->item = *popme;
    *element = &lcur->item;

    bin_heap2_pop(lcur->bh, (void **)&popme);
    return true;
}

merr_t
cn_tree_cursor_seek(
    struct cn_cursor * cur,
    const void *       key,
    u32                len,
    struct kc_filter * filter)
{
    struct cn_tree *tree = cn_get_tree(cur->cncur_cn);
    struct cn_level_cursor *lcur;
    void *lock;
    struct element_source **esrc;
    struct route_node *rtn_curr, *rtn_ekey;
    merr_t err = 0;
    int i;

    rmlock_rlock(&tree->ct_lock, &lock);

    rtn_curr = rmap_lookup(map, key, len);
    rtn_ekey = cur->reverse ? rnode_prev(rtn_curr) : rtn_curr;

    lcur = &cur->cncur_lcur[1];
    rnode_keycpy(rtn_ekey, lcur->next_ekey, sizeof(lcur->next_ekey), &lcur->next_eklen);

    for (i = 0; i < lcur->iterc; i++)
        kvset_iter_release(kvset_cursor_es_h2r(lcur->esrcv[i]));

    err = cn_tree_kvset_refs(rnode_tnode(rtn_curr), lcur);
    rmlock_runlock(lock);

    if (ev(err))
        goto out;

    cur->cncur_flags = kvset_iter_flag_mcache;
    if (cur->reverse)
        cur->cncur_flags |= kvset_iter_flag_reverse;

    /* Prepare iters and binheaps.
     */
    cur->cncur_iterc = 0;
    esrc = cur->cncur_esrcv;

    for (i = 0; i < NUM_LEVELS; i++) {
        bool added;
        lcur = &cur->cncur_lcur[i];

        err = cn_tree_lcur_seek(lcur, key, len, &added);
        if (ev(err))
            goto out;

        if (added) {
            ++cur->cncur_iterc;
            *esrc = &lcur->es;
            ++esrc;
        }
    }

    cur->eof = cur->cncur_iterc ? false : true;

out:
    if (!err)
        err = bin_heap2_prepare(cur->cncur_bh, cur->cncur_iterc, cur->cncur_esrcv);

    if (err) {
        for (i = 0; i < NUM_LEVELS; i++)
            table_apply(cur->cncur_lcur[i].kvref_tab, kvref_tab_putref);
    }

    return err;
}

merr_t
cn_tree_cursor_active_kvsets(struct cn_cursor *cur, u32 *active, u32 *total)
{
    return 0;
}

// TODO Gaurav: make static
/*static*/ merr_t
cn_tree_capped_cursor_update(struct cn_cursor *cur, struct cn_tree *tree)
{
    return 0;
}

merr_t
cn_tree_cursor_update(struct cn_cursor *cur, struct cn_tree *tree)
{
    table_apply(cur->kvset_putref_tab, kvref_tab_putref);
    table_reset(cur->kvset_putref_tab);

    return 0;
}

static void
drop_dups(struct cn_cursor *cur, struct cn_kv_item *item)
{
    struct cn_kv_item *dup;

    while (bin_heap2_peek(cur->cncur_bh, (void **)&dup)) {

        if (key_obj_cmp(&dup->kobj, &item->kobj))
            return;

        /* If dup is ptomb and item isn't, leave dup be so it can hide
         * the appropriate keys.
         */
        if (dup->vctx.is_ptomb)
            return;

        bin_heap2_pop(cur->cncur_bh, (void **)&dup);
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

    key2kobj(&ko_pfx, cur->pfx, cur->pfx_len);

    /* When cursor's pfx_len is larger than tree's pfx_len, allow ptombs to
     * pass through. To correctly compare ptomb w/ cursor's pfx in this
     * case, invert the order of args to keycmp_prefix() and then invert
     * signedness of rc.
     */
    if (item->vctx.is_ptomb && cur->pfx_len > cur->ct_pfx_len) {
        rc = key_obj_cmp_prefix(&item->kobj, &ko_pfx);
        rc = -rc;
    } else {
        rc = key_obj_cmp_prefix(&ko_pfx, &item->kobj);
    }

    if (cur->reverse)
        rc = -rc;

    return rc;
}

merr_t
cn_tree_cursor_read(struct cn_cursor *cur, struct kvs_cursor_element *elem, bool *eof)
{
    struct cn_kv_item   item, *popme;
    u64                 seq;
    bool                found;
    const void *        vdata;
    uint                vlen;
    uint                complen;
    int                 rc;
    struct kv_iterator *kv_iter = 0;
    struct key_obj      filter_ko = { 0 };

    if (ev(cur->merr))
        return cur->merr;

    if (cur->eof) {
        *eof = cur->eof;
        return 0;
    }

    if (HSE_UNLIKELY(cur->filter))
        key2kobj(&filter_ko, cur->filter->kcf_maxkey, cur->filter->kcf_maxklen);

    do {
        enum kmd_vtype vtype;
        u32            vbidx;
        u32            vboff;

        table_apply(cur->kvset_putref_tab, kvref_tab_putref);
        table_reset(cur->kvset_putref_tab);

        if (!bin_heap2_peek(cur->cncur_bh, (void **)&popme)) {
            *eof = (cur->eof = 1);
            return 0;
        }

        /* Copy out bh item before bin_heap2_pop() overwrites its element (*popme).
         */
        item = *popme;
        bin_heap2_pop(cur->cncur_bh, (void **)&popme);

        rc = cur_item_pfx_cmp(cur, &item);
        if (rc < 0) {
            *eof = (cur->eof = 1);
            return 0;
        }

        assert(rc <= 0);

        if (HSE_UNLIKELY(cur->filter && key_obj_cmp(&item.kobj, &filter_ko) > 0)) {
            *eof = (cur->eof = 1);
            return 0;
        }

        kv_iter = kvset_cursor_es_h2r(item.src);
        found = true;

        do {
            if (!kvset_iter_next_vref(kv_iter, &item.vctx, &seq, &vtype, &vbidx,
                                      &vboff, &vdata, &vlen, &complen)) {
                found = false; /* Exhausted all values. */
                break;
            }
        } while (seq > cur->seqno);

        if (!found)
            continue; /* Key doesn't have a value in the cursor's view. */

        cur->merr = kvset_iter_val_get(kv_iter, &item.vctx, vtype, vbidx,
                                       vboff, &vdata, &vlen, &complen);
        if (ev(cur->merr))
            return cur->merr;

        if (cur->pt_set) {
            if (key_obj_cmp_prefix(&cur->pt_kobj, &item.kobj) == 0) {
                if (seq < cur->pt_seq)
                    found = false; /* Key is hidden by a ptomb. */
                else
                    printf("Hello\n");
            } else {
                cur->pt_set = 0;
                cur->pt_seq = 0;
            }
        }

        /* Only store ptomb w/ highest seqno (less than cur's seqno) i.e. first occurrence of
         * this ptomb.
         */
        if (vtype == vtype_ptomb && !cur->pt_set) {
            assert(cur->ct_pfx_len > 0);

            cur->pt_kobj = item.kobj;
            cur->pt_seq = seq;
            cur->pt_set = 1;
        }

        /* A kvset can have a matching key and ptomb such that the key
         * is newer than ptomb. So drop dups only if regular tomb.
         */
        if (vtype == vtype_tomb)
            drop_dups(cur, &item);

        if (vtype == vtype_ptomb)
            found = false;

    } while (!found);

    /* set output */
    elem->kce_kobj = item.kobj;
    kvs_vtuple_init(&elem->kce_vt, (void *)vdata, vlen);
    elem->kce_complen = complen;
    elem->kce_is_ptomb = false; /* cn never returns a ptomb */
    elem->kce_seqnoref = HSE_ORDNL_TO_SQNREF(seq);

    cur->stats.ms_keys_out++;
    cur->stats.ms_key_bytes_out += key_obj_len(&item.kobj);
    cur->stats.ms_val_bytes_out += vlen;

    drop_dups(cur, &item);

    *eof = 0;
    return 0;
}

#if HSE_MOCKING
#include "cn_tree_cursor_ut_impl.i"
#endif /* HSE_MOCKING */
