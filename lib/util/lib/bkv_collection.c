/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <hse/util/event_counter.h>
#include <hse/util/bkv_collection.h>
#include <hse/util/bonsai_tree.h>
#include <hse/util/vlb.h>
#include <hse/util/slab.h>

static struct kmem_cache *bkv_collection_cache;

struct bkv_collection_entry {
    struct bonsai_kv * bkv;
    struct bonsai_val *vlist;
};

struct bkv_collection {
    void *                       bkvcol_cbarg;
    bkv_collection_cb *          bkvcol_cb;
    size_t                       bkvcol_cnt;
    size_t                       bkvcol_cnt_max;
    size_t                       bkvcol_cnt_initial;
    struct bkv_collection_entry *bkvcol_entry;
};

merr_t
bkv_collection_create(
    struct bkv_collection **collection,
    size_t                  cnt,
    bkv_collection_cb *     cb,
    void *                  cbarg)
{
    struct bkv_collection *bkvc;
    size_t                 alloc_cnt;
    size_t                 sz;

    bkvc = kmem_cache_alloc(bkv_collection_cache);
    if (ev(!bkvc))
        return merr(ENOMEM);

    alloc_cnt = VLB_ALLOCSZ_MAX / sizeof(*bkvc->bkvcol_entry);
    if (cnt > alloc_cnt)
        alloc_cnt = cnt;

    sz = (alloc_cnt * sizeof(*bkvc->bkvcol_entry));
    bkvc->bkvcol_entry = vlb_alloc(sz);
    if (ev(!bkvc->bkvcol_entry)) {
        kmem_cache_free(bkv_collection_cache, bkvc);
        return merr(ENOMEM);
    }

    bkvc->bkvcol_cnt_initial = alloc_cnt;
    bkvc->bkvcol_cnt_max = bkvc->bkvcol_cnt_initial;
    bkvc->bkvcol_cnt = 0;
    bkvc->bkvcol_cb = cb;
    bkvc->bkvcol_cbarg = cbarg;

    *collection = bkvc;
    return 0;
}

void
bkv_collection_destroy(struct bkv_collection *bkvc)
{
    size_t oldsz = bkvc->bkvcol_cnt_max * sizeof(*bkvc->bkvcol_entry);
    size_t usedsz = bkvc->bkvcol_cnt * sizeof(*bkvc->bkvcol_entry);

    assert(oldsz >= usedsz);

    if (oldsz > VLB_ALLOCSZ_MAX)
        usedsz = oldsz;

    vlb_free(bkvc->bkvcol_entry, usedsz);
    kmem_cache_free(bkv_collection_cache, bkvc);
}

size_t
bkv_collection_count(struct bkv_collection *bkvc)
{
    return bkvc->bkvcol_cnt;
}

merr_t
bkv_collection_add(struct bkv_collection *bkvc, struct bonsai_kv *bkv, struct bonsai_val *val_list)
{
    struct bkv_collection_entry *entry;

    if (HSE_UNLIKELY(bkvc->bkvcol_cnt >= bkvc->bkvcol_cnt_max)) {
        void * mem;
        size_t newsz, oldsz, usedsz;

        oldsz = bkvc->bkvcol_cnt_max * sizeof(*bkvc->bkvcol_entry);
        usedsz = bkvc->bkvcol_cnt * sizeof(*bkvc->bkvcol_entry);
        assert(oldsz >= usedsz);

        bkvc->bkvcol_cnt_max += bkvc->bkvcol_cnt_initial;
        newsz = bkvc->bkvcol_cnt_max * sizeof(*bkvc->bkvcol_entry);

        mem = vlb_alloc(newsz);
        if (ev(!mem))
            return merr(ENOMEM);

        memcpy(mem, bkvc->bkvcol_entry, usedsz);

        if (oldsz > VLB_ALLOCSZ_MAX)
            usedsz = oldsz;

        vlb_free(bkvc->bkvcol_entry, usedsz);
        bkvc->bkvcol_entry = mem;
    }

    entry = &bkvc->bkvcol_entry[bkvc->bkvcol_cnt++];
    entry->bkv = bkv;
    entry->vlist = val_list;

    return 0;
}

void *
bkv_collection_rock_get(struct bkv_collection *bkvc)
{
    return bkvc->bkvcol_cbarg;
}

/* Caller must lock resources as needed before calling this function.
 */
merr_t
bkv_collection_apply(struct bkv_collection *bkvc)
{
    int    i;
    merr_t err = 0;

    for (i = 0; i < bkvc->bkvcol_cnt; i++) {
        struct bkv_collection_entry *e = &bkvc->bkvcol_entry[i];
        struct bonsai_kv *           bkv = e->bkv;
        struct bonsai_val *          vlist = e->vlist;

        err = bkvc->bkvcol_cb(bkvc->bkvcol_cbarg, bkv, vlist);
        if (ev(err))
            break;
    }

    return err;
}

struct bkv_collection_pair {
    struct bkv_collection *bkvc[2];
    int                    idx[2];
};

static void
bkv_collection_pair_init(
    struct bkv_collection *     bkvc1,
    struct bkv_collection *     bkvc2,
    struct bkv_collection_pair *pair)
{
    pair->bkvc[0] = bkvc1;
    pair->bkvc[1] = bkvc2;
    pair->idx[0] = pair->idx[1] = 0;
}

static bool
bkv_collection_pair_next(
    struct bkv_collection_pair *pair,
    struct bonsai_kv **         bkv,
    struct bonsai_val **        vlist)
{
    struct bkv_collection_entry *e1, *e2;
    int                          rc, idx1, idx2;
    bool                         eof1, eof2;

    idx1 = pair->idx[0];
    e1 = &pair->bkvc[0]->bkvcol_entry[idx1];
    eof1 = idx1 >= pair->bkvc[0]->bkvcol_cnt;

    idx2 = pair->idx[1];
    e2 = &pair->bkvc[1]->bkvcol_entry[idx2];
    eof2 = idx2 >= pair->bkvc[1]->bkvcol_cnt;

    if (eof1 && eof2)
        return false;

    if (eof1)
        rc = 1;
    else if (eof2)
        rc = -1;
    else
        rc = bn_kv_cmp(e1->bkv, e2->bkv);

    if (rc < 0) {
        *bkv = e1->bkv;
        *vlist = e1->vlist;
        pair->idx[0]++;
    } else if (rc > 0) {
        *bkv = e2->bkv;
        *vlist = e2->vlist;
        pair->idx[1]++;
    } else {
        struct bonsai_val *v, **last;

        assert(e1->vlist && e2->vlist);
        last = &e1->vlist;
        for (v = e1->vlist; v; v = v->bv_priv)
            last = &v->bv_priv;

        *last = e2->vlist; /* Add e2->vlist at the end of e1->vlist */
        *bkv = e1->bkv;
        *vlist = e1->vlist;
        pair->idx[0]++;
        pair->idx[1]++;
    }

    return true;
}

merr_t
bkv_collection_finish_pair(struct bkv_collection *bkvc1, struct bkv_collection *bkvc2)
{
    merr_t                     err = 0;
    struct bkv_collection_pair p;
    struct bonsai_kv *         bkv;
    struct bonsai_val *        vlist;

    assert(bkvc1->bkvcol_cb == bkvc2->bkvcol_cb);
    assert(bkvc1->bkvcol_cbarg == bkvc2->bkvcol_cbarg);

    bkv_collection_pair_init(bkvc1, bkvc2, &p);

    while (bkv_collection_pair_next(&p, &bkv, &vlist)) {
        err = bkvc1->bkvcol_cb(bkvc1->bkvcol_cbarg, bkv, vlist);
        if (ev(err))
            break;
    }

    return err;
}

/* Init/Fini
 */
merr_t
bkv_collection_init(void)
{
    bkv_collection_cache = kmem_cache_create(
        "bkv_collection",
        sizeof(struct bkv_collection),
        alignof(struct bkv_collection),
        SLAB_PACKED,
        NULL);

    if (!bkv_collection_cache)
        return merr(ENOMEM);

    return 0;
}

void
bkv_collection_fini(void)
{
    kmem_cache_destroy(bkv_collection_cache);
}
