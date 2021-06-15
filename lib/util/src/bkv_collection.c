/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>
#include <hse_util/bkv_collection.h>
#include <hse_util/vlb.h>
#include <hse_util/slab.h>

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
    size_t                 alloc_cnt = cnt;
    size_t                 sz;

    bkvc = kmem_cache_alloc(bkv_collection_cache);
    if (ev(!bkvc))
        return merr(ENOMEM);

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
    vlb_free(bkvc->bkvcol_entry, bkvc->bkvcol_cnt * sizeof(*bkvc->bkvcol_entry));
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
        size_t newsz, oldsz;

        oldsz = bkvc->bkvcol_cnt_max * sizeof(*bkvc->bkvcol_entry);
        bkvc->bkvcol_cnt_max += bkvc->bkvcol_cnt_initial;
        newsz = bkvc->bkvcol_cnt_max * sizeof(*bkvc->bkvcol_entry);

        mem = vlb_alloc(newsz);
        if (ev(!mem))
            return merr(ENOMEM);

        memcpy(mem, bkvc->bkvcol_entry, oldsz);
        vlb_free(bkvc->bkvcol_entry, oldsz);
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
bkv_collection_finish(struct bkv_collection *bkvc)
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

