/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/conditions.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/alloc.h>
#include <hse_util/slab.h>

#include <hse_ikvdb/limits.h>

#include "../kvset.h"
#include "../cn_tree_internal.h"

#include "mock_mpool.h"
#include "mock_kvset.h"

/* ------------------------------------------------------------
 * Fake kvset data
 *
 * Notes:
 *      Each kvdata struct is an array of key/value pairs, where
 *      both are integers.  The first element of this array reuses
 *      the pair thus:
 *              key is the number of elements in the array,
 *              val is the current position in this array
 *                      (which allows iteration and eof detection)
 *              eof is when d[0].val == d[0].keys (current == nkeys)
 *      Tombstones are val of -1.
 */

static u64 dgen;

struct kvdata {
    int key;
    int val;
    int val_len;
};

int mock_kvset_verbose = 0;

void
mock_kvset_data_reset()
{
    dgen = 0;
}

static struct kvdata *
_make_data(struct nkv_tab *nkv)
{
    int            nkeys = nkv->nkeys;
    struct kvdata *d = calloc(nkeys + 1, sizeof(*d));

    if (d) {
        int i, k = nkv->key1, v = nkv->val1;

        d[0].key = nkeys; /* number of elements */
        d[0].val = 0;     /* current position in array */
        for (i = 1; i <= nkeys; ++i, ++k) {
            size_t buflen = 1 + CN_SMALL_VALUE_THRESHOLD;

            d[i].key = nkv->be ? htonl(k) : k;
            if (v == -1) { /* tombstone */
                d[i].val = v;
                d[i].val_len = 0;
                continue;
            }

            assert(nkv->vmix != 0);
            if (nkv->vmix == VMX_S32) {
                d[i].val = v++;
                d[i].val_len = sizeof(s32);
            } else if (nkv->vmix == VMX_BUF) {
                d[i].val = v++;
                d[i].val_len = buflen;
            } else if (nkv->vmix == VMX_MIXED) {
                if (v % 3 == 0)
                    d[i].val_len = sizeof(u32);
                else if (v % 10 == 0)
                    d[i].val_len = 0;
                else
                    d[i].val_len = buflen;
                d[i].val = v++;
            }
        }
    }

    return d;
}

void *
mock_vref_to_vdata(struct kv_iterator *kvi, uint vboff)
{
    struct mock_kv_iterator *iter = kvi->kvi_context;
    struct kvdata *          d = iter->kvset->iter_data;

    return &d[vboff].val;
}

static merr_t
_make_common(
    struct kv_iterator **kvi,
    int                  src,
    struct mpool *       ds,
    struct kvs_rparams * rp,
    struct kvset_meta *  km)
{
    struct cn_tree           tree;
    struct mock_kv_iterator *iter;
    struct kvset *           kvset;
    merr_t                   err;

    memset(&tree, 0, sizeof(tree));
    tree.ds = ds;

    err = kvset_create(&tree, 0, km, &kvset);
    if (err)
        return err;

    err = kvset_iter_create(kvset, NULL, NULL, NULL, 0, kvi);
    if (err) {
        free(kvset);
        return err;
    }

    iter = (struct mock_kv_iterator *)*kvi;
    iter->src = src;
    return 0;
}

merr_t
mock_make_kvi(struct kv_iterator **kvi, int src, struct kvs_rparams *rp, struct nkv_tab *nkv)
{
    struct kvset_meta km;
    struct kvdata *   ds = 0;
    u64               kid, vid;
    struct kvs_block  local_kblock, local_vblock;
    merr_t            err;

    memset(&km, 0, sizeof(km));

    ds = _make_data(nkv);
    if (!ds)
        return merr(ENOMEM);

    kid = 0x1000 + nkv->key1;
    vid = 0x2000 + nkv->val1;
    km.km_dgen = nkv->dgen;

    local_kblock.bk_blkid = kid;
    local_kblock.bk_handle = 0;
    km.km_kblk_list.n_blks = 1;
    km.km_kblk_list.n_alloc = 1;
    km.km_kblk_list.blks = &local_kblock;

    local_vblock.bk_blkid = vid;
    local_vblock.bk_handle = 0;
    km.km_vblk_list.n_blks = 1;
    km.km_vblk_list.n_alloc = 1;
    km.km_vblk_list.blks = &local_vblock;

    err = _make_common(kvi, src, (struct mpool *)ds, rp, &km);
    if (err)
        free(ds);
    return err;
}

merr_t
mock_make_vblocks(struct kv_iterator **kvi, struct kvs_rparams *rp, int nv)
{
    struct kvset_meta km;
    u64               kid;
    merr_t            err;
    int               i;
    struct kvs_block  local_kblock, *ds;

    /* [HSE_REVISIT]
     *
     * The games being played with what ds is versus how it is used are
     * unsafe. This code used to be:
     *
     *   ds = calloc(nv ?: 1, sizeof(*ds));
     *
     * which (rightfully) caused complaints from valgrind and could cause
     * transient failures.
     */
    ds = calloc(8192 + nv, sizeof(*ds));
    if (!ds)
        return merr(ENOMEM);

    for (i = 0; i < nv; ++i)
        ds[i].bk_blkid = 0x2000 + i;

    kid = 0x1000;
    km.km_dgen = ++dgen;
    km.km_vused = nv * 1000;

    local_kblock.bk_blkid = kid;
    local_kblock.bk_handle = 0;
    km.km_kblk_list.n_blks = 1;
    km.km_kblk_list.n_alloc = 1;
    km.km_kblk_list.blks = &local_kblock;

    km.km_vblk_list.n_blks = nv;
    km.km_vblk_list.n_alloc = nv;
    km.km_vblk_list.blks = ds;

    err = _make_common(kvi, 0, (struct mpool *)ds, rp, &km);
    if (err)
        free(ds);
    return err;
}

/* ------------------------------------------------------------
 * Mocked kvset
 */

static merr_t
_kvset_create(struct cn_tree *tree, u64 tag, struct kvset_meta *km, struct kvset **handle)
{
    struct mock_kvset *mk;
    size_t             alloc_sz;
    int                i, j;

    alloc_sz = sizeof(*mk) + (sizeof(u64) * (km->km_kblk_list.n_blks + km->km_vblk_list.n_blks));

    mk = mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (mk == MAP_FAILED)
        return merr(errno);

    memset(mk->tripwire, 0xaa, sizeof(mk->tripwire));
    mk->alloc_sz = alloc_sz;

    /* Make the tripwire pages inaccessible to catch errant
     * unmocked accesses dead in their tracks.
     */
    if (mprotect(mk, sizeof(mk->tripwire), PROT_NONE))
        return merr(errno);

    mk->entry.le_kvset = (void *)mk;

    mk->stats.kst_keys = 10000;
    mk->stats.kst_kvsets = 1;

    mk->stats.kst_kblks = km->km_kblk_list.n_blks;
    mk->stats.kst_vblks = km->km_vblk_list.n_blks;

    mk->stats.kst_kalen = 32 * 1024 * 1024;
    mk->stats.kst_kwlen = 30 * 1024 * 1024;

    mk->stats.kst_valen = km->km_vused;
    mk->stats.kst_vwlen = km->km_vused;
    mk->stats.kst_vulen = km->km_vused;

    mk->dgen = km->km_dgen;
    mk->iter_data = tree->ds;
    mk->ref = 1; /* as in reality, kvsets are minted ref 1 */

    for (i = 0; i < km->km_kblk_list.n_blks; i++)
        mk->ids[i] = km->km_kblk_list.blks[i].bk_blkid;

    for (j = 0; j < km->km_vblk_list.n_blks; j++, i++)
        mk->ids[i] = km->km_vblk_list.blks[j].bk_blkid;

    *handle = (struct kvset *)mk;

    return 0;
}

static u32
_kvset_get_num_kblocks(struct kvset *kvset)
{
    struct mock_kvset *mk = (void *)kvset;

    return mk->stats.kst_kblks;
}

static u32
_kvset_get_num_vblocks(struct kvset *kvset)
{
    struct mock_kvset *mk = (void *)kvset;

    return mk->stats.kst_vblks;
}

static u64
_kvset_get_dgen(struct kvset *kvset)
{
    struct mock_kvset *mk = (void *)kvset;

    return mk->dgen;
}

static u64
_kvset_get_nth_kblock_id(struct kvset *kvset, u32 index)
{
    struct mock_kvset *mk = (void *)kvset;

    return index < mk->stats.kst_kblks ? mk->ids[index] : 0;
}

static u64
_kvset_get_nth_vblock_id(struct kvset *kvset, u32 index)
{
    struct mock_kvset *mk = (void *)kvset;
    u32                vblk_index_base = mk->stats.kst_kblks;

    return (index < mk->stats.kst_vblks ? mk->ids[vblk_index_base + index] : 0);
}

static u64
_kvset_get_nth_vblock_len(struct kvset *kvset, u32 index)
{
    struct mock_kvset *mk = (void *)kvset;
    struct kvdata *    iterv = mk->iter_data;
    int                i, kvcnt, vcnt = 0;

    if (index >= mk->stats.kst_vblks)
        return 0;

    kvcnt = iterv[0].key; /* number of elements */
    for (i = 1; i <= kvcnt; i++)
        if (iterv[i].val != -1) /* do not count tombstones */
            vcnt++;

    return vcnt * sizeof(int);
}

const struct kvset_stats *
_kvset_statsp(const struct kvset *ks)
{
    struct mock_kvset *mk = (void *)ks;

    return &mk->stats;
}

void
_kvset_stats(const struct kvset *ks, struct kvset_stats *stats)
{
    struct mock_kvset *mk = (void *)ks;

    *stats = mk->stats;
}

void
_kvset_list_add(struct kvset *kvset, struct list_head *head)
{
    struct mock_kvset *mk = (void *)kvset;

    list_add(&mk->entry.le_link, head);
}

void
_kvset_list_add_tail(struct kvset *kvset, struct list_head *head)
{
    struct mock_kvset *mk = (void *)kvset;

    list_add_tail(&mk->entry.le_link, head);
}

static void
_kvset_get_ref(struct kvset *kvset)
{
    struct mock_kvset *mk = (void *)kvset;

    ++mk->ref;
}

static void
_kvset_put_ref(struct kvset *kvset)
{
    struct mock_kvset *mk = (void *)kvset;
    int                cnt;

    if (!kvset)
        return;

    cnt = --mk->ref;
    assert(cnt >= 0);
    if (cnt == 0) {
        if (mk->iter_data != (void *)-1)
            free(mk->iter_data);
        munmap(mk, mk->alloc_sz);
    }
}

/* ------------------------------------------------------------
 * Mocked kvset iterator
 */
void *
_kvset_from_iter(struct kv_iterator *kvi)
{
    struct mock_kv_iterator *iter = kvi->kvi_context;

    return iter->kvset;
}

static void
_kvset_iter_release(struct kv_iterator *kvi)
{
    if (kvi) {
        struct mock_kv_iterator *iter = kvi->kvi_context;

        munmap(iter->base, iter->sz);
    }
}

struct kv_iterator_ops mock_kvset_ops = {
    .kvi_release = _kvset_iter_release,
};

merr_t
_kvset_iter_create(
    struct kvset *           kvset,
    struct workqueue_struct *workq,
    struct workqueue_struct *vra_wq,
    struct perfc_set *       pc,
    enum kvset_iter_flags    flags,
    struct kv_iterator **    handle)
{
    struct mock_kv_iterator *iter;
    size_t                   itersz, kvisz;
    void *                   base;

    itersz = sizeof(*iter) * 2;
    kvisz = sizeof(iter->kvi);

    base = mmap(NULL, itersz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (base == MAP_FAILED)
        return merr(errno);

    memset(base, 0xaa, itersz);

    iter = (base + PAGE_SIZE) - kvisz;

    /* Make the tripwire pages inaccessible to catch errant
     * unmocked accesses dead in their tracks.
     */
    if (mprotect(iter->tripwire, sizeof(iter->tripwire), PROT_NONE))
        return merr(errno);

    iter->kvset = (struct mock_kvset *)kvset;
    iter->src = 0;
    iter->nextkey = 0;
    iter->base = base;
    iter->sz = itersz;

    memset(&iter->kvi, 0, sizeof(iter->kvi));
    iter->kvi.kvi_ops = &mock_kvset_ops;
    iter->kvi.kvi_context = iter;
    iter->kvi.kvi_eof = false;

    *handle = &iter->kvi;

    return 0;
}

static merr_t
_kvset_iter_next_key(struct kv_iterator *kvi, struct key_obj *kobj, struct kvset_iter_vctx *vc)
{
    struct mock_kv_iterator *iter = kvi->kvi_context;
    struct kvdata *          d = iter->kvset->iter_data;

    if (kvi->kvi_eof || iter->nextkey == d[0].key) {
        kvi->kvi_eof = true;
        return 0;
    }

    vc->off = iter->nextkey + 1;
    vc->next = 0;
    vc->kmd = 0;
    vc->nvals = 1;

    d += vc->off;

    kobj->ko_pfx = 0;
    kobj->ko_pfx_len = 0;
    kobj->ko_sfx = &d->key;
    kobj->ko_sfx_len = sizeof(d->key);

    if (mock_kvset_verbose)
        printf(
            "next_key  kvset.%d ent.%d k   %08x\n", iter->src, iter->nextkey, cpu_to_be32(d->key));

    iter->nextkey++;
    return 0;
}

static bool
_kvset_cursor_next(struct element_source *es, void **element)
{
    struct kv_iterator *kvi = kvset_cursor_es_h2r(es);
    struct cn_kv_item * kv = &kvi->kvi_kv;

    *element = 0;

    _kvset_iter_next_key(kvi, &kv->kobj, &kv->vctx);
    if (kvi->kvi_eof)
        return false;

    kv->src = es;
    *element = &kvi->kvi_kv;

    return true;
}

static int valbuf[1 + CN_SMALL_VALUE_THRESHOLD];

static merr_t
_kvset_iter_next_val(
    struct kv_iterator *    kvi,
    struct kvset_iter_vctx *vc,
    enum kmd_vtype          vtype,
    uint                    vbidx,
    uint                    vboff,
    const void **           vdata,
    uint *                  vlen)
{
    struct mock_kv_iterator *iter = kvi->kvi_context;
    struct kvdata *          entry = iter->kvset->iter_data;
    uint                     keyindex;
    static uint              u32val;
    static char              valbuf[1 + CN_SMALL_VALUE_THRESHOLD];

    /* only one value per key */
    if (vc->next != 0)
        return 0;

    entry += vc->off;
    if (entry->val == -1) {
        *vdata = HSE_CORE_TOMB_REG;
        *vlen = 0;
    } else {
        if (entry->val_len == 0) {
            *vlen = 0;
        } else if (entry->val_len == 4) {
            u32val = entry->val;
            *vdata = &u32val;
            *vlen = sizeof(u32);
        } else {
            memset(valbuf, entry->val & 0xff, sizeof(valbuf));
            valbuf[0] = entry->val;
            *vdata = valbuf;
            *vlen = sizeof(valbuf);
        }
    }

    keyindex = entry - (typeof(entry))iter->kvset->iter_data - 1;
    if (mock_kvset_verbose)
        printf("next_val  kvset.%d ent.%d v.%d %d\n", iter->src, keyindex, vc->next, entry->val);

    vc->next++;

    return 0;
}

static bool
_kvset_iter_next_vref(
    struct kv_iterator *    kvi,
    struct kvset_iter_vctx *vc,
    u64 *                   seq,
    enum kmd_vtype *        vtype,
    uint *                  vbidx,
    uint *                  vboff,
    const void **           vdata,
    uint *                  vlen)
{
    struct mock_kv_iterator *iter = kvi->kvi_context;
    struct kvdata *          entry = iter->kvset->iter_data;
    uint                     keyindex;

    /* only one value per key */
    if (vc->next != 0)
        return false; /* no more values */

    entry += vc->off;
    *seq = 1;
    *vbidx = iter->src;
    *vboff = 0;
    *vlen = 0;
    if (entry->val_len == 0 && entry->val == -1) {
        *vtype = vtype_tomb;
    } else {
        if (entry->val_len == 0) {
            *vtype = vtype_zval;
            *vdata = 0;
        } else if (entry->val_len <= CN_SMALL_VALUE_THRESHOLD) {
            *vtype = vtype_ival;
            valbuf[0] = entry->val;
            *vdata = valbuf;
            *vlen = entry->val_len;
        } else {
            *vtype = vtype_val;
            *vlen = entry->val_len;
            *vboff = vc->off;
        }
    }

    keyindex = entry - (typeof(entry))iter->kvset->iter_data - 1;
    if (mock_kvset_verbose)
        printf("next_vref kvset.%d ent.%d v.%d %d\n", iter->src, keyindex, vc->next, entry->val);

    vc->next++;
    return true;
}

merr_t
_kvset_iter_set_start(struct kv_iterator *kvi, int start, int pt_start)
{
    kvi->kvi_es = es_make(_kvset_cursor_next, 0, 0);
    return 0;
}

merr_t
_kvset_iter_seek(struct kv_iterator *kvi, const void *key, int len, bool *eof)
{
    struct mock_kv_iterator *iter = kvi->kvi_context;
    struct kvdata *          d = iter->kvset->iter_data;
    size_t                   sz = sizeof(d[0].key);
    int                      i, rc, nkeys;

    /* find the first key larger than us */
    nkeys = (len == 0) ? 0 : d[0].key;
    for (i = 1; i <= nkeys; ++i) {
        if (len < 0)
            rc = keycmp_prefix(key, -len, &d[i].key, sz);
        else
            rc = keycmp(key, len, &d[i].key, sz);
        if (rc <= 0)
            break;
    }

    iter->nextkey = i - 1;
    *eof = kvi->kvi_eof = iter->nextkey == d[0].key;
    kvi->kvi_es = es_make(_kvset_cursor_next, 0, 0);
    return 0;
}

void
mock_kvset_set(void)
{
    mock_mpool_set();

    /* Allow repeated init() w/o intervening unset() */
    mock_kvset_unset();

    mapi_inject(mapi_idx_kvset_kblk_start, 0);
    mapi_inject(mapi_idx_kvset_get_nth_vblock_handle, 1);
    mapi_inject(mapi_idx_kvset_get_scatter_score, 10);

    MOCK_SET(kvset, _kvset_create);
    MOCK_SET(kvset, _kvset_get_nth_vblock_len);
    MOCK_SET(kvset, _kvset_list_add);
    MOCK_SET(kvset, _kvset_list_add_tail);
    MOCK_SET(kvset, _kvset_get_ref);
    MOCK_SET(kvset, _kvset_put_ref);
    MOCK_SET(kvset, _kvset_iter_set_start);
    MOCK_SET(kvset, _kvset_iter_create);
    MOCK_SET(kvset, _kvset_iter_release);
    MOCK_SET(kvset, _kvset_from_iter);
    MOCK_SET(kvset, _kvset_iter_seek);
    MOCK_SET(kvset, _kvset_iter_next_key);
    MOCK_SET(kvset, _kvset_iter_next_val);
    MOCK_SET(kvset, _kvset_iter_next_vref);

    MOCK_SET(kvset_view, _kvset_get_dgen);
    MOCK_SET(kvset_view, _kvset_get_num_kblocks);
    MOCK_SET(kvset_view, _kvset_get_nth_kblock_id);
    MOCK_SET(kvset_view, _kvset_get_num_vblocks);
    MOCK_SET(kvset_view, _kvset_get_nth_vblock_id);
}

void
mock_kvset_unset(void)
{
    mapi_inject_clear();

    MOCK_UNSET(kvset, _kvset_create);
    MOCK_UNSET(kvset, _kvset_get_nth_vblock_len);
    MOCK_UNSET(kvset, _kvset_list_add);
    MOCK_UNSET(kvset, _kvset_list_add_tail);
    MOCK_UNSET(kvset, _kvset_get_ref);
    MOCK_UNSET(kvset, _kvset_put_ref);
    MOCK_UNSET(kvset, _kvset_iter_create);
    MOCK_UNSET(kvset, _kvset_iter_release);
    MOCK_UNSET(kvset, _kvset_from_iter);
    MOCK_UNSET(kvset, _kvset_iter_seek);
    MOCK_UNSET(kvset, _kvset_iter_next_key);
    MOCK_UNSET(kvset, _kvset_iter_next_val);
    MOCK_UNSET(kvset, _kvset_iter_next_vref);

    MOCK_UNSET(kvset_view, _kvset_get_num_kblocks);
    MOCK_UNSET(kvset_view, _kvset_get_nth_kblock_id);
    MOCK_UNSET(kvset_view, _kvset_get_num_vblocks);
    MOCK_UNSET(kvset_view, _kvset_get_nth_vblock_id);
    MOCK_UNSET(kvset_view, _kvset_get_dgen);
}
