/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/assert.h>
#include <hse_util/logging.h>
#include <hse_util/bloom_filter.h>
#include <hse_util/logging.h>
#include <hse_util/condvar.h>
#include <hse_util/mutex.h>
#include <hse_util/page.h>
#include <hse_util/perfc.h>
#include <hse_util/log2.h>
#include <hse_util/mman.h>
#include <hse_util/keycmp.h>
#include <hse_util/compression_lz4.h>
#include <hse_util/vlb.h>

#include <hse/limits.h>
#include <hse/kvdb_perfc.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvs_rparams.h>

#include "kvs_mblk_desc.h"

/* functions are declared in two files - kvset.h and kvset_view.h */
#define MTF_MOCK_IMPL_kvset
#define MTF_MOCK_IMPL_kvset_view

#include <hse_ikvdb/cndb.h>

#include <mpool/mpool.h>

#include <hse_util/hlog.h>

#include "hblock_reader.h"
#include "kvset.h"
#include "kvset_internal.h"
#include "kblock_reader.h"
#include "vblock_reader.h"
#include "bloom_reader.h"
#include "wbt_reader.h"
#include "blk_list.h"
#include "kcompact.h"
#include "kv_iterator.h"
#include "wbt_internal.h"
#include "cn_metrics.h"
#include "omf.h"
#include "mbset.h"
#include "cn_tree.h"
#include "cn_tree_internal.h"

/*
 * kvset deferred deletes
 *
 * kvsets are created with a ref count of 1 and deleted = 0 (DEL_NONE).
 * This is the normal state, after kvsets are created during open,
 * or after ingest, compact or spill when new kvsets are created.
 *
 * Spill and compact do NOT gain a new ref while they are reading kvsets.
 * References ARE gained by scans for reading, in order to defer deletes
 * until the scan is complete.  CN maintenance activities are considered
 * part of the "in-the-tree" reference, and thus do not add refs.
 *
 * To make ref counts work, a strict protocol must be followed:
 * 1. refs can only be gained under the kvset_list_rlock
 * 2. refs can be put at any time
 * 3. the owner of the last ref must destroy the in-memory kvset
 *
 * Deletes must also follow a strict protocol:
 * 1. The kvset_list_wlock() must be gained.
 * 2. The kvset is unlinked from this list while the lock is held.
 * 3. The kvset_list_wlock() is released.
 * 4. kvset_prepare_delete() is called.
 *
 * At this point, it is possible there was a scan in progress, and the ref
 * count is greater than one.  But is no longer possible for another
 * scan to find this kvset.  The delete flag must be set while holding
 * the ref, which ensures the final put ref will call kvset_destroy
 * and correctly handling mblock deletion.
 */

enum { DEL_NONE = 0, DEL_KEEPV = 1, DEL_ALL = 2 };

struct mbset_locator {
    struct mbset *mbs;
    uint          idx;
};

struct kvset_cache {
    struct kmem_cache *cache;
    size_t             sz;
};

static struct kvset_cache kvset_cache[4] HSE_READ_MOSTLY;
static struct kmem_cache *kvset_iter_cache HSE_READ_MOSTLY;

/* A kvset contains a logical array of vblocks and kblocks reference vblocks by
 * an index into this logical array.  However, data about vblocks are stored
 * in one or more 'struct mbset' objects and are not easily accessible by the
 * logical index.  These functions hide the details of finding vblock info
 * from a logical vblock index.
 */
static HSE_ALWAYS_INLINE struct mbset *
lvx2mbs(struct kvset *ks, uint i)
{
    return ks->ks_vblk2mbs[i].mbs;
}

static HSE_ALWAYS_INLINE uint
lvx2mbs_bnum(struct kvset *ks, uint i)
{
    return ks->ks_vblk2mbs[i].idx;
}

static HSE_ALWAYS_INLINE u64
lvx2mbid(struct kvset *ks, uint i)
{
    return mbset_get_mbid(lvx2mbs(ks, i), lvx2mbs_bnum(ks, i));
}

static HSE_ALWAYS_INLINE struct vblock_desc *
lvx2vbd(struct kvset *ks, uint i)
{
    return mbset_get_udata(lvx2mbs(ks, i), lvx2mbs_bnum(ks, i));
}

static void
_kvset_destroy(struct kvset *ks);

void
kvset_get_ref(struct kvset *ks)
{
    atomic_inc(&ks->ks_ref);
}

static void
kvset_put_ref_final(struct kvset *ks)
{
    bool       callbacks_pending;
    const uint maxtries = 5;
    uint       tries, i;

    /* Wait briefly for any pending vbr_madvise_async() callbacks
     * to complete (likely it's a bug if there are any pending).
     */
    for (tries = 0; tries < maxtries; ++tries) {
        for (i = 0; i < ks->ks_st.kst_vblks; ++i) {
            struct vblock_desc *vbd = lvx2vbd(ks, i);

            if (atomic_read(&vbd->vbd_refcnt) > 0)
                break;
        }

        if (i >= ks->ks_st.kst_vblks)
            break;

        usleep(tries * USEC_PER_SEC);
        ev(1);
    }

    if (tries >= maxtries) {
        log_warn("kvset %lu has lingering vbd references", (ulong)ks->ks_dgen);

        assert(tries < maxtries); /* leak it in release build */
        return;
    }

    /* If 'callbacks_pending' is true, then kvset_destroy() will
     * be invoked on the last mbset destructor callback.  It may
     * well happen on this call stack on the final loop iteration.
     * So once this loop is done, no more touchy the kvset.
     */
    callbacks_pending = ks->ks_mbset_cb_pending;
    i = ks->ks_vbsetc;

    while (i--)
        mbset_put_ref(ks->ks_vbsetv[i]);

    if (!callbacks_pending)
        _kvset_destroy(ks);
}

static void
kvset_put_ref_work(struct cn_work *work)
{
    kvset_put_ref_final(container_of(work, struct kvset, ks_kvset_cn_work));
}

void
kvset_put_ref(struct kvset *ks)
{
    struct cn *cn;

    assert(ks);

    if (atomic_dec_return(&ks->ks_ref) > 0)
        return;

    assert(atomic_read(&ks->ks_ref) == 0);
    log_err("Delete txn %p Delete cookie %p", ks->ks_delete_txn, ks->ks_delete_cookie);
    //assert(ks->ks_delete_txn);
    //assert(ks->ks_delete_cookie);

    cn = cn_tree_get_cn(ks->ks_tree);

    cn_work_submit(cn, kvset_put_ref_work, &ks->ks_kvset_cn_work);
}

static merr_t
kvset_hblk_init(
    struct mpool *mpool,
    struct mblock_props *props,
    struct mpool_mcache_map *map,
    uint8_t **hlog,
    struct kvset_hblk *blk)
{
    merr_t err;
    struct kvs_mblk_desc *hbd = &blk->kh_hblk_desc;

    err = hbr_read_desc(mpool, map, props, blk->kh_hblk.bk_blkid, hbd);
    if (err)
        return err;

    err = hbr_read_seqno_range(hbd, &blk->kh_seqno_min, &blk->kh_seqno_max);
    if (ev(err))
        return err;

    err = hbr_read_ptree_region_desc(hbd, &blk->kh_ptree_desc);
    if (err)
        return err;

    err = hbr_read_metrics(hbd, &blk->kh_metrics);
    if (err)
        return err;

    if (omf_hbh_max_pfx_len(hbd->map_base)) {
        blk->kh_pfx_max = hbd->map_base + omf_hbh_max_pfx_off(hbd->map_base);
        blk->kh_pfx_max_len = omf_hbh_max_pfx_len(hbd->map_base);
        key_disc_init(blk->kh_pfx_max, blk->kh_pfx_max_len, &blk->kh_pfx_max_disc);
    } else {
        blk->kh_pfx_max = NULL;
        blk->kh_pfx_max_len = 0;
        memset(&blk->kh_pfx_max_disc, 0, sizeof(blk->kh_pfx_max_disc));
    }

    if (omf_hbh_min_pfx_len(hbd->map_base)) {
        blk->kh_pfx_min = hbd->map_base + omf_hbh_min_pfx_off(hbd->map_base);
        blk->kh_pfx_min_len = omf_hbh_min_pfx_len(hbd->map_base);
        key_disc_init(blk->kh_pfx_min, blk->kh_pfx_min_len, &blk->kh_pfx_min_disc);
    } else {
        blk->kh_pfx_min = NULL;
        blk->kh_pfx_min_len = 0;
        memset(&blk->kh_pfx_min_disc, 0, sizeof(blk->kh_pfx_min_disc));
    }

    *hlog = hbd->map_base + (omf_hbh_hlog_off_pg(hbd->map_base) * PAGE_SIZE);

    return err;
}

static merr_t
kvset_kblk_init(
    struct kvs_rparams *     rp,
    struct mpool *           ds,
    struct mblock_props     *props,
    struct mpool_mcache_map *kmap,
    u32                      idx,
    struct kvset_kblk *      p)
{
    struct kvs_mblk_desc * kbd = &p->kb_kblk_desc;
    struct kblock_hdr_omf *hdr;
    merr_t                 err;

    err = kbr_get_kblock_desc(ds, kmap, props, idx, p->kb_kblk.bk_blkid, kbd);
    if (ev(err))
        return err;

    err = kbr_read_wbt_region_desc(kbd, &p->kb_wbt_desc);
    if (ev(err))
        return err;

    err = kbr_read_blm_region_desc(kbd, &p->kb_blm_desc);
    if (ev(err))
        return err;

    err = kbr_read_blm_pages(kbd, &p->kb_blm_desc);
    if (ev(err))
        return err;

    err = kbr_read_metrics(kbd, &p->kb_metrics);
    if (ev(err))
        return err;

    hdr = p->kb_kblk_desc.map_base;

    /* Cache min/max key ptrs and lengths, and initialize the
     * min/max key discriminators for use in kblk_plausible().
     */
    p->kb_koff_max = (const char *)hdr + omf_kbh_max_koff(hdr);
    p->kb_klen_max = omf_kbh_max_klen(hdr);

    p->kb_koff_min = (const char *)hdr + omf_kbh_min_koff(hdr);
    p->kb_klen_min = omf_kbh_min_klen(hdr);

    /* If the combined key lengths are short we can cache them nearby
     * in p->kb_ksmall.  Otherwise the caller may try to pack them into
     * a larger outboard buffer (i.e., kvset->ks_klarge).
     */
    if (sizeof(p->kb_ksmall) >= p->kb_klen_max + p->kb_klen_min) {
        p->kb_koff_max = memcpy(p->kb_ksmall, p->kb_koff_max, p->kb_klen_max);
        p->kb_koff_min = memcpy(p->kb_ksmall + p->kb_klen_max, p->kb_koff_min, p->kb_klen_min);
    }

    key_disc_init(p->kb_koff_max, p->kb_klen_max, &p->kb_kdisc_max);
    key_disc_init(p->kb_koff_min, p->kb_klen_min, &p->kb_kdisc_min);

    /* Preload the wbtree nodes.
     */
    if (rp->cn_mcache_wbt > 0) {
        kbr_madvise_wbt_int_nodes(kbd, &p->kb_wbt_desc, MADV_WILLNEED);

        if (rp->cn_mcache_wbt > 1)
            kbr_madvise_wbt_leaf_nodes(kbd, &p->kb_wbt_desc, MADV_WILLNEED);
    }

    /* Preload the bloom filter.
     */
    if (rp->cn_bloom_preload)
        kbr_madvise_bloom(kbd, &p->kb_blm_desc, MADV_WILLNEED);

    return 0;
}

/**
 * blkid_list_to_vec()
 *
 * malloc a vector for blkids, and populate it from a blk_list.  Caller
 * must free the vector when finished.
 */
static u64 *
blkid_list_to_vec(struct blk_list *blkl, size_t bufc, u64 *bufv)
{
    u64 *v = bufv;
    int  i;

    if (blkl->n_blks > bufc) {
        v = malloc_array(blkl->n_blks, sizeof(u64));
        if (ev(!v))
            return NULL;
    }

    for (i = 0; i < blkl->n_blks; i++)
        v[i] = blkl->blks[i].bk_blkid;

    return v;
}

/* This is not a general purpose function!  The caller must ensure mapv is
 * large enough, and must also cleanup on failure.
 */
static merr_t
kvset_map_blklist(
    struct mpool *            mp,
    struct blk_list *         blks,
    struct mpool_mcache_map **mapp)
{
    uint    idc;
    u64    *idv;
    u64     bufv[64];
    merr_t  err;

    idc = blks->n_blks;
    if (!idc)
        return 0;

    idv = blkid_list_to_vec(blks, NELEM(bufv), bufv);
    if (ev(!idv))
        return merr(ENOMEM);

    err = mpool_mcache_mmap(mp, idc, idv, mapp);

    if (idv != bufv)
        free(idv);

    return err;
}

static merr_t
vblock_udata_init(
    struct mbset *       mbs,
    uint                 bnum,
    uint *               argcp,
    u64 *                argv,
    struct mblock_props *props,
    void *               rock)
{
    return vbr_desc_read(
        mbset_get_mp(mbs),
        mbset_get_map(mbs),
        bnum,
        argcp,
        argv,
        props,
        rock);
}

static merr_t
vblock_udata_update(
    struct mbset *       mbs,
    uint                 bnum,
    uint *               argcp,
    u64 *                argv,
    struct mblock_props *props,
    void *               rock)
{
    return vbr_desc_update(
        mbset_get_mp(mbs),
        mbset_get_map(mbs),
        bnum,
        argcp,
        argv,
        props,
        rock);
}

merr_t
kvset_create2(
    struct cn_tree *   tree,
    uint64_t           kvsetid,
    struct kvset_meta *km,
    uint               vbset_cnt_len,
    uint *             vbset_cnts,
    struct mbset ***   vbset_vecs,
    struct kvset **    ks_out)
{
    struct kvset_kblk * lkb, *rkb;
    struct mpool *      mp;
    struct kvs_rparams *rp;
    struct cn_kvdb *    cn_kvdb;

    merr_t        err;
    uint          i, j;
    size_t        alloc_len;
    struct kvset *ks;
    size_t        kcachesz;
    ulong         mavail;
    const uint32_t n_kblks = km->km_kblk_list.n_blks;
    const uint32_t n_vblks = km->km_vblk_list.n_blks;
    uint          vbsetc;
    u64           kvdb_halen, kvdb_kalen, kvdb_valen;
    ulong         hra, kra, vra;
    int           last_kb;

    struct kvs_cparams *cp;

    /* need hblock, kblocks and vblocks optional */
    assert(km->km_hblk.bk_blkid);
    last_kb = n_kblks - 1;

    /* number of vbsets */
    vbsetc = 0;
    for (i = 0; i < vbset_cnt_len; i++)
        vbsetc += vbset_cnts[i];

    /* one allocation for:
     * - the kvset struct
     * - array of struct kvset_kblk for kblocks
     * - array of ptrs to vbsets
     * - array of struct mbset_locator
     */
    alloc_len = sizeof(*ks);
    alloc_len += sizeof(ks->ks_kblks[0]) * n_kblks;
    alloc_len += sizeof(ks->ks_vbsetv[0]) * vbsetc;
    alloc_len += sizeof(ks->ks_vblk2mbs[0]) * n_vblks;

    if (ev(alloc_len > kvset_cache[0].sz))
        ks = alloc_aligned(alloc_len, __alignof__(*ks));
    else if (alloc_len > kvset_cache[1].sz)
        ks = kmem_cache_alloc(kvset_cache[0].cache);
    else if (alloc_len > kvset_cache[2].sz)
        ks = kmem_cache_alloc(kvset_cache[1].cache);
    else if (alloc_len > kvset_cache[3].sz)
        ks = kmem_cache_alloc(kvset_cache[2].cache);
    else
        ks = kmem_cache_alloc(kvset_cache[3].cache);

    if (ev(!ks))
        return merr(ENOMEM);

    cp = cn_tree_get_cparams(tree);

    mp = cn_tree_get_mp(tree);
    rp = cn_tree_get_rp(tree);
    cn_kvdb = cn_tree_get_cnkvdb(tree);

    memset(ks, 0, alloc_len);
    ks->ks_vbsetv = (void *)(ks->ks_kblks + n_kblks);
    ks->ks_vblk2mbs = (void *)(ks->ks_vbsetv + vbsetc);

    assert((void *)ks + alloc_len >= (void *)(ks->ks_vblk2mbs + n_vblks));

    ks->ks_st.kst_kvsets = 1;
    ks->ks_st.kst_vulen = km->km_vused;
    ks->ks_st.kst_hblks = 1;
    ks->ks_st.kst_kblks = n_kblks;
    ks->ks_st.kst_vblks = n_vblks;

    ks->ks_tree = tree;
    ks->ks_entry.le_kvset = ks;
    ks->ks_kvset_sz = alloc_len;

    ks->ks_vbsetc = vbsetc;

    ks->ks_mp = mp;
    ks->ks_rp = rp;
    ks->ks_dgen = km->km_dgen;
    ks->ks_compc = km->km_compc;
    ks->ks_kvsetid = kvsetid;
    ks->ks_cnid = cn_tree_get_cnid(tree);
    ks->ks_cndb = cn_tree_get_cndb(tree);
    ks->ks_pfx_len = cp->pfx_len;
    ks->ks_sfx_len = cp->sfx_len;
    ks->ks_node_level = km->km_node_level;
    ks->ks_nodeid = km->km_nodeid;
    ks->ks_vminlvl = min_t(u16, rp->cn_mcache_vminlvl, U16_MAX);
    ks->ks_vmin = rp->cn_mcache_vmin;
    ks->ks_vmax = rp->cn_mcache_vmax;
    ks->ks_cn_kvdb = cn_kvdb;

    /* initialize atomics */
    atomic_set(&ks->ks_ref, 0);
    atomic_set(&ks->ks_delete_error, 0);
    atomic_set(&ks->ks_mbset_callbacks, 0);

    if (cn_tree_is_capped(ks->ks_tree))
        ks->ks_vra_len = rp->cn_capped_vra;
    else if (n_vblks > 0)
        ks->ks_vra_len = rp->cn_cursor_vra;

    assert(ks->ks_kvsetid != 0);

    if (rp->cn_verify)
        kc_kvset_check(mp, cp, km, tree);

    /* map single hblock */
    err = mpool_mcache_mmap(mp, 1, &km->km_hblk.bk_blkid, &ks->ks_hmap);
    if (ev(err))
        goto err_exit;

    {
        struct mblock_props props;

        err = mpool_mblock_props_get(mp, km->km_hblk.bk_blkid, &props);
        if (ev(err))
            goto err_exit;

        ks->ks_hblk.kh_hblk.bk_blkid = km->km_hblk.bk_blkid;

        err = kvset_hblk_init(mp, &props, ks->ks_hmap, &ks->ks_hlog, &ks->ks_hblk);
        if (ev(err))
            goto err_exit;

        /* kvset_stats from kblocks */
        ks->ks_st.kst_halen += props.mpr_alloc_cap;
        ks->ks_st.kst_hwlen += props.mpr_write_len;
    }

    ks->ks_seqno_min = ks->ks_hblk.kh_seqno_min;
    ks->ks_seqno_max = ks->ks_hblk.kh_seqno_max;
    assert(ks->ks_seqno_min <= ks->ks_seqno_max);

    /* map kblocks */
    err = kvset_map_blklist(mp, &km->km_kblk_list, &ks->ks_kmap);
    if (ev(err))
        goto err_exit;

    kcachesz = 0;

    for (i = 0; i < n_kblks; i++) {
        struct kvset_kblk * kblk = ks->ks_kblks + i;
        struct mblock_props props;

        u64 mbid = km->km_kblk_list.blks[i].bk_blkid;

        err = mpool_mblock_props_get(mp, mbid, &props);
        if (ev(err))
            goto err_exit;

        kblk->kb_kblk.bk_blkid = mbid;

        err = kvset_kblk_init(rp, mp, &props, ks->ks_kmap, i, kblk);
        if (ev(err))
            goto err_exit;

        /* Ignore these keys if they've already been cached
         * to kblk->kb_ksmall by kblk_init().
         */
        if (kblk->kb_koff_max != kblk->kb_ksmall)
            kcachesz += kblk->kb_klen_max + kblk->kb_klen_min;

        /* kvset_stats from kblocks */
        ks->ks_st.kst_kalen += props.mpr_alloc_cap;
        ks->ks_st.kst_kwlen += props.mpr_write_len;
        ks->ks_st.kst_keys += kblk->kb_metrics.num_keys;
    }

    /* Cache the large min/max keys from all the kblocks into a packed
     * buffer to avoid having to reference their mcache mapped header
     * to find them.  The malloc here might be very large and hence
     * fail (esp. in the kernel), but that's ok because we'll simply
     * fall back to using the keys in the mcache mapped header.
     */
    kcachesz = min(kcachesz, rp->cn_kcachesz);
    if (kcachesz > 0) {
        u8 *dst;

        dst = malloc(kcachesz);
        ks->ks_klarge = dst;

        for (i = dst ? 0 : UINT_MAX; i < n_kblks; ++i) {
            struct kvset_kblk *kb = ks->ks_kblks + i;

            /* Ignore these keys if they've already been cached
             * to kb->kb_ksmall by kblk_init().
             */
            if (kb->kb_koff_max == kb->kb_ksmall)
                continue;

            if (dst + kb->kb_klen_max > ks->ks_klarge + kcachesz)
                break;

            kb->kb_koff_max = memcpy(dst, kb->kb_koff_max, kb->kb_klen_max);

            dst += kb->kb_klen_max;

            if (dst + kb->kb_klen_min > ks->ks_klarge + kcachesz)
                break;

            kb->kb_koff_min = memcpy(dst, kb->kb_koff_min, kb->kb_klen_min);

            dst += kb->kb_klen_min;

            /* There is no further need to access the kblock
             * header past this point, and hence its physical
             * pages will eventually be reclaimed by the VMM.
             * For debug builds, we remove all access rights
             * to the kblock header in order to catch those
             * who might otherwise try to access it.
             */
#ifndef NDEBUG
            mprotect(kb->kb_kblk_desc.map_base, PAGE_SIZE, PROT_NONE);
#endif
        }
    }

    if (n_kblks) {
        if (kvset_has_ptree(ks)) {
            if (keycmp(ks->ks_kblks[0].kb_koff_min, ks->ks_kblks[0].kb_klen_min,
                    ks->ks_hblk.kh_pfx_min, ks->ks_hblk.kh_pfx_min_len) > 0) {
                ks->ks_minkey = ks->ks_hblk.kh_pfx_min;
                ks->ks_minklen = ks->ks_hblk.kh_pfx_min_len;
            } else {
                ks->ks_minkey = ks->ks_kblks[0].kb_koff_min;
                ks->ks_minklen = ks->ks_kblks[0].kb_klen_min;
            }

            if (keycmp(ks->ks_kblks[last_kb].kb_koff_max, ks->ks_kblks[last_kb].kb_klen_max,
                    ks->ks_hblk.kh_pfx_max, ks->ks_hblk.kh_pfx_max_len) > 0) {
                ks->ks_maxkey = ks->ks_kblks[last_kb].kb_koff_max;
                ks->ks_maxklen = ks->ks_kblks[last_kb].kb_klen_max;
            } else {
                ks->ks_maxkey = ks->ks_hblk.kh_pfx_max;
                ks->ks_maxklen = ks->ks_hblk.kh_pfx_max_len;
            }

            if (key_disc_cmp(&ks->ks_kblks[0].kb_kdisc_min, &ks->ks_hblk.kh_pfx_min_disc) > 0) {
                ks->ks_kdisc_min = ks->ks_hblk.kh_pfx_min_disc;
            } else {
                ks->ks_kdisc_min = ks->ks_kblks[0].kb_kdisc_min;
            }

            if (key_disc_cmp(&ks->ks_kblks[last_kb].kb_kdisc_max,
                    &ks->ks_hblk.kh_pfx_max_disc) > 0) {
                ks->ks_kdisc_max = ks->ks_kblks[last_kb].kb_kdisc_max;
            } else {
                ks->ks_kdisc_max = ks->ks_hblk.kh_pfx_max_disc;
            }
        } else {
            ks->ks_minkey = ks->ks_kblks[0].kb_koff_min;
            ks->ks_minklen = ks->ks_kblks[0].kb_klen_min;
            ks->ks_maxkey = ks->ks_kblks[last_kb].kb_koff_max;
            ks->ks_maxklen = ks->ks_kblks[last_kb].kb_klen_max;

            ks->ks_kdisc_min = ks->ks_kblks[0].kb_kdisc_min;
            ks->ks_kdisc_max = ks->ks_kblks[last_kb].kb_kdisc_max;
        }
    } else {
        ks->ks_minkey = ks->ks_hblk.kh_pfx_min;
        ks->ks_minklen = ks->ks_hblk.kh_pfx_min_len;
        ks->ks_maxkey = ks->ks_hblk.kh_pfx_max;
        ks->ks_maxklen = ks->ks_hblk.kh_pfx_max_len;

        ks->ks_kdisc_min = ks->ks_hblk.kh_pfx_min_disc;
        ks->ks_kdisc_max = ks->ks_hblk.kh_pfx_max_disc;
    }

    /* Check to see if all keys in this kvset have a common prefix.
     * If so, then remember it so that we can leverage it to reduce
     * the amount of work required to find keys with common prefixes.
     */
    lkb = ks->ks_kblks;
    rkb = ks->ks_kblks + last_kb;

    ks->ks_lcp = min_t(size_t, lkb->kb_klen_min, rkb->kb_klen_max);
    ks->ks_lcp = memlcpq(lkb->kb_koff_min, rkb->kb_koff_max, ks->ks_lcp);

    {
        uint v = 0; /* vblock number (0..n_vblks) */
        uint m = 0; /* index into mbset vector */
        uint k;
        u64 *argv;
        uint argc;

        for (i = 0; i < vbset_cnt_len; i++) {
            for (j = 0; j < vbset_cnts[i]; j++, m++) {
                /* set up refs to mbset #j */
                struct mbset *mbset = vbset_vecs[i][j];
                uint          blks_in_mbset = mbset_get_blkc(mbset);

                /* kvset_stats from vblocks */
                ks->ks_st.kst_valen += mbset_get_alen(mbset);
                ks->ks_st.kst_vwlen += mbset_get_wlen(mbset);

                ks->ks_vbsetv[m] = mbset_get_ref(mbset);
                for (k = 0; k < blks_in_mbset; k++, v++) {
                    ks->ks_vblk2mbs[v].mbs = mbset;
                    ks->ks_vblk2mbs[v].idx = k;
                }
            }
        }

        /* Compute vgroup indices and tally the number of vgroups.
         */
        argc = 0;
        argv = malloc(sizeof(*argv) * (v + 1));
        if (ev(!argv))
            goto err_exit;

        for (i = 0; i < m; ++i) {
            struct mbset *mbset = ks->ks_vbsetv[i];

            mbset_apply(mbset, vblock_udata_update, &argc, argv);
        }

        ks->ks_vgroups = argc;
        free(argv);
    }

    /* begin life with one ref and not deleting */
    kvset_get_ref(ks);
    ks->ks_deleted = DEL_NONE;

    kvdb_halen = atomic_fetch_add(&cn_kvdb->cnd_hblk_size, ks->ks_st.kst_halen);
    kvdb_halen += ks->ks_st.kst_halen;

    kvdb_kalen = atomic_fetch_add(&cn_kvdb->cnd_kblk_size, ks->ks_st.kst_kalen);
    kvdb_kalen += ks->ks_st.kst_kalen;

    kvdb_valen = atomic_fetch_add(&cn_kvdb->cnd_vblk_size, ks->ks_st.kst_valen);
    kvdb_valen += ks->ks_st.kst_valen;

    atomic_inc(&cn_kvdb->cnd_hblk_cnt);
    atomic_add(&cn_kvdb->cnd_kblk_cnt, ks->ks_st.kst_kblks);
    atomic_add(&cn_kvdb->cnd_vblk_cnt, ks->ks_st.kst_vblks);

    if (cn_tree_is_replay(tree))
        goto done;

    hse_meminfo(NULL, &mavail, 30);

    /* Convert from bytes to GiB for comparison w/ mavail. */
    kvdb_halen >>= GB_SHIFT;
    kvdb_kalen >>= GB_SHIFT;
    kvdb_valen >>= GB_SHIFT;

#define ra_lev0(_ra) ((_ra)&0xffu)
#define ra_lev1(_ra) (((_ra) >> 8) & 0xffu)
#define ra_pct(_ra) (((_ra) >> 16) & 0xffu)
#define ra_willneed(_ra) (((_ra) >> 24) & 0x01u)

    /* Enable mcache readahead for cn level zero k/v blocks and for
     * non-zero level k/v blocks if the kvdb size isn't larger than
     * the specified pct usage of system RAM.
     * Note, we avoid doing this when we're reinstantiating a kvdb
     * because we won't know the full size of the kvdb until after
     * we restore all kvsets.
     *
     * [HSE_REVISIT]: The code below expects kvdb_kalen to be the
     * sum of all kblock allocated lens in KVDB.  But that is only
     * true when all KVSes are open.  During startup, KVSes are
     * opened one at a time, so the metric will be wrong until the
     * last kvset of the last KVS is opened.  The same issue
     * applies to kvdb_valen and kvdb_halen.
     */
    hra = rp->cn_mcache_kra_params;
    kra = rp->cn_mcache_kra_params;
    vra = rp->cn_mcache_vra_params;

    if (ks->ks_node_level < ra_lev0(kra) || (!km->km_restored && ks->ks_node_level < ra_lev1(hra) &&
                                             kvdb_halen * 100 < ra_pct(hra) * mavail)) {
        if (ks->ks_node_level == 0 || (ra_willneed(hra) & 0x01))
            kvset_madvise_hblk(ks, MADV_WILLNEED, true);
    }

    if (ks->ks_node_level < ra_lev0(kra) || (!km->km_restored && ks->ks_node_level < ra_lev1(kra) &&
                                             kvdb_kalen * 100 < ra_pct(kra) * mavail)) {
        if (ks->ks_node_level == 0 || (ra_willneed(kra) & 0x01))
            kvset_madvise_kblks(ks, MADV_WILLNEED, true, true);
    }

    if (ks->ks_node_level < ra_lev0(vra) || (!km->km_restored && ks->ks_node_level < ra_lev1(vra) &&
                                             kvdb_valen * 100 < ra_pct(vra) * mavail)) {
        /* Disable cursor vblock readahead and direct mblock
         * reads for all vblocks in this kvset.
         */
        if (ra_willneed(vra) & 0x01) {
            kvset_madvise_vblks(ks, MADV_WILLNEED);
            ks->ks_vminlvl = U16_MAX;
            ks->ks_vra_len = 0;
        } else if (cn_tree_is_capped(ks->ks_tree)) {
            kvset_madvise_capped(ks, MADV_WILLNEED);
            ks->ks_vminlvl = U16_MAX;
        }
    }

done:
    ks->ks_ctime = get_time_ns();

    *ks_out = ks;

    return 0;

err_exit:
    _kvset_destroy(ks);
    return err;
}

merr_t
kvset_create(struct cn_tree *tree, uint64_t kvsetid, struct kvset_meta *km, struct kvset **ks)
{
    merr_t         err;
    uint           n_vblks = km->km_vblk_list.n_blks;
    struct mbset * vbset = 0;
    struct mbset **vbsetv = &vbset;
    uint           vbsetc = 0;
    uint           len = 0;
    uint           flags = 0;

    if (n_vblks) {
        u64 bufv[64];
        u64 *idv;

        idv = blkid_list_to_vec(&km->km_vblk_list, NELEM(bufv), bufv);
        if (ev(!idv))
            return merr(ENOMEM);

        if (km->km_node_level == 0)
            flags |= MBSET_FLAGS_VBLK_ROOT;

        if (km->km_capped)
            flags |= MBSET_FLAGS_CAPPED;

        err = mbset_create(cn_tree_get_mp(tree), n_vblks, idv, sizeof(struct vblock_desc),
                           vblock_udata_init, flags, &vbset);
        if (idv != bufv)
            free(idv);
        if (ev(err))
            return err;

        len = 1;
        vbsetc = 1;
    }

    /* kvset_create2 takes its own mbset ref, must free ours
     * unconditionally after calling kvset_create2.
     */
    err = kvset_create2(tree, kvsetid, km, len, &vbsetc, &vbsetv, ks);
    ev(err);

    if (n_vblks)
        mbset_put_ref(vbset);

    return err;
}

merr_t
kvset_delete_log_record(struct kvset *ks, struct cndb_txn *txn)
{
    merr_t err = cndb_record_kvset_del(ks->ks_cndb, txn, ks->ks_cnid, ks->ks_kvsetid,
                                       &ks->ks_delete_cookie);
    ks->ks_delete_txn = txn;
    return err;
}

static void
_kvset_mbset_destroyed(void *rock, bool mblk_delete_error)
{
    struct kvset *ks = rock;
    struct cn *   cn;
    int           v;

    /* Remember if any mblocks were not deleted so that
     * we can withhold the "ack_d" record from cndb.
     */
    if (mblk_delete_error)
        atomic_inc(&ks->ks_delete_error);

    /* Invoke kvset destructor if this is the last callback */
    v = atomic_inc_return(&ks->ks_mbset_callbacks);
    if (v < ks->ks_vbsetc)
        return;

    cn = cn_tree_get_cn(ks->ks_tree);

    _kvset_destroy(ks);
    cn_ref_put(cn);
}

void
kvset_mark_mblocks_for_delete(struct kvset *ks, bool keepv)
{
    /* NOTE: this function is used during compaction *After* the ACK_C
     * record, so it must not have failure conditions.
     */
    ks->ks_deleted = keepv ? DEL_KEEPV : DEL_ALL;

    /* If we need to delete vblocks, then:
     * Give each mbset a ref to kvset and a callback that drops the ref.
     * This delays destruction of the kvset until all mbsets have been
     * destroyed.  This is needed for one reason: to ensure exactly one
     * ack_d is issued to cndb (in the kvset destructor) after all mbset
     * mblocks have been deleted (which occurs in the mbset destructor).
     */
    if (ks->ks_deleted == DEL_ALL && ks->ks_vbsetc > 0) {
        uint i;

        /* Acquire a reference on cn to prevent cn_close() from
         * completing until after all in-flight mbset destroy
         * operations have completed.  Released in the mbset
         * callback after the kvset has been fully destroyed.
         */
        ks->ks_mbset_cb_pending = true;
        cn_ref_get(cn_tree_get_cn(ks->ks_tree));

        for (i = 0; i < ks->ks_vbsetc; i++) {
            struct mbset *vbset = ks->ks_vbsetv[i];

            mbset_set_delete_flag(vbset);
            mbset_set_callback(vbset, _kvset_mbset_destroyed, ks);
        }
    }
}

static void
cleanup_kblocks(struct kvset *ks)
{
    merr_t err = 0;
    uint   i;

    mpool_mcache_munmap(ks->ks_kmap);

    /* Stop deleting mblocks on the fist sign of trouble and let CNDB
     * finish deleting them during recovery.  We could continue to delete
     * remaining mblocks here, but a delete failure might be indicative of
     * a serious error, and stopping immediately would do less harm.
     */
    for (i = 0; i < ks->ks_st.kst_kblks; i++) {
        if (ks->ks_deleted) {
            err = mpool_mblock_delete(ks->ks_mp, ks->ks_kblks[i].kb_kblk.bk_blkid);
            if (ev(err)) {
                atomic_inc(&ks->ks_delete_error);
                return;
            }
        }
    }
}

static void
_kvset_destroy(struct kvset *ks)
{
    assert(ks);
    assert(atomic_read(&ks->ks_ref) == 0);

    if (ks->ks_cn_kvdb) {
        struct cn_kvdb *cnd = ks->ks_cn_kvdb;

        atomic_dec(&cnd->cnd_hblk_cnt);
        atomic_sub(&cnd->cnd_kblk_cnt, ks->ks_st.kst_kblks);
        atomic_sub(&cnd->cnd_vblk_cnt, ks->ks_st.kst_vblks);

        atomic_sub(&cnd->cnd_hblk_size, ks->ks_st.kst_halen);
        atomic_sub(&cnd->cnd_kblk_size, ks->ks_st.kst_kalen);
        atomic_sub(&cnd->cnd_vblk_size, ks->ks_st.kst_valen);
    }

    mpool_mcache_munmap(ks->ks_hmap);
    if (ks->ks_deleted) {
        const merr_t err = mpool_mblock_delete(ks->ks_mp, ks->ks_hblk.kh_hblk.bk_blkid);
        if (ev(err)) {
            atomic_inc(&ks->ks_delete_error);
            return;
        }
    }

    cleanup_kblocks(ks);

    if ((ks->ks_deleted != DEL_NONE) && !atomic_read(&ks->ks_delete_error))
        cndb_record_kvset_del_ack(ks->ks_cndb, ks->ks_delete_txn, ks->ks_delete_cookie);

    free((void *)ks->ks_klarge);

    if (ks->ks_kvset_sz > kvset_cache[0].sz)
        free_aligned(ks);
    else if (ks->ks_kvset_sz > kvset_cache[1].sz)
        kmem_cache_free(kvset_cache[0].cache, ks);
    else if (ks->ks_kvset_sz > kvset_cache[2].sz)
        kmem_cache_free(kvset_cache[1].cache, ks);
    else if (ks->ks_kvset_sz > kvset_cache[3].sz)
        kmem_cache_free(kvset_cache[2].cache, ks);
    else
        kmem_cache_free(kvset_cache[3].cache, ks);
}

static int
kblk_plausible(
    struct kvset_kblk *    kblk,
    const struct key_disc *kdisc,
    const void *           key,
    int                    len,
    int                    lcp)
{
    bool cmpmin, cmpmax;
    int  rc;

    assert(len != 0);
    assert(lcp >= 0);

    cmpmin = cmpmax = true;

    /* The caller sets lcp (the longest common prefix) to the length
     * of the given key that compares equal to the lcp of all the
     * keys in this kblock.
     */
    if (len > 0 && lcp < sizeof(*kdisc)) {
        rc = key_disc_cmp(kdisc, &kblk->kb_kdisc_max);
        if (rc > 0)
            return rc;
        cmpmax = !rc;

        rc = key_disc_cmp(kdisc, &kblk->kb_kdisc_min);
        if (rc < 0)
            return rc;
        cmpmin = !rc;
    }

    key += lcp;
    len -= lcp;

    /* If the given key is a prefix, has a long length in common
     * with all the keys in this kblock, or its discriminator
     * matches one or both of the kblock's discriminators then
     * we must use keycmp() to determine if it falls within the
     * bounds of this kblock.
     */
    if (cmpmax) {
        const void *kmax = kblk->kb_koff_max;
        u32         lmax = kblk->kb_klen_max;

        if (len > 0)
            rc = keycmp(key, len, kmax + lcp, lmax - lcp);
        else
            rc = keycmp_prefix(key, -len, kmax, lmax);

        if (rc >= 0)
            return rc;
    }

    if (cmpmin) {
        const void *kmin = kblk->kb_koff_min;
        u32         lmin = kblk->kb_klen_min;

        if (len > 0)
            rc = keycmp(key, len, kmin + lcp, lmin - lcp);
        else
            rc = keycmp_prefix(key, -len, kmin, lmin);

        if (rc <= 0)
            return rc;
    }

    return 0; /* key might be in this kblock */
}

bool
kvset_has_ptree(const struct kvset *const ks)
{
    return ks->ks_pfx_len > 0 && ks->ks_hblk.kh_ptree_desc.wbd_n_pages > 0;
}

/**
 * kvset_kblk_start() - determine if a kvset might contain a key.
 *
 * len > 0 => seek;   seek to key
 * len < 0 => create; seek to prefix
 *
 * Return value:
 * i >= 0 : of the first kblock that could possibly contain a match for key.
 * %KVSET_MISS_KEY_TOO_LARGE: key is larger than all key in the kvset.
 * %KVSET_MISS_KEY_TOO_SMALL: key is smaller than all keys in the kvset.
 */
int
kvset_kblk_start(struct kvset *ks, const void *key, int len, bool reverse)
{
    struct key_disc kdisc;
    int             rc, i;

    /* len == 0 ==> full scan */
    if (len == 0)
        return reverse ? ks->ks_st.kst_kblks - 1 : 0;

    if (len > 0) { /* seek */
        key_disc_init(key, len, &kdisc);

        /* if this is a seek (len > 0), can be too small only if rev */
        if (reverse) {
            rc = key_disc_cmp(&kdisc, &ks->ks_kdisc_min);
            if (rc < 0)
                return KVSET_MISS_KEY_TOO_SMALL;
        } else {
            rc = key_disc_cmp(&kdisc, &ks->ks_kdisc_max);
            if (rc > 0)
                return KVSET_MISS_KEY_TOO_LARGE;
        }
    }

    /* create */
    if (reverse) {
        for (i = ks->ks_st.kst_kblks - 1; i >= 0; --i) {
            rc = kblk_plausible(ks->ks_kblks + i, &kdisc, key, len, 0);
            if (rc == 0)
                return i;
            if (rc > 0)
                return len > 0 ? i : KVSET_MISS_KEY_TOO_LARGE;
        }

        /* key must compare smaller than all */
        return KVSET_MISS_KEY_TOO_SMALL;

    } else {
        for (i = 0; i < ks->ks_st.kst_kblks; ++i) {
            rc = kblk_plausible(ks->ks_kblks + i, &kdisc, key, len, 0);
            if (rc == 0)
                return i;
            /*
             * blks are ordered: cannot be in ks if pfx (len < 0)
             * but this is the correct answer for seek (len > 0)
             */
            if (rc < 0)
                return len > 0 ? i : KVSET_MISS_KEY_TOO_SMALL;
        }

        /* key must compare larger than all */
        return KVSET_MISS_KEY_TOO_LARGE;
    }
}

static merr_t
kblk_get_value_ref(
    struct kvset *         ks,
    uint                   kblk_idx,
    struct kvs_ktuple *    kt,
    int                    lcp,
    u64                    seq,
    enum key_lookup_res *  result,
    struct kvs_vtuple_ref *vref)
{
    struct kvset_kblk *kblk = ks->ks_kblks + kblk_idx;

    if (!bloom_reader_lookup(&kblk->kb_blm_desc, kt->kt_hash))
        return 0;

    return wbtr_read_vref(kblk->kb_kblk_desc.map_base, &kblk->kb_wbt_desc, kt, lcp, seq, result, vref);
}

static merr_t
kvset_ptomb_lookup(
    struct kvset *         ks,
    struct kvs_ktuple *    kt,
    u64                    view_seq,
    enum key_lookup_res *  res,
    struct kvs_vtuple_ref *vref)
{
    merr_t err;

    if (ks->ks_pfx_len && kt->kt_len >= ks->ks_pfx_len && kvset_has_ptree(ks)) {
        struct kvs_ktuple pfx;

        kvs_ktuple_init_nohash(&pfx, kt->kt_data, ks->ks_pfx_len);

        err = wbtr_read_vref(
            ks->ks_hblk.kh_hblk_desc.map_base,
            &ks->ks_hblk.kh_ptree_desc,
            &pfx,
            0,
            view_seq,
            res,
            vref);
        if (ev(err))
            return err;
    }

    return 0;
}

static
merr_t
kvset_lookup_vref(
    struct kvset *         ks,
    struct kvs_ktuple *    kt,
    const struct key_disc *kdisc,
    u64                    seq,
    enum key_lookup_res *  result,
    struct kvs_vtuple_ref *vref)
{
    int    first, last;
    int    rc, i;
    int    lcp;
    merr_t err;

    enum key_lookup_res   pt_result;
    struct kvs_vtuple_ref pt_vref;

    lcp = 0;

    first = 0;
    last = ks->ks_st.kst_kblks - 1;

    pt_result = NOT_FOUND;
    err = kvset_ptomb_lookup(ks, kt, seq, &pt_result, &pt_vref);
    if (ev(err))
        return err;

    /* If (kvset->ks_lcp > 0) then all keys in the kvset have a common
     * prefix of at least kvset->ks_lcp bytes.  Here we compute the
     * longest common prefix between the kvset and the target key.
     */
    if (ks->ks_lcp > 0) {
        const void *kmax = ks->ks_kblks->kb_koff_max;

        lcp = memlcpq(kt->kt_data, kmax, ks->ks_lcp);
        if (lcp > 0) {
            lcp -= 1;
            if (lcp >= sizeof(*kdisc))
                goto search;
        }
    }

    /* Check the bounds of the kvset.
     */
    rc = key_disc_cmp(kdisc, &ks->ks_kdisc_max);
    if (rc > 0)
        goto done;

    rc = key_disc_cmp(kdisc, &ks->ks_kdisc_min);
    if (rc < 0)
        goto done;

search:
    while (first <= last) {
        i = (first + last) / 2;

        rc = kblk_plausible(ks->ks_kblks + i, kdisc, kt->kt_data, kt->kt_len, lcp);
        if (rc < 0) {
            last = i - 1;
            continue;
        }
        if (rc > 0) {
            first = i + 1;
            continue;
        }

        err = kblk_get_value_ref(ks, i, kt, lcp, seq, result, vref);
        if (ev(err))
            return err;

        break;
    }

done:
    if (pt_result == FOUND_PTMB) {
        if (*result == NOT_FOUND || pt_vref.vr_seq > vref->vr_seq) {
            *result = pt_result;
            *vref = pt_vref;
        }
    }

    return 0;
}

static merr_t
kvset_get_immediate_value(struct kvs_vtuple_ref *vref, struct kvs_buf *vbuf)
{
    size_t copylen;

    /* should not be here for zero len values */
    if (ev(vref->vi.vr_len == 0)) {
        assert(0);
        vbuf->b_len = 0;
        return 0;
    }

    assert(vbuf->b_buf);
    copylen = vbuf->b_len = vref->vi.vr_len;
    if (copylen > vbuf->b_buf_sz)
        copylen = vbuf->b_buf_sz;
    memcpy(vbuf->b_buf, vref->vi.vr_data, copylen);

    return 0;
}

extern thread_local char tls_vbuf[];
extern const size_t tls_vbufsz;

static merr_t
kvset_lookup_val_direct(
    struct kvset *      ks,
    struct vblock_desc *vbd,
    u16                 vbidx,
    u32                 vboff,
    void *              vbuf,
    u32                 vbufsz,
    u32                 copylen)
{
    struct iovec iov;
    bool         aligned_vbuf;
    bool         aligned_all;
    bool         freeme;
    size_t       off;
    merr_t       err;
    u64          mbid;

    mbid = lvx2mbid(ks, vbidx);

    off = vbd->vbd_off + (vboff & PAGE_MASK);

    iov.iov_len = ALIGN(vboff + copylen, PAGE_SIZE) - (vboff & PAGE_MASK);
    iov.iov_base = vbuf;
    freeme = false;

    aligned_vbuf = IS_ALIGNED((ulong)vbuf, PAGE_SIZE);

    aligned_all = aligned_vbuf && IS_ALIGNED(copylen, PAGE_SIZE) &&
                  IS_ALIGNED(vbd->vbd_off + vboff, PAGE_SIZE);

    /* Eliminate the buffer copy by reading directly into vbuf if
     * everything is sufficiently aligned (i.e., aligned_all is true).
     * If not, try to improve the buffer copy if at least vbuf is
     * aligned and large enough to contain the entire read.
     */
    if (!aligned_all && !(aligned_vbuf && vbufsz >= iov.iov_len)) {
        iov.iov_base = PTR_ALIGN((void *)tls_vbuf, PAGE_SIZE);

        if (iov.iov_len > tls_vbuf + tls_vbufsz - (char *)iov.iov_base) {
            iov.iov_base = vlb_alloc(iov.iov_len);
            if (!iov.iov_base)
                return merr(ENOMEM);

            freeme = true;
        }
    }

    err = mpool_mblock_read(ks->ks_mp, mbid, &iov, 1, off);
    if (err) {
        log_errx("off %lx, len %lx, copylen %u, vbufsz %u: @@e",
                 err, off, iov.iov_len, copylen, vbufsz);
    } else {
        if (!aligned_all) {
            void *src = iov.iov_base + (vboff & ~PAGE_MASK);

            memmove(vbuf, src, copylen);
        }
    }

    if (freeme)
        vlb_free(iov.iov_base, iov.iov_len);

    return 0;
}

static merr_t
kvset_lookup_val_direct_decompress(
    struct kvset       *ks,
    struct vblock_desc *vbd,
    u16                 vbidx,
    u32                 vboff,
    void               *vbuf,
    uint                copylen,
    uint                omlen,
    uint               *outlenp)
{
    struct iovec iov;
    bool         freeme;
    size_t       off;
    merr_t       err;
    void        *src;
    u64          mbid;

    mbid = lvx2mbid(ks, vbidx);

    off = vbd->vbd_off + (vboff & PAGE_MASK);

    iov.iov_len = ALIGN(vboff + omlen, PAGE_SIZE) - (vboff & PAGE_MASK);
    iov.iov_base = PTR_ALIGN((void *)tls_vbuf, PAGE_SIZE);
    freeme = false;

    if (iov.iov_len > tls_vbuf + tls_vbufsz - (char *)iov.iov_base) {
        iov.iov_base = vlb_alloc(iov.iov_len);
        if (!iov.iov_base)
            return merr(ENOMEM);

        freeme = true;
    }

    err = mpool_mblock_read(ks->ks_mp, mbid, &iov, 1, off);
    if (err) {
        log_errx("off %lx, len %lx, copylen %u, omlen %u: @@e",
                 err, off, iov.iov_len, copylen, omlen);
    } else {
        src = iov.iov_base + (vboff & ~PAGE_MASK);

        err = compress_lz4_ops.cop_decompress(src, omlen, vbuf, copylen, outlenp);
    }

    if (freeme)
        vlb_free(iov.iov_base, iov.iov_len);

    return ev(err);
}

static
merr_t
kvset_lookup_val(struct kvset *ks, struct kvs_vtuple_ref *vref, struct kvs_buf *vbuf)
{
    struct vblock_desc *vbd;
    merr_t              err;
    void               *src, *dst;
    uint                omlen, copylen;
    bool direct;

    assert(vref->vr_type == vtype_ival
        || vref->vr_type == vtype_zval
        || vref->vr_type == vtype_val
        || vref->vr_type == vtype_cval);

    if (HSE_UNLIKELY(vref->vr_type == vtype_zval)) {
        vbuf->b_len = 0;
        return 0;
    }

    if (vref->vr_type == vtype_ival)
        return kvset_get_immediate_value(vref, vbuf);

    vbd = lvx2vbd(ks, vref->vb.vr_index);
    assert(vbd);

    /* on-media len, ptr to on-media data */
    omlen = vref->vb.vr_complen ? vref->vb.vr_complen : vref->vb.vr_len;
    src = vbr_value(vbd, vref->vb.vr_off, omlen);

    /* output buffer and how much to copy out */
    dst = vbuf->b_buf;
    copylen = min(vref->vb.vr_len, vbuf->b_buf_sz);

    direct = (copylen >= ks->ks_vmax ||
              (copylen >= ks->ks_vmin && ks->ks_node_level >= ks->ks_vminlvl)) &&
             (vbd->vbd_mblkdesc.mclass != HSE_MCLASS_PMEM);

    if (!copylen)
        goto done;

    if (vref->vb.vr_complen) {
        uint outlen;

        err = 0;

        if (direct)
            err = kvset_lookup_val_direct_decompress(
                ks, vbd, vref->vb.vr_index, vref->vb.vr_off, dst, copylen, omlen, &outlen);

        if (!direct || err) {
            err = compress_lz4_ops.cop_decompress(src, omlen, dst, copylen, &outlen);
            if (ev(err))
                return err;
        }

        if (ev(copylen == vref->vb.vr_len && outlen != copylen)) {
            /* oops: full size buffer, but not able to decompress all data */
            assert(0);
            return merr(EBUG);
        }

    } else {
        if (direct) {
            err = kvset_lookup_val_direct(
                ks, vbd, vref->vb.vr_index, vref->vb.vr_off, vbuf->b_buf, vbuf->b_buf_sz, copylen);
            if (!ev(err))
                goto done;

            err = 0; /* fall through to memcpy */
        }

        memcpy(dst, src, copylen);
    }

  done:
    vbuf->b_len = vref->vb.vr_len;
    return 0;
}

merr_t
kvset_wbti_alloc(void **wbti)
{
    return wbti_alloc((struct wbti **)wbti);
}

void
kvset_wbti_free(void *wbti)
{
    wbti_destroy(wbti);
}

merr_t
kvset_pfx_lookup(
    struct kvset *         ks,
    struct kvs_ktuple *    kt,
    const struct key_disc *kdisc,
    u64                    seq,
    enum key_lookup_res *  res,
    void *                 wbti,
    struct kvs_buf *       kbuf,
    struct kvs_buf *       vbuf,
    struct query_ctx *     qctx)
{
    struct kvs_vtuple_ref vref;
    struct kvset_kblk *   kblk;
    merr_t                err;
    u64                   pt_seq = 0;
    int                   kbidx, last;
    const void *          kmd;

    struct key_obj kobj, kt_obj, kbuf_obj;

    u8          curr_sfx_data[HSE_KVS_KEY_LEN_MAX];
    const void *curr_sfx;

    key2kobj(&kt_obj, kt->kt_data, kt->kt_len);

    err = kvset_ptomb_lookup(ks, kt, seq, res, &vref);
    if (ev(err))
        return err;

    if (*res == FOUND_PTMB)
        pt_seq = vref.vr_seq;

    /* Find the relevant wbt and starting kbidx */
    kbidx = kvset_kblk_start(ks, kt->kt_data, -kt->kt_len, 0);
    if (kbidx < 0)
        goto done; /* eof */

    last = ks->ks_st.kst_kblks - 1;

next_kblk:
    kblk = &ks->ks_kblks[kbidx];

    /* kvset_kblk_start() has positioned the iterator at the first
     * kblock that may have the key (based on min/max ranges).  If
     * the bloom filter finds that the soft prefix doesn't exist
     * in this kblock it most definitely doesn't exist in any
     * subsequent kblock.  It is thus safe to stop looking at
     * this kvset once there's a bloom miss.
     */
    if (!bloom_reader_lookup(&kblk->kb_blm_desc, kt->kt_hash))
        goto done;

    wbti_reset(wbti, kblk->kb_kblk_desc.map_base, &kblk->kb_wbt_desc, kt, 0, 0);

get_more:
    /* Get next key and set kmd to the base addr for the next keys' metadata */
    if (!wbti_next(wbti, &kobj.ko_sfx, &kobj.ko_sfx_len, &kmd)) {
        if (kbidx == last)
            goto done;

        ++kbidx;
        goto next_kblk;
    }

    /* Get the node prefix only after having called wbti_next(). This is
     * because wbti_next() could have advanced the iterator to the next
     * node which may have a different node pfx/pfx_len.
     */
    wbti_prefix(wbti, &kobj.ko_pfx, &kobj.ko_pfx_len);
    if (key_obj_cmp_prefix(&kt_obj, &kobj))
        goto done;

    /* Use the kmd (key metadata) to iterate over each value's metadata (vref).
     * Note we're resuing the vref form above that contained metadata for the
     * prefix tombstone.
     */
    {
        size_t off = 0;
        u64    vseq;
        uint   nvals;

        *res = NOT_FOUND;
        nvals = kmd_count(kmd, &off);
        while (nvals--) {
            wbt_read_kmd_vref(kmd, &off, &vseq, &vref);
            if (seq >= vseq) {
                /* can't be  a ptomb, b/c they're in their own WBT */
                assert(vref.vr_type != vtype_ptomb);
                vref.vr_seq = vseq;
                if (vref.vr_type == vtype_tomb)
                    *res = FOUND_TMB;
                else
                    *res = FOUND_VAL;
                break;
            }
        }

        if (*res == NOT_FOUND)
            goto get_more;

        if (pt_seq && vseq < pt_seq)
            goto get_more; /* key is hidden behind ptomb; skip */
    }

    if (!kobj.ko_sfx_len) {
        assert(kobj.ko_pfx_len > ks->ks_sfx_len);
        curr_sfx = kobj.ko_pfx + kobj.ko_pfx_len - ks->ks_sfx_len;
    } else if (kobj.ko_sfx_len >= ks->ks_sfx_len) {
        curr_sfx = kobj.ko_sfx + kobj.ko_sfx_len - ks->ks_sfx_len;
    } else {
        /* copy out suffix */
        uint  slen = kobj.ko_sfx_len;
        uint  plen = kobj.ko_pfx_len;
        uint  remaining;
        void *p;

        p = curr_sfx_data + ks->ks_sfx_len - slen;
        memcpy(p, kobj.ko_sfx, slen);

        remaining = ks->ks_sfx_len - slen;
        p = (void *)(kobj.ko_pfx + plen - remaining);
        memcpy(curr_sfx_data, p, remaining);
        curr_sfx = curr_sfx_data;
    }

    if (*res == FOUND_TMB) {
        err = qctx_tomb_insert(qctx, curr_sfx, ks->ks_sfx_len);
        if (ev(err))
            return err;

        goto get_more;
    }

    /* compare w/ first key and decide whether to count */
    if (qctx->seen) {
        uint cmplen = min_t(size_t, kbuf->b_len, kbuf->b_buf_sz);

        key2kobj(&kbuf_obj, kbuf->b_buf, cmplen);
        if (!key_obj_cmp(&kobj, &kbuf_obj))
            goto get_more; /* duplicate */
    }

    if (qctx_tomb_seen(qctx, curr_sfx, ks->ks_sfx_len))
        goto get_more; /* skip key. There's a matching tomb. */

    /* This kv-pair counts towards the query's matches. Copy out kv if this
     * is the first seen kv-pair.
     */
    if (++qctx->seen == 1) {
        err = kvset_lookup_val(ks, &vref, vbuf);
        if (ev(err))
            return err;

        /* [HSE_REVISIT] If the caller passes an insufficiently sized
         * buffer, later comparisons against the key (to identify
         * duplicates) will be incorrect.
         * Handle this case by copying out the key in a buffer in the
         * query context.
         */
        key_obj_copy(kbuf->b_buf, kbuf->b_buf_sz, &kbuf->b_len, &kobj);
        goto get_more;
    }

done:
    if (pt_seq)
        *res = FOUND_PTMB;

    return 0;
}

merr_t
kvset_lookup(
    struct kvset *         ks,
    struct kvs_ktuple *    kt,
    const struct key_disc *kdisc,
    u64                    seq,
    enum key_lookup_res *  res,
    struct kvs_buf *       vbuf)
{
    struct kvs_vtuple_ref vref;
    merr_t                err;

    err = kvset_lookup_vref(ks, kt, kdisc, seq, res, &vref);
    if (ev(err))
        return err;

    if (*res != FOUND_VAL)
        return 0;

    return kvset_lookup_val(ks, &vref, vbuf);
}

u64
kvset_get_dgen(struct kvset *ks)
{
    return ks->ks_dgen;
}

u64
kvset_get_seqno_max(struct kvset *ks)
{
    return ks->ks_seqno_max;
}

uint
kvset_get_compc(struct kvset *ks)
{
    return ks->ks_compc;
}

uint
kvset_get_vgroups(struct kvset *ks)
{
    return ks->ks_vgroups;
}

struct cn_tree *
kvset_get_tree(struct kvset *ks)
{
    if (ev(!ks))
        return NULL;

    return ks->ks_tree;
}

u8 *
kvset_get_hlog(struct kvset *ks)
{
    return ks->ks_hlog;
}

u64
kvset_ctime(const struct kvset *kvset)
{
    return kvset->ks_ctime;
}

const struct kvset_stats *
kvset_statsp(const struct kvset *ks)
{
    return &ks->ks_st;
}

void
kvset_stats(const struct kvset *ks, struct kvset_stats *stats)
{
    *stats = *kvset_statsp(ks);
}

void
kvset_stats_add(const struct kvset_stats *add, struct kvset_stats *result)
{
    result->kst_kvsets += add->kst_kvsets;
    result->kst_keys += add->kst_keys;
    result->kst_hblks += add->kst_hblks;
    result->kst_kblks += add->kst_kblks;
    result->kst_vblks += add->kst_vblks;

    result->kst_halen += add->kst_halen;
    result->kst_hwlen += add->kst_hwlen;

    result->kst_kalen += add->kst_kalen;
    result->kst_kwlen += add->kst_kwlen;

    result->kst_valen += add->kst_valen;
    result->kst_vwlen += add->kst_vwlen;
    result->kst_vulen += add->kst_vulen;
}

u64
kvset_get_vulen(struct kvset *ks)
{
    return ks->ks_st.kst_vulen;
}

u64
kvset_get_workid(struct kvset *ks)
{
    return ks->ks_workid;
}

void
kvset_set_workid(struct kvset *ks, u64 id)
{
    ks->ks_workid = id;
}

uint64_t
kvset_get_hblock_id(struct kvset *ks)
{
    return ks->ks_hblk.kh_hblk.bk_blkid;
}

u32
kvset_get_num_kblocks(struct kvset *ks)
{
    return ks->ks_st.kst_kblks;
}

u64
kvset_get_nth_kblock_id(struct kvset *ks, u32 index)
{
    return (index < ks->ks_st.kst_kblks ? ks->ks_kblks[index].kb_kblk.bk_blkid : 0);
}

u32
kvset_get_num_vblocks(struct kvset *ks)
{
    return ks->ks_st.kst_vblks;
}

u64
kvset_get_nth_vblock_id(struct kvset *ks, u32 index)
{
    return (index < ks->ks_st.kst_vblks ? lvx2mbid(ks, index) : 0);
}

u64
kvset_get_nth_vblock_len(struct kvset *ks, u32 index)
{
    struct vblock_desc *vbd = lvx2vbd(ks, index);

    return vbd ? vbd->vbd_len : 0;
}

struct mbset **
kvset_get_vbsetv(struct kvset *ks, uint *vbsetc)
{
    *vbsetc = ks->ks_vbsetc;
    return ks->ks_vbsetv;
}

void
kvset_get_min_key(struct kvset *ks, const void **min_key, uint *min_klen)
{
    struct kvset_kblk *kb = &ks->ks_kblks[0];

    INVARIANT(min_key && min_klen);

    *min_key = kb->kb_koff_min;
    *min_klen = kb->kb_klen_min;
}

void
kvset_get_max_key(struct kvset *ks, const void **max_key, uint *max_klen)
{
    struct kvset_kblk *kb = &ks->ks_kblks[ks->ks_st.kst_kblks - 1];

    INVARIANT(max_key && max_klen);

    *max_key = kb->kb_koff_max;
    *max_klen = kb->kb_klen_max;
}

void
kvset_get_metrics(struct kvset *ks, struct kvset_metrics *m)
{
    struct kvset_kblk *p;
    u32                i;

    memset(m, 0, sizeof(*m));

    m->num_hblocks = ks->ks_st.kst_hblks;
    m->num_kblocks = ks->ks_st.kst_kblks;
    m->num_vblocks = ks->ks_st.kst_vblks;
    m->header_bytes = ks->ks_st.kst_hwlen;
    m->compc = ks->ks_compc;
    m->vgroups = ks->ks_vgroups;
    m->nptombs = ks->ks_hblk.kh_metrics.hm_nptombs;

    for (i = 0; i < ks->ks_st.kst_kblks; i++) {
        p = ks->ks_kblks + i;
        m->num_keys += p->kb_metrics.num_keys;
        m->num_tombstones += p->kb_metrics.num_tombstones;
        m->tot_key_bytes += p->kb_metrics.tot_key_bytes;
        m->tot_val_bytes += p->kb_metrics.tot_val_bytes;
        m->tot_wbt_pages += p->kb_metrics.tot_wbt_pages;
        m->tot_blm_pages += p->kb_metrics.tot_blm_pages;
    }
}

void
kvset_list_add(struct kvset *ks, struct list_head *head)
{
    list_add(&ks->ks_entry.le_link, head);
}

void
kvset_list_add_tail(struct kvset *ks, struct list_head *head)
{
    list_add_tail(&ks->ks_entry.le_link, head);
}

/*----------------------------------------------------------------
 * Kvset Iterator
 */

struct kv_iterator_ops kvset_iter_ops;

/* async_mbio: for asynchronous mblock i/o */
struct async_mbio {
    struct mutex mutex;
    int          pending;
    int          status;
    const char  *cv_wmesg;
    struct cv    cv;
};

struct kr_buf {
    void *node_buf;
    void *kmd_buf;
    uint  node_buf_sz;
    uint  kmd_buf_sz;
    uint  kmd_used_sz;
};

struct kblk_reader {

    struct work_struct work;
    struct mpool *     ds;
    struct async_mbio  mbio;
    struct perfc_set * pc;

    /* io buffers */
    struct kr_buf kr_buf[2];
    u8            kr_bufx;
    bool          asyncio;

    /* reader state */
    bool kr_requested;
    bool kr_eof;

    /* io results */
    struct {
        uint  kr_nodec;
        uint  kr_node_kmd_off_adj;
        void *kr_nodev;
        void *kr_kmd_base;
        uint  kr_bytes;
        uint  kr_ops;
    } iores;

    u64 kr_mbid;
    u16 kr_blk_cnt;
    u16 kr_nodex;
    u16 kr_nodec;
    u16 kr_node_start_pg;
    u16 kr_kmd_start_pg;
    u16 kr_kmd_pgc;
    u16 kr_next_blk_idx;
};

struct vr_buf {
    void *data;
    uint  idx; /* current vblock index tracked by buffer */
    uint  off;
    uint  len;
};

/* A vblock reader is allocated per vgroup. Due to readahead, each buffer
 * must maintain its own vbidx to handle vblock transitions within a vgroup.
 */
struct vblk_reader {
    struct work_struct work;
    struct async_mbio  mbio;
    struct mpool *     ds;
    struct perfc_set * pc;
    /* index, offset, and length of async mblock read */
    uint vr_io_vbidx;
    uint vr_io_offset;
    uint vr_io_len;
    /* mblock properties */
    u64  vr_mbid;
    uint vr_mblk_dstart;
    uint vr_mblk_dlen;
    /* buffer */
    struct vr_buf vr_buf[2];
    uint          vr_buf_sz;
    uint          vr_active; /* index of vr_buf[] that has data */
    bool          vr_requested;
    bool          vr_read_ahead;
    bool          asyncio;
};

enum last_src {
    SRC_NONE = 0,
    SRC_PT,
    SRC_WBT,
};

struct iter_meta {
    const void *last_key;
    u32         last_klen;
    bool        eof;
    const void *kmd;
};

struct wb_pos {
    void *              wb_node;    /* current node */
    void *              wb_pfx;     /* node's lcp */
    u16                 wb_pfx_len; /* length of node's lcp */
    struct wbt_lfe_omf *wb_lfe;     /* current key */
    u16                 wb_nodec;   /* #nodes left in current buffer */
    u16                 wb_keyc;    /* #keys left in current node */

    void *wb_kmd_base;
    uint  wb_node_kmd_off_adj;
};

struct kvset_iterator {
    struct kv_iterator       handle;
    struct kvset *           ks;
    struct wbti *            wbti;
    struct wbti *            pti;
    struct perfc_set *       pc;
    struct cn_merge_stats *  stats;
    uint                     curr_kblk;
    enum last_src            last;
    u32                      vra_flags;
    u32                      vra_len;
    struct workqueue_struct *vra_wq;
    bool                     reverse;
    bool                     asyncio;
    struct iter_meta         wbti_meta;
    struct iter_meta         pti_meta;

    struct ra_hist ra_histv[64];

    /* ------------------------------------------------
     * From here down is for iterating via mblock_read
     * instead of using mcache maps.
     */

    /* reader state */
    struct kblk_reader       kreader;  /* kb work buffer */
    struct vblk_reader *     vreaders; /* vb work buffer */
    struct workqueue_struct *workq;

    struct kblk_reader ptreader; /* kb work buffer for ptombs */

    /* For iterating over keys in a work buffer provided by kreader */
    struct wb_pos wbt_reader;
    struct wb_pos pt_reader;
};

#define handle_to_kvset_iter(_handle) container_of(_handle, struct kvset_iterator, handle)

static void
mbio_init(struct async_mbio *io, const char *wmesg)
{
    mutex_init(&io->mutex);
    cv_init(&io->cv);
    io->status = 0;
    io->pending = 0;
    io->cv_wmesg = wmesg;
}

static void
mbio_arm(struct async_mbio *io)
{
    mutex_lock(&io->mutex);
    assert(!io->pending);
    io->pending = 1;
    mutex_unlock(&io->mutex);
}

static void
mbio_signal(struct async_mbio *io, merr_t err)
{
    mutex_lock(&io->mutex);
    assert(io->pending);
    io->status = err;
    io->pending = 0;
    cv_signal(&io->cv);
    mutex_unlock(&io->mutex);
}

static merr_t
mbio_wait(struct async_mbio *io, struct cn_merge_stats_ops *stats)
{
    merr_t err;
    u64    tstart = 0;

    mutex_lock(&io->mutex);
    if (stats && io->pending)
        tstart = get_time_ns();
    while (io->pending)
        cv_wait(&io->cv, &io->mutex, io->cv_wmesg);
    if (tstart)
        count_ops(stats, 1, 0, get_time_ns() - tstart);
    err = io->status;
    mutex_unlock(&io->mutex);
    return err;
}

static void
kvset_iter_kblock_read(struct work_struct *rock)
{
    struct kblk_reader *     kr = container_of(rock, struct kblk_reader, work);
    struct wbt_node_hdr_omf *hdr;

    struct iovec   iov;
    merr_t         err = 0;
    uint           node_read_cnt;
    size_t         a, b, kblk_off, rlen;
    u32            end_node_kmd_off;
    u32            start_node_kmd_off;
    bool           last_node;
    struct kr_buf *buf;

    assert(kr->kr_nodex < kr->kr_nodec);

    buf = &kr->kr_buf[kr->kr_bufx];

    /* Read leaf nodes from mblock.  Need buffer space for at
     * least two nodes as explained below.
     */
    assert(buf->node_buf_sz > 2 * PAGE_SIZE);
    node_read_cnt = kr->kr_nodec - kr->kr_nodex;
    if (node_read_cnt * PAGE_SIZE > buf->node_buf_sz) {
        last_node = false;
        node_read_cnt = buf->node_buf_sz / PAGE_SIZE;
    } else {
        last_node = true;
    }

    iov.iov_base = buf->node_buf;
    iov.iov_len = node_read_cnt * PAGE_SIZE;
    kblk_off = (kr->kr_node_start_pg + kr->kr_nodex) * PAGE_SIZE;

    rlen = iov.iov_len;
    err = mpool_mblock_read(kr->ds, kr->kr_mbid, &iov, 1, kblk_off);
    if (ev(err))
        goto done;

    perfc_inc(kr->pc, PERFC_RA_CNCOMP_RREQS);
    perfc_add(kr->pc, PERFC_RA_CNCOMP_RBYTES, iov.iov_len);

    /* figure out kmd range that corresponds to leaf nodes */
    hdr = iov.iov_base;
    assert(omf_wbn_magic(hdr) == WBT_LFE_NODE_MAGIC);
    start_node_kmd_off = omf_wbn_kmd(hdr);

    if (last_node) {
        end_node_kmd_off = kr->kr_kmd_pgc * PAGE_SIZE;
    } else {
        /* get end of kmd range last node */
        hdr = iov.iov_base + iov.iov_len - PAGE_SIZE;
        assert(omf_wbn_magic(hdr) == WBT_LFE_NODE_MAGIC);
        end_node_kmd_off = omf_wbn_kmd(hdr);
        /* Cannot read keys from last node b/c we don't have kmd
         * for them.  This is why we insist node buffer is at
         * least two pages.
         */
        node_read_cnt--;
    }

    assert(end_node_kmd_off > start_node_kmd_off);

    a = start_node_kmd_off & ~(PAGE_SIZE - 1);
    b = PAGE_ALIGN(end_node_kmd_off);
    assert(b - a == PAGE_ALIGN(b - a));

    /* kmd read parameters */
    iov.iov_base = buf->kmd_buf;
    iov.iov_len = b - a;
    kblk_off = kr->kr_kmd_start_pg * PAGE_SIZE + a;

    /* is kmd buffer big enough ? */
    if (iov.iov_len > buf->kmd_buf_sz) {
        size_t sz = roundup(iov.iov_len + 1, VLB_ALLOCSZ_MAX);

        iov.iov_base = vlb_alloc(sz);
        if (ev(!iov.iov_base)) {
            err = merr(ENOMEM);
            goto done;
        }

        vlb_free(buf->kmd_buf, buf->kmd_used_sz);

        buf->kmd_used_sz = (sz > VLB_ALLOCSZ_MAX) ? sz : iov.iov_len;
        buf->kmd_buf_sz = sz;
        buf->kmd_buf = iov.iov_base;

    } else if (iov.iov_len > buf->kmd_used_sz) {
        buf->kmd_used_sz = iov.iov_len;
    }

    rlen += iov.iov_len;
    err = mpool_mblock_read(kr->ds, kr->kr_mbid, &iov, 1, kblk_off);
    if (ev(err))
        goto done;

    perfc_inc(kr->pc, PERFC_RA_CNCOMP_RREQS);
    perfc_add(kr->pc, PERFC_RA_CNCOMP_RBYTES, iov.iov_len);

    /* stash results in consumable form for caller */
    kr->iores.kr_ops = 2;
    kr->iores.kr_bytes = rlen;
    kr->iores.kr_nodec = node_read_cnt;
    kr->iores.kr_nodev = buf->node_buf;
    kr->iores.kr_kmd_base = buf->kmd_buf + start_node_kmd_off - a;
    kr->iores.kr_node_kmd_off_adj = start_node_kmd_off;

    /* setup for next read */
    kr->kr_nodex += kr->iores.kr_nodec;
    if (kr->asyncio)
        kr->kr_bufx = !kr->kr_bufx;

done:
    mbio_signal(&kr->mbio, err);
}

enum read_type { READ_WBT = true, READ_PT = false };

static void
kblk_start_read(struct kvset_iterator *iter, struct kblk_reader *kr, enum read_type read_type)
{
    bool success       HSE_MAYBE_UNUSED;

    assert(!kr->mbio.pending);
    assert(iter->workq);

    if (kr->kr_nodex == kr->kr_nodec) {
        struct wbt_desc *wbt;

        if (kr->kr_next_blk_idx >= kr->kr_blk_cnt) {
            kr->kr_eof = true;
            return;
        }

        switch (read_type) {
        case READ_WBT: {
            struct kvset_kblk *kblk;

            /* starting a new kblock */
            kblk = &iter->ks->ks_kblks[kr->kr_next_blk_idx];

            wbt = &kblk->kb_wbt_desc;
            kr->kr_mbid = kblk->kb_kblk.bk_blkid;
            break;
        }
        case READ_PT:
            wbt = &iter->ks->ks_hblk.kh_ptree_desc;
            kr->kr_mbid = iter->ks->ks_hblk.kh_hblk.bk_blkid;
            break;
        }

        kr->kr_nodex = 0;
        kr->kr_nodec = wbt->wbd_leaf_cnt;
        kr->kr_kmd_pgc = wbt->wbd_kmd_pgc;
        kr->kr_node_start_pg = wbt->wbd_first_page;
        kr->kr_kmd_start_pg = (wbt->wbd_first_page + wbt->wbd_root + 1);

        if (kr->kr_kmd_pgc == 0) {
            kr->kr_eof = true;
            return;
        }

        iter->curr_kblk = kr->kr_next_blk_idx;
        kr->kr_next_blk_idx++;
    }

    mbio_arm(&kr->mbio);
    INIT_WORK(&kr->work, kvset_iter_kblock_read);
    if (iter->asyncio) {
        success = queue_work(iter->workq, &kr->work);
        assert(success);
    } else {
        kvset_iter_kblock_read(&kr->work);
    }
}

static void
vr_read_work(struct work_struct *rock)
{
    struct vblk_reader *vr = container_of(rock, struct vblk_reader, work);
    struct iovec        iov;
    merr_t              err;
    int                 empty = !vr->vr_active;
    size_t              vblk_offset;

    iov.iov_base = vr->vr_buf[empty].data;
    iov.iov_len = vr->vr_io_len;

    /* adjust offset for start of vblock data region */
    vblk_offset = vr->vr_io_offset + vr->vr_mblk_dstart;
    err = mpool_mblock_read(vr->ds, vr->vr_mbid, &iov, 1, vblk_offset);
    if (ev(err))
        goto done;

    perfc_inc(vr->pc, PERFC_RA_CNCOMP_RREQS);
    perfc_add(vr->pc, PERFC_RA_CNCOMP_RBYTES, iov.iov_len);

    vr->vr_buf[empty].idx = vr->vr_io_vbidx;
    vr->vr_buf[empty].off = vr->vr_io_offset;
    vr->vr_buf[empty].len = vr->vr_io_len;

done:
    mbio_signal(&vr->mbio, err);
}

static bool
vr_start_read(
    struct vblk_reader *     vr,
    uint                     vbidx,
    uint                     vboff,
    struct workqueue_struct *workq,
    struct kvset *           ks)
{
    bool success HSE_MAYBE_UNUSED;

    /* update mblock properties */
    assert(lvx2vbd(ks, vbidx));
    vr->vr_mblk_dstart = lvx2vbd(ks, vbidx)->vbd_off;
    vr->vr_mblk_dlen = lvx2vbd(ks, vbidx)->vbd_len;
    vr->vr_mbid = lvx2mbid(ks, vbidx);

    /* set io fields for async mblock read */
    vr->vr_io_vbidx = vbidx;
    vr->vr_io_offset = vboff & PAGE_MASK;
    vr->vr_io_len = vr->vr_mblk_dlen - vr->vr_io_offset;
    vr->vr_io_len = PAGE_ALIGN(vr->vr_io_len);
    if (vr->vr_io_len == 0)
        return false;

    if (vr->vr_io_len > vr->vr_buf_sz)
        vr->vr_io_len = vr->vr_buf_sz;

    vr->mbio.pending = 1;

    INIT_WORK(&vr->work, vr_read_work);
    if (vr->asyncio) {
        success = queue_work(workq, &vr->work);
        assert(success);
    } else {
        vr_read_work(&vr->work);
    }

    return true;
}

static HSE_ALWAYS_INLINE bool
vr_have_data(struct vr_buf *buf, uint idx, uint off, uint len)
{
    return (buf->idx == idx && buf->off <= off && off + len <= buf->off + buf->len);
}

static void
kvset_iter_free_buffers(struct kvset_iterator *iter, struct kblk_reader *kr)
{
    uint i;

    /* one allocation for node_buf */
    vlb_free(kr->kr_buf[0].node_buf, kr->kr_buf[0].node_buf_sz * 2);

    /* separate allocations for kmd_buf */
    vlb_free(kr->kr_buf[0].kmd_buf, kr->kr_buf[0].kmd_used_sz);
    vlb_free(kr->kr_buf[1].kmd_buf, kr->kr_buf[1].kmd_used_sz);

    if (iter->vreaders) {
        for (i = 0; i < iter->ks->ks_vgroups; i++)
            vlb_free(iter->vreaders[i].vr_buf[0].data, iter->vreaders[i].vr_buf_sz * 2);
        free(iter->vreaders);
        iter->vreaders = 0;
    }
}

static merr_t
kvset_iter_enable_mblock_read_cmn(struct kvset_iterator *iter, struct kblk_reader *kr)
{
    void *   mem;
    uint64_t node_buf_sz;

    /* compute appropriate node buffer size */
    node_buf_sz = iter->ks->ks_rp->cn_compact_kblk_ra;
    if (node_buf_sz > VLB_ALLOCSZ_MAX / 2)
        node_buf_sz = VLB_ALLOCSZ_MAX / 2;
    if (node_buf_sz < 2 * PAGE_SIZE)
        node_buf_sz = 2 * PAGE_SIZE;
    node_buf_sz = PAGE_ALIGN(node_buf_sz);

    /* two buffers for asyncio, one for syncio */
    mem = vlb_alloc(node_buf_sz * 2);
    if (ev(!mem))
        goto nomem;

    memset(&kr->kr_buf, 0, sizeof(kr->kr_buf));

    kr->kr_buf[0].node_buf = mem;
    kr->kr_buf[0].node_buf_sz = node_buf_sz;
    if (iter->asyncio) {
        kr->kr_buf[1].node_buf = mem + node_buf_sz;
        kr->kr_buf[1].node_buf_sz = node_buf_sz;
    }

    kr->asyncio = iter->asyncio;

    kr->ds = iter->ks->ks_mp;
    kr->pc = iter->pc;

    mbio_init(&kr->mbio, "krmbio");

    return 0;

nomem:
    kvset_iter_free_buffers(iter, kr);
    return merr(ev(ENOMEM));
}

static merr_t
kvset_iter_enable_mblock_read_pt(struct kvset_iterator *iter)
{
    struct kblk_reader *kr = &iter->ptreader;
    merr_t              err;

    err = kvset_iter_enable_mblock_read_cmn(iter, kr);
    if (ev(err))
        return err;

    /* ptombs are stored in the singular hblock */
    kr->kr_blk_cnt = 1;

    return 0;
}

static merr_t
kvset_iter_enable_mblock_read(struct kvset_iterator *iter)
{
    struct kblk_reader *kr = &iter->kreader;
    struct vblk_reader *vr;
    void *              mem;
    uint64_t            vr_buf_sz;
    uint                i;
    merr_t              err;
    uint64_t            ra_size;

    ra_size = iter->ks->ks_rp->cn_compact_vblk_ra;

    /* The root needs twice prefetching as the rest to avoid backlog. Also,
     * when the bandwidth is very low which is seen predominantly in slower
     * drives, it requires a lot more prefetching to maintain backlog in
     * check.
     */
    if (ra_size < HSE_KVS_VALUE_LEN_MAX) {
        if (iter->ks->ks_node_level == 0)
            ra_size = HSE_KVS_VALUE_LEN_MAX;
        ra_size = min_t(uint64_t, ra_size, HSE_KVS_VALUE_LEN_MAX);
    }

    /* Limit buffered reads to values lesser than cn_compact_vblk_ra. The
     * upper level spill/compaction routines make direct reads for the sizes
     * matching or exceeding cn_compact_vblk_ra.
     */
    vr_buf_sz = max_t(uint64_t, PAGE_SIZE, ra_size);

    if (vr_buf_sz > VLB_ALLOCSZ_MAX / 2)
        vr_buf_sz = VLB_ALLOCSZ_MAX / 2;
    vr_buf_sz = PAGE_ALIGN(vr_buf_sz);

    err = kvset_iter_enable_mblock_read_cmn(iter, kr);
    if (ev(err))
        return err;

    /* One vblock reader for each vgroup.  Kvsets produced by
     * ingest, spill or kv-compaction could be handled with one
     * reader because vblocks will be consumed in order.  Kvsets
     * produced by kcompaction will need one reader for each vgroup.
     */
    iter->vreaders = NULL;
    if (iter->ks->ks_vgroups) {
        iter->vreaders = calloc(iter->ks->ks_vgroups, sizeof(*iter->vreaders));
        if (ev(!iter->vreaders))
            goto nomem;
        for (i = 0; i < iter->ks->ks_vgroups; i++) {
            vr = iter->vreaders + i;

            mbio_init(&vr->mbio, "vrmbio");

            mem = vlb_alloc(vr_buf_sz * 2);
            if (ev(!mem))
                goto nomem;

            vr->vr_buf[0].data = mem;
            vr->vr_buf[0].off = 0;
            vr->vr_buf[0].len = 0;
            vr->vr_buf[0].idx = UINT_MAX;

            vr->asyncio = iter->asyncio;
            if (iter->asyncio) {
                vr->vr_buf[1].data = mem + vr_buf_sz;
                vr->vr_buf[1].off = 0;
                vr->vr_buf[1].len = 0;
                vr->vr_buf[1].idx = UINT_MAX;
            }

            vr->vr_active = 0;
            vr->vr_buf_sz = vr_buf_sz;

            vr->ds = iter->ks->ks_mp;
            vr->pc = iter->pc;
        }
    }

    kr->kr_blk_cnt = iter->ks->ks_st.kst_kblks;

    return 0;

nomem:
    kvset_iter_free_buffers(iter, kr);
    return merr(ev(ENOMEM));
}

static void
kvset_iter_mblock_read_start(struct kvset_iterator *iter)
{
    struct kblk_reader *k = &iter->kreader;
    struct kblk_reader *p = &iter->ptreader;

    assert(iter->asyncio);

    p->kr_requested = true;
    kblk_start_read(iter, p, READ_PT);

    /* Initiate first reads */
    k->kr_requested = true;
    kblk_start_read(iter, k, READ_WBT);
    if (iter->ks->ks_st.kst_vblks) {
        struct vblk_reader *vr = &iter->vreaders[0];

        vr->vr_requested = vr_start_read(vr, 0, 0, iter->workq, iter->ks);
    }
}

static bool
kvset_cursor_next(struct element_source *es, void **element)
{
    struct kv_iterator *kvi = kvset_cursor_es_h2r(es);
    struct cn_kv_item * kv = &kvi->kvi_kv;

    *element = 0;

    kvset_iter_next_key(kvi, &kv->kobj, &kv->vctx);
    if (kvi->kvi_eof)
        return false;

    kv->src = es;
    *element = &kvi->kvi_kv;

    return true;
}

merr_t
kvset_iter_create(
    struct kvset *           ks,
    struct workqueue_struct *io_workq,
    struct workqueue_struct *vra_wq,
    struct perfc_set *       pc,
    enum kvset_iter_flags    flags,
    struct kv_iterator **    handle)
{
    merr_t                 err = 0;
    struct kvset_iterator *iter;
    bool                   fullscan;
    bool                   reverse;
    bool                   mblock_read;

    mblock_read = !(flags & kvset_iter_flag_mcache);
    reverse = flags & kvset_iter_flag_reverse;
    fullscan = flags & kvset_iter_flag_fullscan;

    if (ev(reverse && (io_workq || mblock_read)))
        return merr(EINVAL);

    iter = kmem_cache_zalloc(kvset_iter_cache);
    if (ev(!iter))
        return merr(ENOMEM);

    /* If successful, kvset_iter_create() adopts one reference
     * on the kvset from the caller.
     */
    iter->ks = ks;
    iter->handle.kvi_ops = &kvset_iter_ops;
    iter->vra_len = roundup(ks->ks_vra_len, PAGE_SIZE);
    iter->handle.kvi_es = es_make(kvset_cursor_next, 0, 0);

    if (fullscan && !mblock_read) {
        iter->vra_len = roundup(ks->ks_rp->cn_compact_vra, PAGE_SIZE);
        iter->vra_flags |= VBR_FULLSCAN;
    }

    if (reverse) {
        iter->vra_flags |= VBR_REVERSE;
        iter->reverse = reverse;
    }

    iter->vra_len = min_t(u32, iter->vra_len, 1024 * 1024);
    iter->vra_wq = vra_wq;

    iter->workq = io_workq;
    iter->last = SRC_NONE;
    iter->pc = pc;

    if (mblock_read) {
        iter->asyncio = io_workq ? true : false;

        err = kvset_iter_enable_mblock_read(iter);
        if (ev(err))
            goto err_exit1;

        err = kvset_iter_enable_mblock_read_pt(iter);
        if (ev(err))
            goto err_exit2;

        if (iter->asyncio)
            kvset_iter_mblock_read_start(iter);
    }

    kvset_get_ref(ks);
    *handle = &iter->handle;
    return 0;

err_exit2:
    kvset_iter_free_buffers(iter, &iter->kreader);

err_exit1:
    kmem_cache_free(kvset_iter_cache, iter);
    return err;
}

struct element_source *
kvset_iter_es_get(struct kv_iterator *kvi)
{
    return &kvi->kvi_es;
}

struct kvset *
kvset_iter_kvset_get(struct kv_iterator *handle)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    return iter->ks;
}

void
kvset_iter_set_stats(struct kv_iterator *handle, struct cn_merge_stats *stats)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    iter->stats = stats;
}

merr_t
kvset_iter_set_start(struct kv_iterator *handle, int start)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    if (start < iter->curr_kblk)
        return merr(ev(EINVAL));
    iter->curr_kblk = start;

    iter->wbti_meta.eof = iter->pti_meta.eof = true;

    if (start >= 0)
        iter->wbti_meta.eof = false;

    if (kvset_has_ptree(iter->ks))
        iter->pti_meta.eof = false;

    iter->last = SRC_NONE;

    handle->kvi_es = es_make(kvset_cursor_next, 0, 0);

    return 0;
}

void
kvset_madvise_hblk(struct kvset *ks, const int advice, const bool leaves)
{
    assert(advice == MADV_WILLNEED || advice == MADV_DONTNEED);

    if (leaves)
        hbr_madvise_wbt_leaf_nodes(&ks->ks_hblk.kh_hblk_desc, &ks->ks_hblk.kh_ptree_desc, advice);
    hbr_madvise_wbt_int_nodes(&ks->ks_hblk.kh_hblk_desc, &ks->ks_hblk.kh_ptree_desc,
        advice);
    hbr_madvise_kmd(&ks->ks_hblk.kh_hblk_desc, &ks->ks_hblk.kh_ptree_desc, advice);
}

void
kvset_madvise_kblks(struct kvset *ks, int advice, bool blooms, bool leaves)
{
    assert(advice == MADV_WILLNEED || advice == MADV_DONTNEED);

    for (int i = 0; i < ks->ks_st.kst_kblks; i++) {
        struct kvset_kblk *p = ks->ks_kblks + i;

        if (leaves)
            kbr_madvise_wbt_leaf_nodes(&p->kb_kblk_desc, &p->kb_wbt_desc, advice);
        kbr_madvise_wbt_int_nodes(&p->kb_kblk_desc, &p->kb_wbt_desc, advice);
        kbr_madvise_kmd(&p->kb_kblk_desc, &p->kb_wbt_desc, advice);

        if (blooms)
            kbr_madvise_bloom(&p->kb_kblk_desc, &p->kb_blm_desc, advice);
    }
}

void
kvset_madvise_vblks(struct kvset *ks, int advice)
{
    struct workqueue_struct *wq;
    int                      i;

    assert(advice == MADV_WILLNEED || advice == MADV_DONTNEED);

    wq = cn_get_maint_wq(ks->ks_tree->cn);

    for (i = 0; i < ks->ks_vbsetc; i++) {
        struct mbset *v = ks->ks_vbsetv[i];
        int           j;

        for (j = 0; j < v->mbs_idc; j++) {
            struct vblock_desc *vbd = mbset_get_udata(v, j);

            vbr_madvise_async(vbd, 0, vbd->vbd_len, advice, wq);
        }
    }
}

void
kvset_madvise_capped(struct kvset *ks, int advice)
{
    struct workqueue_struct *wq;
    u32                      vra_len;
    int                      i;

    assert(advice == MADV_WILLNEED || advice == MADV_DONTNEED);

    wq = cn_get_maint_wq(ks->ks_tree->cn);
    vra_len = ks->ks_vra_len;

    for (i = 0; i < ks->ks_vbsetc; i++) {
        struct mbset *v = ks->ks_vbsetv[i];
        int           j;

        for (j = 0; j < v->mbs_idc; j++) {
            struct vblock_desc *vbd = mbset_get_udata(v, j);

            vbr_madvise_async(vbd, 0, vra_len, advice, wq);
        }
    }
}

void
kvset_madvise_vmaps(struct kvset *ks, int advice)
{
    uint i;

    assert(advice == MADV_DONTNEED || advice == MADV_RANDOM);

    for (i = 0; i < ks->ks_vbsetc; ++i)
        mbset_madvise(ks->ks_vbsetv[i], advice);
}

void
kvset_iter_mark_eof(struct kv_iterator *handle)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    handle->kvi_eof = iter->wbti_meta.eof = iter->pti_meta.eof = true;
}

/*
 * kvset_iter_seek efficiently moves the iterator to key (or eof)
 *
 * NB: if len < 0, key is a prefix key
 */
merr_t
kvset_iter_seek(struct kv_iterator *handle, const void *key, s32 len, bool *eof)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);
    struct kvset *         ks = iter->ks;
    struct kvset_kblk *    kblk;
    struct kvs_ktuple      kt;
    merr_t                 err;
    int                    start;
    struct wbti *          wbti, *pti;

    kvs_ktuple_init_nohash(&kt, key, len);

    /* If key lies beyond the kvset range in the direction of the cursor,
     * mark iterator as eof. Do this only for cursor seeks, not cursor
     * create.
     */
    if (len > 0) {
        int cmp;

        if (iter->reverse) {
            cmp = keycmp(key, len, ks->ks_minkey, ks->ks_minklen);
            cmp = -cmp;
        } else {
            cmp = keycmp(key, len, ks->ks_maxkey, ks->ks_maxklen);
        }

        if (cmp > 0) {
            kvset_iter_mark_eof(handle);
            *eof = true;
            return 0;
        }
    }

    /* Do not tear down iterators immediately if they can be re-used by
     * this call. If they are not re-used, destroy them at the end.
     * Use the wbt and/or pt to efficiently find the first page where
     * this key may reside, and build or re-use iterators from there.
     */
    wbti = iter->wbti;
    pti = iter->pti;
    iter->wbti = iter->pti = NULL;
    err = 0;

    iter->pti_meta.eof = true;
    if (kvset_has_ptree(ks)) {
        struct kvs_ktuple kt_pfx;

        kvs_ktuple_init_nohash(&kt_pfx, key, ks->ks_pfx_len);

        if (kt_pfx.kt_len > abs(kt.kt_len))
            kt_pfx.kt_len = abs(kt.kt_len);

        if (!pti)
            err = wbti_alloc(&pti);
        if (ev(err)) {
            wbti_destroy(wbti);
            return err;
        }
        wbti_reset(pti, ks->ks_hblk.kh_hblk_desc.map_base, &ks->ks_hblk.kh_ptree_desc, &kt_pfx,
            iter->reverse, 0);
        iter->pti = pti;
        pti = NULL;

        iter->pti_meta.eof = false;
    }

    iter->wbti_meta.eof = true;
    start = kvset_kblk_start(ks, key, len, iter->reverse);
    if (start < 0) {
        /* key is either too large, or too small */
        if ((start == KVSET_MISS_KEY_TOO_LARGE && !iter->reverse) ||
            (start == KVSET_MISS_KEY_TOO_SMALL && iter->reverse)) {
            if (iter->pti_meta.eof) {
                handle->kvi_eof = true;
                wbti_destroy(wbti);
                if (pti) {
                    assert(iter->pti == NULL);
                    wbti_destroy(pti);
                } else {
                    wbti_destroy(iter->pti);
                    iter->pti = NULL;
                }
                *eof = handle->kvi_eof;
                return 0;
            }
            /* No-op. We started out assuming eof. We were right */
        } else {
            start = iter->reverse ? ks->ks_st.kst_kblks - 1 : 0;
            iter->wbti_meta.eof = false;
        }
    } else {
        iter->wbti_meta.eof = false;
    }

    iter->curr_kblk = start;
    kblk = &ks->ks_kblks[iter->curr_kblk];

    if (!iter->wbti_meta.eof) {
        if (!wbti)
            err = wbti_alloc(&wbti);
        if (ev(err)) {
            if (pti) {
                assert(iter->pti == NULL);
                wbti_destroy(pti);
            } else {
                wbti_destroy(iter->pti);
                iter->pti = NULL;
            }
            return err;
        }
        wbti_reset(wbti, kblk->kb_kblk_desc.map_base, &kblk->kb_wbt_desc, &kt, iter->reverse, 0);
        iter->wbti = wbti;
        wbti = NULL;
    }

    iter->last = SRC_NONE;

    *eof = handle->kvi_eof = iter->pti_meta.eof && iter->wbti_meta.eof;

    wbti_destroy(wbti);
    wbti_destroy(pti);

    return 0;
}

static void
wbti_kobj_get(struct kvset_iterator *iter, struct key_obj *kobj)
{
    if (iter->wbti)
        wbti_prefix(iter->wbti, &kobj->ko_pfx, &kobj->ko_pfx_len);
    else {
        kobj->ko_pfx_len = iter->wbt_reader.wb_pfx_len;
        kobj->ko_pfx = iter->wbt_reader.wb_pfx;
    }

    kobj->ko_sfx = iter->wbti_meta.last_key;
    kobj->ko_sfx_len = iter->wbti_meta.last_klen;
}

static void
fetch_wbti(struct kvset_iterator *iter, struct key_obj *kobj, struct kvset_iter_vctx *vc)
{
    wbti_kobj_get(iter, kobj);

    vc->kmd = iter->wbti_meta.kmd;
    vc->is_ptomb = false;
    iter->last = SRC_WBT;
}

static void
pti_kobj_get(struct kvset_iterator *iter, struct key_obj *kobj)
{
    if (iter->pti) {
        wbti_prefix(iter->pti, &kobj->ko_pfx, &kobj->ko_pfx_len);
    } else {
        kobj->ko_pfx_len = iter->pt_reader.wb_pfx_len;
        kobj->ko_pfx = iter->pt_reader.wb_pfx;
    }

    kobj->ko_sfx = iter->pti_meta.last_key;
    kobj->ko_sfx_len = iter->pti_meta.last_klen;
}

static void
fetch_pti(struct kvset_iterator *iter, struct key_obj *kobj, struct kvset_iter_vctx *vc)
{
    pti_kobj_get(iter, kobj);

    vc->kmd = iter->pti_meta.kmd;
    vc->is_ptomb = true;
    iter->last = SRC_PT;
}

static merr_t
kvset_iter_next_wbt_key_mcache(struct kvset_iterator *iter, const void **kdata, uint *klen)
{
    struct kvset *ks = iter->ks;
    merr_t        err;
    bool          preload_wbt_nodes;
    int           inc = iter->reverse ? -1 : 1;

    if (iter->wbti_meta.eof)
        return 0;

next_kblock:
    if (!iter->wbti) {
        struct kvset_kblk *kb;
        bool               eof;

        eof = (iter->reverse && iter->curr_kblk == (uint)-1) ||
              (!iter->reverse && iter->curr_kblk >= ks->ks_st.kst_kblks);

        if (eof) {
            iter->wbti_meta.eof = true;
            return 0;
        }

        assert(iter->curr_kblk < ks->ks_st.kst_kblks);
        kb = ks->ks_kblks + iter->curr_kblk;

        /* Can use 'cn_cursor_kblk_madv' to control use of madvise
         * with mcache map since this code is only used with cursors.
         */
        preload_wbt_nodes = ks->ks_rp->cn_cursor_kra;
        err = wbti_create(
            &iter->wbti, kb->kb_kblk_desc.map_base, &kb->kb_wbt_desc, 0, iter->reverse, preload_wbt_nodes);
        if (ev(err))
            return err;
        assert(iter->wbti);
    }

    if (!wbti_next(iter->wbti, kdata, klen, &iter->wbti_meta.kmd)) {
        wbti_destroy(iter->wbti);
        iter->wbti = 0;
        iter->curr_kblk += inc;

        goto next_kblock;
    }

    return 0;
}

static merr_t
kvset_iter_next_key_read(
    struct kvset_iterator *iter,
    const void **          kdata,
    uint *                 klen,
    enum read_type         read_type)
{
    merr_t                 err;
    struct wb_pos *        wbt_reader;
    struct iter_meta *     meta;
    struct kblk_reader *   kr;
    struct cn_merge_stats *ms = iter->stats;

    if (read_type == READ_WBT) {
        kr = &iter->kreader;
        wbt_reader = &iter->wbt_reader;
        meta = &iter->wbti_meta;
    } else {
        kr = &iter->ptreader;
        wbt_reader = &iter->pt_reader;
        meta = &iter->pti_meta;
    }

    if (wbt_reader->wb_keyc > 0)
        goto next_key;

    /* no more keys in current wbt node */
    if (wbt_reader->wb_nodec > 0) {
        /* new node in current work buffer */
        wbt_reader->wb_node += PAGE_SIZE;
        /* start read for next chunk of kblock *after* first
         * node of current kblock has been processed. */
        if (iter->asyncio && !kr->kr_requested) {
            kr->kr_requested = true;
            kblk_start_read(iter, kr, read_type);
        }
    } else {
        /* We are out of data.  If asyncio: start read (if not
         * already started) and wait. If syncio: start read and wait.
         */
        if (!kr->kr_requested)
            kblk_start_read(iter, kr, read_type);
        else {
            assert(iter->asyncio);
            kr->kr_requested = false;
        }
        err = mbio_wait(&kr->mbio, ms ? &ms->ms_kblk_read_wait : 0);
        if (ev(err))
            return err;
        if (kr->kr_eof) {
            meta->eof = true;
            return 0;
        }
        if (ms)
            count_ops(&ms->ms_kblk_read, kr->iores.kr_ops, kr->iores.kr_bytes, 0);

        /* new work buffer */
        wbt_reader->wb_node = kr->iores.kr_nodev;
        wbt_reader->wb_nodec = kr->iores.kr_nodec;
        wbt_reader->wb_kmd_base = kr->iores.kr_kmd_base;
        wbt_reader->wb_node_kmd_off_adj = kr->iores.kr_node_kmd_off_adj;
    }

    /* just landed on a new node */
    wbt_reader->wb_keyc = omf_wbn_num_keys(wbt_reader->wb_node);
    wbt_reader->wb_pfx_len = omf_wbn_pfx_len(wbt_reader->wb_node);
    wbt_reader->wb_pfx = wbt_reader->wb_node + sizeof(struct wbt_node_hdr_omf);
    wbt_reader->wb_lfe = wbt_reader->wb_pfx + wbt_reader->wb_pfx_len;

    /* prepare for next node (after each key in node is processed) */
    wbt_reader->wb_nodec--;

next_key:
    /* set kdata and klen outputs */
    wbt_lfe_key(wbt_reader->wb_node, wbt_reader->wb_lfe, kdata, klen);

    /* set kmd output, which is used by caller to iterate through values */
    meta->kmd =
        (wbt_reader->wb_kmd_base + wbt_lfe_kmd(wbt_reader->wb_node, wbt_reader->wb_lfe) -
         wbt_reader->wb_node_kmd_off_adj);
    /* prepare for next key */
    wbt_reader->wb_lfe++;
    wbt_reader->wb_keyc--;
    return 0;
}

static
merr_t
kvset_iter_next_wbt_key(struct kv_iterator *handle, const void **kdata, uint *klen)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    if (handle->kvi_eof)
        return 0;

    if (iter->workq)
        return kvset_iter_next_key_read(iter, kdata, klen, READ_WBT);

    return kvset_iter_next_wbt_key_mcache(iter, kdata, klen);
}

static merr_t
kvset_iter_next_pt_key_mcache(struct kvset_iterator *iter, const void **kdata, uint *klen)
{
    struct kvset *ks = iter->ks;
    merr_t        err;
    bool          preload_wbt_nodes, more;

    if (!iter->pti_meta.eof && !iter->pti) {
        if (!kvset_has_ptree(ks)) {
            iter->pti_meta.eof = true;
            return 0;
        }

        preload_wbt_nodes = ks->ks_rp->cn_cursor_kra;
        err = wbti_create(
            &iter->pti,
            ks->ks_hblk.kh_hblk_desc.map_base,
            &ks->ks_hblk.kh_ptree_desc,
            0,
            iter->reverse,
            preload_wbt_nodes);
        if (ev(err))
            return err;
        assert(iter->pti);
    }

    more = wbti_next(
        iter->pti, &iter->pti_meta.last_key, &iter->pti_meta.last_klen, &iter->pti_meta.kmd);

    iter->pti_meta.eof = !more;

    return 0;
}

static merr_t
kvset_iter_next_pt_key(struct kv_iterator *handle, const void **kdata, uint *klen)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    if (handle->kvi_eof || iter->pti_meta.eof)
        return 0;

    if (iter->workq)
        return kvset_iter_next_key_read(iter, kdata, klen, READ_PT);

    return kvset_iter_next_pt_key_mcache(iter, kdata, klen);
}

merr_t
kvset_iter_next_key(struct kv_iterator *handle, struct key_obj *kobj, struct kvset_iter_vctx *vc)
{
    merr_t                 err;
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    if (handle->kvi_eof || (iter->pti_meta.eof && iter->wbti_meta.eof)) {
        handle->kvi_eof = true;
        return 0;
    }

    /* Move the appropriate iterators */
    if (!iter->wbti_meta.eof && (iter->last == SRC_NONE || iter->last == SRC_WBT)) {
        err =
            kvset_iter_next_wbt_key(handle, &iter->wbti_meta.last_key, &iter->wbti_meta.last_klen);
        if (ev(err))
            return err;
    }

    if (!iter->pti_meta.eof && (iter->last == SRC_NONE || iter->last == SRC_PT)) {
        err = kvset_iter_next_pt_key(handle, &iter->pti_meta.last_key, &iter->pti_meta.last_klen);
        if (ev(err))
            return err;
    }

    /* Now compare the two sources and output the right one */
    if (iter->pti_meta.eof && iter->wbti_meta.eof) {
        handle->kvi_eof = true;
        return 0;
    } else if (!iter->pti_meta.eof && !iter->wbti_meta.eof) {
        int            rc;
        struct key_obj pt_kobj, wbt_kobj;

        pti_kobj_get(iter, &pt_kobj);
        wbti_kobj_get(iter, &wbt_kobj);

        /* When key and ptomb match, output the ptomb, so the layer
         * above can cache it with its seqno and then make the right
         * decisions in case of duplicates.
         */
        rc = key_obj_cmp_prefix(&pt_kobj, &wbt_kobj);
        if (iter->reverse)
            rc = -rc;

        if (rc <= 0)
            fetch_pti(iter, kobj, vc);
        else
            fetch_wbti(iter, kobj, vc);
    } else if (!iter->pti_meta.eof) {
        fetch_pti(iter, kobj, vc);
    } else if (!iter->wbti_meta.eof) {
        fetch_wbti(iter, kobj, vc);
    }

    vc->off = 0;
    vc->nvals = 0;
    vc->next = 0;

    return 0;
}

bool
kvset_iter_next_vref(
    struct kv_iterator *    handle,
    struct kvset_iter_vctx *vc,
    u64 *                   seq,
    enum kmd_vtype *        vtype,
    uint *                  vbidx,
    uint *                  vboff,
    const void **           vdata,
    uint *                  vlen,
    uint *                  complen)
{
    assert(vc);
    assert(vc->kmd);

    *vlen = 0;
    *complen = 0;

    if (!vc->off) {
        assert(vc->nvals == 0);
        assert(vc->next == 0);
        vc->nvals = kmd_count(vc->kmd, &vc->off);
    }

    assert(vc->off > 0);
    assert(vc->nvals > 0);
    assert(vc->next <= vc->nvals);
    if (vc->next >= vc->nvals)
        return false;

    kmd_type_seq(vc->kmd, &vc->off, vtype, seq);
    switch (*vtype) {
        case vtype_val:
            kmd_val(vc->kmd, &vc->off, vbidx, vboff, vlen);
            break;
        case vtype_cval:
            kmd_cval(vc->kmd, &vc->off, vbidx, vboff, vlen, complen);
            break;
        case vtype_ival:
            kmd_ival(vc->kmd, &vc->off, vdata, vlen);
            break;
        case vtype_zval:
        case vtype_tomb:
        case vtype_ptomb:
            break;
        default:
            assert(0);
            break;
    }

    vc->next++;
    return true;
}

static merr_t
kvset_iter_get_valptr_read(
    struct kvset_iterator *iter,
    uint                   vbidx,
    uint                   vboff,
    uint                   vlen,
    const void **          vdata)
{
    merr_t                 err;
    struct vblock_desc *   vbd;
    struct vblk_reader *   vr;
    struct vr_buf *        active;
    struct cn_merge_stats *ms = iter->stats;

    assert(vbidx < iter->ks->ks_st.kst_vblks);

    vbd = lvx2vbd(iter->ks, vbidx);
    assert(vbd);

    vr = iter->vreaders + (atomic_read(&vbd->vbd_vgidx) - 1);

    if (ev(vlen > vr->vr_buf_sz)) {
        assert(0);
        return merr(EBUG);
    }

    active = &vr->vr_buf[vr->vr_active];

    if (vr_have_data(active, vbidx, vboff, vlen))
        goto have_data;

    if (vr->vr_requested) {
        assert(vr->asyncio);
        /* wait for previous read to finish */
        err = mbio_wait(&vr->mbio, ms ? &ms->ms_vblk_read1_wait : 0);
        vr->vr_requested = false;
        if (ev(err))
            return err;

        vr->vr_active = !vr->vr_active;
        active = &vr->vr_buf[vr->vr_active];

        if (ms)
            count_ops(&ms->ms_vblk_read1, 1, active->len, 0);

        /* Check if previous read satisfied our need. If not, then
         * read ahead guessed wrong and we need to start a new one
         * with the correct parameters.  This also happens when a
         * value spans two read buffers.
         */
        if (vr_have_data(active, vbidx, vboff, vlen))
            goto have_data;

        /* [HSE_REVISIT] SBUSWNF-3614 */
        ev(1);
    }

    vr->vr_requested = vr_start_read(vr, vbidx, vboff, iter->workq, iter->ks);
    assert(vr->vr_requested);
    vr->vr_read_ahead = true;
    err = mbio_wait(&vr->mbio, ms ? &ms->ms_vblk_read2_wait : 0);
    vr->vr_requested = false;
    if (ev(err))
        return err;
    if (vr->asyncio)
        vr->vr_active = !vr->vr_active;
    active = &vr->vr_buf[vr->vr_active];
    assert(vr_have_data(active, vbidx, vboff, vlen));

    if (ms)
        count_ops(&ms->ms_vblk_read2, 1, active->len, 0);

have_data:

    if (!vr->asyncio)
        goto skip_read_ahead;

    /* Vblock read ahead logic:
     * If 1) read ahead is enabled, and 2) a read has not been requested,
     * and 3) we're part way (1/16-th) through the current buffer, then
     * start the next read. If the request is beyond the vblock, increment
     * the vblock index and reset the offset. If the updated index is
     * greater than the number of vblocks or the target vblock has a
     * different vgroup index, we disable read ahead. If for some reason
     * we have to issue another read to satisfy a future "get value"
     * request, then we re-enable read ahead (see above where vr_read_ahead
     * is set to true).
     */
    if (vr->vr_read_ahead && !vr->vr_requested && vboff - active->off > active->len / 64) {

        uint off;

        off = active->off + active->len;

        if (off >= vr->vr_mblk_dlen) {
            struct vblock_desc *ra_vbd;

            off = 0;
            vbidx++;

            if (vbidx >= iter->ks->ks_st.kst_vblks) {
                vr->vr_read_ahead = false;
                goto skip_read_ahead;
            }

            ra_vbd = lvx2vbd(iter->ks, vbidx);
            if (atomic_read(&ra_vbd->vbd_vgidx) != atomic_read(&vbd->vbd_vgidx)) {
                vr->vr_read_ahead = false;
                goto skip_read_ahead;
            }
        }

        if (off > PAGE_SIZE) {
            /* [HSE_REVISIT] SBUSWNF-3614: adjust this
             * backoff based on max (average?) value size
             * that will be read on this code path from
             * this vblock.
             */
            off -= PAGE_SIZE;
        }

        vr->vr_requested = vr_start_read(vr, vbidx, off, iter->workq, iter->ks);
        if (!vr->vr_requested)
            vr->vr_read_ahead = false;
    }

skip_read_ahead:
    /* Set ptr to value requested by caller  */
    *vdata = active->data + vboff - active->off;

    return 0;
}

static void *
kvset_iter_get_valptr_mcache(struct kvset_iterator *iter, uint vbidx, uint vboff, uint vlen)
{
    struct kvset *      ks = iter->ks;
    struct vblock_desc *vbd;

    vbd = lvx2vbd(ks, vbidx);
    assert(vbd);

    if (iter->vra_len > 0) {
        vbr_readahead(
            vbd,
            vboff,
            vlen,
            iter->vra_flags,
            iter->vra_len,
            NELEM(iter->ra_histv),
            iter->ra_histv,
            iter->vra_wq);
    }

    return vbr_value(vbd, vboff, vlen);
}

static merr_t
kvset_iter_get_valptr(
    struct kv_iterator *handle,
    uint                vbidx,
    uint                vboff,
    uint                vlen,
    const void **       vdata)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);

    if (iter->workq)
        return kvset_iter_get_valptr_read(iter, vbidx, vboff, vlen, vdata);

    *vdata = kvset_iter_get_valptr_mcache(iter, vbidx, vboff, vlen);

    return 0;
}

merr_t
kvset_iter_val_get(
    struct kv_iterator *    handle,
    struct kvset_iter_vctx *vc,
    enum kmd_vtype          vtype,
    uint                    vbidx,
    uint                    vboff,
    const void **           vdata,
    uint *                  vlen,
    uint *                  complen)
{
    switch (vtype) {
        case vtype_val:
            return kvset_iter_get_valptr(handle, vbidx, vboff, *vlen, vdata);
        case vtype_cval:
            return kvset_iter_get_valptr(handle, vbidx, vboff, *complen, vdata);
        case vtype_zval:
            *vdata = 0;
            *vlen = 0;
            *complen = 0;
            return 0;
        case vtype_tomb:
            *vdata = HSE_CORE_TOMB_REG;
            *vlen = 0;
            *complen = 0;
            return 0;
        case vtype_ptomb:
            *vdata = HSE_CORE_TOMB_PFX;
            *vlen = 0;
            *complen = 0;
            return 0;
        case vtype_ival:
            assert(*vdata);
            assert(*vlen);
            *complen = 0;
            return 0;
    }

    /* BUG! */
    assert(false);
    return merr(ev(EBUG));
}

merr_t
kvset_iter_next_val_direct(
    struct kv_iterator *handle,
    enum kmd_vtype      vtype,
    uint                vbidx,
    uint                vboff,
    void *              vdata,
    uint                vlen,
    uint                bufsz)
{
    struct kvset_iterator *iter = handle_to_kvset_iter(handle);
    struct vblock_desc *   vbd;

    vbd = lvx2vbd(iter->ks, vbidx);
    assert(vbd);

    return kvset_lookup_val_direct(iter->ks, vbd, vbidx, vboff, vdata, bufsz, vlen);
}

void
kvset_iter_release(struct kv_iterator *handle)
{
    merr_t                 err;
    struct kvset_iterator *iter;
    struct vblk_reader *   vr;
    uint                   i;

    if (ev(!handle))
        return;

    iter = handle_to_kvset_iter(handle);

    if (iter->workq) {
        /* Due to read-ahead, it is normal for iterators to be released
         * while a read is pending.  We must detect that and wait for
         * pending I/O to complete.
         */
        if (iter->kreader.kr_requested) {
            err = mbio_wait(&iter->kreader.mbio, 0);
            ev(err);
        }
        if (iter->ptreader.kr_requested) {
            err = mbio_wait(&iter->ptreader.mbio, 0);
            ev(err);
        }
        if (iter->vreaders) {
            for (i = 0; i < iter->ks->ks_vgroups; i++) {
                vr = iter->vreaders + i;
                if (vr->vr_requested) {
                    err = mbio_wait(&vr->mbio, 0);
                    ev(err);
                }
            }
        }
    }

    wbti_destroy(iter->wbti);
    wbti_destroy(iter->pti);
    kvset_put_ref(iter->ks);

    kvset_iter_free_buffers(iter, &iter->kreader);
    kvset_iter_free_buffers(iter, &iter->ptreader);

    kmem_cache_free(kvset_iter_cache, iter);
}

struct kv_iterator_ops kvset_iter_ops = {
    .kvi_release = kvset_iter_release,
};

/*
 * This function is needed for kvset_keep_vblocks, in keep.c;
 * kvset_keep_vblocks was moved to keep.c so it could be tested:
 * the short, inlinable functions like kvset_get_num_vblocks()
 * were not replaced by the mocked versions when this function
 * lived here, causing the test to fail.
 */
void *
kvset_from_iter(struct kv_iterator *iv)
{
    return ((struct kvset_iterator *)iv)->ks;
}

void
kvset_maxkey(struct kvset *ks, const void **maxkey, u16 *maxklen)
{
    *maxkey = ks->ks_minkey;
    *maxklen = ks->ks_minklen;
}

void
kvset_minkey(struct kvset *ks, const void **minkey, u16 *minklen)
{
    *minkey = ks->ks_minkey;
    *minklen = ks->ks_minklen;
}

merr_t
kvset_init(void)
{
    struct kmem_cache *cache;
    size_t             sz;
    int                i;

    sz = sizeof(struct kvset_iterator);
    assert(HSE_ACP_LINESIZE >= alignof(struct kvset_iterator));

    cache = kmem_cache_create("kvsiter", sz, HSE_ACP_LINESIZE, 0, NULL);
    if (ev(!cache)) {
        return merr(ENOMEM);
    }

    kvset_iter_cache = cache;

    for (i = 0; i < NELEM(kvset_cache); ++i) {
        size_t align = alignof(struct kvset);
        char   name[32];

        sz = (4096 << (NELEM(kvset_cache) - (i + 1))) - align;

        snprintf(name, sizeof(name), "kvset%zuk", (sz + 1023) / 1024);

        cache = kmem_cache_create(name, sz, align, SLAB_PACKED, NULL);
        if (ev(!cache))
            break;

        kvset_cache[i].cache = cache;
        kvset_cache[i].sz = sz;
    }

    return 0;
}

void
kvset_fini(void)
{
    int i;

    for (i = 0; i < NELEM(kvset_cache); ++i) {
        kmem_cache_destroy(kvset_cache[i].cache);
        kvset_cache[i].cache = NULL;
        kvset_cache[i].sz = 0;
    }

    kmem_cache_destroy(kvset_iter_cache);
}

#if HSE_MOCKING
#include "kvset_ut_impl.i"
#include "kvset_view_ut_impl.i"
#endif /* HSE_MOCKING */
