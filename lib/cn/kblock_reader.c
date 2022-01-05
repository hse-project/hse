/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>
#include <hse_util/arch.h>
#include <hse_util/bloom_filter.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/tuple.h>

#include <mpool/mpool.h>

#include "omf.h"
#include "bloom_reader.h"
#include "wbt_reader.h"
#include "kvs_mblk_desc.h"
#include "cn_metrics.h"
#include "kblock_reader.h"

static HSE_ALWAYS_INLINE bool
kblock_hdr_valid(const struct kblock_hdr_omf *omf)
{
    uint32_t vers = omf_kbh_version(omf);

    return (HSE_LIKELY(omf_kbh_magic(omf) == KBLOCK_HDR_MAGIC &&
                       vers >= KBLOCK_HDR_VERSION5 && vers <= KBLOCK_HDR_VERSION));
}

merr_t
kbr_get_kblock_desc(
    struct mpool *           ds,
    struct mpool_mcache_map *map,
    struct mblock_props     *props,
    u32                      map_idx,
    u64                      kblkid,
    struct kvs_mblk_desc *   kblkdesc)
{
    void *base;

    base = mpool_mcache_getbase(map, map_idx);
    if (!base)
        return merr(ev(EINVAL));

    kblkdesc->ds = ds;
    kblkdesc->mb_id = kblkid;
    kblkdesc->map = map;
    kblkdesc->map_idx = map_idx;
    kblkdesc->map_base = base;
    kblkdesc->mclass = props->mpr_mclass;

    return 0;
}

merr_t
kbr_read_wbt_region_desc_mem(void *wbt_hdr, struct wbt_desc *desc)
{
    desc->wbd_version = wbt_hdr_version(wbt_hdr);

    switch (desc->wbd_version) {
        case WBT_TREE_VERSION:
            desc->wbd_root = omf_wbt_root(wbt_hdr);
            desc->wbd_leaf = omf_wbt_leaf(wbt_hdr);
            desc->wbd_leaf_cnt = omf_wbt_leaf_cnt(wbt_hdr);
            desc->wbd_kmd_pgc = omf_wbt_kmd_pgc(wbt_hdr);
            break;

        default:
            return merr(ev(EINVAL));
    }

    return 0;
}

merr_t
kbr_read_wbt_region_desc(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc)
{
    merr_t err;
    void * pg, *wbt_hdr;
    off_t  pg_idxs[1];

    struct kblock_hdr_omf *kb_hdr;

    pg_idxs[0] = 0;
    err = mpool_mcache_getpages(kblkdesc->map, 1, kblkdesc->map_idx, pg_idxs, &pg);
    if (ev(err))
        return err;

    kb_hdr = pg;
    if (!kblock_hdr_valid(kb_hdr))
        return merr(EINVAL);

    wbt_hdr = (void *)kb_hdr + omf_kbh_wbt_hoff(kb_hdr);

    desc->wbd_first_page = omf_kbh_wbt_doff_pg(kb_hdr);
    desc->wbd_n_pages = omf_kbh_wbt_dlen_pg(kb_hdr);

    err = kbr_read_wbt_region_desc_mem(wbt_hdr, desc);
    ev(err);

    return err;
}

merr_t
kbr_read_seqno_range(struct kvs_mblk_desc *kblkdesc, u64 *seqno_min, u64 *seqno_max)
{
    merr_t                 err;
    off_t                  pg_idxs[1];
    struct kblock_hdr_omf *kb_hdr;
    void *                 pg;

    pg_idxs[0] = 0;
    err = mpool_mcache_getpages(kblkdesc->map, 1, kblkdesc->map_idx, pg_idxs, &pg);
    if (ev(err))
        return err;

    kb_hdr = pg;
    if (!kblock_hdr_valid(kb_hdr))
        return merr(EINVAL);

    *seqno_min = omf_kbh_min_seqno(kb_hdr);
    *seqno_max = omf_kbh_max_seqno(kb_hdr);

    return 0;
}

merr_t
kbr_read_pt_region_desc(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc)
{
    merr_t err;
    void * pg, *pt_hdr;
    off_t  pg_idxs[1];

    struct kblock_hdr_omf *kb_hdr;

    memset(desc, 0, sizeof(*desc));

    pg_idxs[0] = 0;
    err = mpool_mcache_getpages(kblkdesc->map, 1, kblkdesc->map_idx, pg_idxs, &pg);
    if (ev(err))
        return err;

    kb_hdr = pg;
    if (!kblock_hdr_valid(kb_hdr))
        return merr(EINVAL);

    pt_hdr = (void *)kb_hdr + omf_kbh_pt_hoff(kb_hdr);

    desc->wbd_first_page = omf_kbh_pt_doff_pg(kb_hdr);
    desc->wbd_n_pages = omf_kbh_pt_dlen_pg(kb_hdr);

    err = kbr_read_wbt_region_desc_mem(pt_hdr, desc);
    ev(err);

    return err;
}

merr_t
kbr_read_blm_region_desc(struct kvs_mblk_desc *kbd, struct bloom_desc *desc)
{
    merr_t                 err;
    struct kblock_hdr_omf *hdr;
    struct bloom_hdr_omf * blm_omf = NULL;
    void *                 pg = NULL;
    off_t                  pg_idxs[1];
    ulong                  mbid;
    u32                    magic;
    u32                    version;

    memset(desc, 0, sizeof(*desc));
    mbid = kbd->mb_id;

    pg_idxs[0] = 0;
    err = mpool_mcache_getpages(kbd->map, 1, kbd->map_idx, pg_idxs, &pg);
    if (ev(err))
        return err;

    hdr = pg;
    if (!kblock_hdr_valid(hdr))
        return merr(EINVAL);

    blm_omf = (struct bloom_hdr_omf *)(pg + omf_kbh_blm_hoff(hdr));

    magic = omf_bh_magic(blm_omf);
    if (ev(magic != BLOOM_OMF_MAGIC)) {
        log_err("bloom %lx invalid magic %x (expected %x)",
                mbid, magic, BLOOM_OMF_MAGIC);
        return merr(EINVAL);
    }

    /* [HSE_REVISIT] If the bloom implementation has changed then new code
     * may need be written to support previous incarnations.  Meanwhile,
     * it's safe to run without blooms, albeit at a big hit to read perf.
     */
    version = omf_bh_version(blm_omf);
    if (ev(version != BLOOM_OMF_VERSION)) {
        log_err("bloom %lx invalid version %u (expected %u)",
                mbid, version, BLOOM_OMF_VERSION);
        return 0;
    }

    desc->bd_first_page = omf_kbh_blm_doff_pg(hdr);
    desc->bd_n_pages = omf_kbh_blm_dlen_pg(hdr);

    desc->bd_modulus = omf_bh_modulus(blm_omf);
    desc->bd_bktshift = omf_bh_bktshift(blm_omf);
    desc->bd_n_hashes = omf_bh_n_hashes(blm_omf);
    desc->bd_rotl = omf_bh_rotl(blm_omf);
    desc->bd_bktmask = (1u << desc->bd_bktshift) - 1;

    return 0;
}

merr_t
kbr_read_blm_pages(
    struct kvs_mblk_desc *kbd,
    ulong                 cn_bloom_lookup,
    struct bloom_desc *   desc,
    u8 **                 blm_pages_out)
{
    merr_t err;

    *blm_pages_out = NULL;

    if (!desc->bd_n_pages)
        return 0;

    /*
     * If we're in user space and the bloom is mcache mapped then
     * issue an mpool_mcache_getpages() on just the first page, to get
     * the base address of the bloom filter - which we assume is
     * contiguous in virtual address space.
     *
     * Otherwise we allocate a buffer and read the bloom filter
     * into it (works in both user and kernel space).
     *
     * Note that there is no code for an mcached bloom lookup in
     * kernel space, but it is possible.
     */

    if (cn_bloom_lookup == BLOOM_LOOKUP_MCACHE) {
        off_t pgnumv[] = { desc->bd_first_page };
        void *addrv[] = { NULL };

        err = mpool_mcache_getpages(kbd->map, 1, kbd->map_idx, pgnumv, addrv);
        if (ev(err))
            return err;

        *blm_pages_out = addrv[0];
        return 0;
    }

    if (cn_bloom_lookup == BLOOM_LOOKUP_BUFFER) {
        struct iovec iov;
        size_t       off = desc->bd_first_page * PAGE_SIZE;
        size_t       len = desc->bd_n_pages * PAGE_SIZE;
        u8 *         pages;

        pages = alloc_page_aligned(len);
        if (ev(!pages))
            return merr(ENOMEM);

        iov.iov_base = pages;
        iov.iov_len = len;

        err = mpool_mblock_read(kbd->ds, kbd->mb_id, &iov, 1, off);
        if (ev(err)) {
            free_aligned(pages);
            return err;
        }

        *blm_pages_out = pages;
        return 0;
    }

    return 0;
}

void
kbr_free_blm_pages(struct kvs_mblk_desc *kbd, ulong cn_bloom_lookup, void *blm_pages)
{
    if (!blm_pages)
        return;

    if (cn_bloom_lookup == BLOOM_LOOKUP_BUFFER)
        free_aligned(blm_pages);
}

merr_t
kbr_read_metrics(struct kvs_mblk_desc *kblkdesc, struct kblk_metrics *metrics)
{
    merr_t                 err;
    struct kblock_hdr_omf *hdr = NULL;
    void *                 pg = NULL;
    off_t                  pg_idxs[1];

    pg_idxs[0] = 0;
    err = mpool_mcache_getpages(kblkdesc->map, 1, kblkdesc->map_idx, pg_idxs, &pg);
    if (ev(err))
        return err;

    hdr = pg;
    if (!kblock_hdr_valid(hdr))
        return merr(EINVAL);

    metrics->num_keys = omf_kbh_entries(hdr);
    metrics->num_tombstones = omf_kbh_tombs(hdr);
    metrics->tot_key_bytes = omf_kbh_key_bytes(hdr);
    metrics->tot_val_bytes = omf_kbh_val_bytes(hdr);
    metrics->tot_wbt_pages = omf_kbh_wbt_dlen_pg(hdr);
    metrics->tot_blm_pages = omf_kbh_blm_dlen_pg(hdr);

    return 0;
}

static merr_t
kbr_madvise_region(struct kvs_mblk_desc *kblkdesc, u32 pg, u32 pg_cnt, int advice)
{
    merr_t err;
    u32    pg_max = pg + pg_cnt;

    while (pg < pg_max) {

        u32 chunk = min_t(u32, pg_max - pg, HSE_RA_PAGES_MAX);

        err = mpool_mcache_madvise(
            kblkdesc->map, kblkdesc->map_idx, PAGE_SIZE * pg, PAGE_SIZE * chunk, advice);
        if (ev(err))
            return err;

        pg += chunk;
    }

    return 0;
}

void
kbr_madvise_kmd(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc, int advice)
{
    merr_t err;
    u32    pg = desc->wbd_first_page + desc->wbd_root + 1;
    u32    pg_cnt = desc->wbd_kmd_pgc;

    err = kbr_madvise_region(kblkdesc, pg, pg_cnt, advice);

    ev(err);
}

void
kbr_madvise_wbt_leaf_nodes(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc, int advice)
{
    merr_t err;
    u32    pg = desc->wbd_first_page;
    u32    pg_cnt = desc->wbd_leaf_cnt;

    err = kbr_madvise_region(kblkdesc, pg, pg_cnt, advice);

    ev(err);
}

void
kbr_madvise_wbt_int_nodes(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc, int advice)
{
    merr_t err;
    u32    pg = desc->wbd_first_page + desc->wbd_leaf_cnt;
    u32    pg_cnt = (desc->wbd_n_pages - desc->wbd_leaf_cnt - desc->wbd_kmd_pgc);

    err = kbr_madvise_region(kblkdesc, pg, pg_cnt, advice);

    ev(err);
}

void
kbr_madvise_bloom(struct kvs_mblk_desc *kblkdesc, struct bloom_desc *desc, int advice)
{
    merr_t err;
    u32    pg = desc->bd_first_page;
    u32    pg_cnt = desc->bd_n_pages;

    err = kbr_madvise_region(kblkdesc, pg, pg_cnt, advice);

    ev(err);
}
