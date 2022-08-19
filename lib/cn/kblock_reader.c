/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/error/merr.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>
#include <hse_util/arch.h>
#include <hse_util/bloom_filter.h>
#include <hse/logging/logging.h>

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
                       vers >= KBLOCK_HDR_VERSION6 && vers <= KBLOCK_HDR_VERSION));
}

merr_t
kbr_get_kblock_desc(
    struct mpool            *mp,
    struct mpool_mcache_map *map,
    struct mblock_props     *props,
    u32                      map_idx,
    u64                      kblkid,
    struct kvs_mblk_desc    *kblkdesc)
{
    void *base;

    base = mpool_mcache_getbase(map, map_idx);
    if (!base)
        return merr(ev(EINVAL));

    kblkdesc->ds = mp;
    kblkdesc->mbid = kblkid;
    kblkdesc->map = map;
    kblkdesc->map_idx = map_idx;
    kblkdesc->map_base = base;
    kblkdesc->mclass = props->mpr_mclass;

    return 0;
}

merr_t
kbr_read_wbt_region_desc(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc)
{
    merr_t err;
    void * pg;
    struct wbt_hdr_omf *wbt_hdr;
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

    err = wbtr_read_desc(wbt_hdr, desc);
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
    mbid = kbd->mbid;

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
    struct bloom_desc *   desc)
{
    off_t pgnumv[] = { desc->bd_first_page };

    desc->bd_bitmap = NULL;

    if (!desc->bd_n_pages)
        return 0;

    /* Issue an mpool_mcache_getpages() on just the first page to get
     * the base address of the bloom filter - which we assume is
     * contiguous in virtual address space.
     */
    return mpool_mcache_getpages(kbd->map, 1, kbd->map_idx, pgnumv, (void **)&desc->bd_bitmap);
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
    metrics->tot_vused_bytes = omf_kbh_vused_bytes(hdr);
    metrics->tot_wbt_pages = omf_kbh_wbt_dlen_pg(hdr);
    metrics->tot_blm_pages = omf_kbh_blm_dlen_pg(hdr);

    return 0;
}

merr_t
kbr_read_hlog(struct kvs_mblk_desc *kblk, uint8_t **hlog)
{
    struct kblock_hdr_omf *hdr = NULL;

    hdr = mpool_mcache_getbase(kblk->map, kblk->map_idx);
    if (!hdr)
        return merr(EINVAL);

    if (!kblock_hdr_valid(hdr))
        return merr(EPROTO);

    *hlog = (uint8_t *)hdr + (omf_kbh_hlog_doff_pg(hdr) * PAGE_SIZE);

    return 0;
}

static merr_t
kbr_madvise_region(struct kvs_mblk_desc *kblkdesc, u32 pg, u32 pg_cnt, int advice)
{
    u32 pg_max = pg + pg_cnt;

    while (pg < pg_max) {
        u32 chunk = min_t(u32, pg_max - pg, HSE_RA_PAGES_MAX);
        merr_t err;

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
