/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hblock_reader

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <hse_util/compiler.h>
#include <hse_util/event_counter.h>
#include <hse/error/merr.h>
#include <mpool/mpool_structs.h>
#include <mpool/mpool.h>

#include "kvset.h"
#include "hblock_reader.h"
#include "kvs_mblk_desc.h"
#include "omf.h"
#include "wbt_reader.h"

static bool HSE_NONNULL(1)
hblock_hdr_valid(const struct hblock_hdr_omf *omf)
{
    const uint32_t version = omf_hbh_version(omf);
    const uint32_t magic = omf_hbh_magic(omf);

    return HSE_LIKELY(magic == HBLOCK_HDR_MAGIC && version == HBLOCK_HDR_VERSION);
}

static merr_t
hbr_madvise_region(
    struct kvs_mblk_desc *hblk_desc,
    uint32_t pg,
    const uint32_t pg_cnt,
    const int advice)
{
    merr_t err = 0;
    const uint32_t pg_max = pg + pg_cnt;

    while (pg < pg_max) {
        const uint32_t chunk = min_t(uint32_t, pg_max - pg, HSE_RA_PAGES_MAX);

        err = mpool_mcache_madvise(
            hblk_desc->map, hblk_desc->map_idx, PAGE_SIZE * pg, PAGE_SIZE * chunk, advice);
        if (ev(err))
            return err;

        pg += chunk;
    }

    return err;
}

void
hbr_madvise_kmd(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc, int advice)
{
    merr_t err;
    u32    pg = desc->wbd_first_page + desc->wbd_root + 1;
    u32    pg_cnt = desc->wbd_kmd_pgc;

    err = hbr_madvise_region(kblkdesc, pg, pg_cnt, advice);

    ev(err);
}

void
hbr_madvise_wbt_leaf_nodes(
    struct kvs_mblk_desc *const hblk_desc,
    struct wbt_desc *const wbt_desc,
    const int advice)
{
    merr_t err;
    const uint32_t pg = wbt_desc->wbd_first_page;
    const uint32_t pg_cnt = wbt_desc->wbd_leaf_cnt;

    err = hbr_madvise_region(hblk_desc, pg, pg_cnt, advice);

    ev(err);
}

void
hbr_madvise_wbt_int_nodes(
    struct kvs_mblk_desc *const hblk_desc,
    struct wbt_desc *const wbt_desc,
    const int advice)
{
    merr_t err;
    const uint32_t pg = wbt_desc->wbd_first_page + wbt_desc->wbd_leaf_cnt;
    const uint32_t pg_cnt =
        (wbt_desc->wbd_n_pages - wbt_desc->wbd_leaf_cnt - wbt_desc->wbd_kmd_pgc);

    err = hbr_madvise_region(hblk_desc, pg, pg_cnt, advice);

    ev(err);
}

merr_t
hbr_read_desc(
    struct mpool *mpool,
    struct mpool_mcache_map *map,
    struct mblock_props *props,
    uint64_t blkid,
    struct kvs_mblk_desc *mblk_desc)
{
    const void *base;

    /* There is only one hblock within the mcache map. */
    base = mpool_mcache_getbase(map, 0);
    if (!base)
        return merr(EINVAL);

    mblk_desc->ds = mpool;
    mblk_desc->mbid = blkid;
    mblk_desc->map = map;
    mblk_desc->map_idx = 0;
    mblk_desc->map_base = base;
    mblk_desc->mclass = props->mpr_mclass;

    return 0;
}

merr_t
hbr_read_metrics(struct kvs_mblk_desc *hblk_desc, struct hblk_metrics *metrics)
{
    merr_t err;
    struct mblock_props props;

    err = mpool_mblock_props_get(hblk_desc->ds, hblk_desc->mbid, &props);
    if (err)
        return err;

    metrics->hm_size = props.mpr_write_len;
    metrics->hm_nptombs = omf_hbh_num_ptombs(hblk_desc->map_base);

    return 0;
}

merr_t
hbr_read_ptree_region_desc(struct kvs_mblk_desc *mblk_desc, struct wbt_desc *wbt_desc)
{
    merr_t err;
    void * pg;
    off_t pg_idxs[1];
    struct hblock_hdr_omf *hb_hdr;

    memset(wbt_desc, 0, sizeof(*wbt_desc));

    pg_idxs[0] = 0;
    err = mpool_mcache_getpages(mblk_desc->map, 1, mblk_desc->map_idx, pg_idxs, &pg);
    if (ev(err))
        return err;

    hb_hdr = pg;
    if (!hblock_hdr_valid(hb_hdr))
        return merr(EPROTO);

    wbt_desc->wbd_first_page = omf_hbh_ptree_data_off_pg(hb_hdr);
    wbt_desc->wbd_n_pages = omf_hbh_ptree_data_len_pg(hb_hdr);

    return wbtr_read_desc(&hb_hdr->hbh_ptree_hdr, wbt_desc);
}

merr_t
hbr_read_seqno_range(struct kvs_mblk_desc *mblk_desc, uint64_t *seqno_min, uint64_t *seqno_max)
{
    merr_t err;
    off_t pg_idxs[1];
    struct hblock_hdr_omf *hb_hdr;
    void *pg;

    pg_idxs[0] = 0;
    err = mpool_mcache_getpages(mblk_desc->map, 1, mblk_desc->map_idx, pg_idxs, &pg);
    if (ev(err))
        return err;

    hb_hdr = pg;
    if (!hblock_hdr_valid(hb_hdr))
        return merr(EPROTO);

    *seqno_min = omf_hbh_min_seqno(hb_hdr);
    *seqno_max = omf_hbh_max_seqno(hb_hdr);

    return 0;
}

static HSE_ALWAYS_INLINE bool HSE_NONNULL(1)
hblock_vgroup_map_valid(const struct vgroup_map_omf *omf)
{
    const uint32_t magic = omf_vgm_magic(omf);
    const uint32_t version = omf_vgm_version(omf);

    return HSE_LIKELY(magic == VGROUP_MAP_MAGIC && version == VGROUP_MAP_VERSION);
}

merr_t
hbr_read_vgroup_cnt(const struct kvs_mblk_desc *hbd, uint32_t *nvgroups)
{
    const struct vgroup_map_omf *vgm_omf;

    if (ev(omf_hbh_vgmap_len_pg(hbd->map_base) == 0)) {
        *nvgroups = 0;
        return 0; /* no vgmap present */
    }

    vgm_omf = hbd->map_base + (omf_hbh_vgmap_off_pg(hbd->map_base) * PAGE_SIZE);

    if (!hblock_vgroup_map_valid(vgm_omf))
        return merr(EPROTO);

    *nvgroups = omf_vgm_count(vgm_omf);

    return 0;
}

merr_t
hbr_read_vgroup_map(const struct kvs_mblk_desc *hbd, struct vgmap *vgmap, bool *use_vgmap)
{
    const struct vgroup_map_omf *vgm_omf;
    const struct vgroup_map_entry_omf *vgme_omf;
    int i;

    *use_vgmap = false;

    if (ev(omf_hbh_vgmap_len_pg(hbd->map_base) == 0)) {
        vgmap->nvgroups = 0;
        return 0; /* no vgmap present */
    }

    vgm_omf = hbd->map_base + (omf_hbh_vgmap_off_pg(hbd->map_base) * PAGE_SIZE);

    if (!hblock_vgroup_map_valid(vgm_omf))
        return merr(EPROTO);

    vgmap->nvgroups = omf_vgm_count(vgm_omf);

    vgme_omf = (void *)(vgm_omf + 1);

    for (i = 0; i < vgmap->nvgroups; i++, vgme_omf++) {
        vgmap->vbidx_out[i] = omf_vgme_vbidx(vgme_omf);
        vgmap->vbidx_adj[i] = omf_vgme_vbadj(vgme_omf);
        vgmap->vbidx_src[i] = vgmap->vbidx_out[i] + vgmap->vbidx_adj[i];

        if (!(*use_vgmap) && vgmap->vbidx_adj[i] != 0)
            *use_vgmap = true;
    }

    return 0;
}

void
hbr_read_ptree(
    const struct kvs_mblk_desc *hbd,
    const struct wbt_desc      *ptd,
    const uint8_t             **ptree,
    uint32_t                   *ptree_pgc)
{
    INVARIANT(hbd && ptd && ptree && ptree_pgc);

    *ptree = hbd->map_base + (ptd->wbd_first_page * PAGE_SIZE);
    *ptree_pgc = ptd->wbd_n_pages;
}

#if HSE_MOCKING
#include "hblock_reader_ut_impl.i"
#endif /* HSE_MOCKING */
