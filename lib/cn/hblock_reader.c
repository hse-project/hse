/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hblock_reader

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/util/compiler.h>
#include <hse/util/event_counter.h>

#include "hblock_reader.h"
#include "kvs_mblk_desc.h"
#include "kvset.h"
#include "omf.h"
#include "vgmap.h"
#include "wbt_reader.h"

static bool HSE_NONNULL(1)
hblock_hdr_valid(const struct hblock_hdr_omf *omf)
{
    const uint32_t version = omf_hbh_version(omf);
    const uint32_t magic = omf_hbh_magic(omf);

    return HSE_LIKELY(magic == HBLOCK_HDR_MAGIC && version == HBLOCK_HDR_VERSION);
}

void
hbr_madvise_kmd(struct kvs_mblk_desc *md, struct wbt_desc *wbd, int advice)
{
    merr_t err;
    const uint32_t pg = wbd->wbd_first_page + wbd->wbd_root + 1;
    const uint32_t pgc = wbd->wbd_kmd_pgc;

    if (pgc) {
        err = mblk_madvise_pages(md, pg, pgc, advice);
        ev(err);
    }
}

void
hbr_madvise_wbt_leaf_nodes(struct kvs_mblk_desc *md, struct wbt_desc *wbd, int advice)
{
    merr_t err;
    const uint32_t pg = wbd->wbd_first_page;
    const uint32_t pgc = wbd->wbd_leaf_cnt;

    if (pgc) {
        err = mblk_madvise_pages(md, pg, pgc, advice);
        ev(err);
    }
}

void
hbr_madvise_wbt_int_nodes(struct kvs_mblk_desc *md, struct wbt_desc *wbd, int advice)
{
    merr_t err;
    const uint32_t pg = wbd->wbd_first_page + wbd->wbd_leaf_cnt;
    const uint32_t pgc = wbd->wbd_n_pages - wbd->wbd_leaf_cnt - wbd->wbd_kmd_pgc;

    if (pgc) {
        err = mblk_madvise_pages(md, pg, pgc, advice);
        ev(err);
    }
}

merr_t
hbr_read_metrics(struct kvs_mblk_desc *hblk_desc, struct hblk_metrics *metrics)
{
    metrics->hm_size = hblk_desc->wlen_pages * PAGE_SIZE;
    metrics->hm_nptombs = omf_hbh_num_ptombs(hblk_desc->map_base);

    return 0;
}

merr_t
hbr_read_ptree_region_desc(struct kvs_mblk_desc *mblk_desc, struct wbt_desc *wbt_desc)
{
    struct hblock_hdr_omf *hb_hdr;

    memset(wbt_desc, 0, sizeof(*wbt_desc));

    hb_hdr = mblk_desc->map_base;
    if (!hblock_hdr_valid(hb_hdr))
        return merr(EPROTO);

    wbt_desc->wbd_first_page = omf_hbh_ptree_data_off_pg(hb_hdr);
    wbt_desc->wbd_n_pages = omf_hbh_ptree_data_len_pg(hb_hdr);

    return wbtr_read_desc(&hb_hdr->hbh_ptree_hdr, wbt_desc);
}

merr_t
hbr_read_seqno_range(struct kvs_mblk_desc *mblk_desc, uint64_t *seqno_min, uint64_t *seqno_max)
{
    struct hblock_hdr_omf *hb_hdr;

    hb_hdr = mblk_desc->map_base;
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
    struct vgroup_map_omf *vgm_omf;

    if (omf_hbh_vgmap_len_pg(hbd->map_base) == 0) {
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
    struct vgroup_map_omf *vgm_omf;
    struct vgroup_map_entry_omf *vgme_omf;
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
    const struct wbt_desc *ptd,
    uint8_t **ptree,
    uint32_t *ptree_pgc)
{
    INVARIANT(hbd && ptd && ptree && ptree_pgc);

    *ptree = hbd->map_base + (ptd->wbd_first_page * PAGE_SIZE);
    *ptree_pgc = ptd->wbd_n_pages;
}

#if HSE_MOCKING
#include "hblock_reader_ut_impl.i"
#endif /* HSE_MOCKING */
