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
#include <hse_util/hse_err.h>
#include <mpool/mpool_structs.h>
#include <mpool/mpool.h>

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
    const uint32_t pg_cnt = (wbt_desc->wbd_n_pages - wbt_desc->wbd_leaf_cnt - wbt_desc->wbd_kmd_pgc);

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
    void *base;

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

#if HSE_MOCKING
#include "hblock_reader_ut_impl.i"
#endif /* HSE_MOCKING */
