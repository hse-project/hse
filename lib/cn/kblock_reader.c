/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <hse/error/merr.h>
#include <hse/ikvdb/kvs_rparams.h>
#include <hse/ikvdb/tuple.h>
#include <hse/logging/logging.h>
#include <hse/mpool/mpool.h>
#include <hse/util/alloc.h>
#include <hse/util/arch.h>
#include <hse/util/assert.h>
#include <hse/util/bloom_filter.h>
#include <hse/util/compiler.h>
#include <hse/util/event_counter.h>
#include <hse/util/page.h>
#include <hse/util/slab.h>

#include "bloom_reader.h"
#include "cn_metrics.h"
#include "kblock_reader.h"
#include "kvs_mblk_desc.h"
#include "omf.h"
#include "wbt_reader.h"

static HSE_ALWAYS_INLINE bool
kblock_hdr_valid(const struct kblock_hdr_omf *omf)
{
    uint32_t vers = omf_kbh_version(omf);

    return (HSE_LIKELY(
        omf_kbh_magic(omf) == KBLOCK_HDR_MAGIC && vers >= KBLOCK_HDR_VERSION6 &&
        vers <= KBLOCK_HDR_VERSION));
}

merr_t
kbr_read_wbt_region_desc(struct kvs_mblk_desc *kblkdesc, struct wbt_desc *desc)
{
    const struct kblock_hdr_omf *kb_hdr = kblkdesc->map_base;
    const struct wbt_hdr_omf *wbt_hdr;
    merr_t err;

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
    const struct kblock_hdr_omf *hdr = kbd->map_base;
    const struct bloom_hdr_omf *blm_omf = NULL;
    ulong mbid;
    uint32_t magic;
    uint32_t version;

    memset(desc, 0, sizeof(*desc));
    mbid = kbd->mbid;

    if (!kblock_hdr_valid(hdr))
        return merr(EINVAL);

    blm_omf = (void *)hdr + omf_kbh_blm_hoff(hdr);

    magic = omf_bh_magic(blm_omf);
    if (ev(magic != BLOOM_OMF_MAGIC)) {
        log_err("bloom %lx invalid magic %x (expected %x)", mbid, magic, BLOOM_OMF_MAGIC);
        return merr(EINVAL);
    }

    /* [HSE_REVISIT] If the bloom implementation has changed then new code
     * may need be written to support previous incarnations.  Meanwhile,
     * it's safe to run without blooms, albeit at a big hit to read perf.
     */
    version = omf_bh_version(blm_omf);
    if (ev(version != BLOOM_OMF_VERSION)) {
        log_err("bloom %lx invalid version %u (expected %u)", mbid, version, BLOOM_OMF_VERSION);
        return 0;
    }

    desc->bd_first_page = omf_kbh_blm_doff_pg(hdr);
    desc->bd_n_pages = omf_kbh_blm_dlen_pg(hdr);

    desc->bd_modulus = omf_bh_modulus(blm_omf);
    desc->bd_bktshift = omf_bh_bktshift(blm_omf);
    desc->bd_n_hashes = omf_bh_n_hashes(blm_omf);
    desc->bd_rotl = omf_bh_rotl(blm_omf);
    desc->bd_bktmask = (1u << desc->bd_bktshift) - 1;

    if (desc->bd_n_pages)
        desc->bd_bitmap = (void *)kbd->map_base + desc->bd_first_page * PAGE_SIZE;
    else
        desc->bd_bitmap = NULL;

    return 0;
}

merr_t
kbr_read_metrics(struct kvs_mblk_desc *kblkdesc, struct kblk_metrics *metrics)
{
    const struct kblock_hdr_omf *hdr = kblkdesc->map_base;

    if (!kblock_hdr_valid(hdr))
        return merr(EINVAL);

    metrics->num_keys = omf_kbh_entries(hdr);
    metrics->num_tombstones = omf_kbh_tombs(hdr);
    metrics->tot_key_bytes = omf_kbh_key_bytes(hdr);
    metrics->tot_val_bytes = omf_kbh_val_bytes(hdr);
    metrics->tot_kvlen = omf_kbh_kvlen(hdr);
    metrics->tot_vused_bytes = omf_kbh_vused_bytes(hdr);
    metrics->tot_wbt_pages = omf_kbh_wbt_dlen_pg(hdr);
    metrics->tot_blm_pages = omf_kbh_blm_dlen_pg(hdr);

    return 0;
}

void
kbr_madvise_kmd(struct kvs_mblk_desc *md, struct wbt_desc *wbd, int advice)
{
    merr_t err;
    uint32_t pg = wbd->wbd_first_page + wbd->wbd_root + 1;
    uint32_t pg_cnt = wbd->wbd_kmd_pgc;

    if (pg_cnt) {
        err = mblk_madvise_pages(md, pg, pg_cnt, advice);
        ev(err);
    }
}

void
kbr_madvise_wbt_leaf_nodes(struct kvs_mblk_desc *md, struct wbt_desc *wbd, int advice)
{
    merr_t err;
    uint32_t pg = wbd->wbd_first_page;
    uint32_t pg_cnt = wbd->wbd_leaf_cnt;

    if (pg_cnt) {
        err = mblk_madvise_pages(md, pg, pg_cnt, advice);
        ev(err);
    }
}

void
kbr_madvise_wbt_int_nodes(struct kvs_mblk_desc *md, struct wbt_desc *wbd, int advice)
{
    merr_t err;
    uint32_t pg = wbd->wbd_first_page + wbd->wbd_leaf_cnt;
    uint32_t pg_cnt = wbd->wbd_n_pages - wbd->wbd_leaf_cnt - wbd->wbd_kmd_pgc;

    if (pg_cnt) {
        err = mblk_madvise_pages(md, pg, pg_cnt, advice);
        ev(err);
    }
}

void
kbr_madvise_bloom(struct kvs_mblk_desc *md, struct bloom_desc *wbd, int advice)
{
    merr_t err;
    uint32_t pg = wbd->bd_first_page;
    uint32_t pg_cnt = wbd->bd_n_pages;

    if (pg_cnt) {
        err = mblk_madvise_pages(md, pg, pg_cnt, advice);
        ev(err);
    }
}
