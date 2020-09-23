/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/assert.h>
#include <hse_util/arch.h>

#include <mpool/mpool.h>

#include <hse_ikvdb/tuple.h>

#include "omf.h"
#include "vblock_reader.h"

merr_t
vbr_desc_read(
    struct mpool *           ds,
    struct mpool_mcache_map *map,
    uint                     idx,
    uint *                   vgroupsp,
    u64 *                    argv,
    struct mblock_props *    props,
    struct vblock_desc *     vblk_desc)
{
    struct vblock_hdr_omf *hdr;

    bool  supported;
    void *base;
    u64   vgroup;

    base = mpool_mcache_getbase(map, idx);
    if (ev(!base))
        return merr(EINVAL);

    hdr = base;
    vgroup = omf_vbh_vgroup(hdr);

    supported =
        (omf_vbh_magic(hdr) == VBLOCK_HDR_MAGIC && (omf_vbh_version(hdr) == VBLOCK_HDR_VERSION1 ||
                                                    omf_vbh_version(hdr) == VBLOCK_HDR_VERSION2));
    if (ev(!supported))
        return merr(EINVAL);

    memset(vblk_desc, 0, sizeof(*vblk_desc));
    vblk_desc->vbd_mblkdesc.map_base = base;
    vblk_desc->vbd_mblkdesc.mb_id = props->mpr_objid;
    vblk_desc->vbd_mblkdesc.map = map;
    vblk_desc->vbd_mblkdesc.map_idx = idx;
    vblk_desc->vbd_off = PAGE_SIZE;
    vblk_desc->vbd_len = props->mpr_write_len - PAGE_SIZE;
    vblk_desc->vbd_vgroup = vgroup;
    atomic_set(&vblk_desc->vbd_vgidx, 1);
    atomic_set(&vblk_desc->vbd_refcnt, 0);

    return 0;
}

merr_t
vbr_desc_update(
    struct mpool *           ds,
    struct mpool_mcache_map *map,
    uint                     idx,
    uint *                   vgroupsp,
    u64 *                    argv,
    struct mblock_props *    props,
    struct vblock_desc *     vblk_desc)
{
    u64  vgroup = vblk_desc->vbd_vgroup;
    uint i;

    /* Map omf vgroup IDs (i.e., dgens) to a monotonically increasing
     * sequence starting from 1.  The resulting packed indices are
     * used by vbr_readahead() to minimize history table collisions.
     */
    for (i = 0; i < *vgroupsp && argv[i] != vgroup; ++i)
        ; /* do nothing */

    if (i >= *vgroupsp) {
        argv[i] = vgroup;
        *vgroupsp = i + 1;
    }

    atomic_set(&vblk_desc->vbd_vgidx, i + 1);

    return 0;
}

void
vbr_readahead(
    struct vblock_desc *     vbd,
    u32                      voff,
    u32                      vlen,
    u32                      ra_flags,
    u32                      ra_len,
    u32                      rahc,
    struct ra_hist *         rahv,
    struct workqueue_struct *wq)
{
    struct ra_hist *rah;
    size_t          end;
    u16             bkt;
    u16             vgidx;
    bool            reverse;

    assert(ra_len >= PAGE_SIZE);

    reverse = ra_flags & VBR_REVERSE;

    /* The first and last buckets of each vblock group are likely to be hot
     * but we currently have no way to identify them.  As a compromise,
     * we allow the first and last buckets of each vblock to be preloaded
     * organically via mcache.
     */
    bkt = voff / ra_len;
    vgidx = atomic_read(&vbd->vbd_vgidx);
    rah = rahv + (vgidx % rahc);

    /* If we're revisiting this bucket and either we're a reverse
     * cursor or the entire request resides within this bucket then
     * we presume the pages for this bucket are already in core.
     */
    if (rah->vgidx == vgidx && rah->bkt == bkt) {
        if (reverse || (voff + vlen) / ra_len == bkt)
            return;
    }

    /* The first time we visit a vblock we simply mark it as visited
     * and return.  This is in effort to avoid unnecessarily issuing
     * readaheads for short range scans that might never revisit the
     * bucket.  Additionally, this avoids repeated readahead for the
     * same bucket due to vblock scatter induced bucket thrashing
     * (i.e., vblock group ID collions and/or simply more vgroups
     * than slots in rahv[]).
     */
    if (bkt == 0 || (rah->vgidx != vgidx && vlen < ra_len)) {
        if (unlikely(ra_flags & VBR_FULLSCAN)) {
            end = roundup(voff + vlen, ra_len);
            bkt = (voff + vlen) / ra_len;
            voff &= PAGE_MASK;
            goto willneed;
        }

        rah->vgidx = vgidx;
        rah->bkt = bkt;
        return;
    }

    if (reverse) {
        if (rah->vgidx == vgidx && bkt + 1 == rah->bkt)
            end = (bkt - 1) * ra_len;
        else
            end = roundup(voff + vlen, PAGE_SIZE);
        voff = (bkt - 1) * ra_len;
        if (voff >= ra_len)
            voff -= ra_len;
    } else {
        end = roundup(voff + vlen * 2, ra_len);
        bkt = (voff + vlen) / ra_len;
        if (end < (bkt + 2) * ra_len)
            end = (bkt + 2) * ra_len;
        if (rah->vgidx == vgidx && bkt - 1 == rah->bkt)
            voff = (bkt + 1) * ra_len;
        if (voff >= vbd->vbd_len)
            return;
        voff &= PAGE_MASK;
    }

willneed:
    ra_len = end - voff;

    if (voff + ra_len > vbd->vbd_len)
        ra_len = vbd->vbd_len - voff;

    rah->vgidx = vgidx;
    rah->bkt = bkt;

    if (ra_len >= 128 * 1024 && wq) {
        if (vbr_madvise_async(vbd, voff, ra_len, MADV_WILLNEED, wq))
            return;
    }

    vbr_madvise(vbd, voff, ra_len, MADV_WILLNEED);
}

static void
vbr_madvise_async_cb(struct work_struct *work)
{
    struct vbr_madvise_work *w;

    w = container_of(work, struct vbr_madvise_work, vmw_work);

    vbr_madvise(w->vmw_vbd, w->vmw_off, w->vmw_len, w->vmw_advice);

    atomic_dec(&w->vmw_vbd->vbd_refcnt);
    free(w);
}

bool
vbr_madvise_async(
    struct vblock_desc *     vbd,
    uint                     off,
    uint                     len,
    int                      advice,
    struct workqueue_struct *wq)
{
    struct vbr_madvise_work *w;

    if (ev(!wq))
        return false;

    w = malloc(sizeof(*w));
    if (ev(!w))
        return false;

    INIT_WORK(&w->vmw_work, vbr_madvise_async_cb);
    w->vmw_vbd = vbd;
    w->vmw_off = off;
    w->vmw_len = len;
    w->vmw_advice = advice;

    atomic_inc(&vbd->vbd_refcnt);

    return queue_work(wq, &w->vmw_work);
}

void
vbr_madvise(struct vblock_desc *vbd, uint off, uint len, int advice)
{
    u32    pg, pg_cnt, pg_len, pg_max;
    merr_t err;

    pg = (vbd->vbd_off + off) / PAGE_SIZE;
    pg_cnt = len / PAGE_SIZE;
    pg_len = 0;

    if (ev(pg_cnt < 2))
        return;

    for (pg_max = pg + pg_cnt; pg < pg_max; pg += pg_len) {
        pg_len = min_t(u32, pg_max - pg, HSE_RA_PAGES_MAX);

        err = mpool_mcache_madvise(
            vbd->vbd_mblkdesc.map,
            vbd->vbd_mblkdesc.map_idx,
            PAGE_SIZE * pg,
            PAGE_SIZE * pg_len,
            advice);
        if (ev(err))
            break;
    }
}

/* off, len version */
void *
vbr_value(struct vblock_desc *vbd, uint vboff, uint vlen)
{
    assert(vbd->vbd_mblkdesc.map_base);
    assert(vboff + vlen <= vbd->vbd_len);
    return vbd->vbd_mblkdesc.map_base + vbd->vbd_off + vboff;
}
