/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>
#include <sys/mman.h>

#include <hse/error/merr.h>
#include <hse/util/event_counter.h>
#include <hse/util/page.h>
#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/assert.h>
#include <hse/util/arch.h>

#include <hse/mpool/mpool.h>

#include <hse/ikvdb/tuple.h>

#include "omf.h"
#include "vblock_reader.h"
#include "kvs_mblk_desc.h"

merr_t
vbr_desc_read(
    const struct kvs_mblk_desc *mblk,
    struct vblock_desc *vblk_desc)
{
    struct vblock_footer_omf *footer;
    uint32_t wlen;

    wlen = mblk->wlen_pages * PAGE_SIZE;
    footer = mblk->map_base + wlen - VBLOCK_FOOTER_LEN;

    if (ev(omf_vbf_magic(footer) != VBLOCK_FOOTER_MAGIC))
        return merr(EPROTO);

    if (ev(omf_vbf_version(footer) != VBLOCK_FOOTER_VERSION))
        return merr(EPROTO);

    memset(vblk_desc, 0, sizeof(*vblk_desc));

    vblk_desc->vbd_mblkdesc = mblk;
    vblk_desc->vbd_off = 0;
    vblk_desc->vbd_len = wlen - VBLOCK_FOOTER_LEN;
    vblk_desc->vbd_vgroup = omf_vbf_vgroup(footer);
    vblk_desc->vbd_min_koff = vblk_desc->vbd_len + VBLOCK_FOOTER_LEN - (2 * HSE_KVS_KEY_LEN_MAX);
    vblk_desc->vbd_min_klen = omf_vbf_min_klen(footer);
    vblk_desc->vbd_max_koff = vblk_desc->vbd_min_koff + HSE_KVS_KEY_LEN_MAX;
    vblk_desc->vbd_max_klen = omf_vbf_max_klen(footer);

    atomic_set(&vblk_desc->vbd_vgidx, 1);
    atomic_set(&vblk_desc->vbd_refcnt, 0);

    return 0;
}

merr_t
vbr_desc_update_vgidx(
    struct vblock_desc *vblk_desc,
    uint               *vgroupc,
    uint64_t           *vgroupv)
{
    uint64_t  vgroup = vblk_desc->vbd_vgroup;
    uint i;

    /* Map omf vgroup IDs (i.e., kvset ids) to a monotonically increasing
     * sequence starting from 1.  The resulting packed indices are
     * used by vbr_readahead() to minimize history table collisions.
     */
    for (i = 0; i < *vgroupc && vgroupv[i] != vgroup; ++i)
        ; /* do nothing */

    if (i >= *vgroupc) {
        vgroupv[i] = vgroup;
        *vgroupc = i + 1;
    }

    atomic_set(&vblk_desc->vbd_vgidx, i + 1);

    return 0;
}

void
vbr_readahead(
    struct vblock_desc *     vbd,
    uint32_t                 voff,
    size_t                   vlen,
    uint32_t                 ra_flags,
    size_t                   ra_len,
    uint32_t                 rahc,
    struct ra_hist *         rahv,
    struct workqueue_struct *wq)
{
    struct ra_hist *rah;
    size_t          end;
    uint16_t        bkt;
    uint16_t        vgidx;
    bool            reverse;

    assert(ra_len >= PAGE_SIZE);

    reverse = ra_flags & VBR_REVERSE;

    /* The first and last buckets of each vblock group are likely to be hot
     * but we currently have no way to identify them.  As a compromise,
     * we allow the first and last buckets of each vblock to be preloaded
     * organically via the memory map.
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
     * same bucket due to vblock group induced bucket thrashing (i.e.,
     * more vgroups than slots in rahv[]).
     */
    if (bkt == 0 || (rah->vgidx != vgidx && vlen < ra_len)) {
        if (HSE_UNLIKELY(ra_flags & VBR_FULLSCAN)) {
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
    mblk_madvise_pages(vbd->vbd_mblkdesc, off / PAGE_SIZE, len / PAGE_SIZE, advice);
}

/* off, len version */
void *
vbr_value(struct vblock_desc *vbd, uint vboff, uint vlen)
{
    assert(vbd->vbd_mblkdesc->map_base);
    assert(vboff + vlen <= vbd->vbd_len);
    return vbd->vbd_mblkdesc->map_base + vbd->vbd_off + vboff;
}
