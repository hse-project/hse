/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_vblock_builder

#include "vblock_builder.h"

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/assert.h>
#include <hse_util/logging.h>
#include <hse_util/perfc.h>
#include <hse_util/vlb.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/cn.h>

#include <hse/limits.h>
#include <hse/kvdb_perfc.h>

#include "omf.h"
#include "blk_list.h"
#include "cn_mblocks.h"
#include "cn_metrics.h"
#include "cn_perfc.h"

#include <mpool/mpool.h>

#include "vblock_builder_internal.h"

size_t
vbb_estimate_alen(struct cn *cn, size_t wlen, enum mpool_mclass mclass)
{
    u64 zonealloc_unit;

    zonealloc_unit = cn_mpool_dev_zone_alloc_unit_default(cn, mclass);
    return cn_mb_est_alen(
        VBLOCK_MAX_SIZE, zonealloc_unit, wlen, CN_MB_EST_FLAGS_TRUNCATE | CN_MB_EST_FLAGS_PREALLOC);
}

static merr_t
_vblock_start(struct vblock_builder *bld)
{
    merr_t                 err = 0;
    struct mblock_props    mbprop;
    u64                    blkid;
    u64                    tstart;
    struct cn_merge_stats *stats = bld->mstats;
    struct kvs_rparams *   rp;
    enum mpool_mclass      mclass;
    struct mclass_policy * mpolicy = cn_get_mclass_policy(bld->cn);

    tstart = get_time_ns();

    mclass = mclass_policy_get_type(mpolicy, bld->agegroup, HSE_MPOLICY_DTYPE_VALUE);
    if (ev(mclass == MP_MED_INVALID))
        return merr(EINVAL);

    err = mpool_mblock_alloc(bld->ds, mclass, &blkid, &mbprop);
    if (ev(err))
        return err;

    if (stats)
        count_ops(&stats->ms_vblk_alloc, 1, mbprop.mpr_alloc_cap, get_time_ns() - tstart);

    rp = cn_get_rp(bld->cn);

    if (mbprop.mpr_alloc_cap != rp->vblock_size) {
        mpool_mblock_abort(bld->ds, blkid);
        assert(0);
        return merr(ev(EBUG));
    }

    err = blk_list_append(&bld->vblk_list, blkid);
    if (ev(err)) {
        mpool_mblock_abort(bld->ds, blkid);
        return err;
    }

    assert(mbprop.mpr_optimal_wrsz);

    /* set offsets to leave space for header */
    bld->vblk_off = VBLOCK_HDR_LEN;
    bld->wbuf_off = VBLOCK_HDR_LEN;
    bld->blkid = blkid;
    bld->wbuf_len = WBUF_LEN_MAX - (WBUF_LEN_MAX % mbprop.mpr_optimal_wrsz);
    bld->opt_wrsz = mbprop.mpr_optimal_wrsz;

    /* add header to write buffer */
    memset(bld->wbuf, 0x0, VBLOCK_HDR_LEN);
    omf_set_vbh_magic(bld->wbuf, VBLOCK_HDR_MAGIC);
    omf_set_vbh_version(bld->wbuf, VBLOCK_HDR_VERSION2);
    omf_set_vbh_vgroup(bld->wbuf, bld->vgroup);

    return 0;
}

static merr_t
_vblock_write(struct vblock_builder *bld)
{
    merr_t                 err;
    struct iovec           iov;
    struct cn_merge_stats *stats = bld->mstats;
    u64                    tstart;

    assert(bld->blkid);

    iov.iov_base = bld->wbuf;
    iov.iov_len = bld->wbuf_len;

    /* Function mblk_blow_chunks(), which is used in the kblock builder,
     * is not needed here because our write buffer is already
     * smallish (1MiB) and a multiple of the mblock stripe length.
     */
    tstart = get_time_ns();

    err = mpool_mblock_write(bld->ds, bld->blkid, &iov, 1);

    if (stats)
        count_ops(&stats->ms_vblk_write, 1, iov.iov_len, get_time_ns() - tstart);

    if (ev(err)) {
        bld->destruct = true;
        return err;
    }

    bld->wbuf_off = 0;

    perfc_inc(bld->pc, PERFC_RA_CNCOMP_WREQS);
    perfc_add(bld->pc, PERFC_RA_CNCOMP_WBYTES, bld->wbuf_len);

    return 0;
}

static merr_t
_vblock_finish(struct vblock_builder *bld)
{
    merr_t err = 0;
    uint   buflen;
    uint   zfill_len;

    if (bld->blkid && bld->wbuf_off) {

        zfill_len = bld->wbuf_len - bld->wbuf_off;
        if (zfill_len > _vblock_unused_media_space(bld))
            zfill_len = _vblock_unused_media_space(bld);

        buflen = bld->wbuf_len;
        bld->wbuf_len = bld->wbuf_off + zfill_len;

        memset(bld->wbuf + bld->wbuf_off, 0, zfill_len);

        err = _vblock_write(bld);
        bld->wbuf_len = buflen;
    }

    bld->blkid = 0;

    return err;
}

/* Create a vblock builder */
merr_t
vbb_create(
    struct vblock_builder **builder_out,
    struct cn *             cn,
    struct perfc_set *      pc,
    u64                     vgroup)
{
    struct vblock_builder  *bld;
    struct kvs_rparams     *rp;
    void                   *wbuf;

    assert(builder_out);

    rp = cn_get_rp(cn);

    wbuf = vlb_alloc(WBUF_LEN_MAX + sizeof(*bld));
    if (ev(!wbuf))
        return merr(ENOMEM);

    bld = wbuf + WBUF_LEN_MAX;

    memset(bld, 0, sizeof(*bld));
    bld->cn = cn;
    bld->pc = pc;
    bld->ds = cn_get_dataset(cn);
    bld->vgroup = vgroup;
    bld->max_size = rp->vblock_size;
    bld->agegroup = HSE_MPOLICY_AGE_LEAF;
    bld->wbuf = wbuf;

    *builder_out = bld;

    return 0;
}

/* Destroy a vblock builder. Must also abort any mblocks left behind. */
void
vbb_destroy(struct vblock_builder *bld)
{
    if (ev(!bld))
        return;

    abort_mblocks(bld->ds, &bld->vblk_list);
    blk_list_free(&bld->vblk_list);

    vlb_free(bld->wbuf, WBUF_LEN_MAX + sizeof(*bld));
}

/* Add a value to vblock.  Create new vblock if needed. */
merr_t
vbb_add_entry(
    struct vblock_builder *bld,
    const void *           vdata,
    uint                   vlen, /* on-media length */
    u64 *                  vbidout,
    uint *                 vbidxout,
    uint *                 vboffout)
{
    merr_t err;
    uint   voff, space, bytes;

    assert(!bld->destruct);

    assert(vdata);
    assert(vlen);
    assert(vlen <= HSE_KVS_VALUE_LEN_MAX);

    if (HSE_UNLIKELY(!_vblock_has_room(bld, vlen))) {
        err = _vblock_finish(bld);
        if (ev(err))
            return err;
    }

    if (HSE_UNLIKELY(!bld->blkid)) {
        err = _vblock_start(bld);
        if (ev(err))
            return err;
    }

    assert(bld->blkid);
    assert(_vblock_has_room(bld, vlen));

    voff = 0;

    while (voff < vlen) {

        assert(bld->wbuf_off < bld->wbuf_len);

        /* Copy whatever fits into the write buffer. */
        space = bld->wbuf_len - bld->wbuf_off;
        bytes = vlen - voff;
        if (bytes > space)
            bytes = space;

        memcpy(bld->wbuf + bld->wbuf_off, vdata + voff, bytes);

        bld->wbuf_off += bytes;
        voff += bytes;

        /* Issue write if buffer is full. */
        if (bld->wbuf_off == bld->wbuf_len) {
            err = _vblock_write(bld);
            if (ev(err))
                return err;
        }
    }

    assert(bld->wbuf_off < bld->wbuf_len);

    *vboffout = bld->vblk_off - VBLOCK_HDR_LEN;
    *vbidxout = bld->vblk_list.n_blks - 1;
    *vbidout = bld->vblk_list.blks[*vbidxout].bk_blkid;

    bld->vblk_off += vlen;
    bld->vsize += vlen;

    return 0;
}

/* Close out the current vblock, return IDs of all mblocks allocated so far,
 * and mark the builder as closed for business.
 */
merr_t
vbb_finish(struct vblock_builder *bld, struct blk_list *vblks)
{
    merr_t err;

    assert(!bld->destruct);

    bld->destruct = true;

    err = _vblock_finish(bld);
    if (ev(err))
        return err;

    /* Transfer ownership of blk_list and the mblocks in
     * the blk_list to caller  */
    *vblks = bld->vblk_list;
    memset(&bld->vblk_list, 0, sizeof(bld->vblk_list));

    return 0;
}

void
vbb_set_agegroup(struct vblock_builder *bld, enum hse_mclass_policy_age age)
{
    bld->agegroup = age;
}

enum hse_mclass_policy_age
vbb_get_agegroup(struct vblock_builder *bld)
{
    return bld->agegroup;
}

void
vbb_set_merge_stats(struct vblock_builder *bld, struct cn_merge_stats *stats)
{
    bld->mstats = stats;
}

#if HSE_MOCKING
#include "vblock_builder_ut_impl.i"
#endif /* HSE_MOCKING */
