/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_vblock_builder_ext
#include "vblock_builder_ext.h"

#include "vblock_builder.h"

#include "omf.h"
#include "blk_list.h"

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/assert.h>
#include <hse_util/logging.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>

#include <hse/hse_limits.h>
#include <hse/kvdb_perfc.h>

#include "vblock_builder_internal.h"
#include "cn_metrics.h"

struct vbb_ext_elem {
    u64   vbid;
    void *wbuf;
    uint  vbidx;
    uint  opt_wrsz;

    __aligned(SMP_CACHE_BYTES) atomic_t wbuf_off;
    off_t    wbuf_woff;
    atomic_t wbuf_wlen;
    uint     wbuf_len;

    __aligned(SMP_CACHE_BYTES) struct rw_semaphore flush_sem;
};

struct vbb_ext {
    struct vbb_ext_elem *vbbv;
    atomic_t             vbnum;
    uint                 vbbc;
    uint                 vbcappct;
    uint                 vbcap;
    uint                 vbsize;

    __aligned(SMP_CACHE_BYTES) struct mutex vbb_lock;
    atomic_t vbunderutil;
};

static bool
_vblock_ext_threshold_reached(struct vbb_ext *ext)
{
    int cap;

    cap = (ext->vbcap * ext->vbcappct) / 100;
    cap = max_t(uint, cap, 8);

    if (atomic_read(&ext->vbunderutil) > cap)
        atomic_set(&ext->vbunderutil, -1);

    if (atomic_inc_return(&ext->vbnum) > ext->vbcap) {
        atomic_dec(&ext->vbnum);
        return true;
    }

    return false;
}

static merr_t
_vblock_start_ext(struct vblock_builder *bld, u8 slot)
{
    merr_t               err = 0;
    struct mblock_props  mbprop;
    struct vbb_ext_elem *vbb;
    u32                  vbidx;
    u64                  vbid;
    struct vbb_ext *     ext;
    bool                 spare;
    uint                 allocs = 0, perfc_idx;

    struct mclass_policy *mpolicy = cn_get_mclass_policy(bld->cn);
    enum mp_media_classp  mclass;

    ext = bld->vbb_ext;

    if (!ext)
        return merr(ev(ENOENT));

    if (unlikely(_vblock_ext_threshold_reached(ext)))
        return merr_once(ENOSPC);

    spare = !!(bld->flags & KVSET_BUILDER_FLAGS_SPARE);

    do {
        mclass = mclass_policy_get_type(mpolicy, bld->agegroup, HSE_MPOLICY_DTYPE_VALUE, allocs);
        if (mclass == MP_MED_INVALID) {
            if (!err)
                err = merr(ev(EINVAL));

            return err;
        }

        err = mpool_mblock_alloc(bld->ds, mclass, spare, &vbid, &mbprop);
    } while (err && ++allocs < HSE_MPOLICY_MEDIA_CNT);

    if (ev(err))
        return err;

    if (mbprop.mpr_alloc_cap != ext->vbsize) {
        assert(0);
        mpool_mblock_abort(bld->ds, vbid);
        return merr(ev(EBUG));
    }

    mutex_lock(&ext->vbb_lock);
    err = blk_list_append(&bld->vblk_list, vbid);
    if (ev(err)) {
        mutex_unlock(&ext->vbb_lock);
        mpool_mblock_abort(bld->ds, vbid);
        return err;
    }
    vbidx = bld->vblk_list.n_blks - 1;
    mutex_unlock(&ext->vbb_lock);

    vbb = &ext->vbbv[slot];

    vbb->vbidx = vbidx;
    vbb->vbid = vbid;

    assert(mbprop.mpr_optimal_wrsz);
    vbb->opt_wrsz = mbprop.mpr_optimal_wrsz;

    memset(vbb->wbuf, 0x0, VBLOCK_HDR_LEN);
    omf_set_vbh_magic(vbb->wbuf, VBLOCK_HDR_MAGIC);
    omf_set_vbh_version(vbb->wbuf, VBLOCK_HDR_VERSION2);
    omf_set_vbh_vgroup(vbb->wbuf, HSE_C1_VBLOCK_GROUPID);

    atomic_set(&vbb->wbuf_off, VBLOCK_HDR_LEN);
    atomic_set(&vbb->wbuf_wlen, VBLOCK_HDR_LEN);
    vbb->wbuf_len = ext->vbsize - (ext->vbsize % mbprop.mpr_optimal_wrsz);

    perfc_idx = PERFC_BA_CNMCLASS_SYNCK_STAGING + bld->agegroup * HSE_MPOLICY_AGE_CNT +
                HSE_MPOLICY_DTYPE_VALUE * HSE_MPOLICY_DTYPE_CNT +
                ((mclass == MP_MED_CAPACITY) ? 1 : 0);

    if (perfc_idx < PERFC_EN_CNMCLASS)
        perfc_add(cn_pc_mclass_get(bld->cn), perfc_idx, ext->vbsize);

    return 0;
}

merr_t
vbb_create_ext(struct vblock_builder *bld, struct kvs_rparams *rp)
{
    struct vbb_ext_elem *vbbv;
    struct vbb_ext *     ext;

    int  i;
    u64  vbsz;
    u64  sz;
    uint stripew;

    sz = 0;
    vbsz = rp->c1_vblock_size_mb << 20;
    stripew = HSE_C1_DEFAULT_STRIPE_WIDTH;

    sz += sizeof(*ext) + stripew * sizeof(*vbbv);

    ext = calloc(1, sz);
    if (ev(!ext))
        return merr(ENOMEM);

    vbbv = (void *)(ext + 1);

    for (i = 0; i < stripew; i++) {
        vbbv[i].wbuf = alloc_page_aligned(vbsz, GFP_KERNEL);
        if (ev(!vbbv[i].wbuf)) {
            while (--i >= 0)
                free_aligned(vbbv[i].wbuf);

            free(ext);
            return merr(ENOMEM);
        }

        init_rwsem(&vbbv[i].flush_sem);
    }

    mutex_init(&ext->vbb_lock);
    ext->vbsize = vbsz;
    ext->vbbv = vbbv;
    ext->vbcap = rp->c1_vblock_cap;
    ext->vbcappct = rp->c1_vblock_cappct;
    ext->vbbc = stripew;
    atomic_set(&ext->vbnum, 0);
    atomic_set(&ext->vbunderutil, 0);

    bld->vbb_ext = ext;

    return 0;
}

void
vbb_destroy_ext(struct vblock_builder *bld)
{
    struct vbb_ext *     ext;
    struct vbb_ext_elem *vbbv;

    int i;

    ext = bld->vbb_ext;
    vbbv = ext->vbbv;

    for (i = 0; i < ext->vbbc; i++)
        free_aligned(vbbv[i].wbuf);

    mutex_destroy(&ext->vbb_lock);
    free(ext);
}

bool
vbb_verify_entry(struct vblock_builder *bld, u32 vbidx, u64 blkid, u64 blkoff, u32 vlen)
{
    assert(bld->vblk_list.blks);
    assert(bld->vblk_list.n_blks);
    assert(vbidx < bld->vblk_list.n_blks);

    if (bld->vblk_list.blks[vbidx].bk_blkid == blkid) {

        if (vlen && bld->vblk_list.blks[vbidx].bk_needs_commit) {
            hse_log(
                HSE_ERR "vbb_verify_entry failed blkid %ld "
                        "blkoff %ld vlen %d uncommitted block",
                (unsigned long)blkid,
                (unsigned long)blkoff,
                (int)vlen);

            return false;
        }

        bld->vblk_list.blks[vbidx].bk_valid = true;
        return true;
    }

#ifdef HSE_BUILD_DEBUG
    {
        u32 i;

        for (i = 0; i < bld->vblk_list.n_blks; i++)
            assert(bld->vblk_list.blks[i].bk_blkid != blkid);
    }
#endif

    return false;
}

static bool
_vblock_reserve_room(struct vblock_builder *bld, uint vlen, uint *boffout, u8 slot)
{
    struct vbb_ext *     ext;
    struct vbb_ext_elem *vbb;

    uint pos;

    ext = bld->vbb_ext;
    vbb = &ext->vbbv[slot];

    pos = atomic_add_return(vlen, &vbb->wbuf_off);
    if (unlikely(pos >= vbb->wbuf_len))
        return false;

    atomic_add(vlen, &vbb->wbuf_wlen);
    *boffout = pos - vlen;

    return true;
}

static uint
vbb_padding_get(struct vbb_ext_elem *vbb, uint wlen)
{
    uint plen;
    uint owsz;

    owsz = vbb->opt_wrsz;

    plen = owsz - (wlen % owsz);
    if (wlen + plen > vbb->wbuf_len)
        plen = vbb->wbuf_len - wlen;

    return plen;
}

static void
vbb_util_adjust(struct vbb_ext *ext, uint wlen)
{
    uint vbthr;

    /* If the vblock is <50% utilized then increment counter
     * which in turn controls newer vblock allocation.
     */
    vbthr = max_t(uint, ext->vbsize >> 2, 4 << 20);
    if (wlen < vbthr && atomic_read(&ext->vbunderutil) >= 0)
        atomic_inc(&ext->vbunderutil);
}

static merr_t
_vblock_write_ext(struct vblock_builder *bld, u8 slot, bool last_write)
{
    struct iovec         iov;
    struct vbb_ext *     ext;
    struct vbb_ext_elem *vbb;

    merr_t err;
    void * buf;
    uint   owsz;
    uint   wlen;
    uint   rem;

    ext = bld->vbb_ext;
    vbb = &ext->vbbv[slot];
    assert(vbb->vbid);

    buf = vbb->wbuf;
    wlen = atomic_read(&vbb->wbuf_wlen);
    owsz = vbb->opt_wrsz;

    if (last_write) {
        uint plen;

        /* Zero padding for the last write to make it stripe aligned.*/
        plen = vbb_padding_get(vbb, wlen);
        memset(buf + wlen, 0, plen);
        wlen += plen;
        assert((wlen - vbb->wbuf_woff) % owsz == 0);
    }

    assert(wlen >= vbb->wbuf_woff);
    rem = wlen - vbb->wbuf_woff;
    rem = rem - (rem % owsz);

    /* Write out this vblock if the dirty data exceeds 1MiB. If there's
     * nothing to write or if the dirty data is less than a chunk size and
     * is an intermediate write, then do nothing.
     */
    if (rem == 0 || !last_write)
        return 0;

    iov.iov_base = buf + vbb->wbuf_woff;
    iov.iov_len = rem;
    err = mpool_mblock_write(bld->ds, vbb->vbid, &iov, 1);
    if (ev(err))
        goto err_exit;

    vbb->wbuf_woff += rem;
    assert(wlen >= vbb->wbuf_woff);
    assert(last_write || vbb->wbuf_woff <= atomic_read(&vbb->wbuf_off));

    perfc_inc(bld->pc, PERFC_RA_CNCOMP_WREQS);

    if (!last_write)
        return 0;

    vbb_util_adjust(ext, wlen);

    atomic_set(&vbb->wbuf_off, 0);
    atomic_set(&vbb->wbuf_wlen, 0);
    vbb->wbuf_woff = 0;

    return 0;

err_exit:

    bld->destruct = true;

    return err;
}

merr_t
_vblock_finish_ext(struct vblock_builder *bld, u8 slot, bool last_write)
{
    struct vbb_ext *     ext;
    struct vbb_ext_elem *vbb;
    struct blk_list *    blks;

    merr_t err;
    uint   vbidx;

    ext = bld->vbb_ext;
    vbb = &ext->vbbv[slot];

    if (!vbb->vbid || !atomic_read(&vbb->wbuf_off))
        return 0;

    err = _vblock_write_ext(bld, slot, last_write);

    if (!last_write)
        return ev(err);

    blks = &bld->vblk_list;
    vbidx = vbb->vbidx;

    if (vbb->vbid != blks->blks[vbidx].bk_blkid) {
        hse_log(
            HSE_ERR "vbb blkid %lu mismatch with blk list %lu",
            (ulong)vbb->vbid,
            (ulong)blks->blks[vbidx].bk_blkid);
        return merr(ev(EBUG));
    }

    vbb->vbidx = 0;
    vbb->vbid = 0;

    return ev(err);
}

merr_t
vbb_add_entry_ext(
    struct vblock_builder *bld,
    const void *           vdata,
    uint                   vlen,
    bool                   wait,
    u8                     index,
    u64 *                  vbidout,
    uint *                 vbidxout,
    uint *                 vboffout)
{
    struct vbb_ext *     ext;
    struct vbb_ext_elem *vbb;

    uint   boff;
    merr_t err;
    u8     slot;

    assert(!bld->destruct);

    assert(vdata);
    assert(vlen);
    assert(vlen <= HSE_KVS_VLEN_MAX);

    ext = bld->vbb_ext;

    /*
     * Switch to one vblock if there's a history of underutilized vblocks
     * in this mutation interval. This is to improve vblock utilization.
     */
    if (atomic_read(&ext->vbunderutil) < 0)
        index = 0;

    slot = index % ext->vbbc;
    vbb = &ext->vbbv[slot];

    /*
     * The caller holds an exclusive lock if wait flag is set.
     * Filling an existing vblock does not block. If the vblock
     * is full, then the caller is asked to call this function
     * once more with an exclusive lock. This is done by returning
     * EAGAIN.
     */
    down_read(&vbb->flush_sem);
    if (unlikely(!vbb->vbid)) {
        if (!wait) {
            up_read(&vbb->flush_sem);
            return merr_once(EAGAIN);
        }

        err = _vblock_start_ext(bld, slot);
        if (err) {
            up_read(&vbb->flush_sem);
            ev(merr_errno(err) != ENOSPC);
            return err;
        }
    }

    *vbidxout = vbb->vbidx;
    *vbidout = vbb->vbid;

    if (unlikely(!_vblock_reserve_room(bld, vlen, &boff, slot))) {
        if (!wait) {
            up_read(&vbb->flush_sem);
            return merr(EAGAIN);
        }

        err = _vblock_finish_ext(bld, slot, true);
        if (ev(err)) {
            up_read(&vbb->flush_sem);
            return err;
        }

        err = _vblock_start_ext(bld, slot);
        if (ev(err)) {
            up_read(&vbb->flush_sem);
            ev(merr_errno(err) != ENOSPC);
            return err;
        }

        *vbidxout = vbb->vbidx;
        *vbidout = vbb->vbid;

        if (ev(!_vblock_reserve_room(bld, vlen, &boff, slot))) {
            up_read(&vbb->flush_sem);
            return merr(ENOMEM);
        }
    }

    memcpy(vbb->wbuf + boff, vdata, vlen);
    assert(boff >= VBLOCK_HDR_LEN);
    *vboffout = boff - VBLOCK_HDR_LEN;
    up_read(&vbb->flush_sem);

    return 0;
}

void
vbb_get_vblocks(struct vblock_builder *bld, struct blk_list *vblks)
{
    assert(!bld->destruct);

    *vblks = bld->vblk_list;
}

void
vbb_remove_unused_vblocks(struct vblock_builder *bld)
{
    struct blk_list *blks;
    int              i;
    int              invalid;

    blks = &bld->vblk_list;

    assert(!bld->destruct);

    invalid = 0;

    for (i = 0; i < blks->n_blks; i++) {
        if (bld->vblk_list.blks[i].bk_valid)
            continue;
        invalid++;
    }

    if (invalid) {
        hse_log(HSE_DEBUG "c1 vbldr total vblocks %d invalid vblocks %d", blks->n_blks, invalid);

        if (PERFC_ISON(bld->pc)) {
            uint pct;

            pct = (invalid * 100) / blks->n_blks;

            perfc_rec_sample(bld->pc, PERFC_DI_CNCOMP_VBDEAD, pct);
        }
    }
}

u32
vbb_vblock_hdr_len(void)
{
    return VBLOCK_HDR_LEN;
}

merr_t
vbb_finish_entry(struct vblock_builder *bld, u8 index)
{
    struct vbb_ext *     ext;
    struct vbb_ext_elem *vbb;

    u8     slot;
    merr_t err;

    ext = bld->vbb_ext;
    slot = index % ext->vbbc;

    vbb = &ext->vbbv[slot];

    down_write(&vbb->flush_sem);
    err = _vblock_finish_ext(bld, slot, false);
    up_write(&vbb->flush_sem);

    return err;
}

/* Write vblock to media.  Zero-fill the last partial block. */
merr_t
vbb_flush_entry(struct vblock_builder *bld)
{
    struct vbb_ext_elem *vbb;
    struct vbb_ext *     ext;
    struct blk_list *    blks;

    merr_t err;
    int    i;

    ext = bld->vbb_ext;
    blks = &bld->vblk_list;

    assert(!bld->destruct);

    for (i = 0; i < ext->vbbc; i++) {
        vbb = &ext->vbbv[i];

        down_write(&vbb->flush_sem);
        err = _vblock_finish_ext(bld, i, true);
        up_write(&vbb->flush_sem);

        if (ev(err)) {
            hse_elog(HSE_ERR "vblock finish failed: @@e", err);
            return err;
        }
    }

    for (i = 0; i < blks->n_blks; i++) {
        if (!blks->blks[i].bk_needs_commit)
            continue;

        err = mpool_mblock_commit(bld->ds, blks->blks[i].bk_blkid);
        if (err) {
            hse_log(HSE_ERR "mpool_mblock_commit error %d", merr_errno(err));
            return err;
        }

        blks->blks[i].bk_needs_commit = false;
        blks->blks[i].bk_valid = false;
    }

    assert(i == blks->n_blks);

    return 0;
}

u32
vbb_get_blk_count_committed(struct vblock_builder *bld)
{
    int i;
    int count;

    assert(!bld->destruct);

    count = 0;
    for (i = 0; i < bld->vblk_list.n_blks; i++)
        if (!bld->vblk_list.blks[i].bk_needs_commit)
            ++count;

    if (PERFC_ISON(bld->pc))
        perfc_rec_sample(bld->pc, PERFC_DI_CNCOMP_VBCNT, count);

    return count;
}

u32
vbb_get_blk_count(struct vblock_builder *bld)
{
    assert(!bld->destruct);

    return bld->vblk_list.n_blks;
}

merr_t
vbb_blk_list_merge(struct vblock_builder *dst, struct vblock_builder *src, struct blk_list *vblks)
{
    merr_t err = 0;
    u32    i;
    u32    nblks;

    nblks = vblks->n_blks;

    for (i = 0; i < nblks; i++) {
        err = blk_list_append_ext(
            &dst->vblk_list,
            vblks->blks[i].bk_blkid,
            vblks->blks[i].bk_valid,
            vblks->blks[i].bk_needs_commit);
        if (ev(err))
            break;
    }

    if (err) {
        /* Restore the original blklist in the source vbb */
        memcpy(&src->vblk_list, vblks, sizeof(src->vblk_list));
        return err;
    }

    blk_list_free(vblks);
    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "vblock_builder_ext_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
