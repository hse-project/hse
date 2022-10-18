/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_vblock_builder

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/assert.h>
#include <hse/logging/logging.h>
#include <hse_util/perfc.h>
#include <hse_util/vlb.h>
#include <hse/error/merr.h>

#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/cn.h>

#include <hse/limits.h>
#include <hse/kvdb_perfc.h>
#include <mpool/mpool.h>

#include "vblock_builder.h"
#include "omf.h"
#include "blk_list.h"
#include "cn_mblocks.h"
#include "cn_metrics.h"
#include "cn_perfc.h"

#define WBUF_LEN_MAX      ((1024 * 1024) + VBLOCK_FOOTER_LEN)

/**
 * struct vblock_builder - create vblocks from a stream of values
 * @ds:        mpool dataset
 * @pc:        performance counters
 * @vblk_list: list of vblocks
 * @wbuf:      write buffer
 * @wbuf_off:  offset of next unused byte in write buffer
 * @wbuf_len:  length of next write to media
 * @vblk_off:  offset of next unused byte in vblock
 * @vsize:     vblock size for compaction stats.  for vblocks, vsize
 *             is the number of bytes written to the vblock before committing it
 * @destruct:  if true, vlbock builder is ready to be destroyed
 * @mblocksz:  mblock size of specified media class
 * @cur_minklen: min key length
 * @cur_minkey:  a copy of the min key referencing this vblock
 *
 * WBUF_LEN_MAX is the allocated size of the write buffer.  Each mblock write
 * will be at most WBUF_LEN_MAX bytes.  Member @wbuf_len is the actual write
 * size, and is <= WBUF_LEN_MAX.
 *
 * The vblock builder creates as many vblocks as needed to store the values.
 * The write buffer is allocated once when the builder is created, and is
 * reused between vblocks.  The following logic explains how the vlbock
 * builder state is managed as new values are added.
 *
 * When a new value is given to the vblock builder:
 *
 *   Let @vlen be the length of the new value
 *
 *   If current vblock has not been allocated, start a new vblock as follows:
 *     - allocate vblock
 *     - set @wbuf_len to WBUF_LEN_MAX - VBLOCK_FOOTER_LEN, reserving space for footer
 *
 *   If current vblock does not have room for new value:
 *     - write residual contents of @wbuf to mblock
 *     - start a new vblock as described above
 *
 *   While @vlen > 0:
 *     - copy whatever fits into @wbuf (cannot exceed @wbuf_len)
 *     - let @copied be number of bytes copied
 *     - set @vlen -= @copied
 *     - set @wbuf_off += @copied
 *     - if @wbuf_off == @wbuf_len:
 *       -- write @wbuf_len bytes to mblock
 *       -- set @wbuf_off to 0
 *       -- set @vblk_off += @wbuff_off
 */
struct vblock_builder {
    struct mpool *             ds;
    struct cn *                cn;
    struct perfc_set *         pc;
    struct cn_merge_stats *    mstats;
    struct blk_list            vblk_list;
    enum hse_mclass_policy_age agegroup;
    uint64_t                   vsize;
    uint64_t                   blkid;
    uint32_t                   max_size;
    off_t                      vblk_off;
    void *                     wbuf;
    off_t                      wbuf_off;
    unsigned int               wbuf_len;
    uint64_t                   vgroup;
    uint64_t                   tot_vlen;
    bool                       destruct;
    uint32_t                   cur_minklen;
    char                       cur_minkey[HSE_KVS_KEY_LEN_MAX];
};

static inline bool
vblock_has_room(const struct vblock_builder *bld, size_t vlen)
{
    return bld->vblk_off + vlen <= (bld->max_size - VBLOCK_FOOTER_LEN);
}

static inline uint32_t HSE_MAYBE_UNUSED
vblock_unused_media_space(const struct vblock_builder *bld)
{
    return bld->max_size - bld->vblk_off;
}

size_t
vbb_estimate_alen(struct cn *cn, size_t wlen, enum hse_mclass mclass)
{
    u64 zonealloc_unit;

    zonealloc_unit = cn_mpool_dev_zone_alloc_unit_default(cn, mclass);
    return cn_mb_est_alen(
        VBLOCK_MAX_SIZE, zonealloc_unit, wlen, CN_MB_EST_FLAGS_TRUNCATE | CN_MB_EST_FLAGS_PREALLOC);
}

static merr_t
vblock_start(struct vblock_builder *bld, const struct key_obj *min_kobj)
{
    merr_t                 err = 0;
    struct mblock_props    mbprop;
    u64                    blkid;
    u64                    tstart;
    struct cn_merge_stats *stats = bld->mstats;
    enum hse_mclass      mclass;
    struct mclass_policy * mpolicy = cn_get_mclass_policy(bld->cn);

    tstart = get_time_ns();

    mclass = mclass_policy_get_type(mpolicy, bld->agegroup, HSE_MPOLICY_DTYPE_VALUE);
    if (ev(mclass == HSE_MCLASS_INVALID))
        return merr(EINVAL);

    err = mpool_mblock_alloc(bld->ds, mclass, 0, &blkid, &mbprop);
    if (ev(err))
        return err;

    if (stats)
        count_ops(&stats->ms_vblk_alloc, 1, mbprop.mpr_alloc_cap, get_time_ns() - tstart);

    assert(mbprop.mpr_alloc_cap == bld->max_size);

    err = blk_list_append(&bld->vblk_list, blkid);
    if (ev(err)) {
        mpool_mblock_delete(bld->ds, blkid);
        return err;
    }

    bld->vblk_off = bld->wbuf_off = 0;
    bld->blkid = blkid;
    bld->wbuf_len = WBUF_LEN_MAX - VBLOCK_FOOTER_LEN; /* Reserve space for footer */

    /* Store a copy of the first key referencing this vblock.
     * It is written later to the vblock footer as the min key.
     */
    key_obj_copy(bld->cur_minkey, sizeof(bld->cur_minkey), &bld->cur_minklen, min_kobj);

    return 0;
}

static merr_t
vblock_write(struct vblock_builder *bld)
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
vblock_finish(struct vblock_builder *bld, const struct key_obj *max_kobj)
{
    struct vblock_footer_omf *vbfomf;
    uint32_t buflen, zfill_len, klen, max_klen;
    off_t min_koff, max_koff;
    merr_t err = 0;

    if (bld->blkid == 0)
        return 0;

    /* Align the buffer offset to a page boundary and zero out the rounded space */
    zfill_len = PAGE_ALIGN(bld->wbuf_off) - bld->wbuf_off;
    assert(zfill_len <= vblock_unused_media_space(bld));
    memset(bld->wbuf + bld->wbuf_off, 0, zfill_len);
    bld->wbuf_off += zfill_len;

    assert(bld->wbuf_off <= bld->wbuf_len);
    assert(vblock_unused_media_space(bld) >= VBLOCK_FOOTER_LEN);

    vbfomf = bld->wbuf + bld->wbuf_off;
    memset(vbfomf, 0, VBLOCK_FOOTER_LEN);

    omf_set_vbf_magic(vbfomf, VBLOCK_FOOTER_MAGIC);
    omf_set_vbf_version(vbfomf, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(vbfomf, bld->vgroup);

    max_klen = key_obj_len(max_kobj);
    omf_set_vbf_min_klen(vbfomf, bld->cur_minklen);
    omf_set_vbf_max_klen(vbfomf, max_klen);
    omf_set_vbf_rsvd(vbfomf, 0);

    min_koff = bld->wbuf_off + VBLOCK_FOOTER_LEN - (2 * HSE_KVS_KEY_LEN_MAX);
    memcpy(bld->wbuf + min_koff, bld->cur_minkey, bld->cur_minklen);

    max_koff = min_koff + HSE_KVS_KEY_LEN_MAX;
    key_obj_copy(bld->wbuf + max_koff, HSE_KVS_KEY_LEN_MAX, &klen, max_kobj);
    assert(klen == max_klen);

    buflen = bld->wbuf_len;
    bld->wbuf_len = bld->wbuf_off + VBLOCK_FOOTER_LEN;
    err = vblock_write(bld);
    if (!err)
        bld->tot_vlen += (bld->wbuf_len - VBLOCK_FOOTER_LEN);
    bld->wbuf_len = buflen;

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
    struct mpool_mclass_props props;
    struct mclass_policy     *policy;
    struct vblock_builder    *bld;
    void                     *wbuf;
    merr_t                    err;

    assert(builder_out);

    wbuf = vlb_alloc(WBUF_LEN_MAX + sizeof(*bld));
    if (ev(!wbuf))
        return merr(ENOMEM);

    bld = wbuf + WBUF_LEN_MAX;

    memset(bld, 0, sizeof(*bld));
    bld->cn = cn;
    bld->pc = pc;
    bld->ds = cn_get_dataset(cn);
    bld->vgroup = vgroup;
    bld->agegroup = HSE_MPOLICY_AGE_LEAF;
    bld->wbuf = wbuf;

    policy = cn_get_mclass_policy(bld->cn);

    err = mpool_mclass_props_get(
        bld->ds, policy->mc_table[bld->agegroup][HSE_MPOLICY_DTYPE_VALUE], &props);
    if (err)
        return err;

    bld->max_size = props.mc_mblocksz;

    *builder_out = bld;

    return 0;
}

/* Destroy a vblock builder. Must also abort any mblocks left behind. */
void
vbb_destroy(struct vblock_builder *bld)
{
    if (ev(!bld))
        return;

    delete_mblocks(bld->ds, &bld->vblk_list);
    blk_list_free(&bld->vblk_list);

    vlb_free(bld->wbuf, WBUF_LEN_MAX + sizeof(*bld));
}

/* Add a value to vblock.  Create new vblock if needed. */
merr_t
vbb_add_entry(
    struct vblock_builder *bld,
    const struct key_obj  *kobj,
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

    if (HSE_UNLIKELY(!vblock_has_room(bld, vlen))) {
        err = vblock_finish(bld, kobj);
        if (ev(err))
            return err;
    }

    if (HSE_UNLIKELY(!bld->blkid)) {
        err = vblock_start(bld, kobj);
        if (ev(err))
            return err;
        assert(vblock_has_room(bld, vlen));
    }

    assert(bld->blkid);

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
            err = vblock_write(bld);
            if (ev(err))
                return err;
            bld->tot_vlen += bld->wbuf_len;
        }
    }

    assert(bld->wbuf_off < bld->wbuf_len);

    *vboffout = bld->vblk_off;
    *vbidxout = bld->vblk_list.idc - 1;
    *vbidout = bld->vblk_list.idv[*vbidxout];

    bld->vblk_off += vlen;
    bld->vsize += vlen;

    return 0;
}

/* Close out the current vblock, return IDs of all mblocks allocated so far,
 * and mark the builder as closed for business.
 */
merr_t
vbb_finish(struct vblock_builder *bld, struct blk_list *vblks, const struct key_obj *max_kobj)
{
    merr_t err;

    assert(!bld->destruct);

    bld->destruct = true;

    err = vblock_finish(bld, max_kobj);
    if (ev(err))
        return err;

    /* Transfer ownership of blk_list and the mblocks in
     * the blk_list to caller  */
    *vblks = bld->vblk_list;
    memset(&bld->vblk_list, 0, sizeof(bld->vblk_list));

    return 0;
}

merr_t
vbb_set_agegroup(struct vblock_builder *bld, enum hse_mclass_policy_age age)
{
    merr_t                    err;
    struct mclass_policy *    policy;
    struct mpool_mclass_props props;

    bld->agegroup = age;

    policy = cn_get_mclass_policy(bld->cn);

    err = mpool_mclass_props_get(
        bld->ds, policy->mc_table[bld->agegroup][HSE_MPOLICY_DTYPE_VALUE], &props);
    if (err)
        return err;

    bld->max_size = props.mc_mblocksz;

    return err;
}

enum hse_mclass_policy_age
vbb_get_agegroup(const struct vblock_builder *bld)
{
    return bld->agegroup;
}

void
vbb_set_merge_stats(struct vblock_builder *bld, struct cn_merge_stats *stats)
{
    bld->mstats = stats;
}

uint64_t
vbb_vlen_get(const struct vblock_builder *bld)
{
    return bld->tot_vlen;
}

#if HSE_MOCKING
#include "vblock_builder_ut_impl.i"
#endif /* HSE_MOCKING */
