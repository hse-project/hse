/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_kvset_builder

#include <hse/util/platform.h>
#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/event_counter.h>
#include <hse/util/bonsai_tree.h>

#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cn.h>

#include <hse/limits.h>

#include "kcompact.h"
#include "spill.h"

#include "hblock_builder.h"
#include "kblock_builder.h"
#include "vblock_builder.h"
#include "vblock_reader.h"
#include "blk_list.h"
#include "kvset_builder_internal.h"
#include "kvset.h"

merr_t
kvset_builder_create(
    struct kvset_builder **bld_out,
    struct cn *            cn,
    struct perfc_set *     pc,
    u64                    vgroup)
{
    struct kvset_builder *bld;
    merr_t err;

    bld = calloc(1, sizeof(*bld));
    if (ev(!bld))
        return merr(ENOMEM);

    bld->seqno_min = UINT64_MAX;

    err = hbb_create(&bld->hbb, cn, pc);
    if (ev(err))
        goto out;

    err = kbb_create(&bld->kbb, cn, pc);
    if (ev(err))
        goto out;

    err = vbb_create(&bld->vbb, cn, pc, vgroup);
    if (ev(err))
        goto out;

    bld->cn = cn;
    bld->seqno_prev = UINT64_MAX;
    bld->seqno_prev_ptomb = UINT64_MAX;

    *bld_out = bld;

    return 0;

out:
    kbb_destroy(bld->kbb);
    hbb_destroy(bld->hbb);
    free(bld);

    return err;
}

static int
reserve_kmd(struct kmd_info *ki)
{
    uint initial = 16*1024;
    uint need = 256;
    uint min_size = ki->kmd_used + need;
    uint new_size;
    u8 * new_mem;

    if (ki->kmd_size >= min_size)
        return 0;

    if (ki->kmd_size)
        new_size = 2 * ki->kmd_size;
    else
        new_size = initial;

    if (new_size < min_size)
        new_size = min_size;

    new_mem = malloc(new_size);
    if (ev(!new_mem))
        return -1;

    if (ki->kmd) {
        memcpy(new_mem, ki->kmd, ki->kmd_used);
        free(ki->kmd);
    }

    ki->kmd = new_mem;
    ki->kmd_size = new_size;
    return 0;
}

merr_t
kvset_builder_add_key(struct kvset_builder *self, const struct key_obj *kobj)
{
    merr_t err = 0;
    uint   klen;

    if (ev(!kobj))
        return merr(EINVAL);

    klen = key_obj_len(kobj);
    if (ev(!klen || klen > HSE_KVS_KEY_LEN_MAX))
        return merr(EINVAL);

    if (self->key_stats.nptombs > 0) {
        err = hbb_add_ptomb(self->hbb, kobj, self->hblk_kmd.kmd, self->hblk_kmd.kmd_used, &self->key_stats);
        if (ev(err))
            return err;

        /* track the highest seen ptomb if this is a capped cn */
        if (cn_get_flags(self->cn) & CN_CFLAG_CAPPED)
            key_obj_copy(self->last_ptomb, sizeof(self->last_ptomb), &self->last_ptlen, kobj);
    }

    if (self->key_stats.nvals > 0) {
        err = kbb_add_entry(self->kbb, kobj, self->kblk_kmd.kmd, self->kblk_kmd.kmd_used, &self->key_stats);
        if (ev(err))
            return err;
    }

    /* Reset for next key
     */
    self->key_stats.nvals = 0;
    self->key_stats.ntombs = 0;
    self->key_stats.tot_vlen = 0;
    self->key_stats.tot_vused = 0;
    self->key_stats.nptombs = 0;

    self->kblk_kmd.kmd_used = 0;
    self->hblk_kmd.kmd_used = 0;

    self->seqno_prev = UINT64_MAX;
    self->seqno_prev_ptomb = UINT64_MAX;

    return ev(err);
}

/**
 * kvset_builder_add_val() - Add a value or a tombstone to a kvset entry.
 * @builder: Kvset builder object.
 * @kobj: key object
 * @vdata: Pointer to @vlen bytes of uncompressed value data, @complen
 *         bytes of compressed value data, or a special tombstone pointer.
 * @vlen: Length of uncompressed value.
 * @seq: Sequence number of value or tombstone.
 * @complen: Length of compressed value if value is compressed. Must
 *           be set to 0 if value is not compressed.
 *
 * Notes on compression:
 * - If @complen > 0, then the value is already compressed and will be
 *   stored on media as is (even if compression is not enabled for this
 *   kvset).
 *
 * Special cases for tombstones:
 *  - If @vdata == %HSE_CORE_TOMB_PFX, then a prefix tombstone is added
 *    and @vlen is ignored.
 *  - If @vdata == %HSE_CORE_TOMB_REG, then a regular tombstone is added
 *    and @vlen is ignored.
 *  - If @vdata == NULL or @vlen == 0, then a zero-length value is added.
 *  - Otherwise, a non-zero length value is added.
 */
merr_t
kvset_builder_add_val(
    struct kvset_builder   *self,
    const struct key_obj   *kobj,
    const void             *vdata,
    uint                    vlen,
    u64                     seq,
    uint                    complen)
{
    merr_t           err;
    u64              seqno_prev;
    struct kmd_info *ki = vdata == HSE_CORE_TOMB_PFX ? &self->hblk_kmd : &self->kblk_kmd;

    if (ev(reserve_kmd(ki)))
        return merr(ENOMEM);

    if (vdata == HSE_CORE_TOMB_REG) {
        kmd_add_tomb(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq);
        self->key_stats.ntombs++;
    } else if (vdata == HSE_CORE_TOMB_PFX) {
        kmd_add_ptomb(self->hblk_kmd.kmd, &self->hblk_kmd.kmd_used, seq);
        self->key_stats.nptombs++;
        self->last_ptseq = seq;
    } else if (!vdata || vlen == 0) {
        kmd_add_zval(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq);
    } else if (complen == 0 && vlen <= CN_SMALL_VALUE_THRESHOLD) {
        /* Do not currently support compressed valus in KMD as an "ival", so
         * complen must be zero.
         */
        kmd_add_ival(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq, vdata, vlen);
        self->key_stats.tot_vlen += vlen;
    } else {

        uint vbidx = 0, vboff = 0;
        u64 vbid = 0;
        uint omlen; /* on media length */

        assert(vdata);

        /* add value to vblock */

        /* vblock builder needs on-media length */
        omlen = complen ? complen : vlen;
        err = vbb_add_entry(self->vbb, kobj, vdata, omlen, &vbid, &vbidx, &vboff);
        if (ev(err))
            return err;

        if (complen)
            kmd_add_cval(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq, vbidx, vboff, vlen, complen);
        else
            kmd_add_val(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq, vbidx, vboff, vlen);

        /* stats (and space amp) use on-media length */
        self->vused += omlen;
        self->key_stats.tot_vlen += omlen;
        self->key_stats.tot_vused += omlen;
    }

    self->seqno_max = max_t(u64, self->seqno_max, seq);
    self->seqno_min = min_t(u64, self->seqno_min, seq);

    if (vdata == HSE_CORE_TOMB_PFX) {
        seqno_prev = self->seqno_prev_ptomb;
        self->seqno_prev_ptomb = seq;
    } else {
        seqno_prev = self->seqno_prev;
        self->seqno_prev = seq;
        self->key_stats.nvals++;
    }

    assert(seq <= seqno_prev);

    if (seq > seqno_prev)
        return merr(ev(EINVAL));

    return 0;
}

/**
 * kvset_builder_add_vref() - add a VTYPE_UCVAL or VTYPE_CVAL entry its a kvset
 *
 * If @complen > 0, a VTYPE_CVAL entry will written to media.
 * If @complen == 0, a VTYPE_UCVAL entry will written to media.
 */
merr_t
kvset_builder_add_vref(
    struct kvset_builder   *self,
    u64                     seq,
    uint                    vbidx,
    uint                    vboff,
    uint                    vlen,
    uint                    complen)
{
    uint om_len = complen ? complen : vlen; /* on-media length */

    if (reserve_kmd(&self->kblk_kmd))
        return merr(ev(ENOMEM));

    if (complen > 0)
        kmd_add_cval(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq, vbidx, vboff, vlen, complen);
    else
        kmd_add_val(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq, vbidx, vboff, vlen);

    self->vused += om_len;
    self->key_stats.tot_vlen += om_len;
    self->key_stats.tot_vused += om_len;
    self->key_stats.nvals++;

    self->seqno_max = max_t(u64, self->seqno_max, seq);
    self->seqno_min = min_t(u64, self->seqno_min, seq);

    return 0;
}

merr_t
kvset_builder_add_nonval(struct kvset_builder *self, u64 seq, enum kmd_vtype vtype)
{
    struct kmd_info *ki = vtype == VTYPE_PTOMB ? &self->hblk_kmd : &self->kblk_kmd;

    if (reserve_kmd(ki))
        return merr(ev(ENOMEM));

    assert(vtype != VTYPE_ZVAL);
    if (vtype == VTYPE_TOMB) {
        kmd_add_tomb(self->kblk_kmd.kmd, &self->kblk_kmd.kmd_used, seq);
        self->key_stats.ntombs++;
        self->key_stats.nvals++;
    } else if (vtype == VTYPE_PTOMB) {
        kmd_add_ptomb(self->hblk_kmd.kmd, &self->hblk_kmd.kmd_used, seq);
        self->key_stats.nptombs++;
    } else {
        return merr(ev(EBUG));
    }

    self->seqno_max = max_t(u64, self->seqno_max, seq);
    self->seqno_min = min_t(u64, self->seqno_min, seq);

    return 0;
}

void
kvset_builder_adopt_vblocks(
    struct kvset_builder *self,
    size_t                num_vblocks,
    uint64_t             *vblock_ids,
    uint64_t              vtotal,
    struct vgmap         *vgmap)
{
    assert(self->vblk_list.idc == 0);

    self->vblk_list.idv = vblock_ids;
    self->vblk_list.idc = num_vblocks;
    self->vblk_list.n_alloc = num_vblocks;
    self->vtotal = vtotal;

    /* vgroup map is adopted from the compaction worker for k-compacts.
     * This map is established in kvset_keep_vblocks().
     */
    assert(!self->vgmap);
    self->vgmap = vgmap;
}

void
kvset_builder_destroy(struct kvset_builder *bld)
{
    struct mpool *mp;

    if (ev(!bld))
        return;

    mp = cn_get_mpool(bld->cn);

    delete_mblock(mp, bld->hblk_id);
    bld->hblk_id = 0;

    delete_mblocks(mp, &bld->kblk_list);
    blk_list_free(&bld->kblk_list);

    delete_mblocks(mp, &bld->vblk_list);
    blk_list_free(&bld->vblk_list);

    hbb_destroy(bld->hbb);
    kbb_destroy(bld->kbb);
    vbb_destroy(bld->vbb);

    vgmap_free(bld->vgmap);

    free(bld->kblk_kmd.kmd);
    free(bld->hblk_kmd.kmd);
    free(bld);
}

void
kvset_mblocks_destroy(struct kvset_mblocks *blks)
{
    if (blks) {
        blks->hblk_id = 0;
        blk_list_free(&blks->kblks);
        blk_list_free(&blks->vblks);
    }
}

static merr_t
kvset_builder_finish(struct kvset_builder *imp)
{
    merr_t err;
    bool adopted_vbs = (imp->vblk_list.idc > 0);

    INVARIANT(imp->hbb);
    INVARIANT(imp->kbb);
    INVARIANT(imp->vbb);

    if (!kbb_is_empty(imp->kbb)) {
        /* If we haven't adopted any vblocks previously */
        if (!adopted_vbs) {
            struct key_obj min_kobj = { 0 }, max_kobj = { 0 };

            kbb_curr_kblk_min_max_keys(imp->kbb, &min_kobj, &max_kobj);

            err = vbb_finish(imp->vbb, &imp->vblk_list, &max_kobj);
            if (err)
                return err;

            assert(!imp->vgmap);
            /* In the event we have vblocks, there will always be one vgroup. */
            if (imp->vblk_list.idc > 0) {
                imp->vgmap = vgmap_alloc(1);
                if (imp->vgmap) {
                    uint32_t vbidx_out = imp->vblk_list.idc - 1;
                    /* vgmap_src is passed as NULL as the kblocks are rewritten during
                     * ingest/spill/kv-compact.
                     */
                    err = vgmap_vbidx_set(NULL, vbidx_out, imp->vgmap, vbidx_out, 0);
                } else {
                    err = merr(ENOMEM);
                }

                if (!err) {
                    imp->vtotal = vbb_vlen_get(imp->vbb);
                } else {
                    delete_mblocks(cn_get_mpool(imp->cn), &imp->vblk_list);
                    return err;
                }
            }
        }
    } else {
        /* There are no kblocks. This happens when each input key has a
         * tombstone and we are in "drop_tomb" mode. This output kvset is empty
         * and should not be created. Destroy the corresponding hblock vblock
         * builder (which aborts any mblocks they had already allocated) and
         * move on. The empty kblk_list will prevent this kvset from being
         * created.
         */
        vbb_destroy(imp->vbb);
        imp->vbb = NULL;

        if (adopted_vbs) {
            blk_list_free(&imp->vblk_list);
            vgmap_free(imp->vgmap);
            imp->vgmap = NULL;
        }
    }

    err = kbb_finish(imp->kbb, &imp->kblk_list);
    if (err) {
        if (!adopted_vbs)
            delete_mblocks(cn_get_mpool(imp->cn), &imp->vblk_list);

        return err;
    }

    err = hbb_finish(imp->hbb, &imp->hblk_id, imp->vgmap, NULL, NULL, imp->seqno_min,
                     imp->seqno_max, imp->kblk_list.idc, imp->vblk_list.idc,
                     hbb_get_nptombs(imp->hbb), kbb_get_composite_hlog(imp->kbb), NULL, NULL, 0);
    if (err) {
        struct mpool *mp = cn_get_mpool(imp->cn);

        delete_mblocks(mp, &imp->kblk_list);
        if (!adopted_vbs)
            delete_mblocks(mp, &imp->vblk_list);

        return err;
    }

    return 0;
}

merr_t
kvset_builder_get_mblocks(struct kvset_builder *self, struct kvset_mblocks *mblks)
{
    merr_t           err;
    struct blk_list *list;

    err = kvset_builder_finish(self);
    if (ev(err))
        return err;

    /* transfer hblock to caller */
    mblks->hblk_id = self->hblk_id;
    self->hblk_id = 0;

    /* transfer kblock ids to caller */
    list = &self->kblk_list;
    mblks->kblks.idv = list->idv;
    mblks->kblks.idc = list->idc;
    list->idv = 0;
    list->idc = 0;

    /* transfer vblock ids to caller */
    list = &self->vblk_list;
    mblks->vblks.idv = list->idv;
    mblks->vblks.idc = list->idc;
    list->idv = 0;
    list->idc = 0;

    mblks->bl_vtotal = self->vtotal;
    mblks->bl_vused = self->vused;
    mblks->bl_seqno_max = self->seqno_max;
    mblks->bl_seqno_min = self->seqno_min;

    /* copy highest seen ptomb in the builder to cn */
    if (cn_get_flags(self->cn) & CN_CFLAG_CAPPED) {
        mblks->bl_last_ptomb = self->last_ptomb;
        mblks->bl_last_ptlen = self->last_ptlen;
        mblks->bl_last_ptseq = self->last_ptseq;
    }

    return 0;
}

void
kvset_builder_set_agegroup(struct kvset_builder *self, enum hse_mclass_policy_age age)
{
    INVARIANT(age < HSE_MPOLICY_AGE_CNT);

    hbb_set_agegroup(self->hbb, age);
    kbb_set_agegroup(self->kbb, age);
    vbb_set_agegroup(self->vbb, age);
}

void
kvset_builder_set_merge_stats(struct kvset_builder *self, struct cn_merge_stats *stats)
{
    kbb_set_merge_stats(self->kbb, stats);
    vbb_set_merge_stats(self->vbb, stats);
}

#if HSE_MOCKING
#include "kvset_builder_ut_impl.i"
#endif /* HSE_MOCKING */
