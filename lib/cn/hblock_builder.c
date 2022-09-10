/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

 #define MTF_MOCK_IMPL_hblock_builder

#include <errno.h>
#include <stdlib.h>

#include <hse/limits.h>

#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_util/alloc.h>
#include <hse_util/event_counter.h>
#include <hse/error/merr.h>
#include <hse_util/hlog.h>
#include <hse_util/page.h>
#include <hse_util/storage.h>
#include <hse_util/perfc.h>

#include "hblock_builder.h"
#include "omf.h"
#include "wbt_builder.h"
#include "blk_list.h"
#include "kvset.h"
#include "cn_perfc.h"

struct hblock_builder {
    struct mpool              *mpool;
    const struct cn           *cn;
    struct wbb                *ptree;
    struct perfc_set          *pc;
    unsigned int               ptree_pgc;
    uint32_t                   max_size;
    uint32_t                   nptombs;
    enum hse_mclass_policy_age agegroup;
};

static unsigned int
available_pgc(struct hblock_builder *bld)
{
    return (bld->max_size / PAGE_SIZE) - HBLOCK_HDR_PAGES - HLOG_PGC;
}

static void HSE_NONNULL(1)
make_header(
    struct hblock_hdr_omf *hdr,
    const uint64_t min_seqno,
    const uint64_t max_seqno,
    const uint32_t num_ptombs,
    const uint32_t num_kblocks,
    const uint32_t num_vblocks,
    const uint32_t ptree_pgc,
    const uint32_t vgmap_pgc,
    const struct key_obj *const min_pfx,
    const struct key_obj *const max_pfx)
{
    /* If we have one, we must have both */
    assert(((min_pfx && max_pfx) || (!min_pfx && !max_pfx)));

    omf_set_hbh_magic(hdr, HBLOCK_HDR_MAGIC);
    omf_set_hbh_version(hdr, HBLOCK_HDR_VERSION);
    omf_set_hbh_min_seqno(hdr, min_seqno);
    omf_set_hbh_max_seqno(hdr, max_seqno);
    omf_set_hbh_num_ptombs(hdr, num_ptombs);
    omf_set_hbh_num_kblocks(hdr, num_kblocks);
    omf_set_hbh_num_vblocks(hdr, num_vblocks);
    omf_set_hbh_vgmap_off_pg(hdr, HBLOCK_HDR_PAGES);
    omf_set_hbh_vgmap_len_pg(hdr, vgmap_pgc);
    omf_set_hbh_hlog_off_pg(hdr, HBLOCK_HDR_PAGES + vgmap_pgc);
    omf_set_hbh_hlog_len_pg(hdr, HLOG_PGC);
    omf_set_hbh_ptree_data_off_pg(hdr, HBLOCK_HDR_PAGES + vgmap_pgc + HLOG_PGC);
    omf_set_hbh_ptree_data_len_pg(hdr, ptree_pgc);

    if (max_pfx) {
        unsigned int max_pfx_len = 0;

        max_pfx_len = key_obj_len(max_pfx);
        assert(max_pfx_len <= HSE_KVS_PFX_LEN_MAX);

        omf_set_hbh_max_pfx_off(hdr, BYTE_ALIGN(HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX));
        omf_set_hbh_max_pfx_len(hdr, max_pfx_len);

        key_obj_copy((void *)hdr + omf_hbh_max_pfx_off(hdr), HSE_KVS_PFX_LEN_MAX, NULL, max_pfx);
    } else {
        omf_set_hbh_max_pfx_off(hdr, BYTE_ALIGN(HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX));
        omf_set_hbh_max_pfx_len(hdr, 0);
    }

    if (min_pfx) {
        unsigned int min_pfx_len = 0;

        min_pfx_len = key_obj_len(min_pfx);
        assert(min_pfx_len <= HSE_KVS_PFX_LEN_MAX);

        omf_set_hbh_min_pfx_off(hdr, BYTE_ALIGN(HBLOCK_HDR_LEN - HSE_KVS_PFX_LEN_MAX));
        omf_set_hbh_min_pfx_len(hdr, min_pfx_len);

        key_obj_copy((void *)hdr + omf_hbh_min_pfx_off(hdr), HSE_KVS_PFX_LEN_MAX, NULL, min_pfx);
    } else {
        omf_set_hbh_max_pfx_off(hdr, BYTE_ALIGN(HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX));
        omf_set_hbh_max_pfx_len(hdr, 0);
    }
}

static void HSE_NONNULL(1)
make_vgroup_map(const struct vgmap *vgmap, void *outbuf)
{
    struct vgroup_map_omf *vgm_omf = outbuf;
    struct vgroup_map_entry_omf *vgme_omf;

    omf_set_vgm_magic(vgm_omf, VGROUP_MAP_MAGIC);
    omf_set_vgm_version(vgm_omf, VGROUP_MAP_VERSION);
    omf_set_vgm_count(vgm_omf, vgmap->nvgroups);
    omf_set_vgm_rsvd(vgm_omf, 0);

    vgme_omf = (void *)(vgm_omf + 1);
    for (uint32_t i = 0; i < vgmap->nvgroups; i++, vgme_omf++) {
        omf_set_vgme_vbidx(vgme_omf, vgmap->vbidx_out[i]);
        omf_set_vgme_vbadj(vgme_omf, vgmap->vbidx_adj[i]);
    }
}

merr_t
hbb_add_ptomb(
    struct hblock_builder *const bld,
    const struct key_obj *const kobj,
    const void *const kmd,
    uint kmd_len,
    struct key_stats *const stats)
{
    merr_t err;
    bool   added = false;

    assert(stats->nptombs > 0);

    err = wbb_add_entry(bld->ptree, kobj, stats->nptombs, 0, kmd, kmd_len,
        bld->max_size / PAGE_SIZE, &bld->ptree_pgc, &added);

    bld->nptombs += stats->nptombs;

    return !added ? merr(EXFULL) : err;
}

merr_t
hbb_create(struct hblock_builder **bld_out, const struct cn *const cn, struct perfc_set *pc)
{
    merr_t err;
    struct hblock_builder *bld;
    struct mclass_policy *policy;
    struct mpool_mclass_props props;

    bld = malloc(sizeof(*bld));
    if (!bld)
        return merr(ENOMEM);

    bld->nptombs = 0;
    bld->mpool = cn_get_dataset(cn);
    bld->cn = cn;
    bld->pc = pc;
    bld->agegroup = HSE_MPOLICY_AGE_LEAF;

    policy = cn_get_mclass_policy(cn);

    err = mpool_mclass_props_get(
        bld->mpool, policy->mc_table[bld->agegroup][HSE_MPOLICY_DTYPE_KEY], &props);
    if (err)
        goto out;

    bld->max_size = props.mc_mblocksz;

    err = wbb_create(&bld->ptree, bld->max_size / PAGE_SIZE, &bld->ptree_pgc);
    if (err)
        goto out;

out:
    if (err) {
        hbb_destroy(bld);
    } else {
        *bld_out = bld;
    }

    return err;
}

void
hbb_destroy(struct hblock_builder *bld)
{
    if (!bld)
        return;

    wbb_destroy(bld->ptree);
    free(bld);
}

merr_t
hbb_finish(
    struct hblock_builder *bld,
    struct kvs_block      *blk,
    const struct vgmap    *vgmap,
    struct key_obj        *min_pfxp,
    struct key_obj        *max_pfxp,
    const uint64_t         min_seqno,
    const uint64_t         max_seqno,
    const uint32_t         num_kblocks,
    const uint32_t         num_vblocks,
    const uint32_t         num_ptombs,
    const uint8_t         *hlog,
    const uint8_t         *ptree,
    uint32_t               ptree_pgc)
{
    merr_t err;
    enum hse_mclass mclass;
    uint64_t blkid = 0;
    uint32_t vgmap_pgc = 0;
    struct iovec *iov = NULL;
    unsigned int iov_max, iov_idx = 0;
    size_t wlen = 0, sz;
    unsigned int flags = 0;
    struct hblock_hdr_omf *hdr = NULL;
    struct mblock_props props;
    struct key_obj min_pfx = { 0 }, max_pfx = { 0 };
    struct mclass_policy *policy = cn_get_mclass_policy(bld->cn);

    if (!hlog)
        return merr(EINVAL);

    /* In the event that no kblocks were emitted and there are no entries in the
     * ptree, there is no data within containing kvset. Skip the allocation of
     * the hblock. This kvset will not be written to disk.
     */
    if (num_kblocks == 0 && !wbb_entries(bld->ptree))
        return 0;

    assert(min_seqno <= max_seqno);

    min_pfxp = min_pfxp ? min_pfxp : &min_pfx;
    max_pfxp = max_pfxp ? max_pfxp : &max_pfx;

    /* Header and HyperLogLog */
    iov_max = 2;

    if (vgmap) {
        iov_max++;
        sz = sizeof(struct vgroup_map_omf) + vgmap->nvgroups * sizeof(struct vgroup_map_entry_omf);
        vgmap_pgc = roundup(sz, PAGE_SIZE) / PAGE_SIZE;
        assert(vgmap_pgc > 0);
    }

    if (ptree && ptree_pgc > 0) {
        /* ptree is passed in during kvset split */
        iov_max += 1;
    } else if (wbb_entries(bld->ptree)) {
        /* Prefix tombstone tree nodev, internal nodes, KMD */
        iov_max += 1 + wbb_max_inodec_get(bld->ptree) + wbb_kmd_pgc_get(bld->ptree);
    }

    sz = HBLOCK_HDR_LEN + (vgmap ? (vgmap_pgc * PAGE_SIZE) : 0);
    hdr = aligned_alloc(PAGE_SIZE, sz);
    if (!hdr)
        return merr(ENOMEM);
    memset(hdr, 0, sz);

    iov = malloc(sizeof(*iov) * iov_max);
    if (!iov) {
        err = merr(ENOMEM);
        goto out;
    }

    /* Finalize header */
    iov[iov_idx].iov_base = hdr;
    iov[iov_idx++].iov_len = HBLOCK_HDR_LEN;

    if (vgmap) {
        /* Finalize vgroup map */
        iov[iov_idx].iov_base = (char *)hdr + HBLOCK_HDR_LEN;
        iov[iov_idx++].iov_len = sz - HBLOCK_HDR_LEN;
    }

    /* Finalize HyperLogLog */
    iov[iov_idx].iov_base = (void *)hlog;
    iov[iov_idx++].iov_len = HLOG_SIZE;

    wbb_hdr_init(&hdr->hbh_ptree_hdr);
    if (ptree && ptree_pgc > 0) {
        iov[iov_idx].iov_base = (void *)ptree;
        iov[iov_idx++].iov_len = ptree_pgc * PAGE_SIZE;
    } else if (wbb_entries(bld->ptree)) {
        /* Finalize prefix tombstone tree */
        unsigned int cnt;

        ptree_pgc = bld->ptree_pgc;
        err = wbb_freeze(
            bld->ptree, &hdr->hbh_ptree_hdr, bld->ptree_pgc + available_pgc(bld), &ptree_pgc,
            iov + iov_idx, iov_max, &cnt);
        if (err)
            goto out;
        iov_idx += cnt;

        wbb_min_max_keys(bld->ptree, min_pfxp, max_pfxp);
    }

    make_header(hdr, min_seqno, max_seqno, num_ptombs, num_kblocks, num_vblocks,
                ptree_pgc, vgmap_pgc, min_pfxp, max_pfxp);

    if (vgmap)
        make_vgroup_map(vgmap, ((char *)hdr) + HBLOCK_HDR_LEN);

    assert(iov_idx <= iov_max);

    mclass = mclass_policy_get_type(policy, bld->agegroup, HSE_MPOLICY_DTYPE_KEY);
    assert(mclass != HSE_MCLASS_INVALID);

    for (int i = 0; i < iov_idx; i++)
        wlen += iov[i].iov_len;

    /* Set preallocate flag if this hblock's write length >= 90% of the mblock size */
    if (wlen >= (bld->max_size * 9) / 10)
        flags |= MPOOL_MBLOCK_PREALLOC;

    err = mpool_mblock_alloc(bld->mpool, mclass, flags, &blkid, &props);
    if (err)
        goto out;

    err = mpool_mblock_write(bld->mpool, blkid, iov, iov_idx);
    if (err)
        goto out;

    perfc_inc(bld->pc, PERFC_RA_CNCOMP_WREQS);
    perfc_add(bld->pc, PERFC_RA_CNCOMP_WBYTES, wlen);

    blk->bk_blkid = blkid;

out:
    if (err) {
        if (blkid)
            mpool_mblock_delete(bld->mpool, blkid);
    }

    free(iov);
    free(hdr);

    return err;
}

merr_t
hbb_set_agegroup(struct hblock_builder *const bld, const enum hse_mclass_policy_age age)
{
    merr_t                    err;
    struct mclass_policy *    policy;
    struct mpool_mclass_props props;

    bld->agegroup = age;

    policy = cn_get_mclass_policy(bld->cn);

    err = mpool_mclass_props_get(
        bld->mpool, policy->mc_table[bld->agegroup][HSE_MPOLICY_DTYPE_KEY], &props);
    if (err)
        return err;

    /* [HSE_REVISIT]: WBT has already been created, changing this is not going
     * to do anything.
     */
    assert(bld->max_size == props.mc_mblocksz);

    bld->max_size = props.mc_mblocksz;

    return err;
}

uint32_t
hbb_get_nptombs(const struct hblock_builder *bld)
{
    return bld->nptombs;
}

#if HSE_MOCKING
#include "hblock_builder_ut_impl.i"
#endif /* HSE_MOCKING */
