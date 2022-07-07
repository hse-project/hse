/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>
#include <hse_util/assert.h>
#include <hse_util/keycmp.h>
#include <hse_util/logging.h>

#include <hse/limits.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvset_builder.h>

#include <mpool/mpool.h>

#include "kvs_mblk_desc.h"
#include "kvset.h"
#include "kvset_split.h"
#include "kvset_internal.h"
#include "kblock_builder.h"
#include "kblock_reader.h"
#include "vblock_reader.h"
#include "wbt_reader.h"
#include "omf.h"
#include "cn_tree.h"
#include "cn_tree_internal.h"

/**
 * struct kvset_split_work - work struct for kvset split
 */
struct kvset_split_work {
    struct hlog           *hlog_left;  /* composite hlog for the left kvset */
    struct hlog           *hlog_right; /* composite hlog for the right kvset */

    struct hblock_builder *hbb_left;   /* hblock builder for the left hblock */
    struct hblock_builder *hbb_right;  /* hblock builder for the right hblock */
};

/**
 * kblock_copy_range() - copy all keys `k' in range start < k <= end from @kbd
 *
 * @kbd:      kblock descriptor
 * @start:    start key (exclusive)
 * @end :     end key (inclusive)
 * @kblks_out: (output) blklist of kblocks where the keys are copied into
 *
 * Notes:
 * (1) start == NULL implies a copy from the first key
 * (2) end == NULL implies a copy until EOF
 * (3) The output mblock in @kbid_out is not committed.
 *     It is left to the caller to either commit or abort it.
 * (4) This routine can generate > 1 output kblock due to some possible variability from key
 *     compression
 */
static merr_t
kblock_copy_range(
    struct kblock_desc   *kbd,
    const struct key_obj *start, /* exclusive */
    const struct key_obj *end,   /* inclusive */
    struct blk_list      *kblks_out)
{
    struct wbti *wbti = NULL;
    struct kblock_builder *kbb;
    struct key_obj cur = { 0 };
    const void *kmd;
    merr_t err;
    uint64_t tot_keys = 0;

    err = kbb_create(&kbb, kbd->cn, NULL);
    if (err)
        return err;

    if (start) {
        char kbuf[HSE_KVS_KEY_LEN_MAX];
        struct kvs_ktuple seek;
        uint klen;

        key_obj_copy(kbuf, sizeof(kbuf), &klen, start);
        kvs_ktuple_init_nohash(&seek, kbuf, klen);

        err = wbti_create(&wbti, kbd->kd_mbd->map_base, kbd->kd_wbd, &seek, false, false);
    } else {
        err = wbti_create(&wbti, kbd->kd_mbd->map_base, kbd->kd_wbd, NULL, false, false);
    }

    while (!err && wbti_next(wbti, &cur.ko_sfx, &cur.ko_sfx_len, &kmd)) {
        struct key_stats stats = { 0 };
        size_t off = 0, kmd_cnt_off;
        uint nvals;

        wbti_prefix(wbti, &cur.ko_pfx, &cur.ko_pfx_len);

        if (HSE_UNLIKELY(start && key_obj_cmp(&cur, start) == 0))
            continue;
        start = NULL;

        if (HSE_UNLIKELY(end && key_obj_cmp(&cur, end) > 0))
            break;

        nvals = stats.nvals = kmd_count(kmd, &off);
        kmd_cnt_off = off;

        while (nvals--) {
            struct kvs_vtuple_ref vref = { 0 };
            u64 vseq;

            /* Pass NULL for vgmap as vbidx is not used here */
            wbt_read_kmd_vref(kmd, NULL, &off, &vseq, &vref);

            switch (vref.vr_type) {
            case vtype_val:
            case vtype_cval:
                stats.tot_vlen += (vref.vb.vr_complen ? : vref.vb.vr_len);
                break;

            case vtype_ival:
                stats.tot_vlen += vref.vi.vr_len;
                break;

            case vtype_tomb:
                ++stats.ntombs;
                break;

            case vtype_zval:
                break;

            case vtype_ptomb:
            default:
                assert(0);
                break;
            }
        }

        err = kbb_add_entry(kbb, &cur, kmd + kmd_cnt_off, off - kmd_cnt_off, &stats);
        if (!err)
            ++tot_keys;
    }

    if (!err && tot_keys > 0) {
        err = kbb_finish(kbb, kblks_out);
        if(ev(!err && kblks_out->n_blks > 1)) {
            log_info("output kblks %d > 1", kblks_out->n_blks);
        }
    }

    wbti_destroy(wbti);
    kbb_destroy(kbb);

    return err;
}

/**
 * kblock_split() - split a given kblock (@kbd) into two kblocks at @split_key
 *
 * @kbd:        kblock descriptor describing the source kblock
 * @split_key:  the key at which the kblock needs to be split.
 * @kblks_left:  (output) blk list of kblocks containing keys <= split key
 * @kblks_right: (output) blk list of kblocks containing keys > split key
 *
 * NOTE:
 * If either @kbid_left or @kbid_right is not populated and err == 0, then all
 * keys from the source kblock got written to either @kbid_left or @kbid_right
 *
 * The output mblocks (@kbid_left and @kbid_right) are not committed when this
 * function returns. It is up to the caller to abort or commit them.
 */
static merr_t
kblock_split(
    struct kblock_desc   *kbd,
    const struct key_obj *split_key,
    struct blk_list      *kblks_left,
    struct blk_list      *kblks_right)
{
    merr_t err;

    INVARIANT(kbd && split_key && kblks_left && kblks_right);

    err = kblock_copy_range(kbd, NULL, split_key, kblks_left);
    if (!err) {
        err = kblock_copy_range(kbd, split_key, NULL, kblks_right);
        if (!err && (kblks_left->n_blks == 0 && kblks_right->n_blks == 0)) {
            assert(kblks_left->n_blks > 0 || kblks_right->n_blks > 0);
            err = merr(EBUG);
        }
    }

    return err;
}

/**
 * Return a split kblock index for the kblocks in a given kvset by comparing the
 * the min/max keys stored in a kblock header against the split key.
 *
 * Return values:
 *     -1: if all kblocks belongs to the right kvset                         // case 1
 *      i and *overlap = false: left: [0, i], right [i + 1, nkblks - 1]      // case 2
 *      i and *overlap = true:  left: [0, ileft], right [iright, nkblks - 1] // case 3
 */
static int
get_kblk_split_index(struct kvset *ks, const struct key_obj *split_kobj, bool *overlap)
{
    char split_key[HSE_KVS_KEY_LEN_MAX];
    uint32_t split_klen;
    int i;

    *overlap = false;

    key_obj_copy(split_key, sizeof(split_key), &split_klen, split_kobj);

    for (i = 0; i < ks->ks_st.kst_kblks; i++) {
        struct kvset_kblk *kblk = ks->ks_kblks + i;
        int rc1;

        rc1 = keycmp(split_key, split_klen, kblk->kb_koff_min, kblk->kb_klen_min);
        if (rc1 < 0) {
            return i - 1; /* case 1, 2 */
        } else {
            int rc2 = keycmp(split_key, split_klen, kblk->kb_koff_max, kblk->kb_klen_max);
            if (rc2 <= 0) {
                *overlap = (rc2 < 0);
                return i; /* case 2, 3 */
            }
        }
    }

    return ks->ks_st.kst_kblks - 1; /* case 2 */
}

static merr_t
kvset_split_kblocks(
    struct kvset            *ks,
    const struct key_obj    *split_kobj,
    struct kvset_split_work *work,
    struct kvset_split_res  *result)
{
    bool overlap = false;
    int i, split_idx;
    void *hlog;

    split_idx = get_kblk_split_index(ks, split_kobj, &overlap);
    assert(split_idx >= -1 && split_idx < (int)ks->ks_st.kst_kblks);
    assert(split_idx >= 0 || !overlap);

    /* Add kblocks in [0, split_idx - 1] to the left kvset
     * Also generate a composite hlog for the left kvset and the right kvset
     */
    for (i = 0; i < split_idx; i++) {
        blk_list_append(&result->blks_left.kblks, ks->ks_kblks[i].kb_kblk.bk_blkid);

        kbr_read_hlog(&ks->ks_kblks[i].kb_kblk_desc, &hlog);
        hlog_union(work->hlog_left, hlog);
    }

    if (overlap) { /* split kblock at split_idx */
        struct kvset_kblk *kblk = &ks->ks_kblks[split_idx];
        struct kblock_desc kbd;
        struct blk_list kblks_left, kblks_right;
        merr_t err;

        kbd.cn = cn_tree_get_cn(ks->ks_tree);
        kbd.kd_mbd = &kblk->kb_kblk_desc;
        kbd.kd_wbd = &kblk->kb_wbt_desc;

        blk_list_init(&kblks_left);
        blk_list_init(&kblks_right);

        err = kblock_split(&kbd, split_kobj, &kblks_left, &kblks_right);
        if (err)
            return err;
        assert(kblks_left.n_blks > 0 && kblks_right.n_blks > 0);

        /* Append kblks_left to the left kvset, kblks_right to the right kvset, and both
         * kblks_left and kblks_right to the commit list
         */
        for (i = 0; i < kblks_left.n_blks; i++) {
            uint64_t blkid = kblks_left.blks[i].bk_blkid;

            blk_list_append(&result->blks_left.kblks, blkid);
            blk_list_append(&result->blks_commit, blkid);
        }

        for (i = 0; i < kblks_right.n_blks; i++) {
            uint64_t blkid = kblks_right.blks[i].bk_blkid;

            blk_list_append(&result->blks_right.kblks, blkid);
            blk_list_append(&result->blks_commit, blkid);
        }

        /* TODO: Would be accurate here to use the left and right kblock's hlog?
         */
        kbr_read_hlog(&kblk->kb_kblk_desc, &hlog);
        hlog_union(work->hlog_left, hlog);
        hlog_union(work->hlog_right, hlog);

        /* Add the source kblock to the purge list to be destroyed later */
        blk_list_append(&result->blks_purge, kblk->kb_kblk.bk_blkid);
    } else if (split_idx >= 0) { /* no overlap, append this kblock to the left kvset */
        blk_list_append(&result->blks_left.kblks, ks->ks_kblks[split_idx].kb_kblk.bk_blkid);

        kbr_read_hlog(&ks->ks_kblks[split_idx].kb_kblk_desc, &hlog);
        hlog_union(work->hlog_left, hlog);
    }

    /* Add kblocks in [split_idx + 1, nkblks - 1] to the left kvset
     */
    for (i = split_idx + 1; i < ks->ks_st.kst_kblks; i++) {
        blk_list_append(&result->blks_right.kblks, ks->ks_kblks[i].kb_kblk.bk_blkid);

        kbr_read_hlog(&ks->ks_kblks[i].kb_kblk_desc, &hlog);
        hlog_union(work->hlog_right, hlog);
    }

    return 0;
}

/**
 * Return a split vblock index for the specified range of vblocks [start, end] by comparing
 * the min/max keys stored in a vblock footer against the split key.
 *
 * Return values:
 *     start - 1: if all vblocks belongs to the right kvset             // case 1
 *     i and *overlap = false: left: [start, i], right [i + 1, end]     // case 2
 *     i and *overlap = true:  left: [start, i], right [clone(i), end]  // case 3
 */
static int
get_vblk_split_index(
    struct kvset *ks,
    int           start, /* inclusive */
    int           end,   /* inclusive */
    const void   *split_key,
    uint32_t      split_klen,
    bool         *overlap)
{
    int i;

    *overlap = false;
    assert(start <= end && end < kvset_get_num_vblocks(ks));

    for (i = start; i <= end; i++) {
        struct vblock_desc *vbd = kvset_get_nth_vblock_desc(ks, i);
        const void *min_key = vbd->vbd_mblkdesc.map_base + vbd->vbd_min_koff;
        const void *max_key = vbd->vbd_mblkdesc.map_base + vbd->vbd_max_koff;
        int rc1;

        rc1 = keycmp(split_key, split_klen, min_key, vbd->vbd_min_klen);
        if (rc1 < 0) {
            return i - 1; /* case 1, 2 */
        } else {
            int rc2 = keycmp(split_key, split_klen, max_key, vbd->vbd_max_klen);
            if (rc2 < 0) {
                *overlap = true;
                return i; /* case 2, 3 */
            }
        }
    }

    return end; /* case 2 */
}

static merr_t
kvset_split_vblocks(
    struct kvset           *ks,
    const struct key_obj   *split_kobj,
    struct kvset_split_res *result)
{
    struct kvset_vgroup_map *vgmap_src = ks->ks_vgmap;
    struct kvset_vgroup_map *vgmap_left = result->vgmap_left, *vgmap_right = result->vgmap_right;
    int vbidx_left = 0, vbidx_right = 0; /* tracks vblock index for the left and right kvsets */
    int vgidx_left = 0, vgidx_right = 0; /* tracks vgroup index for the left and right kvsets */
    char split_key[HSE_KVS_KEY_LEN_MAX];
    uint32_t split_klen, nvgroups = kvset_get_vgroups(ks);
    int i;

    key_obj_copy(split_key, sizeof(split_key), &split_klen, split_kobj);

    for (i = 0; i < nvgroups; i++) {
        int src_start, src_end, src_split;
        int j, vbcnt = 0;
        bool overlap = false;

        /* Per vgroup start and end output vblock index in the source kvset
         */
        src_start = kvset_vgmap_vbidx_out_start(ks, i);
        src_end = kvset_vgmap_vbidx_out_end(ks, i);

        /* Per vgroup split output vblock index in the source kvset. This index is inclusive
         */
        src_split = get_vblk_split_index(ks, src_start, src_end, split_key, split_klen, &overlap);
        assert(src_split >= src_start - 1 && src_split <= src_end);

        /* Add vblocks in [src_start, src_split] to the left kvset
         */
        for (j = src_start; j <= src_split; j++) {
            blk_list_append(&result->blks_left.vblks, kvset_get_nth_vblock_id(ks, j));
            vbcnt++;
        }

        if (vbcnt > 0) {
            vbidx_left += vbcnt;
            kvset_vgmap_vbidx_set(vgmap_src, src_split, vgmap_left, vbidx_left - 1, vgidx_left);
            vgidx_left++;
        }

        vbcnt = 0; /* reset vbcnt for the right kvset */
        if (overlap) { /* append a clone of the overlapping vblock to the right kvset */
            uint64_t src_mbid = kvset_get_nth_vblock_id(ks, src_split), clone_mbid;
            merr_t err;

            err = mpool_mblock_clone(ks->ks_mp, src_mbid, 0, 0, &clone_mbid);
            if (err)
                return err;

            /* mpool_mblock_clone returns a committed mblock, need not add to the commit blklist */
            blk_list_append(&result->blks_right.vblks, clone_mbid);
            vbcnt++;
        }

        /* Add the remaining vblocks in [src_split + 1, src_end] to the right kvset
         */
        for (j = src_split + 1; j <= src_end; j++) {
            blk_list_append(&result->blks_right.vblks, kvset_get_nth_vblock_id(ks, j));
            vbcnt++;
        }

        if (vbcnt > 0) {
            vbidx_right += vbcnt;
            kvset_vgmap_vbidx_set(vgmap_src, src_end, vgmap_right, vbidx_right - 1, vgidx_right);
            vgidx_right++;
        }
    }

    assert(vgidx_left <= nvgroups);
    assert(vgidx_right <= nvgroups);

    vgmap_left->nvgroups = vgidx_left;
    vgmap_right->nvgroups = vgidx_right;

    return 0;
}

/**
 * The hblock is rewritten in the left and the right kvsets by duplicating the following
 * fields from the hblock in the source kvset:
 *   - min/max seqno, min/max prefix, ptomb tree and its related fields
 *
 * The following fields are regenerated for the left and the right kvsets:
 *   - hlog and vgroup map
 */
static merr_t
kvset_split_hblock(
    struct kvset            *ks,
    struct kvset_split_work *work,
    struct kvset_split_res  *result)
{
    struct kvs_block hblk;
    struct key_obj min_pfx = { 0 }, max_pfx = { 0 };
    uint32_t num_ptombs, ptree_pgc;
    uint64_t min_seqno, max_seqno;
    void *ptree;
    merr_t err;

    min_seqno = ks->ks_hblk.kh_seqno_min;
    max_seqno = ks->ks_hblk.kh_seqno_max;
    num_ptombs = ks->ks_hblk.kh_metrics.hm_nptombs;

    key2kobj(&min_pfx, ks->ks_hblk.kh_pfx_min, ks->ks_hblk.kh_pfx_min_len);
    key2kobj(&max_pfx, ks->ks_hblk.kh_pfx_max, ks->ks_hblk.kh_pfx_max_len);

    ptree = ks->ks_hblk.kh_hblk_desc.map_base +
        ks->ks_hblk.kh_ptree_desc.wbd_first_page * PAGE_SIZE;
    ptree_pgc = ks->ks_hblk.kh_ptree_desc.wbd_n_pages;

    /* Add both the left and the right hblock to the commit list and add the source hblock
     * to the purge list.
     */
    if (result->blks_left.kblks.n_blks > 0 || ptree_pgc > 0) {
        err = hbb_finish(work->hbb_left, &hblk, result->vgmap_left,
                         &min_pfx, &max_pfx, min_seqno, max_seqno,
                         result->blks_left.kblks.n_blks, result->blks_left.vblks.n_blks,
                         num_ptombs, hlog_data(work->hlog_left), ptree, ptree_pgc);
        if (err)
            return err;

        result->blks_left.hblk = hblk;
        blk_list_append(&result->blks_commit, hblk.bk_blkid);
    }

    if (result->blks_right.kblks.n_blks > 0 || ptree_pgc > 0) {
        err = hbb_finish(work->hbb_right, &hblk, result->vgmap_right,
                         &min_pfx, &max_pfx, min_seqno, max_seqno,
                         result->blks_right.kblks.n_blks, result->blks_right.vblks.n_blks,
                         num_ptombs, hlog_data(work->hlog_right), ptree, ptree_pgc);
        if (err)
            return err;

        result->blks_right.hblk = hblk;
        blk_list_append(&result->blks_commit, hblk.bk_blkid);
    }

    blk_list_append(&result->blks_purge, ks->ks_hblk.kh_hblk_desc.mbid);

    return 0;
}

static void
kvset_split_free(
    struct kvset            *ks,
    struct kvset_split_work *work,
    struct kvset_split_res  *result,
    bool                     del_mblks)
{
    hbb_destroy(work->hbb_left);
    hbb_destroy(work->hbb_right);

    hlog_destroy(work->hlog_left);
    hlog_destroy(work->hlog_right);

    blk_list_free(&result->blks_left.kblks);
    blk_list_free(&result->blks_right.kblks);

    blk_list_free(&result->blks_left.vblks);
    blk_list_free(&result->blks_right.vblks);

    blk_list_free(&result->blks_purge);

    for (int i = 0; del_mblks && i < result->blks_commit.n_blks; i++)
        delete_mblock(ks->ks_mp, &result->blks_commit.blks[i]);
    blk_list_free(&result->blks_commit);

    kvset_vgmap_free(result->vgmap_left);
    kvset_vgmap_free(result->vgmap_right);
}

static merr_t
kvset_split_alloc(
    struct kvset            *ks,
    struct kvset_split_work *work,
    struct kvset_split_res  *result)
{
    struct cn *cn = cn_tree_get_cn(ks->ks_tree);
    merr_t err = 0;
    uint32_t nvgroups = kvset_get_vgroups(ks);

    memset(result, 0, sizeof(*result));

    result->vgmap_left = kvset_vgmap_alloc(nvgroups);
    result->vgmap_right = kvset_vgmap_alloc(nvgroups);
    if (!result->vgmap_left || !result->vgmap_right) {
        err = merr(ENOMEM);
        goto errout;
    }

    err = hbb_create(&work->hbb_left, cn);
    if (err)
        goto errout;

    err = hbb_create(&work->hbb_right, cn);
    if (err)
        goto errout;

    err = hlog_create(&work->hlog_left, HLOG_PRECISION);
    if (err)
        goto errout;

    err = hlog_create(&work->hlog_right, HLOG_PRECISION);
    if (err)
        goto errout;

    blk_list_init(&result->blks_left.kblks);
    blk_list_init(&result->blks_right.kblks);

    blk_list_init(&result->blks_left.vblks);
    blk_list_init(&result->blks_right.vblks);

    blk_list_init(&result->blks_purge);
    blk_list_init(&result->blks_commit);

errout:
    if (err)
        kvset_split_free(ks, work, result, false);

    return err;
}

merr_t
kvset_split(
    struct kvset           *ks,
    const struct key_obj   *split_kobj,
    struct kvset_split_res *result)
{
    struct kvset_split_work work = { 0 };
    merr_t err;

    err = kvset_split_alloc(ks, &work, result);
    if (err)
        return err;

    err = kvset_split_kblocks(ks, split_kobj, &work, result);
    if (err)
        goto errout;

    err = kvset_split_vblocks(ks, split_kobj, result);
    if (err)
        goto errout;

    err = kvset_split_hblock(ks, &work, result);
    if (err)
        goto errout;

errout:
    if (err)
        kvset_split_free(ks, &work, result, true);

    return err;
}
