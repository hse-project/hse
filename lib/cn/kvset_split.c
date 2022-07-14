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
#include "hblock_reader.h"
#include "wbt_reader.h"
#include "omf.h"
#include "cn_tree.h"
#include "cn_tree_internal.h"

/**
 * struct kvset_split_work - work struct for kvset split
 */
enum { LEFT = 0, RIGHT = 1 };

struct kvset_split_work {
    struct hlog           *hlog;    /* composite hlog */
    struct hblock_builder *hbb;     /* hblock builder */
    struct vgmap          *vgmap;   /* vgroup map */
};

static void
kvset_split_free(
    struct kvset            *ks,
    struct kvset_split_work *work,
    struct kvset_split_res  *result,
    bool                     del_mblks)
{
    for (int i = LEFT; i <= RIGHT; i++) {
        hbb_destroy(work[i].hbb);
        hlog_destroy(work[i].hlog);
        vgmap_free(work[i].vgmap);
        blk_list_free(&result->blks[i].kblks);
        blk_list_free(&result->blks[i].vblks);
    }

    blk_list_free(&result->blks_purge);

    for (uint32_t i = 0; del_mblks && i < result->blks_commit.n_blks; i++)
        delete_mblock(ks->ks_mp, &result->blks_commit.blks[i]);

    blk_list_free(&result->blks_commit);
}

static merr_t
kvset_split_alloc(
    struct kvset            *ks,
    struct kvset_split_work *work,
    struct kvset_split_res  *result)
{
    struct cn *cn = cn_tree_get_cn(ks->ks_tree);
    merr_t err;
    uint32_t nvgroups = kvset_get_vgroups(ks);

    memset(result, 0, sizeof(*result));

    for (int i = LEFT; i <= RIGHT; i++) {
        if (nvgroups > 0) {
            work[i].vgmap = vgmap_alloc(nvgroups);
            if (!work[i].vgmap) {
                err = merr(ENOMEM);
                goto errout;
            }
        }

        err = hbb_create(&work[i].hbb, cn);
        if (err)
            goto errout;

        err = hlog_create(&work[i].hlog, HLOG_PRECISION);
        if (err)
            goto errout;

        blk_list_init(&result->blks[i].kblks);
        blk_list_init(&result->blks[i].vblks);
    }

    blk_list_init(&result->blks_purge);
    blk_list_init(&result->blks_commit);

    return 0;

errout:
    kvset_split_free(ks, work, result, false);

    return err;
}

/**
 * kblock_copy_range() - copy all keys 'k' in range start < k <= end from @kbd
 *
 * @kbd:       kblock descriptor
 * @start:     start key (exclusive)
 * @end :      end key (inclusive)
 * @kblks_out: (output) blklist of kblocks where the keys are copied into
 *
 * Notes:
 * (1) start == NULL implies a copy from the first key
 * (2) end == NULL implies a copy until EOF
 * (3) The output mblock(s) in @kblks_out is not committed.
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
            uint64_t vseq;

            /* Pass NULL for vgmap as vbidx is not used here */
            wbt_read_kmd_vref(kmd, NULL, &off, &vseq, &vref);

            switch (vref.vr_type) {
            case vtype_val:
            case vtype_cval:
                stats.tot_vlen += (vref.vb.vr_complen ? vref.vb.vr_complen : vref.vb.vr_len);
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
                abort();
            }
        }

        err = kbb_add_entry(kbb, &cur, kmd + kmd_cnt_off, off - kmd_cnt_off, &stats);
        if (!err)
            ++tot_keys;
    }

    if (!err && tot_keys > 0) {
        err = kbb_finish(kbb, kblks_out);
        if (ev(!err && kblks_out->n_blks > 1))
            log_debug("output kblks %d > 1", kblks_out->n_blks);
    }

    wbti_destroy(wbti);
    kbb_destroy(kbb);

    return err;
}

/**
 * kblock_split() - split a given kblock (@kbd) into two kblocks at @split_key
 *
 * @kbd:          kblock descriptor describing the source kblock
 * @split_key:    the key at which the kblock needs to be split.
 * @kblks:        (output) blk list of kblocks containing keys <= split key and keys > split key
 *
 * NOTES:
 * If either @kblks[LEFT] or @kblks[RIGHT] is not populated and err == 0, then all
 * keys from the source kblock got written to either @kblks[left] or @kblks[RIGHT]
 *
 * The output mblocks (@kblks[LEFT] and @kblks[RIGHT]) are not committed when this
 * function returns. It is up to the caller to abort or commit them.
 */
static merr_t
kblock_split(
    struct kblock_desc   *kbd,
    const struct key_obj *split_key,
    struct blk_list      *kblks)
{
    merr_t err;

    INVARIANT(kbd && split_key && kblks);

    err = kblock_copy_range(kbd, NULL, split_key, &kblks[LEFT]);
    if (!err) {
        err = kblock_copy_range(kbd, split_key, NULL, &kblks[RIGHT]);
        if (!err && (kblks[LEFT].n_blks == 0 && kblks[RIGHT].n_blks == 0)) {
            assert(kblks[LEFT].n_blks > 0 || kblks[RIGHT].n_blks > 0);
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
 *      k >= 0 and overlap = false: left: [0, k - 1], right [k, nkblks - 1]
 *      k >= 0 and overlap = true : left: [0, left(k)], right [right(k), nkblks - 1]
 *
 * NOTES:
 *      k = 0 and overlap = false:      All kblocks go to the right
 *      k = nkblks and overlap = false: All kblocks go to the left
 */
static uint32_t
get_kblk_split_index(struct kvset *ks, const struct key_obj *split_kobj, bool *overlap)
{
    char split_key[HSE_KVS_KEY_LEN_MAX];
    uint32_t split_klen, k;

    INVARIANT(ks && split_kobj && overlap);

    *overlap = false;

    key_obj_copy(split_key, sizeof(split_key), &split_klen, split_kobj);

    for (k = 0; k < ks->ks_st.kst_kblks; k++) {
        struct kvset_kblk *kblk = ks->ks_kblks + k;

        if (keycmp(split_key, split_klen, kblk->kb_koff_min, kblk->kb_klen_min) < 0)
            break;
    }

    if (k > 0) {
        struct kvset_kblk *kblk = ks->ks_kblks + k - 1;

        if (keycmp(split_key, split_klen, kblk->kb_koff_max, kblk->kb_klen_max) < 0) {
            *overlap = true;

            return k - 1;
        }
    }

    return k;
}

static merr_t
kblocks_split(
    struct kvset            *ks,
    const struct key_obj    *split_kobj,
    struct kvset_split_work *work,
    struct kvset_split_res  *result)
{
    struct hlog *hlog_left = work[LEFT].hlog;
    struct hlog *hlog_right = work[RIGHT].hlog;
    struct kvset_mblocks *blks_left = &result->blks[LEFT];
    struct kvset_mblocks *blks_right = &result->blks[RIGHT];
    bool overlap = false;
    uint32_t split_idx;
    uint8_t *hlog;
    merr_t err;

    split_idx = get_kblk_split_index(ks, split_kobj, &overlap);
    assert(split_idx <= ks->ks_st.kst_kblks);

    /* Add kblocks in [0, split_idx - 1] to the left kvset
     * Also generate a composite hlog for the left kvset and the right kvset
     */
    for (uint32_t i = 0; i < split_idx; i++) {
        err = blk_list_append(&blks_left->kblks, ks->ks_kblks[i].kb_kblk.bk_blkid);
        if (err)
            goto errout;

        kbr_read_hlog(&ks->ks_kblks[i].kb_kblk_desc, &hlog);
        hlog_union(hlog_left, hlog);
    }

    if (overlap) {
        struct kvset_kblk *kblk = &ks->ks_kblks[split_idx];
        struct kblock_desc kbd;
        struct blk_list kblks[2];
        merr_t err;

        kbd.cn = cn_tree_get_cn(ks->ks_tree);
        kbd.kd_mbd = &kblk->kb_kblk_desc;
        kbd.kd_wbd = &kblk->kb_wbt_desc;

        for (int i = LEFT; i <= RIGHT; i++)
            blk_list_init(&kblks[i]);

        /* split kblock at split_idx */
        err = kblock_split(&kbd, split_kobj, kblks);
        if (err)
            goto errout;
        assert(kblks[LEFT].n_blks > 0 && kblks[RIGHT].n_blks > 0);

        /* Append kblks[LEFT] to the left kvset, kblks[RIGHT] to the right kvset, and both
         * kblks[LEFT] and kblks[RIGHT] to the commit list
         */
        for (uint32_t i = 0; i < kblks[LEFT].n_blks; i++) {
            uint64_t blkid = kblks[LEFT].blks[i].bk_blkid;

            err = blk_list_append(&blks_left->kblks, blkid);
            if (!err)
                err = blk_list_append(&result->blks_commit, blkid);

            if (err)
                goto errout;
        }

        for (uint32_t i = 0; i < kblks[RIGHT].n_blks; i++) {
            uint64_t blkid = kblks[RIGHT].blks[i].bk_blkid;

            err = blk_list_append(&blks_right->kblks, blkid);
            if (!err)
                err = blk_list_append(&result->blks_commit, blkid);

            if (err)
                goto errout;
        }

        /* TODO: Would it be accurate to use the left and right kblock's hlog here?
         */
        kbr_read_hlog(&kblk->kb_kblk_desc, &hlog);
        hlog_union(hlog_left, hlog);
        hlog_union(hlog_right, hlog);

        /* Add the source kblock to the purge list to be destroyed later */
        err = blk_list_append(&result->blks_purge, kblk->kb_kblk.bk_blkid);
        if (err)
            goto errout;

        split_idx++;
    }

    /* Add kblocks in [split_idx, nkblks - 1] to the right kvset
     */
    for (uint32_t i = split_idx; i < ks->ks_st.kst_kblks; i++) {
        err = blk_list_append(&blks_right->kblks, ks->ks_kblks[i].kb_kblk.bk_blkid);
        if (err)
            goto errout;

        kbr_read_hlog(&ks->ks_kblks[i].kb_kblk_desc, &hlog);
        hlog_union(hlog_right, hlog);
    }

    return 0;

errout:
    kvset_split_free(ks, work, result, true);

    return err;
}

/**
 * Return a split vblock index for the specified range of vblocks [start, end] by comparing
 * the min/max keys stored in a vblock footer against the split key.
 *
 * Return values:
 *     v >= start and overlap = false: left: [start, v - 1], right [v, end]
 *     v >= start and overlap = true : left: [start, v], right [clone(v), end]
 *
 * NOTES:
 *     v = start and overlap = false:   All vblocks go to the right
 *     v = end + 1 and overlap = false: All vblocks go to the left
 */
static uint16_t
get_vblk_split_index(
    struct kvset *ks,
    uint16_t      start, /* inclusive */
    uint16_t      end,   /* inclusive */
    const void   *split_key,
    uint32_t      split_klen,
    bool         *overlap)
{
    uint16_t v;

    INVARIANT(ks && split_key && overlap);

    *overlap = false;
    assert(start <= end && end < kvset_get_num_vblocks(ks));

    for (v = start; v <= end; v++) {
        struct vblock_desc *vbd = kvset_get_nth_vblock_desc(ks, v);
        const void *min_key = vbd->vbd_mblkdesc.map_base + vbd->vbd_min_koff;

        if (keycmp(split_key, split_klen, min_key, vbd->vbd_min_klen) < 0)
            break;
    }

    if (v > start) {
        struct vblock_desc *vbd = kvset_get_nth_vblock_desc(ks, v - 1);
        const void *max_key = vbd->vbd_mblkdesc.map_base + vbd->vbd_max_koff;

        if (keycmp(split_key, split_klen, max_key, vbd->vbd_max_klen) < 0) {
            *overlap = true;
            return v - 1;
        }
    }

    return v;
}

/**
 * @vbidx_left, @vbidx_right - tracks vblock index for the left and right kvsets
 * @vgidx_left, @vgidx_right - tracks vgroup index for the left and right kvsets
 *
 */
static merr_t
vblocks_split(
    struct kvset            *ks,
    const struct key_obj    *split_kobj,
    struct kvset_split_work *work,
    struct kvset_split_res  *result)
{
    struct vgmap *vgmap_src = ks->ks_vgmap;
    struct vgmap *vgmap_left = work[LEFT].vgmap;
    struct vgmap *vgmap_right = work[RIGHT].vgmap;
    uint16_t vbidx_left = 0, vbidx_right = 0;
    uint32_t vgidx_left = 0, vgidx_right = 0;
    char split_key[HSE_KVS_KEY_LEN_MAX];
    uint32_t split_klen, nvgroups = kvset_get_vgroups(ks);
    merr_t err;

    key_obj_copy(split_key, sizeof(split_key), &split_klen, split_kobj);

    for (uint32_t i = 0; i < nvgroups; i++) {
        uint16_t src_start, src_end, src_split, end;
        uint32_t vbcnt = 0;
        bool overlap = false;

        /* Per vgroup start and end output vblock index in the source kvset
         */
        src_start = vgmap_vbidx_out_start(ks, i);
        src_end = vgmap_vbidx_out_end(ks, i);

        src_split = get_vblk_split_index(ks, src_start, src_end, split_key, split_klen, &overlap);
        assert(src_split >= src_start && src_split <= src_end + 1);

        /* Add vblocks in [src_start, end - 1] to the left kvset
         */
        end = overlap ? src_split + 1 : src_split;
        for (uint16_t j = src_start; j < end; j++) {
            err = blk_list_append(&result->blks[LEFT].vblks, kvset_get_nth_vblock_id(ks, j));
            if (err)
                goto errout;
            vbcnt++;
        }

        if (vbcnt > 0) {
            vbidx_left += vbcnt;
            err = vgmap_vbidx_set(vgmap_src, end - 1, vgmap_left, vbidx_left - 1, vgidx_left);
            if (err)
                goto errout;
            vgidx_left++;
        }

        vbcnt = 0; /* reset vbcnt for the right kvset */
        if (overlap) {
            /* Append a clone of the overlapping vblock to the right kvset */
            const uint64_t src_mbid = kvset_get_nth_vblock_id(ks, src_split);
            uint64_t clone_mbid;

            err = mpool_mblock_clone(ks->ks_mp, src_mbid, 0, 0, &clone_mbid);
            if (!err) {
                /* mpool_mblock_clone returns a committed mblock, do not add to the commit list */
                err = blk_list_append(&result->blks[RIGHT].vblks, clone_mbid);
                if (err)
                    goto errout;
            }

            vbcnt++;
            src_split++;
        }

        /* Add the remaining vblocks in [src_split, src_end] to the right kvset
         */
        for (uint16_t j = src_split; j <= src_end; j++) {
            err = blk_list_append(&result->blks[RIGHT].vblks, kvset_get_nth_vblock_id(ks, j));
            if (err)
                goto errout;
            vbcnt++;
        }

        if (vbcnt > 0) {
            vbidx_right += vbcnt;
            err = vgmap_vbidx_set(vgmap_src, src_end, vgmap_right, vbidx_right - 1, vgidx_right);
            if (err)
                goto errout;
            vgidx_right++;
        }
    }

    if (nvgroups > 0) {
        assert(vgidx_left <= nvgroups);
        assert(vgidx_right <= nvgroups);

        vgmap_left->nvgroups = vgidx_left;
        vgmap_right->nvgroups = vgidx_right;
    }

    return 0;

errout:
    kvset_split_free(ks, work, result, true);

    return err;
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
hblock_split(struct kvset *ks, struct kvset_split_work *work, struct kvset_split_res *result)
{
    struct kvs_block hblk;
    struct key_obj min_pfx = { 0 }, max_pfx = { 0 };
    struct kvset_mblocks *blks_left = &result->blks[LEFT];
    struct kvset_mblocks *blks_right = &result->blks[RIGHT];
    uint32_t num_ptombs, ptree_pgc;
    uint64_t min_seqno, max_seqno;
    uint8_t *ptree;
    merr_t err = 0;

    min_seqno = ks->ks_hblk.kh_seqno_min;
    max_seqno = ks->ks_hblk.kh_seqno_max;
    num_ptombs = ks->ks_hblk.kh_metrics.hm_nptombs;

    key2kobj(&min_pfx, ks->ks_hblk.kh_pfx_min, ks->ks_hblk.kh_pfx_min_len);
    key2kobj(&max_pfx, ks->ks_hblk.kh_pfx_max, ks->ks_hblk.kh_pfx_max_len);

    hbr_read_ptree(&ks->ks_hblk.kh_hblk_desc, &ks->ks_hblk.kh_ptree_desc, &ptree, &ptree_pgc);

    /* Add both the left and the right hblock to the commit list and add the source hblock
     * to the purge list.
     */
    if (blks_left->kblks.n_blks > 0 || ptree_pgc > 0) {
        err = hbb_finish(work[LEFT].hbb, &hblk, work[LEFT].vgmap,
                         &min_pfx, &max_pfx, min_seqno, max_seqno,
                         blks_left->kblks.n_blks, blks_left->vblks.n_blks,
                         num_ptombs, hlog_data(work[LEFT].hlog), ptree, ptree_pgc);
        if (!err) {
            blks_left->hblk = hblk;
            err = blk_list_append(&result->blks_commit, hblk.bk_blkid);
        }
    }

    if (!err && (blks_right->kblks.n_blks > 0 || ptree_pgc > 0)) {
        err = hbb_finish(work[RIGHT].hbb, &hblk, work[RIGHT].vgmap,
                         &min_pfx, &max_pfx, min_seqno, max_seqno,
                         blks_right->kblks.n_blks, blks_right->vblks.n_blks,
                         num_ptombs, hlog_data(work[RIGHT].hlog), ptree, ptree_pgc);
        if (!err) {
            blks_right->hblk = hblk;
            err = blk_list_append(&result->blks_commit, hblk.bk_blkid);
        }
    }

    if (!err)
        err = blk_list_append(&result->blks_purge, ks->ks_hblk.kh_hblk_desc.mbid);
    else
        kvset_split_free(ks, work, result, true);

    return err;
}

merr_t
kvset_split(
    struct kvset           *ks,
    const struct key_obj   *split_kobj,
    struct kvset_split_res *result)
{
    struct kvset_split_work work[2] = { 0 };
    merr_t err;

    INVARIANT(ks && split_kobj && result);

    err = kvset_split_alloc(ks, work, result);
    if (err)
        return err;

    err = kblocks_split(ks, split_kobj, work, result);
    if (err)
        return err;

    err = vblocks_split(ks, split_kobj, work, result);
    if (err)
        return err;

    err = hblock_split(ks, work, result);
    if (err)
        return err;

    return 0;
}
