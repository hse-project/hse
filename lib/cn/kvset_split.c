/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <stdint.h>

#include <sys/mman.h>

#include <hse/limits.h>

#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/cndb.h>
#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/kvset_builder.h>
#include <hse/logging/logging.h>
#include <hse/mpool/mpool.h>
#include <hse/util/assert.h>
#include <hse/util/event_counter.h>
#include <hse/util/fmt.h>
#include <hse/util/keycmp.h>
#include <hse/util/perfc.h>

#include "cn_perfc.h"
#include "cn_tree.h"
#include "cn_tree_internal.h"
#include "hblock_builder.h"
#include "hblock_reader.h"
#include "kblock_builder.h"
#include "kblock_reader.h"
#include "kvs_mblk_desc.h"
#include "kvset.h"
#include "kvset_internal.h"
#include "kvset_split.h"
#include "omf.h"
#include "vblock_reader.h"
#include "vgmap.h"
#include "wbt_reader.h"

/**
 * struct kvset_split_work - work struct for kvset split
 */
struct kvset_split_work {
    struct hlog *hlog;          /* composite hlog */
    struct hblock_builder *hbb; /* hblock builder */
    struct vgmap *vgmap;        /* vgroup map */
};

static void
free_work(struct kvset_split_work work[static 2])
{
    for (int i = LEFT; i <= RIGHT; i++) {
        hbb_destroy(work[i].hbb);
        hlog_destroy(work[i].hlog);
        vgmap_free(work[i].vgmap);
    }
}

static merr_t
alloc_work(struct kvset *ks, struct perfc_set *pc, struct kvset_split_work work[static 2])
{
    struct cn *cn = cn_tree_get_cn(ks->ks_tree);
    merr_t err;
    uint32_t nvgroups = kvset_get_vgroups(ks);

    for (int i = LEFT; i <= RIGHT; i++) {
        if (nvgroups > 0) {
            work[i].vgmap = vgmap_alloc(nvgroups);
            if (!work[i].vgmap) {
                err = merr(ENOMEM);
                goto errout;
            }
        }

        err = hbb_create(&work[i].hbb, cn, pc);
        if (err)
            goto errout;

        err = hlog_create(&work[i].hlog, HLOG_PRECISION);
        if (err)
            goto errout;
    }

    return 0;

errout:
    free_work(work);

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
    struct kblock_desc *kbd,
    const struct key_obj *start, /* exclusive */
    const struct key_obj *end,   /* inclusive */
    struct blk_list *kblks_out,
    struct hlog *hlog,
    uint64_t *vused)
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

    *vused = 0;

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
            uint64_t vseq, omlen;

            /* Pass NULL for vgmap as vbidx is not used here */
            wbt_read_kmd_vref(kmd, NULL, &off, &vseq, &vref);

            switch (vref.vr_type) {
            case VTYPE_UCVAL:
            case VTYPE_CVAL:
                omlen = (vref.vb.vr_complen ? vref.vb.vr_complen : vref.vb.vr_len);
                stats.tot_vlen += omlen;
                stats.tot_vused += omlen;
                *vused += omlen;
                break;

            case VTYPE_IVAL:
                stats.tot_vlen += vref.vi.vr_len;
                break;

            case VTYPE_TOMB:
                ++stats.ntombs;
                break;

            case VTYPE_ZVAL:
                break;

            case VTYPE_PTOMB:
                abort();
            }
        }

        err = kbb_add_entry(kbb, &cur, kmd + kmd_cnt_off, off - kmd_cnt_off, &stats);
        if (!err)
            ++tot_keys;
    }

    if (!err && tot_keys > 0) {
        err = kbb_finish(kbb, kblks_out);
        if (!err)
            hlog_union(hlog, kbb_get_composite_hlog(kbb));
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
    struct kblock_desc *kbd,
    const struct key_obj *split_key,
    struct blk_list *kblks,
    struct hlog *hlogs[static 2],
    uint64_t vused[static 2])
{
    merr_t err;

    INVARIANT(kbd && split_key && kblks);

    /* Readahead source kblock regions to improve read latency when iterating over its keys
     * inside kblock_copy_range().
     */
    kbr_madvise_kmd(kbd->kd_mbd, kbd->kd_wbd, MADV_WILLNEED);
    kbr_madvise_wbt_leaf_nodes(kbd->kd_mbd, kbd->kd_wbd, MADV_WILLNEED);

    err = kblock_copy_range(kbd, NULL, split_key, &kblks[LEFT], hlogs[LEFT], &vused[LEFT]);
    if (!err) {
        err = kblock_copy_range(kbd, split_key, NULL, &kblks[RIGHT], hlogs[RIGHT], &vused[RIGHT]);
        if (!err && (kblks[LEFT].idc == 0 && kblks[RIGHT].idc == 0)) {
            assert(kblks[LEFT].idc > 0 || kblks[RIGHT].idc > 0);
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
    struct kvset *ks,
    const struct key_obj *split_key,
    struct kvset_split_work work[static 2],
    struct kvset_split_res *result)
{
    struct hlog *hlog_left = work[LEFT].hlog;
    struct hlog *hlog_right = work[RIGHT].hlog;
    struct kvset_mblocks *blks_left = result->ks[LEFT].blks;
    struct kvset_mblocks *blks_right = result->ks[RIGHT].blks;
    bool overlap = false;
    uint32_t split_idx;
    merr_t err = 0;

    split_idx = get_kblk_split_index(ks, split_key, &overlap);
    assert(split_idx <= ks->ks_st.kst_kblks);

    /* Add kblocks in [0, split_idx - 1] to the left kvset
     * Also generate a composite hlog for the left kvset and the right kvset
     */
    for (uint32_t i = 0; i < split_idx; i++) {
        struct kvset_kblk *kblk = &ks->ks_kblks[i];

        err = blk_list_append(&blks_left->kblks, kblk->kb_kblk_desc.mbid);
        if (err)
            return err;

        hlog_union(hlog_left, kblk->kb_hlog);
        blks_left->bl_vused += kblk->kb_metrics.tot_vused_bytes;
    }

    if (overlap) {
        struct kvset_kblk *kblk = &ks->ks_kblks[split_idx];
        struct hlog *hlogs[2] = { hlog_left, hlog_right };
        struct kblock_desc kbd;
        struct blk_list kblks[2];
        uint64_t vused[2] = { 0 };
        merr_t err;

        kbd.cn = cn_tree_get_cn(ks->ks_tree);
        kbd.kd_mbd = &kblk->kb_kblk_desc;
        kbd.kd_wbd = &kblk->kb_wbt_desc;

        for (int i = LEFT; i <= RIGHT; i++)
            blk_list_init(&kblks[i]);

        /* split kblock at split_idx */
        err = kblock_split(&kbd, split_key, kblks, hlogs, vused);

        assert((kblks[LEFT].idc > 0 && kblks[RIGHT].idc > 0) || err);

        /* Append kblks[LEFT] to the left kvset, kblks[RIGHT] to the right kvset, and both
         * kblks[LEFT] and kblks[RIGHT] to the commit list
         */
        for (uint32_t i = 0; i < kblks[LEFT].idc && !err; i++) {
            uint64_t blkid = kblks[LEFT].idv[i];

            err = blk_list_append(&blks_left->kblks, blkid);
            if (!err) {
                blks_left->bl_vused += vused[LEFT];

                err = blk_list_append(result->ks[LEFT].blks_commit, blkid);
            }
        }

        for (uint32_t i = 0; i < kblks[RIGHT].idc && !err; i++) {
            uint64_t blkid = kblks[RIGHT].idv[i];

            err = blk_list_append(&blks_right->kblks, blkid);
            if (!err) {
                blks_right->bl_vused += vused[RIGHT];

                err = blk_list_append(result->ks[RIGHT].blks_commit, blkid);
            }
        }

        /* Add the source kblock to the purge list to be destroyed later */
        if (!err)
            err = blk_list_append(result->blks_purge, kblk->kb_kblk_desc.mbid);

        for (int i = LEFT; i <= RIGHT; i++)
            blk_list_free(&kblks[i]);

        split_idx++;
    }

    /* Add kblocks in [split_idx, nkblks - 1] to the right kvset
     */
    for (uint32_t i = split_idx; i < ks->ks_st.kst_kblks && !err; i++) {
        struct kvset_kblk *kblk = &ks->ks_kblks[i];

        err = blk_list_append(&blks_right->kblks, kblk->kb_kblk_desc.mbid);
        if (!err) {
            hlog_union(hlog_right, ks->ks_kblks[i].kb_hlog);
            blks_right->bl_vused += ks->ks_kblks[i].kb_metrics.tot_vused_bytes;
        }
    }

    return err;
}

struct vgroup_split_metadata {
    bool overlaps; /**< Whether the vgroup overlaps the split key. */
    uint16_t
        vblk_idx; /**< Where the left kvset's vblocks end and the right kvset's vblocks begin */
    off_t offset; /**< Offset into the vblock where the access first occurs */
};

/**
 * Return a split vblock index for the specified range of vblocks [start, end] by comparing
 * the min/max keys stored in a vblock footer against the split key.
 *
 * Return values:
 *     v >= start and overlap = false: left: [start, v - 1], right [v, end]
 *     v >= start and overlap = true : left: [start, punched(v)], right [clone(v), end]
 *
 * NOTES:
 *     v = start and overlap = false:   All vblocks go to the right
 *     v = end + 1 and overlap = false: All vblocks go to the left
 */
static uint16_t
get_vblk_split_index(
    struct kvset * const ks,
    const uint16_t start, /* inclusive */
    const uint16_t end,   /* inclusive */
    const struct key_obj * const split_key,
    bool * const overlap)
{
    uint16_t v;

    INVARIANT(ks && split_key && overlap);
    INVARIANT(start <= end && end < kvset_get_num_vblocks(ks));

    *overlap = false;

    for (v = start; v <= end; v++) {
        struct key_obj min_key;
        const struct vblock_desc *vbd = kvset_get_nth_vblock_desc(ks, v);

        key2kobj(&min_key, vbd->vbd_mblkdesc->map_base + vbd->vbd_min_koff, vbd->vbd_min_klen);

        if (key_obj_cmp(split_key, &min_key) < 0)
            break;
    }

    if (v > start) {
        struct key_obj max_key;
        const struct vblock_desc *vbd = kvset_get_nth_vblock_desc(ks, v - 1);

        key2kobj(&max_key, vbd->vbd_mblkdesc->map_base + vbd->vbd_max_koff, vbd->vbd_max_klen);

        if (key_obj_cmp(split_key, &max_key) < 0) {
            *overlap = true;
            return v - 1;
        }
    }

    return v;
}

static merr_t
mark_vgroup_accesses(
    const uint32_t nvgroups,
    struct vgroup_split_metadata *metadatav,
    struct kvset * const ks,
    const struct key_obj *split_key,
    const struct key_obj *max_key)
{
    merr_t err;
    bool first = true;
    uint32_t accesses = 0;
    struct kv_iterator *iter;

    INVARIANT(key_obj_cmp(split_key, max_key) <= 0);

    err = kvset_iter_create(ks, NULL, NULL, NULL, kvset_iter_flag_mmap, &iter);
    if (ev(err))
        return err;

    err = kvset_iter_seek(iter, split_key->ko_sfx, split_key->ko_sfx_len, NULL);
    if (ev(err))
        goto out;

    while (true) {
        uint vlen;
        uint vbidx;
        uint vboff;
        uint complen;
        uint64_t seqno;
        const void *vdata;
        enum kmd_vtype vtype;
        struct key_obj curr_key;
        struct kvset_iter_vctx vc;

        if (iter->kvi_eof)
            break;

        err = kvset_iter_next_key(iter, &curr_key, &vc);
        if (ev(err))
            goto out;

        /* In the event that this kvset contains the split key, skip it. */
        if (first) {
            first = false;
            if (key_obj_cmp(&curr_key, split_key) == 0)
                continue;
        }

        if (key_obj_cmp(&curr_key, max_key) > 0)
            break;

        while (kvset_iter_next_vref(
            iter, &vc, &seqno, &vtype, &vbidx, &vboff, &vdata, &vlen, &complen))
        {
            uint64_t vgidx;
            const struct vblock_desc *vbd;
            struct vgroup_split_metadata *metadata;

            switch (vtype) {
            case VTYPE_UCVAL:
            case VTYPE_CVAL:
                vbd = kvset_get_nth_vblock_desc(ks, vbidx);
                /* TODO: Why do I need the -1? vblock_reader.c always adds 1 for
                 * some reason that doesn't make sense to me.
                 */
                vgidx = atomic_read(&vbd->vbd_vgidx) - 1;
                assert(vgidx < nvgroups);
                metadata = metadatav + vgidx;
                if (metadata->offset == -1) {
                    metadata->offset = vboff;
                    log_debug("vgidx=%lu vbidx=%u offset=%u", vgidx, vbidx, vboff);
                    /* Exit because we have marked the offset for all vgroups */
                    if (++accesses == nvgroups)
                        goto out;
                }
                /* fallthrough */
            case VTYPE_IVAL:
            case VTYPE_ZVAL:
            case VTYPE_TOMB:
            case VTYPE_PTOMB:
                continue;
            }
        }
    }

out:
    kvset_iter_release(iter);

    return err;
}

/**
 * @vbidx_left, @vbidx_right - tracks vblock index for the left and right kvsets
 * @vgidx_left, @vgidx_right - tracks vgroup index for the left and right kvsets
 *
 */
static merr_t
vblocks_split(
    struct kvset *ks,
    const struct key_obj *split_key,
    struct kvset_split_work work[static 2],
    struct perfc_set *pc,
    struct kvset_split_res *result)
{
    struct key_obj max_key;
    char buf[HSE_KVS_KEY_LEN_MAX + 1];
    struct vgroup_split_metadata *metadatav;
    struct vgmap *vgmap_src = ks->ks_vgmap;
    struct vgmap *vgmap_left = work[LEFT].vgmap;
    struct vgmap *vgmap_right = work[RIGHT].vgmap;
    struct kvset_mblocks *blks_left = result->ks[LEFT].blks;
    struct kvset_mblocks *blks_right = result->ks[RIGHT].blks;
    uint16_t vbidx_left = 0, vbidx_right = 0;
    uint32_t vgidx_left = 0, vgidx_right = 0;
    uint32_t nvgroups = kvset_get_vgroups(ks), perfc_rwc = 0;
    const bool move_left = (blks_right->kblks.idc == 0);
    const bool move_right = (blks_left->kblks.idc == 0);
    uint64_t perfc_rwb = 0;
    merr_t err;

    log_debug("splitting %d vgroups", nvgroups);

    if (move_left && move_right) {
        assert(nvgroups == 0);
        return 0;
    }

    metadatav = malloc(nvgroups * sizeof(*metadatav));
    if (ev(!metadatav))
        return merr(ENOMEM);

    max_key = *split_key;
    for (uint32_t i = 0; i < nvgroups; i++) {
        uint16_t start, end;
        struct vgroup_split_metadata *metadata = metadatav + i;

        /* Per vgroup start and end output vblock index in the source kvset */
        start = vgmap_vbidx_out_start(ks, i);
        end = vgmap_vbidx_out_end(ks, i);

        /* Negative offset implies overlapping vblock was not accessed */
        metadata->offset = -1;
        if (move_left || move_right) {
            log_debug("move_left=%d move_right=%d", move_left, move_right);
            metadata->vblk_idx = move_right ? start : end;
            metadata->overlaps = false;
        } else {
            metadata->vblk_idx =
                get_vblk_split_index(ks, start, end, split_key, &metadata->overlaps);
            if (metadata->overlaps) {
                struct key_obj curr_key;
                const struct vblock_desc *vbd;

                vbd = kvset_get_nth_vblock_desc(ks, metadata->vblk_idx);

                key2kobj(
                    &curr_key, vbd->vbd_mblkdesc->map_base + vbd->vbd_max_koff, vbd->vbd_max_klen);

                fmt_hexp(
                    buf, sizeof(buf), curr_key.ko_sfx, curr_key.ko_sfx_len, "0x", 4, "-", "\0");
                log_debug("vgidx=%u vblkidx=%u maxkey=%s", i, metadata->vblk_idx, buf);
                if (key_obj_cmp(&max_key, &curr_key) < 0)
                    max_key = curr_key;
            }
        }
        assert(metadata->vblk_idx >= start && metadata->vblk_idx <= end + 1);
    }

    fmt_hexp(buf, sizeof(buf), split_key->ko_sfx, split_key->ko_sfx_len, "0x", 4, "-", "\0");
    log_debug("split key: %s", buf);
    fmt_hexp(buf, sizeof(buf), max_key.ko_sfx, max_key.ko_sfx_len, "0x", 4, "-", "\0");
    log_debug("max key: %s", buf);

    if (!(move_left || move_right)) {
        err = mark_vgroup_accesses(nvgroups, metadatav, ks, split_key, &max_key);
        if (ev(err))
            goto out;
    }

    for (uint32_t i = 0; i < nvgroups; i++) {
        uint32_t vbcnt = 0;
        bool overlapping_access;
        uint16_t split, start, end, boundary;
        const struct vgroup_split_metadata *metadata = metadatav + i;

        overlapping_access = metadata->overlaps && metadata->offset >= 0;

        /* Per vgroup start and end output vblock index in the source kvset */
        start = vgmap_vbidx_out_start(ks, i);
        end = vgmap_vbidx_out_end(ks, i);
        split = metadata->vblk_idx;

        log_debug(
            "start=%u end=%u split=%u overlaps=%d offset=%jd overlapping_access=%d", start, end,
            split, metadata->overlaps, metadata->offset, overlapping_access);

        if (!move_left) {
            /* Add the vblocks in [boundary, end] to the right kvset */
            boundary = (overlapping_access || move_right) ? split : split + 1;
            for (uint16_t j = boundary; j <= end; j++) {
                uint32_t alen;
                uint64_t mbid;

                mbid = kvset_get_nth_vblock_id(ks, j);

                if (j == split && overlapping_access) {
                    off_t off;
                    uint64_t clone_mbid;
                    struct mblock_props props;

                    /* We want clone more than enough data in the event the
                     * offset doesn't fall right on a page boundary.
                     */
                    off = metadata->offset;
                    off = off < PAGE_SIZE ? 0 : roundup(off - PAGE_SIZE, PAGE_SIZE);

                    err = mpool_mblock_clone(ks->ks_mp, mbid, off, 0, &clone_mbid);
                    if (!err) {
                        err = blk_list_append(&blks_right->vblks, clone_mbid);
                        if (!err)
                            err = blk_list_append(result->ks[RIGHT].blks_commit, clone_mbid);
                    }

                    if (err)
                        goto out;

                    log_debug("Cloned mblock (0x%" PRIx64 ") starting at offset %jd", mbid, off);

                    err = mpool_mblock_props_get(ks->ks_mp, clone_mbid, &props);
                    if (ev(err))
                        goto out;

                    perfc_rwc++;
                    if (perfc_ison(pc, PERFC_RA_CNCOMP_RBYTES) ||
                        perfc_ison(pc, PERFC_RA_CNCOMP_WBYTES))
                        perfc_rwb += props.mpr_write_len - off;

                    alen = props.mpr_alloc_cap - VBLOCK_FOOTER_LEN;
                    log_debug(
                        "right: cloned id=0x%lx vgidx=%u vblkidx=%u alen=%u", clone_mbid, i, j,
                        alen);
                } else {
                    err = blk_list_append(&blks_right->vblks, mbid);
                    if (err)
                        goto out;

                    alen = kvset_get_nth_vblock_alen(ks, j);
                    log_debug(
                        "right: moved id=0x%lx vgidx=%u vblkidx=%u alen=%u", mbid, i, j, alen);
                }

                vbcnt++;
                blks_right->bl_vtotal += alen;
            }

            if (vbcnt > 0) {
                vbidx_right += vbcnt;

                err = vgmap_vbidx_set(vgmap_src, end, vgmap_right, vbidx_right - 1, vgidx_right);
                if (err)
                    goto out;

                vgidx_right++;
            }
        }

        if (!move_right) {
            /* Add vblocks in [start, boundary] to the left kvset */
            vbcnt = 0; /* reset vbcnt for the left kvset */
            boundary = min(split, end);
            for (uint16_t j = start; j <= boundary; j++) {
                uint32_t alen;
                uint64_t mbid;

                mbid = kvset_get_nth_vblock_id(ks, j);

                if (j == split && overlapping_access) {
                    off_t off;
                    uint32_t wlen;
                    struct mblock_props props;

                    /* Offset must be page aligned. Punching the rest of the
                     * vblock from the page aligned offset up to the vblock
                     * footer.
                     */
                    off = roundup(metadata->offset, PAGE_SIZE);
                    wlen = kvset_get_nth_vblock_wlen(ks, j) - off;

                    err = mpool_mblock_punch(ks->ks_mp, mbid, off, wlen);
                    if (ev(err))
                        goto out;

                    log_debug(
                        "Punched mblock (0x%" PRIx64 ") starting at offset %jd for %u bytes", mbid,
                        off, wlen);

                    err = mpool_mblock_props_get(ks->ks_mp, mbid, &props);
                    if (ev(err))
                        goto out;

                    alen = props.mpr_alloc_cap - VBLOCK_FOOTER_LEN;
                    log_debug(
                        "left: punched id=0x%lx vgidx=%u vblkidx=%u alen=%u", mbid, i, j, alen);
                } else {
                    alen = kvset_get_nth_vblock_alen(ks, j);
                    log_debug("left: moved id=0x%lx vgidx=%u vblkidx=%u alen=%u", mbid, i, j, alen);
                }

                err = blk_list_append(&blks_left->vblks, mbid);
                if (ev(err))
                    goto out;

                vbcnt++;
                blks_left->bl_vtotal += alen;
            }

            if (vbcnt > 0) {
                vbidx_left += vbcnt;

                err = vgmap_vbidx_set(vgmap_src, boundary, vgmap_left, vbidx_left - 1, vgidx_left);
                if (err)
                    goto out;

                vgidx_left++;
            }
        }
    }

    log_debug("left: vtotal=%lu vused=%lu", blks_left->bl_vtotal, blks_left->bl_vused);
    log_debug("right: vtotal=%lu vused=%lu", blks_right->bl_vtotal, blks_right->bl_vused);

    /* Sanity check, so that we don't fall into these asserts elsewhere later
     * on.
     */
    assert(blks_left->bl_vtotal >= blks_left->bl_vused);
    assert(blks_right->bl_vtotal >= blks_right->bl_vused);

    if (nvgroups > 0) {
        assert(vgidx_left <= nvgroups);
        assert(vgidx_right <= nvgroups);

        vgmap_left->nvgroups = vgidx_left;
        vgmap_right->nvgroups = vgidx_right;

        if (perfc_ison(pc, PERFC_RA_CNCOMP_RBYTES))
            perfc_add2(pc, PERFC_RA_CNCOMP_RREQS, perfc_rwc, PERFC_RA_CNCOMP_RBYTES, perfc_rwb);

        if (perfc_ison(pc, PERFC_RA_CNCOMP_WBYTES))
            perfc_add2(pc, PERFC_RA_CNCOMP_WREQS, perfc_rwc, PERFC_RA_CNCOMP_WBYTES, perfc_rwb);
    }

out:
    free(metadatav);

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
hblock_split(
    struct kvset *ks,
    struct kvset_split_work work[static 2],
    struct kvset_split_res *result)
{
    struct key_obj min_pfx = { 0 }, max_pfx = { 0 };
    struct kvset_mblocks *blks_left = result->ks[LEFT].blks;
    struct kvset_mblocks *blks_right = result->ks[RIGHT].blks;
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
    if (ptree_pgc == 0)
        ptree = NULL;

    /* Add both the left and the right hblock to the commit list and add the source hblock
     * to the purge list.
     */
    if (blks_left->kblks.idc > 0 || ptree) {
        err = hbb_finish(
            work[LEFT].hbb, &blks_left->hblk_id, work[LEFT].vgmap, &min_pfx, &max_pfx, min_seqno,
            max_seqno, blks_left->kblks.idc, blks_left->vblks.idc, num_ptombs,
            hlog_data(work[LEFT].hlog), ptree, &ks->ks_hblk.kh_ptree_desc, ptree_pgc);
        if (!err)
            err = blk_list_append(result->ks[LEFT].blks_commit, blks_left->hblk_id);
    }

    if (!err && (blks_right->kblks.idc > 0 || ptree)) {
        err = hbb_finish(
            work[RIGHT].hbb, &blks_right->hblk_id, work[RIGHT].vgmap, &min_pfx, &max_pfx, min_seqno,
            max_seqno, blks_right->kblks.idc, blks_right->vblks.idc, num_ptombs,
            hlog_data(work[RIGHT].hlog), ptree, &ks->ks_hblk.kh_ptree_desc, ptree_pgc);
        if (!err)
            err = blk_list_append(result->ks[RIGHT].blks_commit, blks_right->hblk_id);
    }

    return err ? err : blk_list_append(result->blks_purge, ks->ks_hblk.kh_hblk_desc.mbid);
}

static merr_t
kvset_split(
    struct kvset *ks,
    const struct key_obj *split_key,
    struct perfc_set *pc,
    struct kvset_split_res *result)
{
    struct kvset_split_work work[2] = { 0 };
    merr_t err;

    INVARIANT(ks && split_key && result);

    err = alloc_work(ks, pc, work);
    if (err)
        return err;

    err = kblocks_split(ks, split_key, work, result);
    if (err)
        goto errout;

    err = vblocks_split(ks, split_key, work, pc, result);
    if (err)
        goto errout;

    err = hblock_split(ks, work, result);
    if (err)
        goto errout;

    for (int i = 0; i < 2; i++) {
        *(result->ks[i].vgmap) = work[i].vgmap;
        work[i].vgmap = NULL;
    }

errout:
    free_work(work);

    return err;
}

void
kvset_split_worker(struct work_struct *work)
{
    struct kvset_split_wargs *wargs = container_of(work, struct kvset_split_wargs, work);

    wargs->err = kvset_split(wargs->ks, wargs->split_kobj, wargs->pc, &wargs->result);

    atomic_dec_rel(wargs->inflightp);
}
