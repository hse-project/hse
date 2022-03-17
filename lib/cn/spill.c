/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvdb_perfc.h>

/* [HSE_REVISIT] - Why is this at the top of this file? */

#define MTF_MOCK_IMPL_spill
#include "spill.h"
#if HSE_MOCKING
#include "spill_ut_impl.i"
#endif /* HSE_MOCKING */

#include "cn_tree.h"
#include "cn_tree_internal.h"
#include "cn_tree_compact.h"
#include "kvset.h"
#include "cn_metrics.h"
#include "kv_iterator.h"
#include "blk_list.h"

/**
 * struct merge_item -- an item in the bin_heap
 */
struct merge_item {
    struct key_obj         kobj;
    struct kvset_iter_vctx vctx;
    uint                   src;
};

static int
merge_item_compare(const void *a_blob, const void *b_blob)
{
    const struct merge_item *a = a_blob;
    const struct merge_item *b = b_blob;
    int                      rc;

    /* Tie breaker: If keycmp() return 0, the keys are equal, in this case
     * lower numbered merge sources contain newer data and must come out
     * of the binheap first.
     */
    rc = key_obj_cmp(&a->kobj, &b->kobj);
    if (rc)
        return rc;
    if (a->src < b->src)
        return -1;
    if (a->src > b->src)
        return 1;
    return 0;
}

static merr_t
replenish(struct bin_heap *bh, struct kv_iterator **iterv, uint src, struct cn_merge_stats *stats)
{
    struct kv_iterator *iter = iterv[src];
    merr_t              err;
    struct merge_item   item;

    if (HSE_UNLIKELY(iter->kvi_eof))
        return 0;

    err = kvset_iter_next_key(iter, &item.kobj, &item.vctx);
    if (ev(err))
        return err;
    if (HSE_UNLIKELY(iter->kvi_eof))
        return 0;

    item.src = src;

    err = bin_heap_insert(bh, &item);
    if (ev(err))
        return err;

    stats->ms_keys_in++;
    stats->ms_key_bytes_in += key_obj_len(&item.kobj);

    return 0;
}

static merr_t
merge_init(
    struct bin_heap **     bh_out,
    struct kv_iterator **  iterv,
    u32                    iterc,
    struct cn_merge_stats *stats)
{
    u32    i;
    merr_t err;

    err = bin_heap_create(bh_out, iterc, sizeof(struct merge_item), merge_item_compare);
    if (ev(err))
        goto err_exit1;

    stats->ms_srcs = iterc;

    for (i = 0; i < iterc; i++) {
        err = replenish(*bh_out, iterv, i, stats);
        if (ev(err))
            goto err_exit2;
    }

    return 0;

err_exit2:
    bin_heap_destroy(*bh_out);
err_exit1:
    return err;
}

/* return true if item returned, false if no more items */
static HSE_ALWAYS_INLINE bool
get_next_item(
    struct bin_heap *      bh,
    struct kv_iterator **  iterv,
    struct merge_item *    item,
    struct cn_merge_stats *stats,
    merr_t *               err_out)
{
    bool got_item;

    got_item = bin_heap_get_delete(bh, item);
    if (got_item)
        *err_out = replenish(bh, iterv, item->src, stats);
    else
        *err_out = 0;
    return got_item;
}

static merr_t
kv_spill_prepare(struct cn_tstate_omf *omf, void *arg)
{
    struct cn_tree *    tree = arg;
    struct cn_khashmap *khashmap;

    khashmap = cn_tree_get_khashmap(tree);
    if (!khashmap)
        return 0;

    spin_lock(&khashmap->khm_lock);
    if (khashmap->khm_gen > khashmap->khm_gen_committed) {
        omf_set_ts_khm_mapv(omf, khashmap->khm_mapv, sizeof(khashmap->khm_mapv));
        omf_set_ts_khm_gen(omf, khashmap->khm_gen);
    }
    spin_unlock(&khashmap->khm_lock);

    return 0;
}

static void
kv_spill_commit(const struct cn_tstate_omf *omf, void *arg)
{
    struct cn_tree *    tree = arg;
    struct cn_khashmap *khashmap;

    khashmap = cn_tree_get_khashmap(tree);
    if (!khashmap)
        return;

    spin_lock(&khashmap->khm_lock);
    khashmap->khm_gen_committed = omf_ts_khm_gen(omf);
    spin_unlock(&khashmap->khm_lock);
}

static void
kv_spill_abort(struct cn_tstate_omf *omf, void *arg)
{
}

static inline bool
is_spill_to_intnode(struct cn_tree_node *pnode, uint child)
{
    return pnode->tn_childv[child] && !cn_node_isleaf(pnode->tn_childv[child]);
}

#include "spill_hash.c"

static merr_t
get_kvset_builder(struct cn_compaction_work *w, uint cnum, struct kvset_builder **bldr_out)
{
    struct kvset_builder *bldr = NULL;
    merr_t err;

    err = kvset_builder_create(&bldr, cn_tree_get_cn(w->cw_tree), w->cw_pc, w->cw_dgen_hi);
    if (!err) {
        struct cn_tree_node *pnode;

        kvset_builder_set_merge_stats(bldr, &w->cw_stats);

        /* TODO: Remove HSE_MPOLICY_AGE_INTERNAL once we move to a strict 2-level cN tree */
        pnode = w->cw_node;
        if (w->cw_action == CN_ACTION_SPILL) {
            if (is_spill_to_intnode(pnode, cnum))
                kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_INTERNAL);
            else
                kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_LEAF);
        } else {
            if (cn_node_isleaf(pnode))
                kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_LEAF);
            if (cn_node_isroot(pnode))
                kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_ROOT);
            else
                kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_INTERNAL);
        }
    }

    *bldr_out = bldr;

    return err;
}

/*
 * [HSE_REVISIT] direct read path allocates buffer. Performing direct reads into the buffer
 * in kvset builder without this is a future opportunity.
 */
static merr_t
get_direct_read_buf(uint len, bool aligned_voff, u32 *bufsz, void **buf)
{
    uint bufsz_min = len;

    if (ev(len > HSE_KVS_VALUE_LEN_MAX)) {
        assert(len <= HSE_KVS_VALUE_LEN_MAX);
        return merr(EBUG);
    }

    /* If value offset is not page aligned then allocate one additional page to prevent a
     * potential copy inside direct read function
     */
    if (!aligned_voff)
        bufsz_min += PAGE_SIZE;

    if (!(*buf) || *bufsz < bufsz_min) {
        const uint vlen_max = HSE_KVS_VALUE_LEN_MAX;

        *bufsz = (len < vlen_max / 4) ? vlen_max / 4 :
            ((len < vlen_max / 2) ? vlen_max / 2 : vlen_max);

        /* add an extra page if not aligned */
        if (bufsz_min < *bufsz)
            *bufsz += PAGE_SIZE;

        free_aligned(*buf);

        *buf = alloc_aligned(*bufsz, PAGE_SIZE);
        if (!(*buf))
            return merr(ENOMEM);
    }

    return 0;
}

static uint
get_route(
    struct cn_compaction_work *w,
    struct key_obj            *kobj,
    char                      *ekbuf,
    size_t                     ekbuf_sz,
    uint                      *eklen)
{
    uint cnum;

    if (w->cw_action == CN_ACTION_SPILL) {
        char kbuf[HSE_KVS_KEY_LEN_MAX];
        uint klen;

        assert(w->cw_tree->ct_route_map);
        assert(w->cw_outc > 1 && w->cw_level == 0);

        key_obj_copy(kbuf, sizeof(kbuf), &klen, kobj);
        cnum = cn_tree_route_get(w->cw_tree, kbuf, klen, ekbuf, ekbuf_sz, eklen);
    } else {
        assert(w->cw_outc == 1);
        cnum = 0;
    }

    return cnum;
}

static void
put_route(struct cn_compaction_work *w, uint cnum)
{
    if (w->cw_action == CN_ACTION_SPILL)
        cn_tree_route_put(w->cw_tree, cnum);
}

/**
 * cn_spill() - merge key-value streams, then spill kv-pairs one node at a time or
 *              kv-compact into a node.
 * Requirements:
 *   - Each input iterator must produce keys in sorted order.
 *   - Iterator iterv[i] must contain newer entries than iterv[i+1].
 */
merr_t
cn_spill(struct cn_compaction_work *w)
{
    struct bin_heap *bh;
    struct merge_item curr;
    struct kvset_builder *child = NULL;
    struct cn_khashmap *khashmap = NULL;
    struct key_obj ekobj = { 0 }, prev_kobj;
    struct cn_tree *tree = w->cw_tree;

    char ekbuf[HSE_KVS_KEY_LEN_MAX];
    uint vlen, complen, omlen, eklen, direct_read_len, cnum, prev_cnum;
    uint curr_klen HSE_MAYBE_UNUSED;
    u32 bufsz = 0;
    void *buf = NULL;
    merr_t err;

    u64  seq, emitted_seq = 0, emitted_seq_pt = 0;
    bool emitted_val = false, bg_val = false, more, gt_max_edge = false;
    bool kvcompact = (w->cw_action == CN_ACTION_COMPACT_KV);
    bool spill = (w->cw_action == CN_ACTION_SPILL);

    u64  tstart, tprog = 0;
    u64  dbg_prev_seq HSE_MAYBE_UNUSED;
    uint dbg_prev_src HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    uint seqno_errcnt = 0;
    bool dbg_dup HSE_MAYBE_UNUSED;

    /* Variables for tracking the last ptomb context */
    struct key_obj pt_kobj = { 0 };
    bool pt_set = false;
    u64 pt_seq = 0;

    /* TODO: Using spill by hash will be gone once we completely move to a 2-level cN tree
     * with a full fledged route map
     */
    if (!tree->rp->cn_incr_rspill || !tree->ct_route_map || (spill && w->cw_level > 0))
        return cn_spill_hash(w);

    assert(w->cw_kvset_cnt);
    assert(w->cw_inputv);

    if (w->cw_prog_interval && w->cw_progress)
        tprog = jiffies;

    /*
     * We must issue a direct read for all values that will not fit into the vblock readahead
     * buffer.  Since all direct reads require page size alignment any value whose length is
     * greater than the buffer size minus one page must be read directly from disk (vs from the
     * readahead buffer).
     */
    direct_read_len = w->cw_rp->cn_compact_vblk_ra;
    direct_read_len -= PAGE_SIZE;

    memset(w->cw_outv, 0, w->cw_outc * sizeof(*w->cw_outv));

    err = merge_init(&bh, w->cw_inputv, w->cw_kvset_cnt, &w->cw_stats);
    if (err)
        return err;

    more = get_next_item(bh, w->cw_inputv, &curr, &w->cw_stats, &err);
    if (more)
        cnum = get_route(w, &curr.kobj, ekbuf, sizeof(ekbuf), &eklen);

    while (!err && more) {
        bool new_key = true;

        if (!child) {
            err = get_kvset_builder(w, cnum, &child);
            if (err) {
                put_route(w, cnum);
                break;
            }
            /*
             * Add ptomb to 'child' if a ptomb context is carried forward from the
             * previous node spill, i.e., this ptomb spans across multiple children.
             */
            if (pt_set && (!w->cw_drop_tombv[cnum] || pt_seq > w->cw_horizon)) {
                const void *pt_vdata = HSE_CORE_TOMB_PFX;

                err = kvset_builder_add_val(child, pt_seq, pt_vdata, 0, 0);
                if (!err)
                    err = kvset_builder_add_key(child, &pt_kobj);

                if (err) {
                    put_route(w, cnum);
                    kvset_builder_destroy(child);
                    break;
                }

                w->cw_stats.ms_keys_out++;
                w->cw_stats.ms_key_bytes_out += key_obj_len(&pt_kobj);
            }
        }
        assert(child);

        key2kobj(&ekobj, ekbuf, eklen);
        assert(!gt_max_edge || key_obj_ncmp(&curr.kobj, &ekobj, eklen) > 0);

        tstart = perfc_ison(w->cw_pc, PERFC_DI_CNCOMP_VGET) ? 1 : 0;

        while (more && (kvcompact || gt_max_edge ||
                        key_obj_ncmp(&curr.kobj, &ekobj, eklen) <= 0)) {
            if (atomic_read(w->cw_cancel_request)) {
                err = merr(ESHUTDOWN);
                break;
            }

            curr_klen = key_obj_len(&curr.kobj);
            assert(curr_klen >= w->cw_cp->sfx_len || curr.vctx.is_ptomb);

            if (new_key) {
                bg_val = false;
                emitted_val = false;
                emitted_seq = 0;
                emitted_seq_pt = 0;

                dbg_prev_seq = 0;
                dbg_prev_src = 0;
                dbg_nvals_this_key = 0;
                dbg_dup = false;
            }

            while (!bg_val) {
                const void *   vdata = NULL;
                bool           should_emit = false;
                enum kmd_vtype vtype;
                u32            vbidx;
                u32            vboff;
                bool           direct;

                if (tstart > 0)
                    tstart = get_time_ns();

                if (!kvset_iter_next_vref(w->cw_inputv[curr.src], &curr.vctx, &seq, &vtype, &vbidx,
                                          &vboff, &vdata, &vlen, &complen))
                    break;

                omlen = (vtype == vtype_val) ? vlen : ((vtype == vtype_cval) ? complen : 0);

                direct = omlen > direct_read_len;
                if (direct) {
                    err = get_direct_read_buf(omlen, !(vboff % PAGE_SIZE), &bufsz, &buf);
                    if (err)
                        break;

                    err = kvset_iter_next_val_direct(w->cw_inputv[curr.src], vtype, vbidx,
                                                     vboff, buf, omlen, bufsz);
                    vdata = buf;
                } else {
                    err = kvset_iter_next_val(w->cw_inputv[curr.src], &curr.vctx, vtype, vbidx,
                                              vboff, &vdata, &vlen, &complen);
                }
                if (err)
                    break;

                if (tstart > 0) {
                    u64 t = get_time_ns() - tstart;

                    perfc_rec_sample(w->cw_pc, PERFC_DI_CNCOMP_VGET, t);
                }

                if (HSE_UNLIKELY(dbg_nvals_this_key && dbg_prev_seq <= seq)) {
                    assert(0);
                    seqno_errcnt++;
                }

                assert(!HSE_CORE_IS_PTOMB(vdata) || !w->cw_pfx_len || w->cw_pfx_len == curr_klen);
                dbg_nvals_this_key++;
                dbg_prev_seq = seq;

                bg_val = (seq <= w->cw_horizon);

                /* Set ptomb context and annihilate keys irrespective of bg_val */
                if (pt_set && seq < pt_seq)
                    break; /* drop val */

                if (HSE_CORE_IS_PTOMB(vdata)) {
                    pt_set = true;
                    pt_kobj = curr.kobj;
                    pt_seq = seq;
                }

                if (HSE_CORE_IS_PTOMB(vdata))
                    should_emit = !emitted_seq_pt || seq < emitted_seq_pt;
                else
                    should_emit = !emitted_seq || seq < emitted_seq;

                should_emit = should_emit || !emitted_val;

                /* Compare seq to emitted_seq to ensure when a key has values in two kvsets with
                 * the same sequence number, then only the value from the first kvset is emitted.
                 */
                if (should_emit) {
                    if (w->cw_drop_tombv[cnum] && HSE_CORE_IS_TOMB(vdata) && bg_val)
                        continue; /* skip value */

                    err = kvset_builder_add_val(child, seq, vdata, vlen, complen);
                    if (err)
                        break;

                    w->cw_stats.ms_val_bytes_out += complen ? complen : vlen;
                    emitted_val = true;
                    if (HSE_CORE_IS_PTOMB(vdata))
                        emitted_seq_pt = seq;
                    else
                        emitted_seq = seq;
                } else {
                    /* The same key can appear in two input kvsets with overlapping sequence
                     * numbers. The following assertions verify that we aren't here for other
                     * reasons (e.g., input kvsets that violate assumptions about sequence numbers).
                     */
                    assert(dbg_prev_src < curr.src);
                    assert(seq == emitted_seq);
                    if (seq > emitted_seq)
                        seqno_errcnt++;

                    /* Two ptombs can have the same seqno only if they are part of a txn. But if
                     * that is the case, those ptombs will never be dups. So, there can never be
                     * duplicate ptombs with the same seqno.
                     */
                    assert(vdata != HSE_CORE_TOMB_PFX);
                }
            }

            if (err)
                break;

            prev_kobj = curr.kobj;

            dbg_dup = false;
            dbg_nvals_this_key = 0;
            dbg_prev_src = curr.src;

            more = get_next_item(bh, w->cw_inputv, &curr, &w->cw_stats, &err);
            if (err)
                break;

            if (more) {
                if (0 == key_obj_cmp(&curr.kobj, &prev_kobj)) {
                    dbg_dup = true;
                    new_key = false;
                    assert(dbg_prev_src <= curr.src);
                    continue;
                } else if (pt_set && key_obj_cmp_prefix(&pt_kobj, &curr.kobj) != 0) {
                    pt_set = false; /* cached ptomb key is no longer valid */
                }
            }

            if (emitted_val) {
                err = kvset_builder_add_key(child, &prev_kobj);
                if (err)
                    break;

                w->cw_stats.ms_keys_out++;
                w->cw_stats.ms_key_bytes_out += key_obj_len(&prev_kobj);
            }

            new_key = true;

            if (tprog) {
                u64 now = jiffies;

                if (now - tprog > w->cw_prog_interval) {
                    tprog = now;
                    w->cw_progress(w);
                }
            }
        }

        if (err) {
            put_route(w, cnum);
            kvset_builder_destroy(child);
            break;
        }

        prev_cnum = cnum;
        assert(!gt_max_edge || !more);
        if (more) {
            cnum = get_route(w, &curr.kobj, ekbuf, sizeof(ekbuf), &eklen);
            /* This accommodates keys that are greater than the maximum edge in the route map */
            if (prev_cnum == cnum)
                gt_max_edge = true;
        }

        if (!more || !gt_max_edge) {
            err = kvset_builder_get_mblocks(child, &w->cw_outv[prev_cnum]);
            if (err) {
                while (prev_cnum-- > 0) {
                    abort_mblocks(w->cw_ds, &w->cw_outv[prev_cnum].kblks);
                    abort_mblocks(w->cw_ds, &w->cw_outv[prev_cnum].vblks);
                }
                memset(w->cw_outv, 0, w->cw_outc * sizeof(*w->cw_outv));
            }

            put_route(w, cnum);
            kvset_builder_destroy(child);
            child = NULL;
        }
    }

    bin_heap_destroy(bh);
    free_aligned(buf);

    /* We must ensure the latest version of the key hash map is persisted
     * if it changed while we were using it (regardless of who changed it,
     * and especially if we changed it, regardless of error).
     */
    khashmap = cn_tree_get_khashmap(tree);
    if (khashmap) {
        merr_t err2;
        bool   update;

        spin_lock(&khashmap->khm_lock);
        update = (khashmap->khm_gen > khashmap->khm_gen_committed);
        spin_unlock(&khashmap->khm_lock);

        if (update) {
            struct cn_tstate *ts = tree->ct_tstate;

            err2 = ts->ts_update(ts, kv_spill_prepare, kv_spill_commit, kv_spill_abort, tree);
            err = err ?: err2;
        }
    }

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    return err;
}
