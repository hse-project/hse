/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/event_counter.h>
#include <hse/logging/logging.h>

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
#include "route.h"

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
get_kvset_builder(struct cn_compaction_work *w, uint32_t idx, struct kvset_builder **bldr_out)
{
    struct kvset_builder *bldr = NULL;
    merr_t err;

    w->cw_kvsetidv[idx] = cndb_kvsetid_mint(cn_tree_get_cndb(w->cw_tree));

    err = kvset_builder_create(&bldr, cn_tree_get_cn(w->cw_tree), w->cw_pc, w->cw_kvsetidv[idx]);
    if (!err) {
        kvset_builder_set_merge_stats(bldr, &w->cw_stats);
        kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_LEAF);
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

struct route_info {
    struct route_node  *rnode;
    struct key_obj      ekobj;
    bool                last_node;
    char                ekey[HSE_KVS_KEY_LEN_MAX];
};

static void
cn_spill_route_get(
    struct cn_tree *tree,
    struct key_obj *kobj,
    struct route_info *ri)
{
    unsigned klen;

    assert(sizeof(ri->ekey) == HSE_KVS_KEY_LEN_MAX);

    /* Borrow callers output buffer to convert input key obj to a char
     * buffer as required by the route API.
     */
    key_obj_copy(ri->ekey, sizeof(ri->ekey), &klen, kobj);

    ri->rnode = cn_tree_route_get(tree, ri->ekey, klen);
    assert(ri->rnode);

    route_node_keycpy(ri->rnode, ri->ekey, sizeof(ri->ekey), &klen);
    key2kobj(&ri->ekobj, ri->ekey, klen);

    ri->last_node = route_node_islast(ri->rnode);
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
    struct key_obj prev_kobj = { 0 };
    struct route_info ri = {};

    uint vlen, complen, omlen, direct_read_len;
    uint curr_klen HSE_MAYBE_UNUSED;
    u32 bufsz = 0;
    void *buf = NULL;
    merr_t err;
    uint output_nodec = 0;

    u64  seq, emitted_seq = 0, emitted_seq_pt = 0;
    bool emitted_val = false, bg_val = false, more;
    bool kvcompact = (w->cw_action == CN_ACTION_COMPACT_KV);

    u64  tstart, tprog = 0;
    u64  dbg_prev_seq HSE_MAYBE_UNUSED;
    uint dbg_prev_src HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    bool dbg_dup HSE_MAYBE_UNUSED;
    uint seqno_errcnt = 0;

    /* Variables for tracking the last ptomb context */
    struct key_obj pt_kobj = { 0 };
    bool pt_set = false;
    u64 pt_seq = 0;

    assert(w->cw_kvset_cnt);
    assert(w->cw_inputv);

    tstart = perfc_ison(w->cw_pc, PERFC_DI_CNCOMP_VGET) ? 1 : 0;

    if (w->cw_prog_interval && w->cw_progress)
        tprog = jiffies;

    /* We must issue a direct read for all values that will not fit into the vblock readahead
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
        cn_spill_route_get(w->cw_tree, &curr.kobj, &ri);

    while (!err && more) {
        bool new_key = true;

        if (!child) {
            err = get_kvset_builder(w, output_nodec, &child);
            if (err)
                break;
            assert(child);

            /* Add ptomb to 'child' if a ptomb context is carried forward from the
             * previous node spill, i.e., this ptomb spans across multiple children.
             */
            if (pt_set && (!w->cw_drop_tombs || pt_seq > w->cw_horizon)) {

                err = kvset_builder_add_val(child, &pt_kobj, HSE_CORE_TOMB_PFX, 0, pt_seq, 0);
                if (!err)
                    err = kvset_builder_add_key(child, &pt_kobj);

                if (err) {
                    kvset_builder_destroy(child);
                    break;
                }

                w->cw_stats.ms_keys_out++;
                w->cw_stats.ms_key_bytes_out += key_obj_len(&pt_kobj);
            }
        }

        while (more && (kvcompact || ri.last_node || key_obj_cmp(&curr.kobj, &ri.ekobj) <= 0)) {

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
                    err = kvset_iter_val_get(w->cw_inputv[curr.src], &curr.vctx, vtype, vbidx,
                                              vboff, &vdata, &vlen, &complen);
                }

                if (err)
                    break;

                if (tstart > 0) {
                    u64 t = get_time_ns() - tstart;

                    perfc_dis_record(w->cw_pc, PERFC_DI_CNCOMP_VGET, t);
                }

                if (HSE_UNLIKELY(dbg_nvals_this_key && dbg_prev_seq <= seq)) {
                    assert(0);
                    seqno_errcnt++;
                }

                assert(!HSE_CORE_IS_PTOMB(vdata) || !w->cw_pfx_len || w->cw_pfx_len == curr_klen);
                dbg_nvals_this_key++;
                dbg_prev_seq = seq;

                bg_val = (seq <= w->cw_horizon);

                if (bg_val && pt_set && w->cw_horizon >= pt_seq && pt_seq > seq)
                    break; /* drop val if it and pt are beyond horizon */

                /* Set ptomb context irrespective of bg_val for tombstone propagation */
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
                    if (w->cw_drop_tombs && HSE_CORE_IS_TOMB(vdata) && bg_val)
                        continue; /* skip value */

                    err = kvset_builder_add_val(child, &curr.kobj, vdata, vlen, seq, complen);
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
                if (key_obj_cmp(&curr.kobj, &prev_kobj) == 0) {
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

            if (atomic_read(w->cw_cancel_request)) {
                err = merr(ESHUTDOWN);
                break;
            }
        }

        if (err) {
            kvset_builder_destroy(child);
            break;
        }

        assert(!ri.last_node || !more);

        if (!more || !ri.last_node) {
            err = kvset_builder_get_mblocks(child, &w->cw_outv[output_nodec]);
            if (err) {
                while (output_nodec-- > 0) {
                    delete_mblock(w->cw_mp, &w->cw_outv[output_nodec].hblk);
                    delete_mblocks(w->cw_mp, &w->cw_outv[output_nodec].kblks);
                    delete_mblocks(w->cw_mp, &w->cw_outv[output_nodec].vblks);
                }
                memset(w->cw_outv, 0, w->cw_outc * sizeof(*w->cw_outv));
            } else {
                w->cw_output_nodev[output_nodec++] = route_node_tnode(ri.rnode);
            }

            kvset_builder_destroy(child);
            child = NULL;
        }

        if (more)
            cn_spill_route_get(w->cw_tree, &curr.kobj, &ri);
    }

    bin_heap_destroy(bh);
    free_aligned(buf);

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    return err;
}
