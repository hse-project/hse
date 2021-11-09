/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvset_builder.h>

/* [HSE_REVISIT] - Why is this at the top of this file? */

#define MTF_MOCK_IMPL_kcompact
#include "kcompact.h"
#if HSE_MOCKING
#include "kcompact_ut_impl.i"
#endif /* HSE_MOCKING */

#include "kvset.h"
#include "cn_metrics.h"
#include "kv_iterator.h"
#include "cn_tree.h"
#include "cn_tree_internal.h"
#include "cn_tree_compact.h"

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

/**
 * kcompact() - merge key-value streams in a single output stream
 * Requirements:
 *   - Each input iterator must produce keys in sorted order.
 *   - Iterator iterv[i] must contain newer entries than iterv[i+1].
 */
static merr_t
kcompact(struct cn_compaction_work *w)
{
    struct bin_heap * bh;
    struct merge_item curr;
    merr_t            err;

    enum kmd_vtype vtype;
    uint           vbidx, vboff, vlen, complen;
    const void *   vdata;

    u64  seq, emitted_seq = 0, emitted_seq_pt = 0;
    bool emitted_val, horizon, more;

    struct key_obj prev_kobj, pt_kobj = { 0 };

    bool pt_set = false;
    u64  pt_seq = 0;
    u64  tprog = 0;

    u64 dbg_prev_seq HSE_MAYBE_UNUSED;
    uint dbg_prev_src HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    bool dbg_dup HSE_MAYBE_UNUSED;

    uint seqno_errcnt = 0;

    /* 'vbm_used' counts only the values referenced after this compaction;
     * however, waste accumulates from compact-to-compact
     */
    w->cw_vbmap.vbm_used = 0;

    if (w->cw_prog_interval && w->cw_progress)
        tprog = jiffies;

    err = merge_init(&bh, w->cw_inputv, w->cw_kvset_cnt, &w->cw_stats);
    if (ev(err))
        return err;

    more = get_next_item(bh, w->cw_inputv, &curr, &w->cw_stats, &err);
    if (!more || ev(err))
        goto done;

new_key:

    if (atomic_read(w->cw_cancel_request)) {
        err = merr(ev(ESHUTDOWN));
        goto done;
    }

    if (tprog) {
        u64 now = jiffies;

        if (now - tprog > w->cw_prog_interval) {
            tprog = now;
            w->cw_progress(w);
        }
    }

    emitted_val = false;
    horizon = true;
    emitted_seq = 0;
    emitted_seq_pt = 0;

    dbg_prev_seq = 0;
    dbg_prev_src = 0;
    dbg_nvals_this_key = 0;
    dbg_dup = false;

get_values:
    vdata = NULL;

    while (horizon &&
           kvset_iter_next_vref(
               w->cw_inputv[curr.src], &curr.vctx, &seq, &vtype, &vbidx, &vboff,
               &vdata, &vlen, &complen))
    {
        bool should_emit = false;

        /* Assertion logic:
         *   if (dbg_nvals_this_key)
         *       assert(dbg_prev_seq > seq);
         */
        if (HSE_UNLIKELY(dbg_nvals_this_key && dbg_prev_seq <= seq)) {
            assert(0);
            seqno_errcnt++;
        }

        dbg_nvals_this_key++;
        dbg_prev_seq = seq;

        if (seq <= w->cw_horizon) {
            horizon = false;
            if (pt_set && seq < pt_seq)
                continue; /* skip value */

            if (vtype == vtype_ptomb) {
                pt_set = true;
                pt_kobj = curr.kobj;
                assert(key_obj_len(&curr.kobj) == w->cw_pfx_len);
                pt_seq = seq;
            }

            if (w->cw_drop_tombv[0] && (vtype == vtype_tomb || vtype == vtype_ptomb))
                continue; /* skip value */
        }

        if (vtype == vtype_ptomb)
            should_emit = !emitted_seq_pt || seq < emitted_seq_pt;
        else
            should_emit = !emitted_seq || seq < emitted_seq;

        should_emit = should_emit || !emitted_val;

        /* Compare seq to emitted_seq to ensure when a key has values
         * in two kvsets with the same sequence number, that only the
         * value from the first kvset is emitted.
         */
        if (should_emit) {

            switch (vtype) {
                case vtype_val:
                case vtype_cval:
                    err = kvset_builder_add_vref(
                        w->cw_child[0], seq, vbidx + w->cw_vbmap.vbm_map[curr.src],
                        vboff, vlen, complen);
                    break;
                case vtype_zval:
                case vtype_ival:
                    err = kvset_builder_add_val(w->cw_child[0], seq, vdata, vlen, 0);
                    break;
                default:
                    err = kvset_builder_add_nonval(w->cw_child[0], seq, vtype);
                    break;
            }
            if (ev(err))
                goto done;
            emitted_val = true;

            if (vtype == vtype_ptomb)
                emitted_seq_pt = seq;
            else
                emitted_seq = seq;

            w->cw_stats.ms_val_bytes_out += complen ? complen : vlen;
            w->cw_vbmap.vbm_used += complen ? complen : vlen;
        } else {
            /* The only time we ever land here is when the same
             * key appears in two input kvsets with overlapping
             * sequence numbers.  For example:
             *
             * Kvset #1: MEAL --> [[11,BURGERS], [10,BEER]]
             * Kvset #2: MEAL --> [[10,SPAM], [9,FRIES]]
             *
             * We have already emitted BURGERS and BEER, are
             * currently processing SPAM (which must be be
             * discarded), and will get FRIES on the next
             * iteration.
             *
             * The following assertions verify that we aren't here
             * for other reasons (e.g., input kvsets that violate
             * assumptions about sequence numbers).
             */
            assert(dbg_prev_src < curr.src);
            assert(seq == emitted_seq);
            if (seq > emitted_seq)
                seqno_errcnt++;

            assert(vdata != HSE_CORE_TOMB_PFX);
        }
    }

    prev_kobj = curr.kobj;

    dbg_dup = false;
    dbg_nvals_this_key = 0;
    dbg_prev_src = curr.src;

    more = get_next_item(bh, w->cw_inputv, &curr, &w->cw_stats, &err);
    if (ev(err))
        goto done;

    if (more) {
        if (0 == key_obj_cmp(&curr.kobj, &prev_kobj)) {
            dbg_dup = true;
            assert(dbg_prev_src <= curr.src);
            goto get_values;
        } else if (pt_set && key_obj_cmp_prefix(&pt_kobj, &curr.kobj) != 0) {
            pt_set = false;
        }
    }

    if (emitted_val) {
        err = kvset_builder_add_key(w->cw_child[0], &prev_kobj);
        if (ev(err))
            goto done;
        w->cw_stats.ms_keys_out++;
        w->cw_stats.ms_key_bytes_out += key_obj_len(&prev_kobj);
    }

    if (more)
        goto new_key;

done:
    w->cw_vbmap.vbm_waste = w->cw_vbmap.vbm_tot - w->cw_vbmap.vbm_used;
    bin_heap_destroy(bh);

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    return err;
}

merr_t
cn_kcompact(struct cn_compaction_work *w)
{
    merr_t               err;
    struct cn_tree_node *pnode;

    err = kvset_builder_create(
        &w->cw_child[0],
        cn_tree_get_cn(w->cw_tree),
        w->cw_pc,
        w->cw_dgen_hi);
    if (ev(err))
        goto done;

    pnode = w->cw_node;
    if (pnode) {
        if (cn_node_isroot(pnode))
            kvset_builder_set_agegroup(w->cw_child[0], HSE_MPOLICY_AGE_ROOT);
        else if (cn_node_isleaf(pnode))
            kvset_builder_set_agegroup(w->cw_child[0], HSE_MPOLICY_AGE_LEAF);
        else
            kvset_builder_set_agegroup(w->cw_child[0], HSE_MPOLICY_AGE_INTERNAL);
    }

    kvset_builder_set_merge_stats(w->cw_child[0], &w->cw_stats);

    err = kcompact(w);
    if (ev(err))
        goto done;

    /* get resulting mblocks */
    err = kvset_builder_get_mblocks(w->cw_child[0], w->cw_outv);
    if (ev(err))
        goto done;

    /* kvset builder should not have created vblocks during kcompaction */
    assert(w->cw_outv->vblks.blks == 0);
    assert(w->cw_outv->vblks.n_blks == 0);

    /* kcompact --> reuse existing vblocks */
    if (w->cw_vbmap.vbm_blkv) {
        w->cw_outv->vblks.blks = w->cw_vbmap.vbm_blkv;
        w->cw_outv->vblks.n_blks = w->cw_vbmap.vbm_blkc;
        w->cw_vbmap.vbm_blkv = 0;
        w->cw_vbmap.vbm_blkc = 0;
    }

done:
    kvset_builder_destroy(w->cw_child[0]);
    return err;
}
