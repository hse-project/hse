/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_kcompact

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvset_builder.h>

#include "kcompact.h"

#include "kvset.h"
#include "cn_metrics.h"
#include "kv_iterator.h"
#include "cn_tree.h"
#include "cn_tree_internal.h"
#include "cn_tree_compact.h"

static int
kv_item_compare(const void *a, const void *b)
{
    const struct cn_kv_item *item_a = a;
    const struct cn_kv_item *item_b = b;

    /* In the event the keys are equal, the bin heap implementation will return
     * the key from the earliest element source by index. We can use this as a
     * proxy for the newest key since the element sources are ordered from
     * newest kvset to oldest kvset.
     */
    return key_obj_cmp(&item_a->kobj, &item_b->kobj);
}

/**
 * kcompact() - merge key-value streams in a single output stream
 * Requirements:
 *   - Each input iterator must produce keys in sorted order.
 *   - Iterator iterv[i] must contain newer entries than iterv[i+1].
 */
static merr_t
kcompact(struct cn_compaction_work *w, struct kvset_builder *bldr)
{
    merr_t err;
    struct cn_kv_item *curr;
    struct bin_heap2 *bh = NULL;
    struct element_source **sources = NULL;

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
    uint dbg_prev_idx HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    bool dbg_dup HSE_MAYBE_UNUSED;

    uint seqno_errcnt = 0;

    /* 'vbm_used' counts only the values referenced after this compaction;
     * however, waste accumulates from compact-to-compact
     */
    w->cw_vbmap.vbm_used = 0;

    if (w->cw_prog_interval && w->cw_progress)
        tprog = jiffies;

    err = bin_heap2_create(w->cw_kvset_cnt, kv_item_compare, &bh);
    if (ev(err))
        return err;

    sources = malloc(w->cw_kvset_cnt * sizeof(*sources));
    if (!sources) {
        err = merr(ENOMEM);
        goto done;
    }

    for (uint i = 0; i < w->cw_kvset_cnt; i++) {
        struct kv_iterator *iter = w->cw_inputv[i];

        sources[i] = kvset_iter_es_get(iter);
    }

    err = bin_heap2_prepare(bh, w->cw_kvset_cnt, sources);
    if (ev(err))
        goto done;
    /* In the event this assert fails, at least one iterator is EOF and the idea
     * that struct element_source::es_sort will properly index the vblock map is
     * incorrect. Kvsets won't typically exist if they have no prefix tombstones
     * or keys.
     */
    assert(bin_heap2_width(bh) == w->cw_kvset_cnt);

    w->cw_stats.ms_srcs = w->cw_kvset_cnt;

    more = bin_heap2_peek(bh, (void **)&curr);
    while (more) {
        uint idx = curr->src->es_sort;
        struct kv_iterator *iter = kvset_cursor_es_h2r(curr->src);

        if (atomic_read(w->cw_cancel_request)) {
            err = merr(ESHUTDOWN);
            goto done;
        }

        if (tprog) {
            const u64 now = jiffies;

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
        dbg_prev_idx = 0;
        dbg_nvals_this_key = 0;
        dbg_dup = false;

    values:
        vdata = NULL;
        w->cw_stats.ms_keys_in++;
        w->cw_stats.ms_key_bytes_in += key_obj_len(&curr->kobj);

        while (horizon && kvset_iter_next_vref(iter, &curr->vctx, &seq, &vtype, &vbidx, &vboff,
                &vdata, &vlen, &complen)) {
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
                    pt_kobj = curr->kobj;
                    assert(key_obj_len(&curr->kobj) == w->cw_pfx_len);
                    pt_seq = seq;
                }

                if (w->cw_drop_tombs && (vtype == vtype_tomb || vtype == vtype_ptomb))
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
                        bldr, seq, vbidx + w->cw_vbmap.vbm_map[idx], vboff, vlen, complen);
                    break;
                case vtype_zval:
                case vtype_ival:
                    err = kvset_builder_add_val(bldr, &curr->kobj, vdata, vlen, seq, 0);
                    break;
                default:
                    err = kvset_builder_add_nonval(bldr, seq, vtype);
                    break;
                }
                if (ev(err))
                    goto done;
                emitted_val = true;

                if (vtype == vtype_ptomb)
                    emitted_seq_pt = seq;
                else
                    emitted_seq = seq;

                if (complen) {
                    w->cw_stats.ms_val_bytes_out += complen;
                    w->cw_vbmap.vbm_used += complen;
                } else {
                    w->cw_stats.ms_val_bytes_out += vlen;
                    w->cw_vbmap.vbm_used += vlen;
                }
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
                assert(dbg_prev_idx < idx);
                assert(seq == emitted_seq);
                if (seq > emitted_seq)
                    seqno_errcnt++;

                assert(vdata != HSE_CORE_TOMB_PFX);
            }
        }

        prev_kobj = curr->kobj;

        dbg_dup = false;
        dbg_nvals_this_key = 0;
        dbg_prev_idx = idx;

        /* Discard the result from pop(). This bin heap is backed by a kv
         * iterator which has a buffer (kvi_kv) which curr points to. pop()
         * will not give us the data the we expect because of the backing
         * buffer, so we call it in order to force all the side effects to
         * occur, but only grab the next value after pop() calls heapify().
         */
        bin_heap2_pop(bh, NULL);
        more = bin_heap2_peek(bh, (void **)&curr);
        if (more) {
            iter = kvset_cursor_es_h2r(curr->src);
            idx = curr->src->es_sort;

            if (key_obj_cmp(&curr->kobj, &prev_kobj) == 0) {
                dbg_dup = true;
                assert(dbg_prev_idx <= idx);
                goto values;
            }

            if (pt_set && key_obj_cmp_prefix(&pt_kobj, &curr->kobj) != 0)
                pt_set = false;
        }

        if (emitted_val) {
            err = kvset_builder_add_key(bldr, &prev_kobj);
            if (ev(err))
                goto done;
            w->cw_stats.ms_keys_out++;
            w->cw_stats.ms_key_bytes_out += key_obj_len(&prev_kobj);
        }
    }

done:
    w->cw_vbmap.vbm_waste = w->cw_vbmap.vbm_tot - w->cw_vbmap.vbm_used;
    bin_heap2_destroy(bh);
    free(sources);

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    return err;
}

merr_t
cn_kcompact(struct cn_compaction_work *w)
{
    merr_t                err;
    struct cn_tree_node  *pnode;
    struct kvset_builder *bldr;

    w->cw_kvsetidv[0] = cndb_kvsetid_mint(cn_tree_get_cndb(w->cw_tree));

    err = kvset_builder_create(
        &bldr,
        cn_tree_get_cn(w->cw_tree),
        w->cw_pc,
        w->cw_kvsetidv[0]);
    if (ev(err))
        return err;

    pnode = w->cw_node;
    if (pnode) {
        if (cn_node_isroot(pnode))
            kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_ROOT);
        else if (cn_node_isleaf(pnode))
            kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_LEAF);
        else
            kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_INTERNAL);
    }

    kvset_builder_set_merge_stats(bldr, &w->cw_stats);

    err = kcompact(w, bldr);
    if (ev(err))
        goto done;

    /* During k-compaction, vblocks will not be generated. Instead, they will be
     * inherited from the input kvsets.
     */
    if (w->cw_vbmap.vbm_blkc > 0) {
        struct vgmap *vgmap = w->cw_vgmap[0];

        assert(vgmap && w->cw_input_vgroups == vgmap->nvgroups);
        kvset_builder_adopt_vblocks(bldr, w->cw_vbmap.vbm_blkc, w->cw_vbmap.vbm_blkv, vgmap);
        w->cw_vgmap[0] = NULL; /* reset after adopting the vgmap to the kvset builder */

        w->cw_vbmap.vbm_blkv = NULL;
        w->cw_vbmap.vbm_blkc = 0;
    }

    /* get resulting mblocks */
    err = kvset_builder_get_mblocks(bldr, w->cw_outv);
    if (ev(err))
        goto done;

done:
    kvset_builder_destroy(bldr);

    return err;
}

#if HSE_MOCKING
#include "kcompact_ut_impl.i"
#endif /* HSE_MOCKING */
