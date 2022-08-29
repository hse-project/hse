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
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/cn.h>

#include "kvcompact.h"

#include "cn_tree.h"
#include "cn_tree_internal.h"
#include "cn_tree_compact.h"
#include "kvset.h"
#include "cn_metrics.h"
#include "kv_iterator.h"
#include "blk_list.h"
#include "route.h"

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

        free(*buf);

        *buf = aligned_alloc(PAGE_SIZE, *bufsz);
        if (!(*buf))
            return merr(ENOMEM);
    }

    return 0;
}

merr_t
cn_kvcompact(struct cn_compaction_work *w)
{
    struct bin_heap2 *bh = 0;
    struct kvset_builder *bldr = NULL;
    struct key_obj prev_kobj = { 0 };

    uint vlen, complen, omlen, direct_read_len;
    uint curr_klen HSE_MAYBE_UNUSED;
    u32 bufsz = 0;
    void *buf = NULL;
    merr_t err;

    u64  seq, emitted_seq = 0, emitted_seq_pt = 0;
    bool emitted_val = false, bg_val = false;

    struct key_obj pt_kobj = {0};
    u64 pt_seq = 0;
    bool pt_set = false;

    u64  tstart, tprog = 0;
    u64  dbg_prev_seq = 0;
    uint dbg_prev_idx HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    bool dbg_dup HSE_MAYBE_UNUSED;
    uint seqno_errcnt = 0;
    bool new_key;
    bool more;
    struct cn_kv_item *curr = NULL;
    struct element_source **bh_sources;

    assert(w->cw_kvset_cnt);
    assert(w->cw_inputv);

    bh_sources = malloc(w->cw_kvset_cnt * sizeof(*bh_sources));
    if (!bh_sources)
        return merr(ENOMEM);

    err = bin_heap2_create(w->cw_kvset_cnt, kv_item_compare, &bh);
    if (err)
        goto out;

    if (w->cw_prog_interval && w->cw_progress)
        tprog = jiffies;

    /* We must issue a direct read for all values that will not fit into the vblock readahead
     * buffer.  Since all direct reads require page size alignment any value whose length is
     * greater than the buffer size minus one page must be read directly from disk (vs from the
     * readahead buffer).
     */
    direct_read_len = w->cw_rp->cn_compact_vblk_ra;
    direct_read_len -= PAGE_SIZE;

    w->cw_kvsetidv[0] = cndb_kvsetid_mint(cn_tree_get_cndb(w->cw_tree));

    err = kvset_builder_create(&bldr, cn_tree_get_cn(w->cw_tree), w->cw_pc, w->cw_kvsetidv[0]);
    if (err)
        goto out;

    kvset_builder_set_merge_stats(bldr, &w->cw_stats);
    kvset_builder_set_agegroup(bldr, HSE_MPOLICY_AGE_LEAF);

    new_key = true;

    tstart = perfc_ison(w->cw_pc, PERFC_DI_CNCOMP_VGET) ? 1 : 0;

    more = bin_heap2_peek(bh, (void **)&curr);
    if (curr) {
        w->cw_stats.ms_keys_in++;
        w->cw_stats.ms_key_bytes_in += key_obj_len(&curr->kobj);
    }

    while (more) {
        uint idx = curr->src->es_sort;
        struct kv_iterator *iter = kvset_cursor_es_h2r(curr->src);

        curr_klen = key_obj_len(&curr->kobj);
        assert(curr_klen >= w->cw_cp->sfx_len || curr->vctx.is_ptomb);

        if (new_key) {
            bg_val = false;
            emitted_val = false;
            emitted_seq = 0;
            emitted_seq_pt = 0;

            dbg_prev_seq = 0;
            dbg_prev_idx = 0;
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

            if (!kvset_iter_next_vref(iter, &curr->vctx, &seq, &vtype, &vbidx,
                                      &vboff, &vdata, &vlen, &complen))
                break;

            omlen = (vtype == vtype_val) ? vlen : ((vtype == vtype_cval) ? complen : 0);

            direct = omlen > direct_read_len;
            if (direct) {
                err = get_direct_read_buf(omlen, !(vboff % PAGE_SIZE), &bufsz, &buf);
                if (err)
                    break;

                err = kvset_iter_next_val_direct(iter, vtype, vbidx, vboff, buf, omlen, bufsz);
                vdata = buf;
            } else {
                err = kvset_iter_val_get(iter, &curr->vctx, vtype, vbidx,
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
                pt_kobj = curr->kobj;
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

                err = kvset_builder_add_val(bldr, &curr->kobj, vdata, vlen, seq, complen);
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
                assert(dbg_prev_idx < idx);
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

        if (curr) {
            w->cw_stats.ms_keys_in++;
            w->cw_stats.ms_key_bytes_in += key_obj_len(&curr->kobj);
        }

        if (more) {
            if (key_obj_cmp(&curr->kobj, &prev_kobj) == 0) {
                dbg_dup = true;
                new_key = false;
                assert(dbg_prev_idx <= curr->src->es_sort);
                continue;
            } else if (pt_set && key_obj_cmp_prefix(&pt_kobj, &curr->kobj) != 0) {
                pt_set = false; /* cached ptomb key is no longer valid */
            }
        }

        if (emitted_val) {
            err = kvset_builder_add_key(bldr, &prev_kobj);
            if (err)
                goto out;

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
            goto out;
        }
    }

    err = kvset_builder_get_mblocks(bldr, &w->cw_outv[0]);
    if (!err)
        w->cw_output_nodev[0] = w->cw_node;

out:
    kvset_builder_destroy(bldr);
    bin_heap2_destroy(bh);
    free(bh_sources);
    free(buf);

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    return err;
}
