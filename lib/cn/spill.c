/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/util/platform.h>
#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/page.h>
#include <hse/util/event_counter.h>
#include <hse/logging/logging.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/cn.h>

#define MTF_MOCK_IMPL_spill
#include "spill.h"

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

struct spillctx {
    struct cn_compaction_work *work;

    uint64_t         sgen;

    /* Merge Loop */
    struct bin_heap        *bh;
    struct element_source **bh_sources;
    bool                    more;
    struct cn_kv_item      *curr;

    /* Ptomb */
    struct key_obj pt_kobj;
    u64            pt_seq; /* [HSE_REVISIT]: Need a list of seqnos to carry all ptombs across leaves. */
    bool           pt_set;
};

merr_t
cn_spill_create(struct cn_compaction_work *w, struct spillctx **sctx_out)
{
    struct spillctx *s;
    size_t sz;
    merr_t err;

    sz = sizeof(*s) + w->cw_kvset_cnt * sizeof(*s->bh_sources);

    s = malloc(sz);
    if (!s)
        return merr(ENOMEM);

    memset(s, 0, sizeof(*s));
    s->bh_sources = (void *)(s + 1);

    err = bin_heap_create(w->cw_kvset_cnt, kv_item_compare, &s->bh);
    if (err)
        goto out;

    for (uint i = 0; i < w->cw_kvset_cnt; i++) {
        struct kv_iterator *iter = w->cw_inputv[i];

        s->bh_sources[i] = kvset_iter_es_get(iter);
    }

    err = bin_heap_prepare(s->bh, w->cw_kvset_cnt, s->bh_sources);
    if (err)
        goto out;

    s->work = w;
    s->sgen = w->cw_sgen;

    s->more = bin_heap_peek(s->bh, (void **)&s->curr);
    if (s->curr) {
        w->cw_stats.ms_keys_in++;
        w->cw_stats.ms_key_bytes_in += key_obj_len(&s->curr->kobj);
    }

    *sctx_out = s;

out:
    if (err) {
        bin_heap_destroy(s->bh);
        free(s);
    }

    return err;
}

void
cn_spill_destroy(struct spillctx *sctx)
{
    if (!sctx)
        return;

    bin_heap_destroy(sctx->bh);
    free(sctx);
}

void
cn_subspill_get_kvset_meta(struct subspill *ss, struct kvset_meta *km)
{
    struct cn_compaction_work *w = ss->ss_work;

    memset(km, 0, sizeof(*km));

    km->km_dgen_hi = w->cw_dgen_hi;
    km->km_dgen_lo = w->cw_dgen_lo;
    km->km_vused = ss->ss_mblks.bl_vused;
    km->km_vgarb = ss->ss_mblks.bl_vtotal - km->km_vused;

    km->km_hblk_id = ss->ss_mblks.hblk_id;
    km->km_kblk_list = ss->ss_mblks.kblks;
    km->km_vblk_list = ss->ss_mblks.vblks;

    km->km_rule = w->cw_rule;
    km->km_capped = cn_is_capped(w->cw_tree->cn);
    km->km_restored = false;

    km->km_compc = 0;
    km->km_nodeid = ss->ss_node->tn_nodeid;
}

merr_t
cn_subspill(
    struct subspill     *ss,
    struct spillctx     *sctx,
    struct cn_tree_node *node,
    uint64_t             node_dgen,
    const void          *ekey,
    uint                 eklen)
{
    struct cn_compaction_work *w = sctx->work;
    struct bin_heap *bh = sctx->bh;
    struct kvset_builder *child = NULL;
    struct key_obj prev_kobj = { 0 };

    uint vlen, complen, omlen, direct_read_len;
    uint curr_klen HSE_MAYBE_UNUSED;
    u32 bufsz = 0;
    void *buf = NULL;
    merr_t err;

    u64  seq, emitted_seq = 0, emitted_seq_pt = 0;
    bool emitted_val = false, bg_val = false;

    u64  tstart, tprog = 0;
    u64  dbg_prev_seq = 0;
    uint dbg_prev_idx HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    bool dbg_dup HSE_MAYBE_UNUSED;
    uint seqno_errcnt = 0;
    bool new_key;
    struct key_obj ekobj;

    key2kobj(&ekobj, ekey, eklen);

    assert(w->cw_kvset_cnt);
    assert(w->cw_inputv);

    memset(ss, 0, sizeof(*ss));

    ss->ss_sgen = w->cw_sgen;

    if (w->cw_prog_interval && w->cw_progress)
        tprog = jiffies;

    /* We must issue a direct read for all values that will not fit into the vblock readahead
     * buffer.  Since all direct reads require page size alignment any value whose length is
     * greater than the buffer size minus one page must be read directly from disk (vs from the
     * readahead buffer).
     */
    direct_read_len = w->cw_rp->cn_compact_vblk_ra;
    direct_read_len -= PAGE_SIZE;

    ss->ss_added = false;
    ss->ss_work = w;

    if (!sctx->more && !sctx->pt_set)
        return 0;

    /* Proceed only if either the curr key belongs in this leaf node OR there's a ptomb that needs
     * to be propagated to this child.
     */
    if (!sctx->pt_set && key_obj_cmp(&sctx->curr->kobj, &ekobj) > 0)
        return 0;

    w->cw_kvsetidv[0] = ss->ss_kvsetid = cndb_kvsetid_mint(cn_tree_get_cndb(w->cw_tree));

    err = kvset_builder_create(&child, cn_tree_get_cn(w->cw_tree), w->cw_pc, ss->ss_kvsetid);
    if (err)
        return err;

    assert(child);

    kvset_builder_set_merge_stats(child, &w->cw_stats);
    kvset_builder_set_agegroup(child, HSE_MPOLICY_AGE_LEAF);

    /* Add ptomb to 'child' if a ptomb context is carried forward from the
     * previous node spill, i.e., this ptomb spans across multiple children.
     */
    if (sctx->pt_set && (!w->cw_drop_tombs || sctx->pt_seq > w->cw_horizon)) {
        err = kvset_builder_add_val(child, &sctx->pt_kobj, HSE_CORE_TOMB_PFX, 0, sctx->pt_seq, 0);
        if (!err)
            err = kvset_builder_add_key(child, &sctx->pt_kobj);

        if (err) {
            kvset_builder_destroy(child);
            return err;
        }

        w->cw_stats.ms_keys_out++;
        w->cw_stats.ms_key_bytes_out += key_obj_len(&sctx->pt_kobj);

        ss->ss_added = true;
        if (key_obj_cmp_prefix(&sctx->pt_kobj, &ekobj) < 0)
            sctx->pt_set = false;
    }

    new_key = true;

    tstart = perfc_ison(w->cw_pc, PERFC_DI_CNCOMP_VGET) ? 1 : 0;

    while (sctx->more && key_obj_cmp(&sctx->curr->kobj, &ekobj) <= 0) {
        uint idx = sctx->curr->src->es_sort;
        struct kv_iterator *iter = kvset_cursor_es_h2r(sctx->curr->src);

        curr_klen = key_obj_len(&sctx->curr->kobj);

        if (new_key) {
            bg_val = false;
            emitted_val = false;
            emitted_seq = 0;
            emitted_seq_pt = 0;

            dbg_prev_seq = 0;
            dbg_prev_idx = 0;
            dbg_nvals_this_key = 0;
            dbg_dup = false;

            if (sctx->pt_set && key_obj_cmp_prefix(&sctx->pt_kobj, &sctx->curr->kobj) != 0)
                sctx->pt_set = false; /* cached ptomb key is no longer valid */
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

            if (!kvset_iter_next_vref(iter, &sctx->curr->vctx,
                                      &seq, &vtype, &vbidx,
                                      &vboff, &vdata, &vlen, &complen))
                break;

            omlen = (vtype == VTYPE_UCVAL) ? vlen : ((vtype == VTYPE_CVAL) ? complen : 0);

            direct = omlen > direct_read_len;
            if (direct) {
                err = get_direct_read_buf(omlen, !(vboff % PAGE_SIZE), &bufsz, &buf);
                if (err)
                    break;

                err = kvset_iter_next_val_direct(iter, vtype, vbidx,
                                                 vboff, buf, omlen, bufsz);
                vdata = buf;
            } else {
                err = kvset_iter_val_get(iter, &sctx->curr->vctx, vtype, vbidx,
                                          vboff, &vdata, &vlen, &complen);
            }

            if (err)
                break;

            if (tstart > 0) {
                uint64_t t = get_time_ns() - tstart;

                perfc_dis_record(w->cw_pc, PERFC_DI_CNCOMP_VGET, t);
            }

            if (HSE_UNLIKELY(dbg_nvals_this_key && dbg_prev_seq <= seq)) {
                assert(0);
                seqno_errcnt++;
            }

            assert(!HSE_CORE_IS_PTOMB(vdata) || !w->cw_pfx_len || w->cw_pfx_len == curr_klen);
            dbg_nvals_this_key++;
            dbg_prev_seq = seq;

            if (sctx->curr->vctx.dgen <= node_dgen)
                break;

            bg_val = (seq <= w->cw_horizon);

            if (bg_val && sctx->pt_set && w->cw_horizon >= sctx->pt_seq && sctx->pt_seq > seq)
                break; /* drop val if it and pt are beyond horizon */

            /* Set ptomb context irrespective of bg_val for tombstone propagation */
            if (HSE_CORE_IS_PTOMB(vdata)) {
                sctx->pt_set = true;
                sctx->pt_kobj = sctx->curr->kobj;
                sctx->pt_seq = seq;
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

                err = kvset_builder_add_val(child, &sctx->curr->kobj, vdata, vlen, seq, complen);
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

        prev_kobj = sctx->curr->kobj;

        dbg_dup = false;
        dbg_nvals_this_key = 0;
        dbg_prev_idx = idx;

        /* Discard the result from pop(). This bin heap is backed by a kv
         * iterator which has a buffer (kvi_kv) which curr points to. pop()
         * will not give us the data the we expect because of the backing
         * buffer, so we call it in order to force all the side effects to
         * occur, but only grab the next value after pop() calls heapify().
         */
        bin_heap_pop(bh, NULL);
        sctx->more = bin_heap_peek(bh, (void **)&sctx->curr);

        if (sctx->curr) {
            w->cw_stats.ms_keys_in++;
            w->cw_stats.ms_key_bytes_in += key_obj_len(&sctx->curr->kobj);
        }

        if (sctx->more) {
            if (key_obj_cmp(&sctx->curr->kobj, &prev_kobj) == 0) {
                dbg_dup = true;
                new_key = false;
                assert(dbg_prev_idx <= sctx->curr->src->es_sort);
                continue;
            }
        }

        if (emitted_val) {
            err = kvset_builder_add_key(child, &prev_kobj);
            if (err)
                break;

            ss->ss_added = true;
            w->cw_stats.ms_keys_out++;
            w->cw_stats.ms_key_bytes_out += key_obj_len(&prev_kobj);
        }

        new_key = true;

        if (tprog) {
            uint64_t now = jiffies;

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

    err = kvset_builder_get_mblocks(child, &ss->ss_mblks);

out:

    /* The cached ptomb needs to be propagated only if the current node's edge key has the same
     * prefix as the cached ptomb.
     */
    if (sctx->pt_set && key_obj_cmp_prefix(&sctx->pt_kobj, &ekobj) != 0)
        sctx->pt_set = false;

    kvset_builder_destroy(child);
    free(buf);

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    ss->ss_node = node;

    return err;
}

#if HSE_MOCKING
#include "spill_ut_impl.i"
#endif /* HSE_MOCKING */
