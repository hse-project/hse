/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
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
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/cn.h>

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

struct spillctx {
    struct cn_compaction_work *work;
    uint64_t                   sgen;

    /* Merge Loop */
    struct bin_heap  *bh;
    bool              more;
    struct merge_item curr;

    /* Ptomb */
    struct key_obj pt_kobj;
    u64            pt_seq; /* [HSE_REVISIT]: Need a list of seqnos to carry all ptombs across leaves. */
    bool           pt_set;
};

merr_t
cn_spill_init(struct cn_compaction_work *w, struct spillctx **sctx_out)
{
    struct spillctx *s;
    merr_t err;

    s = calloc(1, sizeof(*s));
    if (!s)
        return merr(ENOMEM);

    err = merge_init(&s->bh, w->cw_inputv, w->cw_kvset_cnt, &w->cw_stats);
    if (err) {
        free(s);
        return err;
    }

    s->work = w;
    s->sgen = w->cw_sgen;
    s->more = get_next_item(s->bh, w->cw_inputv, &s->curr, &w->cw_stats, &err);

    *sctx_out = s;
    return 0;
}

void
cn_spill_fini(struct spillctx *sctx)
{
    if (!sctx)
        return;

    bin_heap_destroy(sctx->bh);
    free(sctx);
}

void
cn_subspill_kvset_meta_get(struct subspill *ss, struct kvset_meta *km)
{
    struct cn_compaction_work *w = ss->w;

    memset(km, 0, sizeof(*km));

    km->km_dgen = w->cw_dgen_hi;
    km->km_vused = ss->ss_mblks.bl_vused;

    km->km_hblk = ss->ss_mblks.hblk;
    km->km_kblk_list = ss->ss_mblks.kblks;
    km->km_vblk_list = ss->ss_mblks.vblks;

    km->km_rule = w->cw_rule;
    km->km_capped = cn_is_capped(w->cw_tree->cn);
    km->km_restored = false;

    km->km_compc = 0;
    km->km_nodeid = ss->node->tn_nodeid;
}

void
cn_subspill_enqueue(struct subspill *ss, struct cn_tree_node *tn)
{
    struct list_head *p;
    struct subspill *entry;

    mutex_lock(&tn->tn_mut_lock);

    /* Add ss at the right position in the node's mutation list. The list is sorted by
     * sgen - smallest to largest.
     */
    list_for_each(p, &tn->tn_mut_list) {
        entry = list_entry(p, typeof(*entry), ss_link);

        if (ss->ss_sgen < entry->ss_sgen)
            break;
    }

    list_add_tail(&ss->ss_link, p);
    mutex_unlock(&tn->tn_mut_lock);
}

uint64_t
cn_subspill_sgen_get(struct subspill *ss)
{
    return ss->ss_sgen;
}

// TODO Gaurav: Move to cn_tree_node or wherever
struct subspill *
cn_node_first_subspill(struct cn_tree_node *tn)
{
    struct subspill *entry;
    bool found = false;

    mutex_lock(&tn->tn_mut_lock);

    entry = list_first_entry_or_null(&tn->tn_mut_list, typeof(*entry), ss_link);
    if (entry && entry->ss_sgen == atomic_read(&tn->tn_sgen) + 1) {
        list_del(&entry->ss_link);
        found = true;
    }

    mutex_unlock(&tn->tn_mut_lock);

    return found ? entry : NULL;
}

merr_t
cn_subspill(
    struct spillctx           *sctx,
    struct subspill           *ss,
    struct cn_tree_node       *node,
    uint64_t                   node_dgen,
    void                      *ekey,
    uint                       eklen)
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
    uint dbg_prev_src HSE_MAYBE_UNUSED;
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

    ss->added = false;
    ss->w = w;

    if (!sctx->more || key_obj_cmp(&sctx->curr.kobj, &ekobj) > 0) {
        if (!sctx->pt_set)
            return 0; /* Nothing to do */
    }

    ss->kvsetid = cndb_kvsetid_mint(cn_tree_get_cndb(w->cw_tree));

    err = get_kvset_builder(w, 0, &child);
    if (err)
        return err;

    assert(child);

    /* Add ptomb to 'child' if a ptomb context is carried forward from the
     * previous node spill, i.e., this ptomb spans across multiple children.
     */
    if (sctx->more && sctx->pt_set && (!w->cw_drop_tombs || sctx->pt_seq > w->cw_horizon)) {

        err = kvset_builder_add_val(child, &sctx->pt_kobj, HSE_CORE_TOMB_PFX, 0, sctx->pt_seq, 0);
        if (!err)
            err = kvset_builder_add_key(child, &sctx->pt_kobj);

        if (err) {
            kvset_builder_destroy(child);
            return err;
        }

        w->cw_stats.ms_keys_out++;
        w->cw_stats.ms_key_bytes_out += key_obj_len(&sctx->pt_kobj);
    }

    new_key = true;

    tstart = perfc_ison(w->cw_pc, PERFC_DI_CNCOMP_VGET) ? 1 : 0;

    while (sctx->more && key_obj_cmp(&sctx->curr.kobj, &ekobj) <= 0) {

        if (new_key && atomic_read(w->cw_cancel_request)) {
            err = merr(ESHUTDOWN);
            goto out;
        }

        curr_klen = key_obj_len(&sctx->curr.kobj);
        assert(curr_klen >= w->cw_cp->sfx_len || sctx->curr.vctx.is_ptomb);

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

            if (!kvset_iter_next_vref(w->cw_inputv[sctx->curr.src], &sctx->curr.vctx,
                                      &seq, &vtype, &vbidx,
                                      &vboff, &vdata, &vlen, &complen))
                break;

            omlen = (vtype == vtype_val) ? vlen : ((vtype == vtype_cval) ? complen : 0);

            direct = omlen > direct_read_len;
            if (direct) {
                err = get_direct_read_buf(omlen, !(vboff % PAGE_SIZE), &bufsz, &buf);
                if (err)
                    break;

                err = kvset_iter_next_val_direct(w->cw_inputv[sctx->curr.src], vtype, vbidx,
                                                 vboff, buf, omlen, bufsz);
                vdata = buf;
            } else {
                err = kvset_iter_val_get(w->cw_inputv[sctx->curr.src], &sctx->curr.vctx, vtype, vbidx,
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

            if (sctx->curr.vctx.dgen <= node_dgen)
                break;

            bg_val = (seq <= w->cw_horizon);

            if (bg_val && sctx->pt_set && w->cw_horizon >= sctx->pt_seq && sctx->pt_seq > seq)
                break; /* drop val if it and pt are beyond horizon */

            /* Set ptomb context irrespective of bg_val for tombstone propagation */
            if (HSE_CORE_IS_PTOMB(vdata)) {
                sctx->pt_set = true;
                sctx->pt_kobj = sctx->curr.kobj;
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

                err = kvset_builder_add_val(child, &sctx->curr.kobj, vdata, vlen, seq, complen);
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
                assert(dbg_prev_src < sctx->curr.src);
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

        prev_kobj = sctx->curr.kobj;

        dbg_dup = false;
        dbg_nvals_this_key = 0;
        dbg_prev_src = sctx->curr.src;

        sctx->more = get_next_item(bh, w->cw_inputv, &sctx->curr, &w->cw_stats, &err);
        if (err)
            break;

        if (sctx->more) {
            if (key_obj_cmp(&sctx->curr.kobj, &prev_kobj) == 0) {
                dbg_dup = true;
                new_key = false;
                assert(dbg_prev_src <= sctx->curr.src);
                continue;
            } else if (sctx->pt_set && key_obj_cmp_prefix(&sctx->pt_kobj, &sctx->curr.kobj) != 0) {
                sctx->pt_set = false; /* cached ptomb key is no longer valid */
            }
        }

        if (emitted_val) {
            err = kvset_builder_add_key(child, &prev_kobj);
            if (err)
                break;

            ss->added = true;
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

        if (err)
            goto out;
    }

    err = kvset_builder_get_mblocks(child, &ss->ss_mblks);

out:
    kvset_builder_destroy(child);
    free_aligned(buf);

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    ss->node = node;

    return err;
}

// TODO Gaurav: Ugh...
void
cn_comp_kvset_append(
    struct cn_compaction_work *work,
    struct cn_tree_node       *node,
    struct kvset              *kvset);

// TODO Gaurav: Move this to a separate file, or rename file
merr_t
cn_kvcompact(struct cn_compaction_work *w)
{
    struct bin_heap *bh;
    struct kvset_builder *bldr = NULL;
    struct key_obj prev_kobj = { 0 };

    uint vlen, complen, omlen, direct_read_len;
    uint curr_klen HSE_MAYBE_UNUSED;
    u32 bufsz = 0;
    void *buf = NULL;
    merr_t err;

    u64  seq, emitted_seq = 0, emitted_seq_pt = 0;
    bool emitted_val = false, bg_val = false;

    struct key_obj pt_kobj;
    u64 pt_seq = 0;
    bool pt_set = false;

    u64  tstart, tprog = 0;
    u64  dbg_prev_seq = 0;
    uint dbg_prev_src HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    bool dbg_dup HSE_MAYBE_UNUSED;
    uint seqno_errcnt = 0;
    bool new_key;
    bool more;
    struct merge_item curr;

    err = merge_init(&bh, w->cw_inputv, w->cw_kvset_cnt, &w->cw_stats);
    if (err)
        return err;

    assert(w->cw_kvset_cnt);
    assert(w->cw_inputv);

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

    // TODO Gaurav: destroy binheap
    err = get_kvset_builder(w, 0, &bldr);
    if (err)
        return err;

    assert(bldr);

    new_key = true;

    tstart = perfc_ison(w->cw_pc, PERFC_DI_CNCOMP_VGET) ? 1 : 0;

    more = get_next_item(bh, w->cw_inputv, &curr, &w->cw_stats, &err);

    while (more) {

        if (new_key && atomic_read(w->cw_cancel_request)) {
            err = merr(ESHUTDOWN);
            goto out;
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

            if (!kvset_iter_next_vref(w->cw_inputv[curr.src], &curr.vctx,
                                      &seq, &vtype, &vbidx,
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

                err = kvset_builder_add_val(bldr, &curr.kobj, vdata, vlen, seq, complen);
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
            err = kvset_builder_add_key(bldr, &prev_kobj);
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

        if (err)
            goto out;
    }

    err = kvset_builder_get_mblocks(bldr, &w->cw_outv[0]);
    if (!err)
        w->cw_output_nodev[0] = w->cw_node;

out:
    bin_heap_destroy(bh);
    kvset_builder_destroy(bldr);
    free_aligned(buf);

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    return err;
}
