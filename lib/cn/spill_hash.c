/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * TODO: Remove this file after we move completely to a 2-level cN tree with a full
 * fledged route map
 */

/**
 * kv_spill_hash() - merge key-value streams, then partition by child
 * Requirements:
 *   - Each input iterator must produce keys in sorted order.
 *   - Iterator iterv[i] must contain newer entries than iterv[i+1].
 */
static merr_t
kv_spill_hash(struct cn_compaction_work *w)
{
    struct bin_heap *     bh;
    struct merge_item     curr;
    merr_t                err;
    struct kvset_builder *child;

    u64   hash;
    uint  vlen;
    uint  complen;
    uint  omlen;
    uint  cnum;
    u32   childmask; /* mask: which children get kvpairs */
    void *buf = NULL;
    u32   bufsz = 0;

    struct cn_khashmap *khashmap = NULL;

    bool emitted_val, bg_val, more;
    u64  seq, emitted_seq = 0, emitted_seq_pt = 0;
    uint curr_klen;

    struct key_obj prev_kobj;

    /* pt_kobj is set to a prefix that can annihilate keys - i.e. it has a
     * seqno <= horizon
     */
    struct key_obj pt_kobj = { 0 };
    bool           pt_set = false;
    u64            pt_seq = 0;
    u32            pt_spread; /* mask: which children get ptomb */

    uint   seqno_errcnt = 0;
    size_t hashlen, cn_sfx_len;
    uint   direct_read_len;
    u64    tstart;
    u64    tprog = 0;

    u64 dbg_prev_seq HSE_MAYBE_UNUSED;
    uint dbg_prev_src HSE_MAYBE_UNUSED;
    uint dbg_nvals_this_key HSE_MAYBE_UNUSED;
    bool dbg_dup HSE_MAYBE_UNUSED;

    if (w->cw_prog_interval && w->cw_progress)
        tprog = jiffies;

    err = merge_init(&bh, w->cw_inputv, w->cw_kvset_cnt, &w->cw_stats);
    if (ev(err))
        return err;

    more = get_next_item(bh, w->cw_inputv, &curr, &w->cw_stats, &err);
    if (!more || ev(err))
        goto done;

    cn_sfx_len = w->cw_cp->sfx_len;

    /* We must issue a direct read for all values that will not fit into
     * the vblock readahead buffer.  Since all direct reads require page
     * size alignment any value whose length is greater than the buffer
     * size minus one page must be read directly from disk (vs from the
     * readahead buffer).
     */
    direct_read_len = w->cw_rp->cn_compact_vblk_ra;
    direct_read_len -= PAGE_SIZE;

    tstart = perfc_ison(w->cw_pc, PERFC_DI_CNCOMP_VGET) ? 1 : 0;

new_key:
    pt_spread = 0;
    childmask = 0;

    if (atomic_read(w->cw_cancel_request)) {
        err = merr(ESHUTDOWN);
        goto done;
    }

    if (tprog) {
        u64 now = jiffies;

        if (now - tprog > w->cw_prog_interval) {
            tprog = now;
            w->cw_progress(w);
        }
    }

    /* Caller sets cw_pfx_len appropriately for the current
     * level, so no need to adapt the hash according to the
     * tree level.
     */
    curr_klen = key_obj_len(&curr.kobj);
    assert(curr_klen >= cn_sfx_len || curr.vctx.is_ptomb);

    hashlen = w->cw_pfx_len;
    hashlen = hashlen ?: curr_klen - cn_sfx_len;

    hash = pfx_obj_hash64(&curr.kobj, hashlen);

    /* Check w->cw_tree because merge_test sets it to NULL.
     */
    if (w->cw_outc > 1 && w->cw_tree) {
        if (w->cw_level == 0 && w->cw_tree->ct_route_map) {
            char kbuf[HSE_KVS_KEY_LEN_MAX];
            size_t kbufsz = w->cw_pfx_len;
            uint klen;

            key_obj_copy(kbuf, kbufsz, &klen, &curr.kobj);
            if (klen > kbufsz)
                klen = kbufsz;

            cnum = cn_tree_route_create(w->cw_tree, kbuf, klen, hash, w->cw_level);
        } else {
            cnum = cn_tree_route_create(w->cw_tree, NULL, 0, hash, w->cw_level);
        }
    } else {
        cnum = 0;
    }
    child = w->cw_child[cnum];

    bg_val = false;
    emitted_val = false;
    emitted_seq = 0;
    emitted_seq_pt = 0;

    dbg_prev_seq = 0;
    dbg_prev_src = 0;
    dbg_nvals_this_key = 0;
    dbg_dup = false;

get_values:

    while (!bg_val) {
        const void *   vdata = NULL;
        bool           should_emit = false;
        enum kmd_vtype vtype;
        u32            vbidx;
        u32            vboff;
        bool           direct;

        if (tstart > 0)
            tstart = get_time_ns();

        if (!kvset_iter_next_vref(
                w->cw_inputv[curr.src], &curr.vctx, &seq, &vtype, &vbidx, &vboff,
                &vdata, &vlen, &complen))
            break;

        if (vtype == vtype_val)
            omlen = vlen;
        else if (vtype == vtype_cval)
            omlen = complen;
        else
            omlen = 0;

        direct = omlen > direct_read_len;

        /* [HSE_REVISIT] direct read path allocates buffer. Performing
         * direct reads into the buffer in kvset builder without this
         * is a future opportunity.
         */
        if (direct) {
            uint bufsz_min;

            if (ev(omlen > HSE_KVS_VALUE_LEN_MAX)) {
                assert(omlen <= HSE_KVS_VALUE_LEN_MAX);
                err = merr(EBUG);
                goto done;
            }

            bufsz_min = omlen;

            /* If value offset is not page aligned then allocate
             * one additional page to prevent a potential copy
             * inside direct read function
             */
            if (vboff % PAGE_SIZE)
                bufsz_min += PAGE_SIZE;

            if (!buf || bufsz < bufsz_min) {
                free_aligned(buf);

                if (omlen < HSE_KVS_VALUE_LEN_MAX / 4)
                    bufsz = HSE_KVS_VALUE_LEN_MAX / 4;
                else if (omlen < HSE_KVS_VALUE_LEN_MAX / 2)
                    bufsz = HSE_KVS_VALUE_LEN_MAX / 2;
                else
                    bufsz = HSE_KVS_VALUE_LEN_MAX;

                /* add an extra page if not aligned */
                if (bufsz_min < bufsz)
                    bufsz += PAGE_SIZE;

                buf = alloc_aligned(bufsz, PAGE_SIZE);
                if (!buf) {
                    err = merr(ENOMEM);
                    goto done;
                }
            }

            err = kvset_iter_next_val_direct(
                w->cw_inputv[curr.src], vtype, vbidx, vboff, buf, omlen, bufsz);
            vdata = buf;
        } else {
            err = kvset_iter_val_get(
                w->cw_inputv[curr.src], &curr.vctx, vtype, vbidx, vboff, &vdata, &vlen, &complen);
        }
        if (ev(err))
            goto done;

        if (tstart > 0) {
            u64 t = get_time_ns() - tstart;

            perfc_rec_sample(w->cw_pc, PERFC_DI_CNCOMP_VGET, t);
        }

        /* Assertion logic:
         *   if (dbg_nvals_this_key)
         *       assert(dbg_prev_seq > seq);
         */
        if (HSE_UNLIKELY(dbg_nvals_this_key && dbg_prev_seq <= seq)) {
            assert(0);
            seqno_errcnt++;
        }

        /* If we are spreading ptombs to all children, cw_pfx_len is 0.
         * Else, if ptomb, curr.klen should match cw_pfx_len.
         */
        assert(!HSE_CORE_IS_PTOMB(vdata) || !w->cw_pfx_len || w->cw_pfx_len == curr_klen);

        dbg_nvals_this_key++;
        dbg_prev_seq = seq;

        bg_val = (seq <= w->cw_horizon);

        if (bg_val) {
            if (pt_set && seq < pt_seq)
                break; /* drop val */

            if (HSE_CORE_IS_PTOMB(vdata)) {
                pt_set = true;
                pt_kobj = curr.kobj;
                pt_seq = seq;
            }
        }

        if (HSE_CORE_IS_PTOMB(vdata))
            should_emit = !emitted_seq_pt || seq < emitted_seq_pt;
        else
            should_emit = !emitted_seq || seq < emitted_seq;

        should_emit = should_emit || !emitted_val;

        /* Compare seq to emitted_seq to ensure when a key has values
         * in two kvsets with the same sequence number, that only the
         * value from the first kvset is emitted.
         */
        if (should_emit) {
            if (HSE_UNLIKELY(HSE_CORE_IS_PTOMB(vdata)) && w->cw_pfx_len == 0 && w->cw_outc > 1) {
                /* prefixed cn tree. But spilling by full hash.
                 * Pass on ptomb to all children
                 */
                int i;

                for (i = 0; i < w->cw_outc; i++) {
                    if (w->cw_drop_tombv[i] && bg_val)
                        continue;

                    err = kvset_builder_add_val(w->cw_child[i], seq, vdata, vlen, 0);
                    if (ev(err))
                        goto done;

                    emitted_val = true;
                    emitted_seq_pt = seq;
                    pt_spread |= (1 << i);
                }
            } else {
                if (w->cw_drop_tombv[cnum] && HSE_CORE_IS_TOMB(vdata) && bg_val)
                    continue; /* skip value */

                err = kvset_builder_add_val(child, seq, vdata, vlen, complen);
                if (ev(err))
                    goto done;

                w->cw_stats.ms_val_bytes_out += complen ? complen : vlen;
                emitted_val = true;
                childmask |= (1 << cnum);
                if (HSE_CORE_IS_PTOMB(vdata))
                    emitted_seq_pt = seq;
                else
                    emitted_seq = seq;
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
            assert(dbg_prev_src < curr.src);
            assert(seq == emitted_seq);
            if (seq > emitted_seq)
                seqno_errcnt++;

            /* Two ptombs can have the same seqno only if they are
             * part of a txn. But if that is the case, those ptombs
             * will never be dups. So, there can never be duplicate
             * ptombs with the same seqno.
             */
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
            /* cached ptomb key is no longer valid */
            pt_set = false;
        }
    }

    if (emitted_val) {
        if (pt_spread) {
            int i;
            u32 spillmask = pt_spread | childmask;

            for (i = 0; i < w->cw_outc; i++) {
                if ((spillmask & (1 << i)) == 0)
                    continue;

                err = kvset_builder_add_key(w->cw_child[i], &prev_kobj);
                if (ev(err))
                    goto done;

                w->cw_stats.ms_keys_out++;
                w->cw_stats.ms_key_bytes_out += key_obj_len(&prev_kobj);
            }

        } else {
            err = kvset_builder_add_key(child, &prev_kobj);
            if (ev(err))
                goto done;

            w->cw_stats.ms_keys_out++;
            w->cw_stats.ms_key_bytes_out += key_obj_len(&prev_kobj);
        }
    }

    if (more)
        goto new_key;

done:
    bin_heap_destroy(bh);
    free_aligned(buf);

    /* We must ensure the latest version of the key hash map is persisted
     * if it changed while we were using it (regardless of who changed it,
     * and especially if we changed it, regardless of error).
     */
    khashmap = cn_tree_get_khashmap(w->cw_tree);
    if (khashmap) {
        merr_t err2;
        bool   update;

        spin_lock(&khashmap->khm_lock);
        update = (khashmap->khm_gen > khashmap->khm_gen_committed);
        spin_unlock(&khashmap->khm_lock);

        if (update) {
            struct cn_tstate *ts = w->cw_tree->ct_tstate;

            err2 = ts->ts_update(ts, kv_spill_prepare, kv_spill_commit, kv_spill_abort, w->cw_tree);
            err = err ?: err2;
        }
    }

    if (seqno_errcnt)
        log_warn("seqno errcnt %u", seqno_errcnt);

    if (tprog)
        w->cw_progress(w);

    return err;
}

merr_t
cn_spill_hash(struct cn_compaction_work *w)
{
    merr_t err;
    uint   i;

    assert(w->cw_kvset_cnt);
    assert(w->cw_inputv);

    memset(w->cw_outv, 0, w->cw_outc * sizeof(*w->cw_outv));

    for (i = 0; i < w->cw_outc; i++) {
        struct cn_tree_node *pnode;

        err = kvset_builder_create(
            &w->cw_child[i],
            cn_tree_get_cn(w->cw_tree),
            w->cw_pc,
            w->cw_dgen_hi);
        if (ev(err))
            goto done;

        kvset_builder_set_merge_stats(w->cw_child[i], &w->cw_stats);

        pnode = w->cw_node;
        if (pnode && w->cw_action == CN_ACTION_SPILL) {
            if (is_spill_to_intnode(pnode, i))
                kvset_builder_set_agegroup(w->cw_child[i], HSE_MPOLICY_AGE_INTERNAL);
            else
                kvset_builder_set_agegroup(w->cw_child[i], HSE_MPOLICY_AGE_LEAF);
        }

        if (pnode && w->cw_action == CN_ACTION_COMPACT_KV) {
            if (cn_node_isleaf(pnode))
                kvset_builder_set_agegroup(w->cw_child[i], HSE_MPOLICY_AGE_LEAF);
            else if (cn_node_isroot(pnode))
                kvset_builder_set_agegroup(w->cw_child[i], HSE_MPOLICY_AGE_ROOT);
            else
                kvset_builder_set_agegroup(w->cw_child[i], HSE_MPOLICY_AGE_INTERNAL);
        }
    }

    err = kv_spill_hash(w);
    if (ev(err))
        goto done;

    /* Get each child's output mblocks */
    for (i = 0; i < w->cw_outc; i++) {
        err = kvset_builder_get_mblocks(w->cw_child[i], &w->cw_outv[i]);
        if (ev(err))
            break;
    }

    if (err) {
        while (i-- > 0) {
            abort_mblocks(w->cw_ds, &w->cw_outv[i].kblks);
            abort_mblocks(w->cw_ds, &w->cw_outv[i].vblks);
        }
        memset(w->cw_outv, 0, w->cw_outc * sizeof(*w->cw_outv));
    }

done:
    /* Applies to success and failure paths */
    for (i = 0; i < w->cw_outc; i++)
        kvset_builder_destroy(w->cw_child[i]);

    return err;
}
