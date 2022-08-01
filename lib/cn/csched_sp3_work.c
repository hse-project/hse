/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_csched_sp3_work

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_rparams.h>

#include "csched_sp3_work.h"

#include "cn_tree_compact.h"
#include "cn_tree_internal.h"
#include "kvset.h"
#include "kvset_internal.h"

static bool
sp3_node_is_idle(struct cn_tree_node *tn)
{
    struct list_head *       head;
    struct kvset_list_entry *le;

    /* Node is idle IFF no kvsets are marked. */
    head = &tn->tn_kvset_list;
    list_for_each_entry (le, head, le_link) {
        if (kvset_get_workid(le->le_kvset) != 0)
            return false;
    }

    return true;
}

/* Estimate effect of a compaction operation on space amp.  Also
 * estimates the total number of mblocks bytes.
 */
static void
sp3_work_estimate(struct cn_compaction_work *w)
{
    u64 keys = 0;
    u64 halen = 0;
    u64 kalen = 0;
    u64 valen = 0;

    bool src_is_leaf;
    bool dst_is_leaf;
    s64  consume;
    s64  produce;
    uint percent_keep;
    uint i;

    struct kvset_list_entry *le;

    le = w->cw_mark;
    for (i = 0; i < w->cw_kvset_cnt; i++) {

        const struct kvset_stats *stats = kvset_statsp(le->le_kvset);

        keys += stats->kst_keys;
        halen += stats->kst_kalen;
        kalen += stats->kst_kalen;
        valen += stats->kst_valen;

        le = list_prev_entry(le, le_link);
    }

    consume = 0;
    produce = 0;
    percent_keep = 100;
    src_is_leaf = cn_node_isleaf(w->cw_node);
    dst_is_leaf = false; /* TBD below */

    switch (w->cw_action) {
    case CN_ACTION_NONE:
    case CN_ACTION_SPLIT:
        break;

    case CN_ACTION_COMPACT_K:
        /* Assume no garbage collection, thus percent_keep == 100 */
        consume = halen + kalen;
        dst_is_leaf = src_is_leaf;
        break;

    case CN_ACTION_COMPACT_KV:
        consume = halen + kalen + valen;
        percent_keep = 100 * 100 / cn_ns_samp(&w->cw_ns);
        dst_is_leaf = src_is_leaf;
        break;

    case CN_ACTION_SPILL:
        assert(cn_node_isroot(w->cw_node));
        consume = halen + kalen + valen;
        percent_keep = 100 * 100 / cn_ns_samp(&w->cw_ns);
        dst_is_leaf = true;
        break;
    }

    produce = consume * percent_keep / 100;

    w->cw_est.cwe_keys += keys;
    w->cw_est.cwe_read_sz += consume;
    w->cw_est.cwe_write_sz += produce;

    if (src_is_leaf)
        w->cw_est.cwe_samp.l_alen -= consume;
    else
        w->cw_est.cwe_samp.i_alen -= consume;

    if (dst_is_leaf) {
        /* Optimistic assumption: spilling to leaf creates no garbage.
         * This prevents spikes in our samp estimate, which in turn
         * avoids un-necessary compactions.
         */
        w->cw_est.cwe_samp.l_alen += produce;
        w->cw_est.cwe_samp.l_good += produce;
    } else {
        w->cw_est.cwe_samp.i_alen += produce;
    }
}

/* Handle root spill
 */
static uint
sp3_work_wtype_root(
    struct sp3_node *         spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    uint runlen_min, runlen_max, runlen;
    struct kvset_list_entry *le;
    size_t sizemb_max, wlen;

    *action = CN_ACTION_SPILL;
    *rule = CN_CR_RSPILL;
    *mark = NULL;

    /* walk from tail (oldest), skip kvsets that are busy */
    list_for_each_entry_reverse(le, &tn->tn_kvset_list, le_link) {
        if (kvset_get_workid(le->le_kvset) == 0) {
            *mark = le;
            break;
        }
    }

    if (!*mark)
        return 0;

    runlen_min = thresh->rspill_runlen_min;
    runlen_max = thresh->rspill_runlen_max;
    sizemb_max = thresh->rspill_sizemb_max;
    runlen = 1;
    wlen = 0;

    /* Look for a contiguous sequence of non-busy kvsets.
     *
     * TODO: Starting with the first non-busy kvset, count the number of
     * kvsets contiguous from the first that would all spill to the same
     * leaf node.
     */
    while ((le = list_prev_entry_or_null(le, le_link, &tn->tn_kvset_list))) {
        if (kvset_get_workid(le->le_kvset) != 0)
            break;

        wlen += kvset_get_kwlen(le->le_kvset) + kvset_get_vwlen(le->le_kvset);

        /* Limit spill size once we have a sufficiently long run length.
         *
         * TODO: Ignore the size check if all preceding kvsets would spill
         * to the same leaf node.
         */
        if (runlen >= runlen_min && wlen >= (sizemb_max << 20))
            break;

        ++runlen;
    }

    /* TODO: If the number of contiguous kvsets that would all spill
     * to the same leaf node is one or more then return that number
     * as a zero-writeamp spill operation (e.g., CN_ACTION_ZSPILL)
     * irrespective of runlen_min, runlen_max, and sizemb_max.
     */

    if (runlen < runlen_min)
        return 0;

    if (wlen < VBLOCK_MAX_SIZE) {
        *rule = CN_CR_TSPILL; /* tiny root spill */
        return runlen;
    }

    /* Avoid leaving behind a run too short to spill.  This helps
     * clear the root node after a load or large ingest of tombs.
     */
    if (runlen > runlen_max)
        runlen -= runlen_min;

    return min_t(uint, runlen, runlen_max);
}

static uint
sp3_work_wtype_idle(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_comp_rule        *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct kvset_list_entry *le;
    struct list_head *head;
    uint kvsets;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    *action = CN_ACTION_COMPACT_KV;

    kvsets = cn_ns_kvsets(&tn->tn_ns);

    /* Keep idle index nodes fully compacted to improve scanning
     * (e.g., mongod index nodes that rarely change after load).
     */
    if (cn_ns_vblks(&tn->tn_ns) < kvsets) {
        *rule = CN_CR_IDLE_INDEX;
        return kvsets;
    }

    /* Otherwise, compact the node if the resulting size is smaller
     * than a single vblock (rare, but happens).
     */
    if (cn_ns_clen(&tn->tn_ns) < VBLOCK_MAX_SIZE) {
        *rule = CN_CR_IDLE_SIZE;
        return kvsets;
    }

    /* Compact if the preponderance of keys appears to be tombs.
     */
    if (cn_ns_tombs(&tn->tn_ns) * 100 > cn_ns_keys_uniq(&tn->tn_ns) * 90) {
        *rule = CN_CR_IDLE_TOMB;
        return kvsets;
    }

    return 0;
}

static uint
sp3_work_wtype_split(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_comp_rule        *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct kvset_list_entry *le;
    struct list_head *head;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);

    *action = CN_ACTION_SPLIT;
    *rule = CN_CR_SPLIT;

    ev_debug(1);

    return cn_ns_kvsets(&tn->tn_ns);
}

static uint
sp3_work_wtype_garbage(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_comp_rule        *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct kvset_list_entry *le;
    struct list_head *head;
    uint kvsets;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    kvsets = cn_ns_kvsets(&tn->tn_ns);

    *action = CN_ACTION_COMPACT_KV;
    *rule = CN_CR_GARBAGE;

    return min_t(uint, kvsets, thresh->lcomp_runlen_max);
}

static uint
sp3_work_wtype_scatter(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_comp_rule        *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct kvset_list_entry *le;
    struct list_head *head;
    uint runlen_max;
    uint runlen;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    *action = CN_ACTION_COMPACT_KV;
    *rule = CN_CR_SCATTERF;

    runlen_max = thresh->lscat_runlen_max;
    runlen = cn_ns_kvsets(&tn->tn_ns);

    /* Find the oldest kvset which has vgroup scatter.
     */
    list_for_each_entry_reverse(le, head, le_link) {
        if (kvset_get_vgroups(le->le_kvset) > 1) {
            *mark = le;
            break;
        }

        *rule = CN_CR_SCATTERP;
        --runlen;
    }

    /* Include the next oldest kvset if it's reasonably small
     * (to prevent repeated scatter remediation of tiny kvsets
     * from creating unnecessarily long nodes).
     */
    if (runlen > 0) {
        le = list_next_entry_or_null(*mark, le_link, head);
        if (le) {
            struct kvset_stats stats;

            kvset_stats(le->le_kvset, &stats);

            if (stats.kst_kwlen + stats.kst_vwlen < (256ul << 20)) {
                *mark = le;
                ++runlen_max;
                ++runlen;
            }
        }
    }

    return min_t(uint, runlen, runlen_max);
}

static uint
sp3_work_wtype_length(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_comp_rule        *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    uint runlen_min = thresh->llen_runlen_min;
    uint runlen_max = thresh->llen_runlen_max;
    uint kvsets;

    kvsets = cn_ns_kvsets(&tn->tn_ns);

    /* Start from old kvsets, find first run of 'runlen_min' kvsets with
     * the same 'compc' value, then k-compact those kvsets and up to
     * 'runlen_max' newer.
     */
    if (kvsets >= runlen_min) {
        struct kvset_list_entry *le;
        struct list_head *head;
        uint compc = UINT_MAX;
        size_t vwlen = 0;
        uint runlen = 0;

        head = &tn->tn_kvset_list;
        *mark = list_last_entry(head, typeof(*le), le_link);
        *action = CN_ACTION_COMPACT_K;
        *rule = CN_CR_LENGTHK;

        list_for_each_entry_reverse(le, head, le_link) {
            if (runlen < runlen_min) {
                uint tmp = kvset_get_compc(le->le_kvset);

                if (compc != tmp) {
                    compc = tmp;
                    *mark = le;
                    runlen = 0;
                    vwlen = 0;
                }
            }

            vwlen += kvset_get_vwlen(le->le_kvset);

            if (++runlen >= runlen_max)
                break;
        }

        /* If the run is sufficiently long then fully compact (i.e.,
         * kv-compact) all the kvsets in the run if the sum of values
         * would fit into a single vblock.  Otherwise compact just the
         * keys (i.e., k-compact).
         */
        if (runlen >= runlen_min) {
            if (vwlen < VBLOCK_MAX_SIZE) {
                *action = CN_ACTION_COMPACT_KV;
                *rule = CN_CR_LENGTHV;
            }

            return runlen;
        }

        /* Fully compact the entire node if the resulting size is smaller
         * than a single vblock (rare, but happens).
         */
        if (cn_ns_clen(&tn->tn_ns) < VBLOCK_MAX_SIZE) {
            *mark = list_last_entry(head, typeof(*le), le_link);
            *action = CN_ACTION_COMPACT_KV;
            *rule = CN_CR_LENGTHV;
            return kvsets;
        }

        /* Don't let lightweight nodes grow too long.  For the most part
         * this only applies to "index" nodes (i.e., nodes where the values
         * are much smaller than the keys).
         */
        if (kvsets > runlen_min && cn_ns_vblks(&tn->tn_ns) < kvsets) {
            *mark = list_last_entry(head, typeof(*le), le_link);
            *action = CN_ACTION_COMPACT_KV;
            *rule = CN_CR_INDEXF;

            /* If the oldest kvset is larger than the next oldest kvset
             * and there's not much garbage then start with the next
             * oldest kvset, otherwise start with the oldest kvset.
             */
            le = list_prev_entry(*mark, le_link);

            if (kvset_get_kwlen(le->le_kvset) < kvset_get_kwlen((*mark)->le_kvset) &&
                cn_ns_clen(&tn->tn_ns) * 100 > cn_ns_alen(&tn->tn_ns) * 85) {

                *rule = CN_CR_INDEXP;
                *mark = le;
                return kvsets - 1;
            }

            return kvsets;
        }
    }

    return 0;
}

/**
 * sp3_work() - determine if a given node needs maintenance
 * @tn: the cn tree node to check
 * @wtype: type of work to consider
 * @thresh: thresholds for work (eg, min/max kvsets)
 * @debug: debug flag
 * @wp: work struct
 */
merr_t
sp3_work(
    struct sp3_node            *spn,
    enum sp3_work_type          wtype,
    struct sp3_thresholds      *thresh,
    uint                        debug,
    struct cn_compaction_work **wp)
{
    struct cn_tree *tree;
    struct cn_tree_node *      tn;
    struct cn_compaction_work *w;
    struct kvset_list_entry *  le;
    void *                     lock;
    uint                       i;
    bool                       have_token;

    uint                     n_kvsets = 0;
    enum cn_action           action = CN_ACTION_NONE;
    enum cn_comp_rule        rule = CN_CR_NONE;
    struct kvset_list_entry *mark = NULL;

    tn = spn2tn(spn);
    tree = tn->tn_tree;

    if (tree->rp->cn_maint_disable)
        return 0;

    if (!*wp) {
        *wp = calloc(1, sizeof(*w));
        if (ev(!*wp))
            return merr(ENOMEM);
    }

    /* Actions requiring exclusive access to the node must acquire and hold
     * the token through completion of the action.  Actions that can run
     * concurrently must acquire the token to ensure there's not an exclusive
     * action running and then must release the token before returning.
     */
    have_token = cn_node_comp_token_get(tn);
    if (!have_token)
        return 0;

    /* The tree lock must be acquired to obtain a stable view of the node
     * and its stats, otherwise an asynchronously completing job could
     * morph them while they're being examined.
     */
    rmlock_rlock(&tree->ct_lock, &lock);

    if (tree->ct_rspills_wedged) {
        if (!sp3_node_is_idle(tn))
            goto locked_nowork;

        log_info("re-enable compaction after wedge");
        tree->ct_rspills_wedged = false;
    }

    if (cn_node_isleaf(tn)) {
        switch (wtype) {
        case wtype_split:
            n_kvsets = sp3_work_wtype_split(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_garbage:
            n_kvsets = sp3_work_wtype_garbage(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_scatter:
            n_kvsets = sp3_work_wtype_scatter(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_length:
            n_kvsets = sp3_work_wtype_length(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_idle:
            n_kvsets = sp3_work_wtype_idle(spn, thresh, &mark, &action, &rule);
            break;

        default:
            assert(0);
            break;
        }
    } else {
        switch (wtype) {
        case wtype_root:
            n_kvsets = sp3_work_wtype_root(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_idle:
            n_kvsets = sp3_work_wtype_idle(spn, thresh, &mark, &action, &rule);
            break;

        default:
            assert(0);
            break;
        }
    }

    if (n_kvsets == 0)
        goto locked_nowork;

    switch (action) {
    case CN_ACTION_SPILL:
        uint jobs = atomic_read(&tn->tn_busycnt) >> 16;

        if (!cn_node_isroot(tn))
            abort();

        if (jobs > 2)
            goto locked_nowork;

        cn_node_comp_token_put(tn);
        have_token = false;
        break;

    case CN_ACTION_COMPACT_K:
    case CN_ACTION_COMPACT_KV:
    case CN_ACTION_SPLIT:

        /* All other actions are node-wise mutually exclusive.
         */
        if (atomic_read(&tn->tn_busycnt) > 0)
            goto locked_nowork;
        break;

    default:
        goto locked_nowork;
    }

    /* The upper 16 bits of busycnt contains the count of currently
     * running jobs, while the lower 16 bits contains the count of
     * kvsets undergoing spill/compact.  This information is used
     * to avoid scheduling work requests that cannot run under the
     * current conditions.  See sp3_dirty_node() for details.
     */
    atomic_add(&tn->tn_busycnt, (1u << 16) + n_kvsets);

    w = *wp;

    assert(mark);

    /* mark the kvsets with dgen_lo */
    w->cw_dgen_lo = kvset_get_dgen(mark->le_kvset);
    le = mark;
    for (i = 0; i < n_kvsets; i++) {
        assert(&le->le_link != &tn->tn_kvset_list);
        assert(kvset_get_workid(le->le_kvset) == 0);
        kvset_set_workid(le->le_kvset, w->cw_dgen_lo);
        w->cw_dgen_hi = kvset_get_dgen(le->le_kvset);
        w->cw_nh++; /* Only ever 1 hblock per kvset */
        w->cw_nk += kvset_get_num_kblocks(le->le_kvset);
        w->cw_nv += kvset_get_num_vblocks(le->le_kvset);
        w->cw_input_vgroups += kvset_get_vgroups(le->le_kvset);
        le = list_prev_entry(le, le_link);
    }

    cn_node_stats_get(tn, &w->cw_ns);

    rmlock_runlock(lock);

    w->cw_node = tn;
    w->cw_tree = tree;
    w->cw_mp = tree->mp;
    w->cw_rp = tree->rp;
    w->cw_cp = tree->ct_cp;
    w->cw_pfx_len = tree->ct_cp->pfx_len;

    w->cw_kvset_cnt = n_kvsets;
    w->cw_mark = mark;
    w->cw_action = action;
    w->cw_comp_rule = rule;
    w->cw_debug = debug;

    w->cw_have_token = have_token;
    w->cw_rspill_conc = !have_token && (action == CN_ACTION_SPILL);

    w->cw_compc = kvset_get_compc(w->cw_mark->le_kvset);
    w->cw_pc = cn_get_perfc(tree->cn, w->cw_action);

    w->cw_t0_enqueue = get_time_ns();

    INIT_LIST_HEAD(&w->cw_rspill_link);

    if (w->cw_rspill_conc) {
        /* ensure concurrent root spills complete in order */
        mutex_lock(&tree->ct_rspills_lock);
        list_add_tail(&w->cw_rspill_link, &tree->ct_rspills_list);
        mutex_unlock(&tree->ct_rspills_lock);
    }

    sp3_work_estimate(w);

    return 0;

locked_nowork:
    if (have_token)
        cn_node_comp_token_put(tn);
    rmlock_runlock(lock);
    return 0;
}

#if HSE_MOCKING
#include "csched_sp3_work_ut_impl.i"
#endif /* HSE_MOCKING */
