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

#define SIZE_1GIB       ((size_t)1 << 30)

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
sp3_work_estimate(struct cn_compaction_work *w, uint internal_children, uint leaf_children)
{
    u64 keys = 0;
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
        case CN_ACTION_END:
            break;

        case CN_ACTION_COMPACT_K:
            /* Assume no garbage collection, thus percent_keep == 100 */
            consume = kalen;
            dst_is_leaf = src_is_leaf;
            break;

        case CN_ACTION_COMPACT_KV:
            consume = kalen + valen;
            percent_keep = 100 * 100 / cn_ns_samp(&w->cw_ns);
            dst_is_leaf = src_is_leaf;
            break;

        case CN_ACTION_SPILL:
            /* If any child is an internal node, then assume
         * this operation will simply move data to other internal
         * nodes (no net effect on samp).  Otherwise assume all data
         * will move to leaf nodes.
         *
         * If we have both leaf and internal children, then data will
         * be split between 'i_alen' and 'l_alen', but this usually
         * happens in prefix trees where one prefix dominates, in
         * which case most of the data will land in the internal
         * node used by the dominant prefix.
         */
            consume = kalen + valen;
            percent_keep = 100 * 100 / cn_ns_samp(&w->cw_ns);
            dst_is_leaf = cn_node_isroot(w->cw_node) || !internal_children;
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

static uint
sp3_work_ispill_find_kvsets(struct sp3_node *spn, uint n_max, struct kvset_list_entry **mark)
{
    uint                     n_kvsets;
    struct kvset_list_entry *le;
    struct cn_tree_node *    tn;

    *mark = NULL;
    tn = spn2tn(spn);

    /* walk from tail (oldest), skip kvsets that are busy */
    list_for_each_entry_reverse(le, &tn->tn_kvset_list, le_link) {
        if (kvset_get_workid(le->le_kvset) == 0) {
            *mark = le;
            break;
        }
    }

    if (!*mark)
        return 0;

    n_kvsets = 1;

    /* look for sequence of non-busy kvsets */
    while ((le = list_prev_entry_or_null(le, le_link, &tn->tn_kvset_list))) {
        if (n_kvsets == n_max)
            break;

        if (kvset_get_workid(le->le_kvset) != 0)
            break;

        n_kvsets++;
    }

    return n_kvsets;
}

/* Handle an internal node that needs to be spilled.
 * Notes:
 * - The "compc" check ensures that k-compacted kvsets are spilled one
 *   at a time.
 * Pros:
 *   - Prevent those possibly large kvsets from being spilled in giant
 *     spill operation.
 * Cons:
 *   - Smaller spills can lead to lower mblock utilization.
 *   - Higher write amp due to less GC during spill operation, and
 *     more kvsets in child node that will then have to be
 *     k-compacted or kv-compacted.
 */
static uint
sp3_work_ispill(
    struct sp3_node *         spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    uint cnt_min, cnt_max, cnt;

    if (tn->tn_loc.node_level > 0) {
        cnt_min = thresh->ispill_kvsets_min;
        cnt_max = thresh->ispill_kvsets_max;
    } else {
        cnt_min = thresh->rspill_kvsets_min;
        cnt_max = thresh->rspill_kvsets_max;
    }

    cnt = sp3_work_ispill_find_kvsets(spn, cnt_max, mark);
    if (cnt < cnt_min)
        return 0;

    *action = CN_ACTION_SPILL;
    *rule = CN_CR_ISPILL;

    if (tn->tn_loc.node_level > 0) {
        uint compc = kvset_get_compc((*mark)->le_kvset);
        uint64_t clen = cn_ns_clen(&tn->tn_ns);

        /* If there is another job currently spilling this node then wait
         * to schedule additional jobs until there are a sufficient number
         * of kvsets to spill.
         */
        if (compc < 2 && cnt < cnt_max / 2) {
            if (atomic_read(&tn->tn_busycnt) > 0)
                return 0;
        }

        /* If the spill size is large and the oldest kvset is heavily
         * compacted then spill only the oldest kvset.  If the oldest
         * kvset is lightly compacted then just reduce the spill count.
         *
         * Otherwise, if the spill size is tiny then defer the spill
         * until there are a sufficient number of kvsets to spill.
         */
        if (clen > tn->tn_size_max / 2 ||
            cn_ns_keys(&tn->tn_ns) > ((uint64_t)thresh->ispill_pop_keys << 20)) {

            if (compc > 2) {
                *rule = CN_CR_ISPILL_ONE;
                cnt = 1;
            } else if (compc > 0) {
                cnt = min(cnt, cnt_max / 2);
            }
        }
        else if (clen < SIZE_1GIB) {
            if (cnt < cnt_max / 2)
                return 0;

            *rule = CN_CR_ITINY;
        }
    } else {
        uint64_t clen = cn_ns_clen(&tn->tn_ns);

        *rule = CN_CR_RSPILL;

        /* Defer tiny root spills...
         */
        if (clen < SIZE_1GIB) {
            if (cnt < cnt_max)
                return 0;

            *rule = CN_CR_RTINY;
        }
    }

    return cnt;
}

/* Handle an internal node that has been partially spilled.
 *
 * When a leaf node "pops", sp3_work_leaf_size() will typically spill
 * just one kvset from the node, leaving behind a partially spilled
 * internal node.  The scheduler will then schedule ispill jobs
 * (via sp3_work_ispill()) to continue spilling internal nodes until
 * the leaf threshold for the tree has been met and the node size
 * falls below the ispill_pop_szgb threshold.
 *
 * Regardless, the scheduler will schedule icompact jobs (via this
 * function) on internal nodes in order to keep them from growing
 * too long until they are sufficiently large to be spilled via
 * sp3_work_ispill().
 */
static uint
sp3_work_icompact(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_comp_rule        *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    uint runlen_min = thresh->llen_runlen_min;
    uint runlen_max = thresh->llen_runlen_max;

    if (cn_ns_kvsets(&tn->tn_ns) >= runlen_min) {
        struct kvset_list_entry *le;
        struct list_head *head;
        uint compc = UINT_MAX;
        uint runlen = 0;

        head = &tn->tn_kvset_list;
        *mark = list_last_entry(head, typeof(*le), le_link);

        list_for_each_entry_reverse(le, head, le_link) {
            uint tmp = kvset_get_compc(le->le_kvset);

            if (compc != tmp && runlen < runlen_min) {
                compc = tmp;
                *mark = le;
                runlen = 1;
            } else if (++runlen >= runlen_max) {
                break;
            }
        }

        if (runlen >= runlen_min) {
            uint64_t clen = cn_ns_clen(&tn->tn_ns);

            *action = CN_ACTION_COMPACT_K;
            *rule = CN_CR_ILONG;

            /* Mitigate creation of ginormous kvsets during initial
             * spill as they clog up the spill pipeline.
             */
            if (compc > 1 && clen > tn->tn_size_max / 2)
                return max(runlen_min / 2, 2u);

            /* kv-compact if the run includes the oldest kvset and the
             * spill size is so small that a spill would likely result
             * in compounding space amplification.
             */
            if (clen < SIZE_1GIB && list_is_last(&(*mark)->le_link, head)) {
                *action = CN_ACTION_COMPACT_KV;
                *rule = CN_CR_ITINY;
            }

            return runlen;
        }
    }

    return 0;
}

static uint
sp3_work_node_idle(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_comp_rule        *rule)
{
    struct kvset_list_entry *le;
    struct cn_tree_node *tn;
    struct list_head *head;

    uint idlec = thresh->llen_idlec;
    uint vgroups = 0;
    uint runlen = 0;

    tn = spn2tn(spn);
    head = &tn->tn_kvset_list;

    /* Compact the least compacted kvsets.  Must include
     * all kvsets compacted fewer than idlec times.
     */
    list_for_each_entry(le, head, le_link) {
        if (kvset_get_compc(le->le_kvset) >= idlec)
            break;

        vgroups += kvset_get_vgroups(le->le_kvset);
        *mark = le;
        ++runlen;
    }

    if (runlen < SP3_LLEN_RUNLEN_MIN || runlen >= vgroups)
        return 0;

    *action = CN_ACTION_COMPACT_KV;
    *rule = CN_CR_LSHORT_IDLE_VG;

    return runlen;
}

/**
 * Handle leaf node that exceeds or is close to max size.  If expected
 * size after spill is more than a configured percentage of max size
 * then spill.  Otherwise kv-compact if the max size has been reached.
 *
 * The "compc" check ensures that k-compacted kvsets are spilled one
 * at a time.
 *
 * Pros:
 *   - Prevent those possibly large kvsets from being spilled in giant
 *     spill operation.
 * Cons:
 *   - Smaller spills can lead to lower mblock utilization
 *   - Higher write amp due to less GC during spill operation, and
 *     more kvsets ikn child node that will then have to be
 *     k-compacted or kv-compacted.
 *   - When only one kvset is spilled, a lot of data is left behind
 *     and the leaf_pct drops.  This increases perceived space amp and
 *     creates pressure to compact leaves, which results in spilling
 *     and or kv-compacting nodes that are not yet full.  The fix for
 *     this is to not compact leaves when leaf_pct is out of spec.
 */
static uint
sp3_work_leaf_size(
    struct sp3_node *         spn,
    struct sp3_thresholds *   thresh,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule)
{
    struct list_head *       head;
    struct cn_tree_node *    tn;
    struct kvset_list_entry *le;

    tn = spn2tn(spn);

    assert(tn->tn_loc.node_level <= tn->tn_tree->ct_depth_max);

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);

    *action = CN_ACTION_SPILL;
    *rule = CN_CR_LBIG;

    if (kvset_get_compc((*mark)->le_kvset) > 0) {
        *rule = CN_CR_LBIG_ONE;
        return 1;
    }

    return min_t(uint, cn_ns_kvsets(&tn->tn_ns), thresh->lcomp_kvsets_max);
}

static uint
sp3_work_leaf_garbage(
    struct sp3_node *         spn,
    struct sp3_thresholds *   thresh,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule)
{
    struct list_head *       head;
    struct cn_tree_node *    tn;
    struct kvset_list_entry *le;
    uint                     kvsets;

    tn = spn2tn(spn);

    assert(tn->tn_loc.node_level <= tn->tn_tree->ct_depth_max);

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    kvsets = cn_ns_kvsets(&tn->tn_ns);

    *action = CN_ACTION_COMPACT_KV;
    *rule = CN_CR_LGARB;

    return min_t(uint, kvsets, thresh->lcomp_kvsets_max);
}

static uint
sp3_work_leaf_len(
    struct sp3_node *         spn,
    struct sp3_thresholds *   thresh,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct cn_node_stats stats;

    uint runlen_min = thresh->llen_runlen_min;
    uint runlen_max = thresh->llen_runlen_max;

    cn_node_stats_get(tn, &stats);

    /* Start from old kvsets, find first run of 'runlen_min' kvsets with
     * the same 'compc' value, then k-compact those kvsets and up to
     * 'runlen_max' newer.
     */
    if (cn_ns_kvsets(&stats) >= runlen_min) {
        struct kvset_list_entry *le;
        struct list_head *head;
        uint runlen = 0;
        uint compc = UINT_MAX;
        uint tmp;

        head = &tn->tn_kvset_list;
        *mark = list_last_entry(head, typeof(*le), le_link);
        *action = CN_ACTION_COMPACT_K;
        *rule = CN_CR_LLONG;

        list_for_each_entry_reverse (le, head, le_link) {
            tmp = kvset_get_compc(le->le_kvset);
            if (compc != tmp && runlen < runlen_min) {
                compc = tmp;
                *mark = le;
                runlen = 1;
            } else if (++runlen >= runlen_max) {
                break;
            }
        }

        if (runlen >= runlen_min) {
            if (compc > 0) {
                uint64_t clen = cn_ns_clen(&stats);

                /* Mitigate creation of ginormous kvsets while we await
                 * a leaf spill as they clog up the spill pipeline.
                 */
                if (clen > tn->tn_size_max && list_is_last(&(*mark)->le_link, head)) {
                    runlen = max(runlen_min / 2, 2u);
                } else {
                    runlen = runlen_min;
                }
            }

            return runlen;
        }

        /* Don't let lightweight nodes grow too long.  For the most part this only
         * applies to "index" nodes (i.e., nodes where the values are much smaller
         * than the keys).
         */
        if (cn_ns_kvsets(&stats) > runlen_min &&
            cn_ns_vblks(&stats) < cn_ns_kvsets(&stats)) {

            le = list_last_entry(head, typeof(*le), le_link);
            compc = kvset_get_compc(le->le_kvset);
            runlen = 0;

            list_for_each_entry(le, head, le_link) {
                if (kvset_get_compc(le->le_kvset) >= compc)
                    break;

                *mark = le;
                ++runlen;
            }

            if (runlen < runlen_min) {
                *mark = list_last_entry(head, typeof(*le), le_link);
                *action = CN_ACTION_COMPACT_KV;
            }

            *rule = CN_CR_LSHORT_LW;
            return runlen_min;
        }
    }

    return 0;
}

uint
sp3_node_scatter_pct_compute(struct sp3_node *spn)
{
    struct list_head *       head;
    struct kvset_list_entry *le;
    struct cn_node_stats     stats;
    struct cn_tree_node *    tn;

    uint n_spct = 0;
    uint n_scatter = 0;

    tn = spn2tn(spn);
    cn_node_stats_get(tn, &stats);

    /* To handle a node having kvsets with zero vblocks. */
    if (cn_ns_vblks(&stats) == 0)
        return 0;

    head = &tn->tn_kvset_list;
    list_for_each_entry (le, head, le_link) {
        u64  vulen;
        uint vulen_pct;
        uint scatter;
        uint score;

        score = kvset_get_scatter_score(le->le_kvset);
        vulen = kvset_vulen(&le->le_kvset->ks_st);
        vulen_pct = (vulen * 100) / cn_ns_vulen(&stats);
        scatter = vulen_pct * score;
        n_scatter += scatter;

        /* Stash scatter temporarily in the kvset instance. */
        kvset_set_scatter_pct(le->le_kvset, scatter);
    }

    if (n_scatter == 0)
        return 0;

    /* Loop another time and set the scatter percent for each kvset. */
    list_for_each_entry (le, head, le_link) {
        uint k_scatter;
        uint k_spct;
        uint k_score;

        k_scatter = kvset_get_scatter_pct(le->le_kvset);

        assert(n_scatter != 0 && k_scatter <= n_scatter);
        k_spct = (k_scatter * 100) / n_scatter;
        k_spct = clamp_t(uint, k_spct, 1, 100);
        kvset_set_scatter_pct(le->le_kvset, k_spct);

        /* [HSE_REVISIT]: Node's scatter percent doesn't factor in
         * its length.
         */
        k_score = kvset_get_scatter_score(le->le_kvset);
        n_spct += (k_score > 1 ? k_spct : 0);
    }

    return clamp_t(uint, n_spct, 1, 100);
}

static uint
sp3_work_leaf_scatter(
    struct sp3_node *         spn,
    struct sp3_thresholds *   thresh,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule)
{
    struct list_head *       head;
    struct cn_tree_node *    tn;
    struct cn_node_stats     stats;
    struct kvset_list_entry *le;
    struct kvset *           k;

    uint n_kvsets;
    uint n_spct_tgt; /* node's target scatter pct. */
    uint n_spct_cur; /* node's scatter pct. */
    uint n_non_spct; /* node's non-scatter pct. */

    /* If the node scatter percent doesn't exceed threshold, return. */
    n_spct_cur = sp3_node_scatter_pct_compute(spn);
    n_spct_tgt = thresh->lscatter_pct;
    if (n_spct_cur <= n_spct_tgt)
        return 0;

    tn = spn2tn(spn);
    cn_node_stats_get(tn, &stats);

    head = &tn->tn_kvset_list;
    *mark = NULL;
    n_kvsets = 0;
    n_non_spct = 0;
    n_spct_cur = 0;

    list_for_each_entry_reverse (le, head, le_link) {
        uint k_spct_cur;
        uint k_score;

        k_score = kvset_get_scatter_score(le->le_kvset);
        k_spct_cur = kvset_get_scatter_pct(le->le_kvset);
        if (k_score > 1)
            n_spct_cur += k_spct_cur;
        else
            n_non_spct += k_spct_cur;

        if (n_spct_cur > n_spct_tgt) {
            if (k_score == 1)
                break;

            *mark = *mark ?: le;
            ++n_kvsets;

            n_non_spct += k_spct_cur;
            if (n_non_spct >= 100 - n_spct_tgt)
                break;
        }
    }

    if (ev(!*mark))
        return 0;

    k = (*mark)->le_kvset;
    if (n_kvsets > 1 || (n_kvsets == 1 && kvset_get_scatter_score(k) > 1 &&
                         kvset_get_scatter_pct(k) > (100 - n_spct_tgt) / 4)) {

        *action = CN_ACTION_COMPACT_KV;
        *rule = CN_CR_LSCATTER;

        return n_kvsets;
    }

    return 0;
}

/**
 * sp3_work() - determine if a given node needs maintenance
 * @tn: the cn tree node to check
 * @thresh: thresholds for work (eg, min/max kvsets)
 * @wtype: type of work to consider
 * @debug: debug flag
 * @qnum_out: sts queue
 * @wp: work struct
 */
merr_t
sp3_work(
    struct sp3_node *           spn,
    struct sp3_thresholds *     thresh,
    enum sp3_work_type          wtype,
    uint                        debug,
    struct cn_compaction_work **wp)
{
    struct cn_tree_node *      tn;
    struct cn_compaction_work *w;
    struct kvset_list_entry *  le;
    void *                     lock;
    uint                       i;
    uint                       ichildc;
    uint                       lchildc;
    bool                       have_token;

    uint                     n_kvsets = 0;
    enum cn_action           action = CN_ACTION_NONE;
    enum cn_comp_rule        rule = CN_CR_NONE;
    struct kvset_list_entry *mark = NULL;

    tn = spn2tn(spn);

    if (tn->tn_tree->rp->cn_maint_disable)
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
    rmlock_rlock(&tn->tn_tree->ct_lock, &lock);

    if (tn->tn_rspills_wedged) {
        if (!sp3_node_is_idle(tn))
            goto locked_nowork;

        log_info("re-enable compaction after wedge");
        tn->tn_rspills_wedged = false;
    }

    /* [HSE_REVISIT] If the node has morphed since this work request was
     * generated then we should discard this request as it may no longer
     * be applicable (i.e., the node's composition has changed, and may
     * have changed from a leaf to an internal node).
     */
    if (cn_node_isleaf(tn)) {
        switch (wtype) {
        case wtype_leaf_size:
            n_kvsets = sp3_work_leaf_size(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_leaf_garbage:
            n_kvsets = sp3_work_leaf_garbage(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_node_len:
            n_kvsets = sp3_work_leaf_len(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_leaf_scatter:
            n_kvsets = sp3_work_leaf_scatter(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_node_idle:
            n_kvsets = sp3_work_node_idle(spn, thresh, &mark, &action, &rule);
            break;

        default:
            ev_warn(1);
            assert(0);
            break;
        }
    } else {
        switch (wtype) {
        case wtype_rspill:
        case wtype_ispill:
            n_kvsets = sp3_work_ispill(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_node_len:
            n_kvsets = sp3_work_icompact(spn, thresh, &mark, &action, &rule);
            break;

        case wtype_node_idle:
            n_kvsets = sp3_work_node_idle(spn, thresh, &mark, &action, &rule);
            break;

        default:
            ev_info(1); /* node morphed from leaf to internal node */
            break;
        }
    }

    if (n_kvsets == 0)
        goto locked_nowork;

    if (action == CN_ACTION_SPILL) {

        if (tn->tn_loc.node_level == tn->tn_tree->ct_depth_max) {

            if (!tn->tn_terminal_node_warning) {
                tn->tn_terminal_node_warning = true;
                log_warn("cnid %lu node (%lu,%lu) at max depth",
                         (ulong)tn->tn_tree->cnid,
                         (ulong)tn->tn_loc.node_level,
                         (ulong)tn->tn_loc.node_offset);
            }

            goto locked_nowork;
        }

        /* Restrict concurrent spills to root and internal nodes,
         * and limit the concurrency to three jobs.
         */
        if (!cn_node_isleaf(tn)) {
            uint jobs = atomic_read(&tn->tn_busycnt) >> 16;

            if (jobs > 2)
                goto locked_nowork;

            cn_node_comp_token_put(tn);
            have_token = false;
        }
    } else {

        /* All other actions are node-wise mutually exclusive.
         */
        if (atomic_read(&tn->tn_busycnt) > 0)
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
    assert(n_kvsets);
    assert(action > CN_ACTION_NONE);
    assert(action < CN_ACTION_END);

    /* mark the kvsets with dgen_lo */
    w->cw_dgen_lo = kvset_get_dgen(mark->le_kvset);
    le = mark;
    for (i = 0; i < n_kvsets; i++) {
        assert(&le->le_link != &tn->tn_kvset_list);
        assert(kvset_get_workid(le->le_kvset) == 0);
        kvset_set_workid(le->le_kvset, w->cw_dgen_lo);
        w->cw_dgen_hi = kvset_get_dgen(le->le_kvset);
        w->cw_nk += kvset_get_num_kblocks(le->le_kvset);
        w->cw_nv += kvset_get_num_vblocks(le->le_kvset);
        le = list_prev_entry(le, le_link);
    }

    lchildc = 0;
    ichildc = 0;
    for (i = 0; i < tn->tn_tree->ct_cp->fanout; i++) {
        if (tn->tn_childv[i]) {
            if (cn_node_isleaf(tn->tn_childv[i]))
                lchildc++;
            else
                ichildc++;
        }
    }

    cn_node_stats_get(tn, &w->cw_ns);

    rmlock_runlock(lock);

    w->cw_node = tn;
    w->cw_tree = tn->tn_tree;
    w->cw_ds = tn->tn_tree->ds;
    w->cw_rp = tn->tn_tree->rp;
    w->cw_cp = tn->tn_tree->ct_cp;
    w->cw_pfx_len = tn->tn_tree->ct_cp->pfx_len;

    w->cw_kvset_cnt = n_kvsets;
    w->cw_mark = mark;
    w->cw_action = action;
    w->cw_comp_rule = rule;
    w->cw_debug = debug;

    w->cw_have_token = have_token;
    w->cw_rspill_conc = !have_token && (action == CN_ACTION_SPILL);

    w->cw_compc = kvset_get_compc(w->cw_mark->le_kvset);
    w->cw_pc = cn_get_perfc(tn->tn_tree->cn, w->cw_action);

    w->cw_t0_enqueue = get_time_ns();

    INIT_LIST_HEAD(&w->cw_rspill_link);

    if (w->cw_action == CN_ACTION_SPILL && !tn->tn_pfx_spill)
        w->cw_pfx_len = 0;

    if (w->cw_rspill_conc) {
        /* ensure concurrent root spills complete in order */
        mutex_lock(&tn->tn_rspills_lock);
        list_add_tail(&w->cw_rspill_link, &tn->tn_rspills);
        mutex_unlock(&tn->tn_rspills_lock);
    }

    sp3_work_estimate(w, ichildc, lchildc);

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
