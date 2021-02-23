/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
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

#define SIZE_128MIB ((size_t)128 << 20)
#define SIZE_1GIB   ((size_t)1 << 30)

/* The bonus count limits bonus work (scatter and idle)
 * [HSE_REVISIT] Do this correctly via job queues...
 */
#define SP3_BONUS_MAX_IDLE 1
#define SP3_BONUS_MAX_SCAT 2

static atomic_t sp3_bonus;

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
    struct list_head *       head;
    uint                     n_kvsets;
    struct kvset_list_entry *le;
    struct cn_tree_node *    tn;

    *mark = NULL;
    tn = spn2tn(spn);

    /* walk from tail (oldest), skip kvsets that are busy */
    head = &tn->tn_kvset_list;
    for (le = list_last_entry(head, typeof(*le), le_link); &le->le_link != head;
         le = list_prev_entry(le, le_link)) {

        if (kvset_get_workid(le->le_kvset) == 0) {
            *mark = le;
            break;
        }
    }

    if (!*mark)
        return 0;

    n_kvsets = 1;

    /* look for sequence of non-busy kvsets */
    for (le = list_prev_entry(le, le_link); &le->le_link != head;
         le = list_prev_entry(le, le_link)) {

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
 *   at a time.  The only time internal nodes are have k-compacted
 *   kvsets is when a k-compacted kvset is left behind after a leaf
 *   pop.
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
    uint                      cnt_min,
    uint                      cnt_max,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule)
{
    struct cn_tree_node *tn;
    uint                 cnt;

    cnt = sp3_work_ispill_find_kvsets(spn, cnt_max * 4, mark);
    if (cnt < 1 || cnt < cnt_min)
        return 0;

    *action = CN_ACTION_SPILL;

    tn = spn2tn(spn);

    if (tn->tn_loc.node_level > 0) {

        struct cn_node_stats stats;
        ulong                clen;

        cn_node_stats_get(tn, &stats);
        clen = cn_ns_clen(&stats);

        if (clen < SIZE_128MIB) {
            if (cnt < cnt_min)
                return 0;

            /* Don't let tiny interior nodes grow too long, they might
             * never be large enough to spill.
             */
            *action = CN_ACTION_COMPACT_KV;
            *rule = CN_CR_ILONG_LW;
            return cnt;
        } else if (clen < SIZE_1GIB) {
            *rule = CN_CR_SPILL_TINY;
            return cnt;
        } else if (kvset_get_compc((*mark)->le_kvset) > 1) {
            *rule = CN_CR_SPILL_ONE;
            return 1;
        }
    }

    *rule = CN_CR_SPILL;

    return min(cnt, cnt_max);
}

/**
 * Handle leaf node that exceeds or is close to max size.  If expected
 * size after spill is more than a configured percentage of max size
 * then spill.  Otherwise kv-compact.
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
    u64                      clen;
    uint                     kvsets;

    uint cnt_max = thresh->lcomp_kvsets_max;

    tn = spn2tn(spn);

    assert(tn->tn_loc.node_level <= tn->tn_tree->ct_depth_max);

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    clen = cn_ns_clen(&tn->tn_ns);
    kvsets = cn_ns_kvsets(&tn->tn_ns);

    *action = CN_ACTION_COMPACT_KV;
    *rule = CN_CR_LBIG;

    if (clen * 100 > thresh->lcomp_pop_pct * tn->tn_size_max) {

        if (kvset_get_compc((*mark)->le_kvset) > 0) {
            cnt_max = 1;
            *rule = CN_CR_LBIG_ONE;
        }

        *action = CN_ACTION_SPILL;
    }

    return min_t(uint, kvsets, cnt_max);
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
    u64                      clen;
    uint                     kvsets;

    uint cnt_max = thresh->lcomp_kvsets_max;

    tn = spn2tn(spn);

    assert(tn->tn_loc.node_level <= tn->tn_tree->ct_depth_max);

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    clen = cn_ns_clen(&tn->tn_ns);
    kvsets = cn_ns_kvsets(&tn->tn_ns);

    if (clen * 100 > thresh->lcomp_pop_pct * tn->tn_size_max) {
        /* Expected size after spill is more than a configured
         * percentage of max size: spill.
         */
        *action = CN_ACTION_SPILL;
    } else {
        /* Node is not big enough to spill.  If there's more than
         * one kvset, then kv-compact.  Otherwise do nothing.
         */
        if (kvsets > 1)
            *action = CN_ACTION_COMPACT_KV;
        else
            return 0;
    }

    *rule = CN_CR_LGARB;

    return min_t(uint, kvsets, cnt_max);
}

static bool
sp3_work_leaf_is_idle(struct cn_tree_node *tn, uint idlem)
{
    struct kvset_list_entry *le;
    u64                      ttl;

    le = list_first_entry(&tn->tn_kvset_list, typeof(*le), le_link);

    ttl = kvset_ctime(le->le_kvset) + (idlem * 60) * NSEC_PER_SEC;

    return (get_time_ns() > ttl);
}

static uint
sp3_work_leaf_len(
    struct sp3_node *         spn,
    struct sp3_thresholds *   thresh,
    struct kvset_list_entry **mark,
    enum cn_action *          action,
    enum cn_comp_rule *       rule,
    atomic_t **               bonusp)
{
    struct cn_tree_node *    tn;
    struct list_head *       head;
    struct cn_node_stats     stats;
    struct kvset_list_entry *le;

    uint runlen_min = thresh->llen_runlen_min;
    uint runlen_max = thresh->llen_runlen_max;
    uint kvcompc = thresh->llen_kvcompc;
    uint idlem = thresh->llen_idlem;
    uint idlec = thresh->llen_idlec;

    tn = spn2tn(spn);
    cn_node_stats_get(tn, &stats);

    /* Start from old kvsets, find first run of 'runlen_min' kvsets with
     * the same 'compc' value, then k-compact those kvsets and up to
     * 'runlen_max' newer.
     */
    if (cn_ns_kvsets(&stats) >= SP3_LLEN_RUNLEN_MIN) {
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

        /* Mitigate compounding of vblock scatter to improve
         * value locality-of-reference and cursor scanning.
         */
        if (compc == kvcompc && tn->tn_loc.node_level > 1) {
            *action = CN_ACTION_COMPACT_KV;
            *rule = CN_CR_LLONG_SCATTER;
        }

        if (runlen >= runlen_min)
            return (compc > 0) ? runlen_min : runlen;

        /* Don't let lightweight nodes grow too long.  For the most part this only
         * applies to "index" nodes (i.e., nodes where the values are much smaller
         * than the keys).
         */
        if (cn_ns_kvsets(&stats) > runlen_min && cn_ns_clen(&stats) < SIZE_1GIB) {
            *mark = list_last_entry(head, typeof(*le), le_link);

            /* Exclude the oldest kvset (if possible) as it should already
             * be highly compacted.
             */
            le = list_prev_entry(*mark, le_link);
            if (kvset_get_compc((*mark)->le_kvset) > kvset_get_compc(le->le_kvset))
                *mark = le;

            *action = CN_ACTION_COMPACT_KV;
            *rule = CN_CR_LSHORT_LW;
            return runlen_min;
        }

        /* Compact the least compacted kvsets if the node is idle.
         */
        if (compc < idlec && sp3_work_leaf_is_idle(tn, idlem)) {
            runlen = 0;
            list_for_each_entry (le, head, le_link) {
                if (kvset_get_compc(le->le_kvset) >= idlec)
                    break;
                *mark = le;
                ++runlen;
            }

            if (runlen < SP3_LLEN_RUNLEN_MIN)
                return 0;

            if (atomic_inc_return(&sp3_bonus) > SP3_BONUS_MAX_IDLE) {
                atomic_dec(&sp3_bonus);
                return 0;
            }

            if (kvset_get_vgroups((*mark)->le_kvset) > 1) {
                *action = CN_ACTION_COMPACT_KV;
                *rule = CN_CR_LSHORT_IDLE_VG;
            } else {
                *rule = CN_CR_LSHORT_IDLE;
            }

            *bonusp = &sp3_bonus;
            return min(runlen, runlen_max);
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
    enum cn_comp_rule *       rule,
    atomic_t **               bonusp)
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
    u64  now;

    tn = spn2tn(spn);

    /* Check if the node has timed-out. */
    now = get_time_ns();
    if (now < spn->spn_timeout)
        return 0;

    /* If the node scatter percent doesn't exceed threshold, return. */
    n_spct_cur = sp3_node_scatter_pct_compute(spn);
    n_spct_tgt = thresh->lscatter_pct;
    if (n_spct_cur <= n_spct_tgt)
        return 0;

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

        if (atomic_inc_return(&sp3_bonus) > SP3_BONUS_MAX_SCAT) {
            atomic_dec(&sp3_bonus);
            return 0;
        }

        *action = CN_ACTION_COMPACT_KV;
        *rule = CN_CR_LSCATTER;
        *bonusp = &sp3_bonus;

        return n_kvsets;
    }

    spn->spn_timeout = ULONG_MAX;

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
    uint *                      qnum_out,
    struct cn_compaction_work **wp)
{
    struct cn_tree_node *      tn;
    struct cn_compaction_work *w;
    struct kvset_list_entry *  le;
    void *                     lock;
    uint                       i;
    uint                       ichildc;
    uint                       lchildc;
    bool                       use_token;

    uint                     n_kvsets = 0;
    enum cn_action           action = CN_ACTION_NONE;
    enum cn_comp_rule        rule = CN_CR_NONE;
    struct kvset_list_entry *mark = NULL;
    atomic_t *               bonus = NULL;

    *qnum_out = 0;
    tn = spn2tn(spn);

    if (tn->tn_tree->rp->cn_maint_disable)
        return 0;

    if (!*wp) {
        *wp = calloc(1, sizeof(*w));
        if (ev(!*wp))
            return merr(ENOMEM);
    }

    /* Root node and internal nodes support concurrent
     * operations (rspill and ispill).  Leaf nodes do not.
     */
    use_token = tn->tn_parent && cn_node_isleaf(tn);
    if (use_token && !cn_node_comp_token_get(tn))
        return 0;

    rmlock_rlock(&tn->tn_tree->ct_lock, &lock);

    if (tn->tn_rspills_wedged) {
        if (!sp3_node_is_idle(tn))
            goto locked_nowork;
        tn->tn_rspills_wedged = false;
        hse_log(HSE_NOTICE "re-enable compaction after wedge");
    }

    if (cn_node_isleaf(tn)) {

        switch (wtype) {
            case wtype_leaf_size:
                n_kvsets = sp3_work_leaf_size(spn, thresh, &mark, &action, &rule);
                *qnum_out = SP3_QNUM_LEAFBIG;
                break;

            case wtype_leaf_garbage:
                n_kvsets = sp3_work_leaf_garbage(spn, thresh, &mark, &action, &rule);
                *qnum_out = SP3_QNUM_LEAF;
                break;

            case wtype_node_len:
                n_kvsets = sp3_work_leaf_len(spn, thresh, &mark, &action, &rule, &bonus);
                *qnum_out = SP3_QNUM_LEAF;
                break;

            case wtype_leaf_scatter:
                n_kvsets = sp3_work_leaf_scatter(spn, thresh, &mark, &action, &rule, &bonus);
                *qnum_out = SP3_QNUM_LEAFBIG;
                break;

            default:
                ev(1, HSE_WARNING);
                break;
        }
    } else {
        uint cmin;
        uint cmax;

        switch (wtype) {
            case wtype_rspill:
            case wtype_node_len:
                cmin = thresh->rspill_kvsets_min;
                cmax = thresh->rspill_kvsets_max;
                break;
            case wtype_ispill:
                cmin = thresh->ispill_kvsets_min;
                cmax = thresh->ispill_kvsets_max;
                break;
            default:
                ev(1, HSE_WARNING);
                goto locked_nowork;
        }

        n_kvsets = sp3_work_ispill(spn, cmin, cmax, &mark, &action, &rule);

        *qnum_out = SP3_QNUM_INTERN;
    }

    if (n_kvsets == 0)
        goto locked_nowork;

    if (action == CN_ACTION_SPILL && tn->tn_loc.node_level == tn->tn_tree->ct_depth_max) {

        if (!tn->tn_terminal_node_warning) {
            tn->tn_terminal_node_warning = true;
            hse_log(
                HSE_WARNING "cnid %lu node (%lu,%lu) at max depth",
                (ulong)tn->tn_tree->cnid,
                (ulong)tn->tn_loc.node_level,
                (ulong)tn->tn_loc.node_offset);
        }

        goto locked_nowork;
    }

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
    for (i = 0; i < tn->tn_tree->ct_cp->cp_fanout; i++) {
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
    w->cw_pfx_len = tn->tn_tree->ct_cp->cp_pfx_len;

    w->cw_kvset_cnt = n_kvsets;
    w->cw_mark = mark;
    w->cw_action = action;
    w->cw_comp_rule = rule;
    w->cw_bonus = bonus;
    w->cw_debug = debug;

    w->cw_have_token = use_token;
    w->cw_rspill_conc = !use_token && (action == CN_ACTION_SPILL);

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
    if (use_token)
        cn_node_comp_token_put(tn);
    rmlock_runlock(lock);
    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "csched_sp3_work_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
