/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_csched_sp3_work

#include <hse_util/event_counter.h>
#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse/logging/logging.h>

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

    case CN_ACTION_SPLIT:
        consume = halen + kalen + valen;
        percent_keep = 100;
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
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_rule             *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    uint runlen_min, runlen_max, runlen;
    struct kvset_list_entry *le;
    size_t wlen_max, wlen;

    *action = CN_ACTION_SPILL;
    *rule = CN_RULE_RSPILL;
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

    wlen = kvset_get_kwlen(le->le_kvset) + kvset_get_vwlen(le->le_kvset);
    wlen_max = thresh->rspill_wlen_max;

    runlen_min = thresh->rspill_runlen_min;
    runlen_max = thresh->rspill_runlen_max;
    runlen = 1;

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
        if (runlen >= runlen_min && wlen >= wlen_max)
            break;

        ++runlen;
    }

    /* TODO: If the number of contiguous kvsets that would all spill
     * to the same leaf node is one or more then return that number
     * as a zero-writeamp spill operation (e.g., CN_ACTION_ZSPILL)
     * irrespective of runlen_min, runlen_max, and wlen_max.
     */

    if (runlen < runlen_min)
        return 0;

    if (wlen < VBLOCK_MAX_SIZE) {
        if (runlen < runlen_max)
            return 0; /* defer tiny spills */

        *rule = CN_RULE_TSPILL; /* tiny root spill */
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
    enum cn_rule             *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct kvset_list_entry *le;
    struct list_head *head;
    uint kvsets;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    kvsets = cn_ns_kvsets(&tn->tn_ns);

    if (tn->tn_isroot) {
        *action = CN_ACTION_SPILL;
        *rule = CN_RULE_RSPILL;
        return kvsets;
    }

    if (kvsets < 2)
        return 0;

    *action = CN_ACTION_COMPACT_KV;

    /* Keep idle index nodes fully compacted to improve scanning
     * (e.g., mongod index nodes that rarely change after load).
     */
    if (cn_ns_vblks(&tn->tn_ns) < kvsets) {
        const uint keys_max = thresh->lcomp_split_keys / 2;

        /* Skip oldest kvsets with enormous key counts.
         */
        for (le = *mark; le; le = list_prev_entry_or_null(le, le_link, head)) {
            const struct kvset_stats *stats = kvset_statsp(le->le_kvset);

            if (stats->kst_keys < keys_max)
                break;

            kvsets--;
        }

        kvsets = (kvsets > 1) ? kvsets : 0;
        *rule = CN_RULE_IDLE_INDEX;
        *mark = le;

        return min_t(uint, kvsets, thresh->lcomp_runlen_max);
    }

    /* Otherwise, compact the node if the resulting size is smaller
     * than a single vblock (rare, but happens).
     */
    if (cn_ns_clen(&tn->tn_ns) < VBLOCK_MAX_SIZE) {
        *rule = CN_RULE_IDLE_SIZE;
        return kvsets;
    }

    /* Compact the node if the preponderance of keys appears to be tombs or
     * if all kvsets are ptomb-only.
     */
    if ((cn_ns_tombs(&tn->tn_ns) * 100 > cn_ns_keys_uniq(&tn->tn_ns) * 90) ||
        cn_ns_keys(&tn->tn_ns) == 0) {
        *rule = CN_RULE_IDLE_TOMB;
        return kvsets;
    }

    return 0;
}

/* This function is invoked periodically for each node that needs to be
 * split until the function returns non-zero.
 *
 * If conditions are favorable to split we set the "tn_ss_splitting" flag
 * to request a split.  Until then, we must make the following checks
 * on each invocation in order to avoid stalling a root spill:
 *
 * 1) Defer requesting a split if there are already "split_cnt_max" splits
 *    active in the tree (i.e., the max number of concurrent splits), or
 *    we are in a "cool down" period having recently run the max number
 *    of concurrent splits.
 *
 * 2) If the root node is too long then wait for root spill to catch up.
 *
 * 3) If there's an active spill to this node then defer requesting a split
 *    in hopes we can split some other node that isn't currently undergoing
 *    an active spill.  We try this at most a few times, because if the tree
 *    has "split_cnt_max" nodes or fewer they might all be undergoing an
 *    active spill (which could potentially take a very long time).
 *
 * If none of the above conditions hold, then we request a split by setting
 * the "tn_ss_splitting" flag to true, which will prevent new spills into this
 * node.  However, if this node is currently undergoing an active spill then
 * we must return 0 to avoid starting a split.  We then re-evalutate the
 * spilling condition on each invocation until all spills to this node have
 * completed (i.e., tn_ss_spilling == 0).  Only then may we start the split.
 */
static uint
sp3_work_wtype_split(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_rule             *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct cn_tree *tree = tn->tn_tree;
    struct kvset_list_entry *le;
    struct list_head *head;
    bool splittable;
    bool expandable;
    uint kvsets;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    *action = CN_ACTION_SPLIT;
    *rule = CN_RULE_SPLIT;

    kvsets = cn_ns_kvsets(&tn->tn_ns);

    /* Recheck to see if this node should be split, as while awaiting
     * an opportunity to split an rspill could have shrunk this node
     * below the split size, or we might have reached max fanout.
     */
    splittable = (kvsets > 0) &&
        (cn_ns_clen(&tn->tn_ns) >= tn->tn_split_size ||
         cn_ns_keys_uniq(&tn->tn_ns) >= thresh->lcomp_split_keys);

    mutex_lock(&tn->tn_ss_lock);
    expandable = (tree->ct_fanout < CN_FANOUT_MAX - atomic_read(&tree->ct_split_cnt));

    if (splittable && expandable) {
        uint spilling = atomic_read(&tn->tn_ss_spilling);

        if (!tn->tn_ss_splitting) {
            if (atomic_read(&tree->ct_split_cnt) >= thresh->split_cnt_max ||
                jclock_ns < tree->ct_split_dly) {

                tn->tn_ss_visits = 0;
                kvsets = 0;
            } else if (cn_ns_kvsets(&tree->ct_root->tn_ns) >= thresh->rspill_runlen_min * 3) {
                tn->tn_ss_visits = 0;
                kvsets = 0;
            } else if (spilling && tn->tn_ss_visits < thresh->split_cnt_max) {
                tn->tn_ss_visits++;
                kvsets = 0;
            } else {
                if (atomic_inc_return(&tree->ct_split_cnt) >= thresh->split_cnt_max)
                    tree->ct_split_dly = jclock_ns + NSEC_PER_SEC * 3;

                /* By setting tn_ss_splitting to true we are committing
                 * to split this node despite the fact that we may not
                 * be able to start the split right now if the node is
                 * currently being spilled.
                 */
                tn->tn_ss_splitting = true;
                tn->tn_ss_visits = 0;
            }
        }

        /* Defer starting the split if there are active spills to this node.
         * This most often occurs on trees with one leaf, and rarely on trees
         * with many leaves (but largely depends on the spill pattern).
         */
        if (spilling)
            kvsets = 0;
    } else {
        if (tn->tn_ss_splitting) {
            tn->tn_ss_splitting = false;
            atomic_dec(&tree->ct_split_cnt);
            cv_broadcast(&tn->tn_ss_cv);
            ev_debug(1);
        }

        tn->tn_ss_visits = 0;

        /* If the route map is expandable then the node size must have risen
         * above then below the split threshold, so we issue a cheap k-compact
         * to ensure this node gets back into the scheduler's consideration.
         *
         * Otherwise, we simply drop this request, meaning that no new work
         * will be scheduled for this node until the next spill into it
         * (which might never happen).
         */
        if (expandable) {
            while (kvsets > thresh->llen_runlen_min) {
                *mark = list_prev_entry(*mark, le_link);
                kvsets--;
            }

            *action = CN_ACTION_COMPACT_K;
            *rule = CN_RULE_LENGTH_MIN;
            ev_debug(1);
        } else {
            *mark = NULL;
            kvsets = 0;
            ev_debug(1);
        }
    }
    mutex_unlock(&tn->tn_ss_lock);

    return kvsets;
}

static uint
sp3_work_wtype_garbage(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_rule             *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct cn_node_stats *ns = &tn->tn_ns;
    struct kvset_list_entry *le;
    struct list_head *head;
    uint kvsets;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    *action = CN_ACTION_COMPACT_KV;
    *rule = CN_RULE_GARBAGE;

    kvsets = cn_ns_kvsets(ns);

    /* If the preponderance of keys are tombs then perform a k-compaction
     * on the entire node to avoid unnecessarily rewriting vblocks.  If
     * this approach fails to annihilate all the keys, then it at least
     * buys us some time (at low cost) to allow for more tombs to arrive
     * before we perform a full kv-compaction.
     */
    if (kvsets > 1 && cn_ns_tombs(ns) * 100 > cn_ns_keys_uniq(ns) * 97) {
        *action = CN_ACTION_COMPACT_K;
        ev_debug(1);
        return kvsets;
    }

    return min_t(uint, kvsets, thresh->lcomp_runlen_max);
}

static uint
sp3_work_wtype_scatter(
    struct sp3_node          *spn,
    struct sp3_thresholds    *thresh,
    struct kvset_list_entry **mark,
    enum cn_action           *action,
    enum cn_rule             *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    struct kvset_list_entry *le;
    struct list_head *head;
    uint runlen_max;
    uint runlen;

    head = &tn->tn_kvset_list;
    *mark = list_last_entry_or_null(head, typeof(*le), le_link);
    *action = CN_ACTION_COMPACT_KV;
    *rule = CN_RULE_SCATTERF;

    runlen_max = thresh->lscat_runlen_max;
    runlen = cn_ns_kvsets(&tn->tn_ns);

    /* Find the oldest kvset which has vgroup scatter.
     */
    list_for_each_entry_reverse(le, head, le_link) {
        if (kvset_get_vgroups(le->le_kvset) > 1) {
            *mark = le;
            break;
        }

        *rule = CN_RULE_SCATTERP;
        --runlen;
    }

    /* Include the next oldest kvset if it's reasonably small
     * (to prevent repeated scatter remediation of tiny kvsets
     * from creating unnecessarily long nodes).
     */
    if (runlen > 0) {
        le = list_next_entry_or_null(*mark, le_link, head);
        if (le) {
            const struct kvset_stats *stats = kvset_statsp(le->le_kvset);

            if (stats->kst_kwlen + stats->kst_vwlen < (256ul << 20)) {
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
    enum cn_rule             *rule)
{
    struct cn_tree_node *tn = spn2tn(spn);
    uint keys_max = thresh->lcomp_split_keys / 2;
    uint runlen_min = thresh->llen_runlen_min;
    uint runlen_max = thresh->llen_runlen_max;
    uint kvsets;

    kvsets = cn_ns_kvsets(&tn->tn_ns);

    if (kvsets >= runlen_min) {
        const struct kvset_stats *stats = NULL;
        struct kvset_list_entry *le;
        struct list_head *head;
        uint compc = UINT_MAX;
        size_t vwlen = 0;
        size_t wlen = 0;
        uint runlen = 0;

        head = &tn->tn_kvset_list;
        *mark = list_last_entry(head, typeof(*le), le_link);
        *action = CN_ACTION_COMPACT_K;
        *rule = CN_RULE_LENGTH_MIN;

        /* If the node has an unexpectedly large number of uncompacted kvsets
         * then limit keys_max to prefer kvsets with smaller key counts and
         * hence reduce the node length as quickly as possible.
         */
        if (kvsets > runlen_max) {
            ulong kmax = 0;
            uint n = 0;

            list_for_each_entry(le, head, le_link) {
                if (kvset_get_compc(le->le_kvset) > 0)
                    break;

                stats = kvset_statsp(le->le_kvset);
                if (stats->kst_keys > kmax)
                    kmax = stats->kst_keys;
                ++n;
            }

            if (n > runlen_max) {
                *rule = CN_RULE_LENGTH_MAX;
                keys_max = kmax;
            }
        }

        /* Start from oldest kvset, find first run of 'runlen_min' kvsets
         * with the same 'compc' value, then k-compact those kvsets and up
         * to 'runlen_max' newer.  Skip kvsets with enormous key counts.
         * Include contiguous ptomb-only kvsets in the run.
         */
        list_for_each_entry_reverse(le, head, le_link) {
            if (runlen < runlen_min) {
                uint tmp = kvset_get_compc(le->le_kvset);

                if (compc != tmp || stats->kst_keys > keys_max) {
                    compc = tmp;
                    *mark = le;
                    runlen = 0;
                    vwlen = 0;
                    wlen = 0;
                }
            }

            stats = kvset_statsp(le->le_kvset);
            vwlen += stats->kst_vwlen;
            wlen += stats->kst_kwlen + stats->kst_vwlen;

            if (stats->kst_keys == 0)
                ++runlen_max;

            if (++runlen >= runlen_max)
                break;
        }

        /* If the run is sufficiently long then fully compact (i.e.,
         * kv-compact) all the kvsets in the run if the sum of values
         * would fit into a single vblock.  Otherwise compact just the
         * keys (i.e., k-compact).
         */
        if (runlen >= runlen_min) {
            if (wlen < VBLOCK_MAX_SIZE) {
                *action = CN_ACTION_COMPACT_KV;
                *rule = CN_RULE_LENGTH_WLEN;
            } else if (vwlen < VBLOCK_MAX_SIZE) {
                *action = CN_ACTION_COMPACT_KV;
                *rule = CN_RULE_LENGTH_VWLEN;
            }

            return runlen;
        }

        /* Fully compact the entire node if the resulting size is smaller
         * than a single vblock (rare, but happens).
         */
        if (cn_ns_clen(&tn->tn_ns) < VBLOCK_MAX_SIZE) {
            *mark = list_last_entry(head, typeof(*le), le_link);
            *action = CN_ACTION_COMPACT_KV;
            *rule = CN_RULE_LENGTH_CLEN;
            return kvsets;
        }

        /* Repeated compaction of tiny kvsets can make a node grow long
         * and push the run-length based k-compaction far into the future.
         * We address that here by looking for a run of kvsets with only
         * a small number of keys.
         */
        if (kvsets > runlen_max) {
            uint64_t keys_max = 32ul << 20;

            *action = CN_ACTION_COMPACT_K;
            *rule = CN_RULE_COMPC;
            runlen = 0;
            vwlen = 0;

            list_for_each_entry(le, head, le_link) {
                const struct kvset_stats *stats = kvset_statsp(le->le_kvset);

                if (stats->kst_keys > keys_max)
                    break;

                keys_max -= stats->kst_keys;
                vwlen += stats->kst_vwlen;
                *mark = le;
                runlen++;
            }

            if (runlen > runlen_min) {
                if (vwlen < VBLOCK_MAX_SIZE) {
                    *action = CN_ACTION_COMPACT_KV;
                    *rule = CN_RULE_INDEX;
                }

                return min_t(uint, runlen, runlen_max);
            }
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
    enum cn_rule             rule = CN_RULE_NONE;
    struct kvset_list_entry *mark = NULL;

    tn = spn2tn(spn);
    tree = tn->tn_tree;

    if (tree->rp->cn_maint_disable)
        return merr(EAGAIN);

    if (!*wp) {
        *wp = calloc(1, sizeof(*w));
        if (ev(!*wp))
            return merr(ENOMEM);
    }

    /* Caller uses these fields to relay information back to csched,
     * so ensure they have sane defaults.  If this function returns
     * zero csched will drop the request unless cw_resched is true.
     */
    (*wp)->cw_action = CN_ACTION_NONE;
    (*wp)->cw_resched = false;

    /* Actions requiring exclusive access to the node must acquire and hold
     * the token through completion of the action.  Actions that can run
     * concurrently must acquire the token to ensure there's not an exclusive
     * action running and then must release the token before returning.
     */
    have_token = cn_node_comp_token_get(tn);
    if (!have_token) {
        (*wp)->cw_resched = tn->tn_isroot;
        return 0;
    }

    /* The tree lock must be acquired to obtain a stable view of the node
     * and its stats, otherwise an asynchronously completing job could
     * morph them while they're being examined.
     */
    rmlock_rlock(&tree->ct_lock, &lock);

    if (tree->ct_rspills_wedged) {
        if (!sp3_node_is_idle(tn)) {
            (*wp)->cw_resched = tn->tn_isroot;
            goto locked_nowork;
        }

        if (tn->tn_isroot) {
            log_info("root node unwedged, spills enabled");
            tree->ct_rspills_wedged = false;
        }
    }

    if (cn_node_isleaf(tn)) {
        switch (wtype) {
        case wtype_split:
            n_kvsets = sp3_work_wtype_split(spn, thresh, &mark, &action, &rule);

            /* Set the resched flag to prevent csched from dropping this request
             * should sp3_work_wtype_split() return 0 to defer the split.
             */
            (*wp)->cw_resched = mark && !n_kvsets;
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

    if (action == CN_ACTION_SPILL) {
        assert(cn_node_isroot(tn));

        if ((atomic_read(&tn->tn_busycnt) >> 16) > 2)
            goto locked_nowork;

        cn_node_comp_token_put(tn);
        have_token = false;
    } else {
        assert(action != CN_ACTION_NONE);
        assert(atomic_read(&tn->tn_busycnt) == 0);

        /* tn_ss_splitting is not atomic.  It is set to true only by this
         * thread, and false only by compaction threads, and both whilst
         * holding tn_ss_lock.  The compaction token, however, provides
         * a full barrier which ensures we always see the most current
         * value despite not holding the lock.
         */
        if (action != CN_ACTION_SPLIT && tn->tn_ss_splitting) {
            ev_debug(1);
            goto locked_nowork;
        }
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

    w->cw_compc = kvset_get_compc(mark->le_kvset);

    /* If mark is at the end of the list or the compc of the first kvset
     * past the mark is higher than the mark's then we can advance the
     * compc for the new kvset.
     */
    le = list_next_entry_or_null(mark, le_link, &tn->tn_kvset_list);
    if (!le || w->cw_compc < kvset_get_compc(le->le_kvset))
        w->cw_compc++;

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
    w->cw_rule = rule;
    w->cw_debug = debug;

    w->cw_have_token = have_token;
    w->cw_pc = cn_get_perfc(tree->cn, w->cw_action);

    w->cw_t0_enqueue = get_time_ns();

    /* Ensure concurrent root spills complete in order */
    if (w->cw_action == CN_ACTION_SPILL)
        w->cw_sgen = ++tree->ct_sgen;

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
