/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_csched_sp3

#include <bsd/string.h>

#include <hse/experimental.h>

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/rest_api.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "csched_sp3.h"
#include "csched_sp3_work.h"

#include "cn_tree_compact.h"
#include "cn_tree_internal.h"
#include "kvset.h"

struct mpool;

struct perfc_name csched_sp3_perfc[] _dt_section = {
    NE(PERFC_BA_SP3_SAMP,       2, "spaceamp",                 "c_sp3_samp"),
    NE(PERFC_BA_SP3_REDUCE,     2, "reduce flag",              "c_sp3_reduce"),

    NE(PERFC_BA_SP3_LGOOD_CURR, 3, "currrent leaf used size ", "c_sp3_lgood"),
    NE(PERFC_BA_SP3_LGOOD_TARG, 3, "target leaf used size",    "t_sp3_lgood"),
    NE(PERFC_BA_SP3_LSIZE_CURR, 3, "currrent leaf size",       "c_sp3_lsize"),
    NE(PERFC_BA_SP3_LSIZE_TARG, 3, "target leaf size",         "t_sp3_lsize"),
    NE(PERFC_BA_SP3_RSIZE_CURR, 3, "currrent non-leaf size",   "c_sp3_rsize"),
    NE(PERFC_BA_SP3_RSIZE_TARG, 3, "target non-leaf size",     "t_sp3_rsize"),
};
NE_CHECK(csched_sp3_perfc, PERFC_EN_SP3, "csched_sp3_perfc table/enum mismatch");

/*
 * The scheduler monitors multiple cn trees to determine what compaction jobs
 * to run and when to run them.
 *
 * Terminology
 * -----------
 *   r_node -- cn tree internal node
 *   l_node -- cn tree leaf node in
 *   r_xxx  -- something to do with internal nodes
 *   l_xxx  -- something to do with leaf nodes
 *
 * Why use "r_" instead of "i_"?  Two reasons.  First, use of "inode" might
 * cause confusion with files system inodes.  Second, "i" is virtually
 * indistinguishable from "l" in some fonts.  So we use "r".  The mnemonic for
 * "r" is "routing node" since, in a cn tree, internal nodes essentially form
 * a routing network to get data to leaf nodes.  The obvious overlap with "r"
 * for root node is unfortuntate, but not disastrous because, in a cn tree,
 * root nodes and internal nodes have almost identical treatment.
 *
 *
 * Threads
 * -------
 * There is one internal thread, referred to as the "monitor" thread,
 * started in sp3_create.
 *
 * There are several external threads that interact with the scheduler:
 *    - Ingest threads, created in c0
 *    - STS job threads, created in sts_create().
 *    - Open/Close threads (threads that call cn_open() and cn_close().
 *
 * Events
 * ------
 *    - Add / Remove trees (invoked by open/close threads)
 *    - Notify ingest complete (invoked ingest threads)
 *    - Notify compaction complete (invoked by job threads)
 *
 * Schedule Policy
 * ---------------
 * This scheduler manages the overall space amplification, which is often
 * referrred to as "space amp" or "samp".  Space amp is defined as:
 *
 *    samp = actual_kvdb_size / logical_kvdb_size
 *
 * where,
 *
 *    actual_kvdb_size = total media space used by kvdb
 *    logical_kvdb_size = sum of all key and value lengths after
 *                        eliminating duplicate and deleted entries
 *
 * We take some liberties in the computation of actual_kvdb_size:
 *    - We only count kblock and vblock capacities.
 *    - We do not count CNDB mlogs or any other mlogs.
 *    - We do not count mpool overhead.
 *
 * Let:
 *    R_SIZE = sum of all mblock sizes in all internal cn tree nodes
 *    L_SIZE = sum of all mblock sizes in all leaf cn tree nodes
 *    L_GOOD = estimated value of L_SIZE after full compaction
 *             of all leaf nodes.
 *
 * Our approach to controlling space amp is:
 *   - Track actual garbage in leaf nodes with hyperloglog.
 *   - Pretend internal nodes are 100% garbage (because we can't easily use
 *     hyperloglog on internal nodes).
 *   - Ensure L_SIZE is much larger than R_SIZE.
 *
 * We then compute the estimated space amp, SAMP_EST, as follows:
 *
 *    SAMP_EST = (L_SIZE + R_SIZE) / L_GOOD
 *
 * Due to the assumption that internal nodes are all garbage, SAMP_EST is an
 * upper bound on the actual space amp.  Let SAMP_MAX represent the maximum
 * allowed space amp.  This scheduler aims to keep SAMP_MAX >= SAMP_EST, or:
 *
 *    SAMP_MAX >= (L_SIZE + R_SIZE) / L_GOOD
 *
 * Note if R_SIZE decreases, SAMP_EST descreases.  The same is true if L_GOOD
 * increases.  This is how the scheduler manages space amp:
 *
 *    - If L_GOOD gets too small relative to L_SIZE, then compact leaf nodes.
 *    - If R_SIZE gets too large relative to L_SIZE, then spill internal nodes
 *      to leaves.
 *
 * Min/max for values L_GOOD:
 *    L_GOOD_MIN = L_SIZE / SAMP_MAX  // when R_SIZE == 0
 *    L_GOOD_MAX = L_SIZE             // no garbage in leaves
 *
 * Min/max for values R_SIZE:
 *    R_SIZE_MIN = 0                   // internal nodes empty
 *    R_SIZE_MAX = L_SIZE*(SAMP_MAX-1) // when L_GOOD == L_SIZE
 *
 * Summary:
 *    - Run-time parameters, with example values:
 *          csched_samp_max     - max space amp (1.5)
 *          csched_lo_th_pct  - space amp low water mark (25%)
 *          csched_hi_th_pct  - space amp low water mark (75%)
 *          csched_leaf_pct - percent data to keep in leaves (90%)
 *
 *    - Spill internal node data into leaf nodes to ensure:
 *          L_SIZE / (L_SIZE + R_SIZE) > csched_leaf_pct
 *
 *    - Compute samp high and low water marks (HWM, LWM) based on run-time
 *      parameters.
 *
 *    - If SAMP_EST exceeds HWM, enable leaf compaction to drive SAMP_EST to
 *      LWM. When it drops below LWM, disable leaf compaction.
 *
 *    - The scheduler also implements logic to limit individual node lengh and
 *      size because long nodes decrease query performance, and large nodes
 *      are hard to compact and spill.  This extra logic is not strictly
 *      required to manage space amp.
 */

/* Red-Black Trees */
#define RBT_RI_ALEN 0 /* root and internal nodes sorted by alen */
#define RBT_L_PCAP  1 /* leaf nodes sorted by pct capacity */
#define RBT_L_GARB  2 /* leaf nodes sorted by garbage */
#define RBT_LI_LEN  3 /* internal and leaf nodes, sorted by #kvsets */
#define RBT_L_SCAT  4 /* leaf nodes sorted by vblock scatter */
#define RBT_LI_IDLE 5 /* internal and leaf nodes sorted by ttl */

#define CSCHED_SAMP_MAX_MIN  100
#define CSCHED_SAMP_MAX_MAX  999
#define CSCHED_LO_TH_PCT_MIN 5
#define CSCHED_LO_TH_PCT_MAX 95
#define CSCHED_HI_TH_PCT_MIN 5
#define CSCHED_HI_TH_PCT_MAX 95
#define CSCHED_LEAF_PCT_MIN  1
#define CSCHED_LEAF_PCT_MAX  99

struct sp3_qinfo {
    uint qjobs;
    uint qjobs_max;
};

/**
 * struct sp3 - kvdb scheduler policy
 * @ds:           to access mpool qos
 * @rp:           kvb run-time params
 * @sts:          short term scheduler
 * @running:      set to false by sp3_destroy
 * @mon_tlist:    monitored trees
 * @spn_rlist:    list of all nodes ready for rspill
 * @spn_alist:    list of all nodes from all monitored trees
 * @new_tlist_lock: lock for list of new trees
 * @new_tlist:    list of new trees
 * @mon_lock:     mutex used with @mon_cv
 * @mon_signaled: set by sp3_monitor_wake()
 * @mon_cv:       monitor thread conditional var
 * @samp_reduce:  if true, compact while samp > LWM
 * @mon_wq:       monitor thread workqueue
 * @mon_work:     monitor thread work struct
 * @name:         name for logging and data tree
 */
struct sp3 {
    /* Accessed only by monitor thread */
    struct mpool            *ds;
    struct kvdb_rparams     *rp;
    struct sts              *sts;
    struct sp3_thresholds    thresh;
    struct throttle_sensor  *throttle_sensor_root;
    struct kvdb_health      *health;
    atomic_int               running;
    struct sp3_qinfo         qinfo[SP3_QNUM_MAX];

    struct rb_root rbt[RBT_MAX] HSE_L1D_ALIGNED;

    struct list_head mon_tlist HSE_L1D_ALIGNED;
    struct list_head spn_rlist;
    struct list_head spn_alist;
    atomic_int       sp_ingest_count;
    atomic_int       sp_prune_count;
    uint             activity;
    bool             idle;
    uint             jobs_started;
    uint             jobs_finished;
    uint             jobs_max;
    uint             rr_job_type;
    u64              job_id;

    struct cn_compaction_work *wp;

    struct {
        /* mirror selected kvdb_rparams */
        u64 csched_samp_max;
        u64 csched_lo_th_pct;
        u64 csched_hi_th_pct;
        u64 csched_leaf_pct;
    } inputs;

    /* Working parameters, derived from kvdb_rparams mirrored
     * in 'struct inputs'.
     */
    uint samp_max;
    uint samp_hwm;
    uint samp_lwm;

    /* Current and target values for space amp and leaf percent.
     * Target refers the expected values after all active
     * compaction jobs finish.
     */
    bool samp_reduce;
    uint samp_curr;
    uint samp_targ;
    uint lpct_targ;

    /* Throttle sensors */
    u64         rspill_dt_prev;
    atomic_long rspill_dt;


    u64 qos_log_ttl;

    /* Tree shape report */
    bool tree_shape_bad;
    uint lvl_max;

    u64                  leaf_pop_size;
    struct cn_samp_stats samp;
    struct cn_samp_stats samp_wip;
    struct perfc_set     sched_pc;

    /* Accessed by monitor and infrequently by open/close threads */
    struct mutex     new_tlist_lock HSE_L1D_ALIGNED;
    struct list_head new_tlist;

    /* Accessed by monitor, open/close, ingest and jobs threads */
    struct mutex     mon_lock HSE_L1D_ALIGNED;
    bool             mon_signaled;
    struct cv        mon_cv;

    /* Accessed monitor and infrequently by job threads */
    struct mutex     work_list_lock HSE_L1D_ALIGNED;
    struct list_head work_list;

    u64  ucomp_prev_report_ns HSE_L1D_ALIGNED;
    bool ucomp_active;
    bool ucomp_canceled;

    /* The following fields are rarely touched.
     */
    struct workqueue_struct *mon_wq;
    struct work_struct mon_work;
    char name[];
};

/* cn_tree 2 sp3_tree */
#define tree2spt(_tree) (&(_tree)->ct_sched.sp3t)

/* Scale of kvdb rparms */
#define EXT_SCALE 100

/* Internal scale, to get better precision with scalar math.
 * ONE is defined simply for readability in
 * expressions such as '(1 + r) / r'.
 */
#define SCALE 10000
#define ONE   SCALE

/* Easy-ish access to run-time parameters */
#define debug_samp_work(_sp)   (csched_rp_dbg_samp_work((_sp)->rp))
#define debug_samp_ingest(_sp) (csched_rp_dbg_samp_ingest((_sp)->rp))
#define debug_tree_life(_sp)   (csched_rp_dbg_tree_life((_sp)->rp))
#define debug_dirty_node(_sp)  (csched_rp_dbg_dirty_node((_sp)->rp))
#define debug_sched(_sp)       (csched_rp_dbg_sched((_sp)->rp))
#define debug_qos(_sp)         (csched_rp_dbg_qos((_sp)->rp))
#define debug_rbtree(_sp)      (csched_rp_dbg_rbtree((_sp)->rp))

static void
sp3_dirty_node(struct sp3 *sp, struct cn_tree_node *tn);

static inline bool
qfull(struct sp3 *sp, uint qnum)
{
    struct sp3_qinfo *qi = sp->qinfo + qnum;

    return qi->qjobs >= qi->qjobs_max;
}

static inline uint
qthreads(struct sp3 *sp, uint qnum)
{
    uint64_t rparam = sp->rp->csched_qthreads;
    uint n;

    n = (rparam >> (qnum * 8)) & 0xff;

    return clamp_t(uint, n, 1, 16);
}

static inline double
safe_div(double numer, double denom)
{
    return denom == 0.0 ? 0.0 : numer / denom;
}

static inline double
scale2dbl(u64 samp)
{
    return (1.0 / SCALE) * samp;
}

static inline uint
samp_est(struct cn_samp_stats *s, uint scale)
{
    return scale * safe_div(s->i_alen + s->l_alen, s->l_good);
}

static inline uint
samp_pct_leaves(struct cn_samp_stats *s, uint scale)
{
    return scale * safe_div(s->l_alen, s->i_alen + s->l_alen);
}

static inline uint
samp_pct_good(struct cn_samp_stats *s, uint scale)
{
    return scale * safe_div(s->l_good, s->l_alen);
}

static inline uint
samp_pct_garbage(struct cn_samp_stats *s, uint scale)
{
    assert(s->l_alen >= s->l_good);

    return scale * safe_div(s->l_alen - s->l_good, s->l_alen);
}

static void
sp3_node_init(struct sp3 *sp, struct sp3_node *spn)
{
    struct cn_tree_node *tn;
    uint ttl, tx;

    spn->spn_initialized = true;

    for (tx = 0; tx < RBT_MAX; tx++)
        RB_CLEAR_NODE(&spn->spn_rbe[tx].rbe_node);

    tn = spn2tn(spn);
    INIT_LIST_HEAD(&spn->spn_rlink);
    INIT_LIST_HEAD(&spn->spn_alink);

    /* Append to list of all nodes from all managed trees.
     */
    list_add_tail(&spn->spn_alink, &sp->spn_alist);

    ttl = sp->rp ? sp->rp->csched_node_min_ttl : 13;
    spn->spn_ttl = (ttl << tn->tn_loc.node_level);
}

static void
sp3_monitor_wake(struct sp3 *sp)
{
    /* Signal monitor thread (our cv_signal requres lock to be held). */
    mutex_lock(&sp->mon_lock);
    sp->mon_signaled = true;
    cv_signal(&sp->mon_cv);
    mutex_unlock(&sp->mon_lock);
}

static bool
sp3_tree_is_managed(struct cn_tree *tree)
{
    struct sp3_tree *spt = tree2spt(tree);

    /* Use link as indicator of scheduler's knowledge of tree.
     * Relies on use of list_del_init when removing items from list.
     */
    return spt->spt_tlink.next && !list_empty(&spt->spt_tlink);
}

static void
sp3_samp_target(struct sp3 *sp, struct cn_samp_stats *ss)
{
    ss->i_alen = sp->samp.i_alen + sp->samp_wip.i_alen;
    ss->l_alen = sp->samp.l_alen + sp->samp_wip.l_alen;
    ss->l_good = sp->samp.l_good + sp->samp_wip.l_good;
}

static void
sp3_log_samp_overall_type(struct cn_samp_stats *s, const char *type, bool work_in_progress)
{
    uint pct_good = 0;
    uint pct_leaves = 0;
    uint est = 0;

    if (!work_in_progress) {
        pct_good = samp_pct_good(s, 100);
        pct_leaves = samp_pct_leaves(s, 100);
        est = samp_est(s, 100);
    }

    slog_info(
        HSE_SLOG_START("cn_samp_work"),
        HSE_SLOG_FIELD("type", "%s", type),
        HSE_SLOG_FIELD("samp", "%u", est),
        HSE_SLOG_FIELD("ialen", "%ld", s->i_alen),
        HSE_SLOG_FIELD("lalen", "%ld", s->l_alen),
        HSE_SLOG_FIELD("lgood", "%ld", s->l_good),
        HSE_SLOG_FIELD("lgarb", "%ld", s->l_alen - s->l_good),
        HSE_SLOG_FIELD("lgood_pct", "%u", pct_good),
        HSE_SLOG_FIELD("leaf_pct", "%u", pct_leaves),
        HSE_SLOG_END);
}

static void
sp3_log_samp_overall(struct sp3 *sp)
{
    struct cn_samp_stats curr;
    struct cn_samp_stats targ;
    struct cn_samp_stats wip;

    curr = sp->samp;
    wip = sp->samp_wip;
    sp3_samp_target(sp, &targ);

    perfc_set(&sp->sched_pc, PERFC_BA_SP3_LGOOD_CURR, (u64)curr.l_good);
    perfc_set(&sp->sched_pc, PERFC_BA_SP3_LSIZE_CURR, (u64)curr.l_alen);
    perfc_set(&sp->sched_pc, PERFC_BA_SP3_RSIZE_CURR, (u64)curr.i_alen);

    perfc_set(&sp->sched_pc, PERFC_BA_SP3_LGOOD_TARG, (u64)targ.l_good);
    perfc_set(&sp->sched_pc, PERFC_BA_SP3_LSIZE_TARG, (u64)targ.l_alen);
    perfc_set(&sp->sched_pc, PERFC_BA_SP3_RSIZE_TARG, (u64)targ.i_alen);

    sp3_log_samp_overall_type(&curr, "current", false);
    sp3_log_samp_overall_type(&wip, "wrk_in_prog", true);
    sp3_log_samp_overall_type(&targ, "target", false);
}

static void
sp3_log_samp_one_tree(struct cn_tree *tree)
{
    struct cn_samp_stats *s;
    long                  i_avg_sz;
    long                  l_avg_sz;

    s = &tree->ct_samp;
    i_avg_sz = (tree->ct_i_nodec ? s->i_alen / tree->ct_i_nodec : 0) >> 20;
    l_avg_sz = (tree->ct_l_nodec ? s->l_alen / tree->ct_l_nodec : 0) >> 20;

    slog_info(
        HSE_SLOG_START("cn_samp_tree"),
        HSE_SLOG_FIELD("cnid", "%lu", tree->cnid),
        HSE_SLOG_FIELD("ialen", "%ld", s->i_alen),
        HSE_SLOG_FIELD("lalen", "%ld", s->l_alen),
        HSE_SLOG_FIELD("lgood", "%ld", s->l_good),
        HSE_SLOG_FIELD("lgarb", "%ld", s->l_alen - s->l_good),
        HSE_SLOG_FIELD("samp", "%u", samp_est(s, 100)),
        HSE_SLOG_FIELD("inodes", "%u", tree->ct_i_nodec),
        HSE_SLOG_FIELD("lnodes", "%u", tree->ct_l_nodec),
        HSE_SLOG_FIELD("lgood_pct", "%u", samp_pct_good(s, 100)),
        HSE_SLOG_FIELD("leaf_pct", "%u", samp_pct_leaves(s, 100)),
        HSE_SLOG_FIELD("ialen_avg_M", "%ld", i_avg_sz),
        HSE_SLOG_FIELD("lalen_avg_M", "%ld", l_avg_sz),
        HSE_SLOG_END);
}

static void
sp3_log_samp_each_tree(struct sp3 *sp)
{
    struct cn_tree *tree;

    list_for_each_entry (tree, &sp->mon_tlist, ct_sched.sp3t.spt_tlink)
        sp3_log_samp_one_tree(tree);
}

static void
sp3_log_progress(struct cn_compaction_work *w, struct cn_merge_stats *ms, bool final)
{
    struct cn_work_est *est = &w->cw_est;
    double              progress;
    double              vblk_read_efficiency;
    const char *        msg_type;
    u64                 qt, pt, bt, ct;

    if (final) {
        msg_type = "final";
        progress = 1.0 * ms->ms_keys_in / est->cwe_keys;
        qt = w->cw_t1_qtime ? (w->cw_t1_qtime - w->cw_t0_enqueue) / 1000 : 0;
        pt = w->cw_t2_prep ? (w->cw_t2_prep - w->cw_t1_qtime) / 1000 : 0;
        bt = w->cw_t3_build ? (w->cw_t3_build - w->cw_t2_prep) / 1000 : 0;
        ct = w->cw_t4_commit ? (w->cw_t4_commit - w->cw_t3_build) / 1000 : 0;

    } else {
        msg_type = "progress";
        progress = 1.0 * w->cw_stats.ms_keys_in / est->cwe_keys;
        qt = pt = bt = ct = 0;
    }

    vblk_read_efficiency =
        safe_div(1.0 * ms->ms_val_bytes_out, ms->ms_vblk_read1.op_size + ms->ms_vblk_read2.op_size);

    /* [HSE_REVISIT] I think this exceeds the maximum number of arguments
     * per function call specified by the C spec (127), right?
     */
    slog_info(
        HSE_SLOG_START("cn_comp_stats"),
        HSE_SLOG_FIELD("type", "%s", msg_type),
        HSE_SLOG_FIELD("job", "%u", w->cw_job.sj_id),
        HSE_SLOG_FIELD("comp", "%s", cn_action2str(w->cw_action)),
        HSE_SLOG_FIELD("rule", "%s", cn_comp_rule2str(w->cw_comp_rule)),
        HSE_SLOG_FIELD("cnid", "%lu", w->cw_tree->cnid),
        HSE_SLOG_FIELD("lvl", "%u", w->cw_node->tn_loc.node_level),
        HSE_SLOG_FIELD("off", "%u", w->cw_node->tn_loc.node_offset),
        HSE_SLOG_FIELD("leaf", "%u", (uint)cn_node_isleaf(w->cw_node)),
        HSE_SLOG_FIELD("pct", "%3.1f", 100 * progress),
        HSE_SLOG_FIELD("vrd_eff", "%.3f", vblk_read_efficiency),

        HSE_SLOG_FIELD("kblk_alloc_ops", "%ld", ms->ms_kblk_alloc.op_cnt),
        HSE_SLOG_FIELD("kblk_alloc_sz", "%ld", ms->ms_kblk_alloc.op_size),
        HSE_SLOG_FIELD("kblk_alloc_ns", "%ld", ms->ms_kblk_alloc.op_time),

        HSE_SLOG_FIELD("kblk_write_ops", "%ld", ms->ms_kblk_write.op_cnt),
        HSE_SLOG_FIELD("kblk_write_sz", "%ld", ms->ms_kblk_write.op_size),
        HSE_SLOG_FIELD("kblk_write_ns", "%ld", ms->ms_kblk_write.op_time),

        HSE_SLOG_FIELD("vblk_alloc_ops", "%ld", ms->ms_vblk_alloc.op_cnt),
        HSE_SLOG_FIELD("vblk_alloc_sz", "%ld", ms->ms_vblk_alloc.op_size),
        HSE_SLOG_FIELD("vblk_alloc_ns", "%ld", ms->ms_vblk_alloc.op_time),

        HSE_SLOG_FIELD("vblk_write_ops", "%ld", ms->ms_vblk_write.op_cnt),
        HSE_SLOG_FIELD("vblk_write_sz", "%ld", ms->ms_vblk_write.op_size),
        HSE_SLOG_FIELD("vblk_write_ns", "%ld", ms->ms_vblk_write.op_time),

        HSE_SLOG_FIELD("vblk_read1_ops", "%ld", ms->ms_vblk_read1.op_cnt),
        HSE_SLOG_FIELD("vblk_read1_sz", "%ld", ms->ms_vblk_read1.op_size),
        HSE_SLOG_FIELD("vblk_read1_ns", "%ld", ms->ms_vblk_read1.op_time),

        HSE_SLOG_FIELD("vblk_read1wait_ops", "%ld", ms->ms_vblk_read1_wait.op_cnt),
        HSE_SLOG_FIELD("vblk_read1wait_ns", "%ld", ms->ms_vblk_read1_wait.op_time),

        HSE_SLOG_FIELD("vblk_read2_ops", "%ld", ms->ms_vblk_read2.op_cnt),
        HSE_SLOG_FIELD("vblk_read2_sz", "%ld", ms->ms_vblk_read2.op_size),
        HSE_SLOG_FIELD("vblk_read2_ns", "%ld", ms->ms_vblk_read2.op_time),

        HSE_SLOG_FIELD("vblk_read2wait_ops", "%ld", ms->ms_vblk_read2_wait.op_cnt),
        HSE_SLOG_FIELD("vblk_read2wait_ns", "%ld", ms->ms_vblk_read2_wait.op_time),

        HSE_SLOG_FIELD("kblk_read_ops", "%ld", ms->ms_kblk_read.op_cnt),
        HSE_SLOG_FIELD("kblk_read_sz", "%ld", ms->ms_kblk_read.op_size),
        HSE_SLOG_FIELD("kblk_read_ns", "%ld", ms->ms_kblk_read.op_time),

        HSE_SLOG_FIELD("kblk_readwait_ops", "%ld", ms->ms_kblk_read_wait.op_cnt),
        HSE_SLOG_FIELD("kblk_readwait_ns", "%ld", ms->ms_kblk_read_wait.op_time),

        HSE_SLOG_FIELD("vblk_dbl_reads", "%ld", ms->ms_vblk_wasted_reads),

        HSE_SLOG_FIELD("queue_us", "%lu", qt),
        HSE_SLOG_FIELD("prep_us", "%lu", pt),
        HSE_SLOG_FIELD("merge_us", "%lu", bt),
        HSE_SLOG_FIELD("commit_us", "%lu", ct),
        HSE_SLOG_END);
}

static void
sp3_log_job_samp(
    struct sp3 *               sp,
    struct cn_compaction_work *w,
    const char *               stage,
    struct cn_samp_stats *     samp)
{
    slog_info(
        HSE_SLOG_START("cn_job_samp"),
        HSE_SLOG_FIELD("job", "%u", w->cw_job.sj_id),
        HSE_SLOG_FIELD("stage", "%s", stage),
        HSE_SLOG_FIELD("cnid", "%lu", w->cw_tree->cnid),
        HSE_SLOG_FIELD("lvl", "%u", w->cw_node->tn_loc.node_level),
        HSE_SLOG_FIELD("off", "%u", w->cw_node->tn_loc.node_offset),
        HSE_SLOG_FIELD("comp", "%s", cn_action2str(w->cw_action)),
        HSE_SLOG_FIELD("rule", "%s", cn_comp_rule2str(w->cw_comp_rule)),
        HSE_SLOG_FIELD("ialen", "%ld", samp->i_alen),
        HSE_SLOG_FIELD("lalen", "%ld", samp->l_alen),
        HSE_SLOG_FIELD("lgood", "%ld", samp->l_good),
        HSE_SLOG_END);
}

static void
sp3_refresh_samp(struct sp3 *sp)
{
    u64 samp, lwm, hwm, leaf, r;
    u64 good_max, good_min;
    u64 good_hwm, good_lwm;
    u64 samp_hwm, samp_lwm;
    u64 range;

    bool csched_samp_max_changed = sp->inputs.csched_samp_max != sp->rp->csched_samp_max,
         csched_lo_th_pct_changed = sp->inputs.csched_lo_th_pct != sp->rp->csched_lo_th_pct,
         csched_hi_th_pct_changed = sp->inputs.csched_hi_th_pct != sp->rp->csched_hi_th_pct,
         csched_leaf_pct_changed = sp->inputs.csched_leaf_pct != sp->rp->csched_leaf_pct;

    /* Early return if nothing changed */
    if (!csched_samp_max_changed && !csched_lo_th_pct_changed && !csched_hi_th_pct_changed &&
        !csched_leaf_pct_changed)
        return;

    if (csched_samp_max_changed) {
        const u64 new_val =
            clamp_t(u64, sp->rp->csched_samp_max, CSCHED_SAMP_MAX_MIN, CSCHED_SAMP_MAX_MAX);

        log_info("sp3 kvdb_rparam csched_samp_max changed from %lu to %lu",
                 (ulong)sp->inputs.csched_samp_max,
                 (ulong)new_val);
        sp->inputs.csched_samp_max = new_val;
    }
    if (csched_lo_th_pct_changed) {
        const u64 new_val =
            clamp_t(u64, sp->rp->csched_lo_th_pct, CSCHED_LO_TH_PCT_MIN, CSCHED_LO_TH_PCT_MAX);

        log_info("sp3 kvdb_rparam csched_lo_th_pct changed from %lu to %lu",
                 (ulong)sp->inputs.csched_lo_th_pct,
                 (ulong)new_val);
        sp->inputs.csched_lo_th_pct = new_val;
    }
    if (csched_hi_th_pct_changed) {
        const u64 new_val =
            clamp_t(u64, sp->rp->csched_hi_th_pct, CSCHED_HI_TH_PCT_MIN, CSCHED_HI_TH_PCT_MAX);

        log_info("sp3 kvdb_rparam csched_hi_th_pct changed from %lu to %lu",
                 (ulong)sp->inputs.csched_hi_th_pct,
                 (ulong)new_val);
        sp->inputs.csched_hi_th_pct = new_val;
    }
    if (csched_leaf_pct_changed) {
        const u64 new_val =
            clamp_t(u64, sp->rp->csched_leaf_pct, CSCHED_LEAF_PCT_MIN, CSCHED_LEAF_PCT_MAX);

        log_info("sp3 kvdb_rparam csched_leaf_pct changed from %lu to %lu",
                 (ulong)sp->inputs.csched_leaf_pct,
                 (ulong)new_val);
        sp->inputs.csched_leaf_pct = new_val;
    }

    log_info("sp3 new samp input params: samp %lu, lwm_pct %lu, hwm_pct %lu, leaf_pct %lu",
             (ulong)sp->inputs.csched_samp_max,
             (ulong)sp->inputs.csched_lo_th_pct,
             (ulong)sp->inputs.csched_hi_th_pct,
             (ulong)sp->inputs.csched_leaf_pct);

    /* Input params (from kvdb_rparams) are scaled up by 100.
     * Internally we scale up by SCALE (10000) to get more
     * resolution.  Multiply each input param by SCALE/100 to
     * convert to our internal scale factor.
     */
    samp = sp->inputs.csched_samp_max * SCALE / EXT_SCALE;
    lwm = sp->inputs.csched_lo_th_pct * SCALE / EXT_SCALE;
    hwm = sp->inputs.csched_hi_th_pct * SCALE / EXT_SCALE;
    leaf = sp->inputs.csched_leaf_pct * SCALE / EXT_SCALE;
    r = ONE - leaf;

    /* "Good" is the fraction of leaf data that is not garbage.
     * A value of 1.0 means no garbage, 0.30 means 70% garbage.
     * The max good value is 1.0.  The min good value is:
     *
     *   good_min = (1 + R) / S
     *
     * where R is the ratio of internal to leaf and S is the space
     * amp.  For example, if we aim to keep 90% of data in leaves,
     * and S=1.3, then R=0.1 (10% in non-leaves), and:
     *
     *   good_min =  1.1 / 1.3 = 0.84
     *
     * This means, w/ 10% of data in non-leaves, that we
     * assume is garbage, we can't let good drop below 84%,
     * alternatively, we can't get leaf garbage exceed 16%.
     *
     * The low and high water marks are precentages in the range
     * between good_min and good_max (1.0).
     */
    good_max = ONE;
    good_min = SCALE * (ONE + r) / samp;
    range = good_max - good_min;

    good_lwm = good_min + (ONE - lwm) * range / SCALE;
    good_hwm = good_min + (ONE - hwm) * range / SCALE;

    samp_lwm = SCALE * (ONE + r) / good_lwm;
    samp_hwm = SCALE * (ONE + r) / good_hwm;

    /* save in sp3 struct */
    sp->samp_lwm = samp_lwm;
    sp->samp_hwm = samp_hwm;
    sp->samp_max = samp;

    log_info("sp3 samp derived params:"
             " samp lo/hi/max: %.3f %.3f %.3f"
             " good/leaf ratio min/lo/hi: %.3f %.3f %.3f",
             scale2dbl(sp->samp_lwm),
             scale2dbl(sp->samp_hwm),
             scale2dbl(sp->samp_max),
             scale2dbl(good_min),
             scale2dbl(good_lwm),
             scale2dbl(good_hwm));
}

static uint
sp3_node_scatter_score_compute(struct sp3_node *spn)
{
    struct list_head *       head;
    struct kvset_list_entry *le;
    struct cn_tree_node *    tn;

    uint n_score = 0;

    tn = spn2tn(spn);
    head = &tn->tn_kvset_list;

    list_for_each_entry (le, head, le_link) {
        uint k_score;

        k_score = kvset_get_scatter_score(le->le_kvset);

        /* [HSE_REVISIT]: A node's scatter score doesn't factor in
         * its node length. Including the node length could allow
         * us to merge the node length and scatter metric into one.
         */
        if (k_score > 1)
            n_score += k_score;
    }

    tn->tn_ns.ns_scatter = n_score;

    return n_score;
}

static void
sp3_refresh_thresholds(struct sp3 *sp)
{
    struct sp3_thresholds thresh = {};
    struct sp3_node *spn;
    uint64_t v;

    /* root node spill settings */
    v = sp->rp->csched_rspill_params;
    if (v != U64_MAX) {
        if (v) {
            thresh.rspill_kvsets_max = (v >> 0) & 0xff;
            thresh.rspill_kvsets_min = (v >> 8) & 0xff;
        } else {
            thresh.rspill_kvsets_max = 8;
            thresh.rspill_kvsets_min = 4;
        }
        thresh.rspill_kvsets_min = max(thresh.rspill_kvsets_min, SP3_RSPILL_KVSETS_MIN);
    }

    /* internal node spill settings */
    v = sp->rp->csched_ispill_params;
    if (v != U64_MAX) {
        if (v) {
            thresh.ispill_kvsets_max = (v >> 0) & 0xff;
            thresh.ispill_kvsets_min = (v >> 8) & 0xff;
            thresh.ispill_pop_szgb = (v >> 16) & 0xff;
            thresh.ispill_pop_keys = (v >> 24) & 0xff;
        } else {
            thresh.ispill_kvsets_max = 8;
            thresh.ispill_kvsets_min = 1;
            thresh.ispill_pop_szgb = 4;
            thresh.ispill_pop_keys = 16;
        }
        thresh.ispill_kvsets_min = max(thresh.ispill_kvsets_min, SP3_ISPILL_KVSETS_MIN);
    }

    /* leaf node compaction settings */
    v = sp->rp->csched_leaf_comp_params;
    if (v != U64_MAX) {
        if (v) {
            thresh.lcomp_kvsets_max = (v >> 0) & 0xff;
            thresh.lcomp_kvsets_min = (v >> 8) & 0xff;
            thresh.lcomp_pop_pct = (v >> 16) & 0xff;
            thresh.lcomp_pop_keys = (v >> 24) & 0xff;
        } else {
            thresh.lcomp_kvsets_max = 12;
            thresh.lcomp_kvsets_min = 2;
            thresh.lcomp_pop_pct = 100;
            thresh.lcomp_pop_keys = 128;
        }
        thresh.lcomp_kvsets_min = max(thresh.lcomp_kvsets_min, SP3_LCOMP_KVSETS_MIN);
    }

    /* leaf node length settings */
    v = sp->rp->csched_leaf_len_params;
    if (v != U64_MAX) {
        if (v) {
            thresh.llen_runlen_max = (v >> 0) & 0xff;
            thresh.llen_runlen_min = (v >> 8) & 0xff;
            thresh.llen_idlec = (v >> 24) & 0xff;
            thresh.llen_idlem = (v >> 32) & 0xff;
        } else {
            thresh.llen_runlen_max = 8;
            thresh.llen_runlen_min = 4;
            thresh.llen_idlec = 0; /* disabled by default */
            thresh.llen_idlem = 10;
        }
        thresh.llen_runlen_min = max(thresh.llen_runlen_min, SP3_LLEN_RUNLEN_MIN);
    }

    /* leaf node scatter settings */
    v = sp->rp->csched_vb_scatter_pct;
    thresh.lscatter_pct = clamp_t(u64, v, 0, 100);

    if (!memcmp(&thresh, &sp->thresh, sizeof(thresh)))
        return;

    /* Thresholds changed so re-compute work trees...
     */
    sp->thresh = thresh;

    list_for_each_entry(spn, &sp->spn_alist, spn_alink) {
        sp3_dirty_node(sp, spn2tn(spn));
    }

    log_info("sp3 thresholds:"
             " rspill: min/max %u/%u,"
             " ispill: min/max/sz/keys %u/%u/%u/%u,"
             " lcomp: min/max/pct/keys %u/%u/%u%%/%u,"
             " llen: min/max %u/%u,"
             " idlec: %u,"
             " idlem: %u,"
             " lscatter_pct: %u%%",

             thresh.rspill_kvsets_min,
             thresh.rspill_kvsets_max,

             thresh.ispill_kvsets_min,
             thresh.ispill_kvsets_max,
             thresh.ispill_pop_szgb,
             thresh.ispill_pop_keys,

             thresh.lcomp_kvsets_min,
             thresh.lcomp_kvsets_max,
             thresh.lcomp_pop_pct,
             thresh.lcomp_pop_keys,

             thresh.llen_runlen_min,
             thresh.llen_runlen_max,

             thresh.llen_idlec,
             thresh.llen_idlem,

             thresh.lscatter_pct);
}

static void
sp3_refresh_worker_counts(struct sp3 *sp)
{
    sp->jobs_max = 0;

    for (size_t i = 0; i < NELEM(sp->qinfo); i++) {
        sp->qinfo[i].qjobs_max = qthreads(sp, i);
        sp->jobs_max += sp->qinfo[i].qjobs_max;
    }
}

static void
sp3_refresh_settings(struct sp3 *sp)
{
    sp3_refresh_samp(sp);
    sp3_refresh_thresholds(sp);
    sp3_refresh_worker_counts(sp);
}

/*****************************************************************
 *
 * SP3 user-initiated compaction (ucomp)
 *
 */

static void
sp3_ucomp_cancel(struct sp3 *sp)
{
    if (!sp->ucomp_active) {
        log_info("ignoring request to cancel user-initiated"
                 " compaction because there is no active request");
        return;
    }

    log_info("canceling user-initiated compaction");

    sp->ucomp_active = false;
    sp->ucomp_canceled = true;
}

static void
sp3_ucomp_start(struct sp3 *sp)
{
    if (sp->ucomp_active)
        log_info("restarting user-initiated compaction (was already active)");
    else
        log_info("starting user-initiated compaction");

    sp->ucomp_active = true;
    sp->ucomp_canceled = false;
    sp->samp_reduce = true;
}

static void
sp3_ucomp_report(struct sp3 *sp, bool final)
{
    uint curr = samp_est(&sp->samp, 100);

    if (final) {

        log_info("user-initiated compaction complete: space_amp %u.%02u",
                 curr / 100, curr % 100);

    } else {

        u64  started = sp->jobs_started;
        u64  finished = sp->jobs_finished;
        uint goal = sp->samp_lwm * 100 / SCALE;

        log_info("user-initiated compaction in progress:"
                 " jobs: active %lu, started %lu, finished %lu;"
                 " space_amp: current %u.%02u, goal %u.%02u;",
                 started - finished,
                 started,
                 finished,
                 curr / 100,
                 curr % 100,
                 goal / 100,
                 goal % 100);
    }
}

static void
sp3_ucomp_check(struct sp3 *sp)
{
    if (sp->ucomp_active) {

        bool completed = sp->idle || sp->samp_curr < sp->samp_lwm;
        u64  now = get_time_ns();
        bool report = now > sp->ucomp_prev_report_ns + 5 * NSEC_PER_SEC;

        if (completed) {
            sp->ucomp_active = false;
            sp->ucomp_canceled = false;
        }

        if (completed || report) {
            sp->ucomp_prev_report_ns = now;
            sp3_ucomp_report(sp, completed);
        }
    }
}

/*****************************************************************
 *
 * SP3 red-black trees
 *
 */

static void
sp3_rb_erase(struct rb_root *root, struct sp3_rbe *rbe)
{
    if (!RB_EMPTY_NODE(&rbe->rbe_node)) {
        rb_erase(&rbe->rbe_node, root);
        RB_CLEAR_NODE(&rbe->rbe_node);
    }
}

static void
sp3_rb_insert(struct rb_root *root, struct sp3_rbe *new_node)
{
    struct rb_node **link = &root->rb_node;
    struct rb_node * parent = 0;
    u64              weight = new_node->rbe_weight;

    assert(RB_EMPTY_NODE(&new_node->rbe_node));

    while (*link) {

        struct sp3_rbe *this;

        this = rb_entry(*link, struct sp3_rbe, rbe_node);
        parent = *link;

        if (weight > this->rbe_weight)
            link = &(*link)->rb_left;
        else if (weight < this->rbe_weight)
            link = &(*link)->rb_right;
        else {
            assert((u64)new_node != (u64)this);
            if ((u64)new_node > (u64)this)
                link = &(*link)->rb_left;
            else
                link = &(*link)->rb_right;
        }
    }

    rb_link_node(&new_node->rbe_node, parent, link);
    rb_insert_color(&new_node->rbe_node, root);
}

static void
sp3_node_insert(struct sp3 *sp, struct sp3_node *spn, uint tx, u64 weight)
{
    struct rb_root *root = sp->rbt + tx;
    struct sp3_rbe *rbe = spn->spn_rbe + tx;

    assert(tx < RBT_MAX);

    if (!RB_EMPTY_NODE(&rbe->rbe_node)) {
        if (rbe->rbe_weight == weight)
            return;

        sp3_rb_erase(root, rbe);
    }

    rbe->rbe_weight = weight;
    sp3_rb_insert(root, rbe);
}

static void
sp3_node_remove(struct sp3 *sp, struct sp3_node *spn, uint tx)
{
    struct rb_root *root = sp->rbt + tx;
    struct sp3_rbe *rbe = spn->spn_rbe + tx;

    sp3_rb_erase(root, rbe);
}

static void
sp3_node_unlink(struct sp3 *sp, struct sp3_node *spn)
{
    uint tx;

    for (tx = 0; tx < RBT_MAX; tx++)
        sp3_rb_erase(sp->rbt + tx, spn->spn_rbe + tx);
}

/* Remove all nodes from all rb trees that belong to given cn_tree */
static void
sp3_unlink_all_nodes(struct sp3 *sp, struct cn_tree *tree)
{
    struct cn_tree_node *tn;
    struct tree_iter     iter;

    tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);

    while (NULL != (tn = tree_iter_next(tree, &iter))) {
        struct sp3_node *spn = tn2spn(tn);

        sp3_node_unlink(sp, spn);

        list_del_init(&spn->spn_rlink);
        list_del_init(&spn->spn_alink);
    }
}

static_assert(NELEM(((struct sp3_node *)0)->spn_rbe) == RBT_MAX,
              "number of elements of spn_rbe[] is not RBT_MAX");

static void
sp3_dirty_node_locked(struct sp3 *sp, struct cn_tree_node *tn)
{
    struct sp3_node *spn = tn2spn(tn);
    uint64_t nkvsets_total, nkvsets, nkeys;
    uint garbage = 0, scatter = 0, jobs;

    jobs = atomic_read_acq(&tn->tn_busycnt);
    nkeys = cn_ns_keys(&tn->tn_ns);

    nkvsets_total = cn_ns_kvsets(&tn->tn_ns);
    nkvsets = nkvsets_total - (jobs & 0xffffu);
    jobs >>= 16;

    if (tn->tn_parent) {

        /* RBT_LI_LEN: internal and leaf nodes sorted by number of kvsets.
         */
        if (nkvsets >= sp->thresh.llen_runlen_min && jobs < 1) {
            uint64_t weight = (nkvsets << 32) | nkeys;

            sp3_node_insert(sp, spn, RBT_LI_LEN, weight);
        } else {
            sp3_node_remove(sp, spn, RBT_LI_LEN);
        }

        /* RBT_LI_IDLE: Nodes sorted by idle check expiration time.
         * Time is a negative offset in 4-second intervals from
         * UINT32_MAX in order to work correctly with the rb-tree
         * weight comparator logic.
         */
        if (nkvsets >= 2 && jobs < 1) {
            if (sp->thresh.llen_idlec > 0 && sp->thresh.llen_idlem > 0) {
                uint64_t ttl = sp->thresh.llen_idlem * 60;
                uint64_t weight = UINT32_MAX - (jclock_ns >> 32) - ttl;

                weight = (weight << 32) | nkvsets;

                sp3_node_insert(sp, spn, RBT_LI_IDLE, weight);
            }
        } else {
            sp3_node_remove(sp, spn, RBT_LI_IDLE);
        }

    } else {

        /* If this root node is ready to spill then ensure it's on the list
         * in FIFO order, retaining its current position if it's already on
         * the list.  List order is otherwise managed by sp3_check_roots().
         */
        if (nkvsets >= sp->thresh.rspill_kvsets_min && jobs < 3) {
            if (list_empty(&spn->spn_rlink))
                list_add_tail(&spn->spn_rlink, &sp->spn_rlist);
        } else {
            list_del_init(&spn->spn_rlink);
        }
    }

    if (cn_node_isleaf(tn)) {
        garbage = samp_pct_garbage(&tn->tn_samp, 100);

        /* RBT_L_GARB: leaf nodes sorted by pct garbage.
         * Range: 0 <= rbe_weight <= 100.  If rbe_weight == 3, then
         * node has 3% garbage.
         */
        if (garbage && tn->tn_ns.ns_pcap && jobs < 1) {
            uint64_t weight = ((uint64_t)garbage << 32) | nkeys;

            sp3_node_insert(sp, spn, RBT_L_GARB, weight);
        } else {
            sp3_node_remove(sp, spn, RBT_L_GARB);
        }

        /* RBT_L_PCAP: Leaf nodes sorted by pct capacity and secondarily by
         * number of keys.  If the node's size doesn't exceed the "pop_pct"
         * threshold then we check to see if the number of keys exceeds the
         * "pop_keys" threshold.  If so, we insert this node into the tree
         * with "pop_pct" capacity to ensure it gets spilled.
         */
        if (tn->tn_ns.ns_pcap >= sp->thresh.lcomp_pop_pct && jobs < 1) {
            uint64_t weight = ((uint64_t)tn->tn_ns.ns_pcap << 32) | nkeys;

            sp3_node_insert(sp, spn, RBT_L_PCAP, weight);
        } else {
            uint64_t pop_keys = (uint64_t)sp->thresh.lcomp_pop_keys << 20;

            pop_keys *= tn->tn_loc.node_level;

            if (nkeys > pop_keys && jobs < 1) {
                uint64_t weight = ((uint64_t)sp->thresh.lcomp_pop_pct << 32) | nkeys;

                sp3_node_insert(sp, spn, RBT_L_PCAP, weight);
            } else {
                sp3_node_remove(sp, spn, RBT_L_PCAP);
            }
        }

        if (sp->thresh.lscatter_pct < 100 && jobs < 1) {
            scatter = sp3_node_scatter_score_compute(spn);

            if (scatter >= SP3_LSCAT_THRESH_MIN) {
                uint64_t weight = UINT32_MAX - (jclock_ns >> 32) - spn->spn_ttl;

                /* Inserts within the same 4-second window are sorted
                 * first by the scatter score then by number of kvsets.
                 */
                weight = (weight << 32) | (scatter << 16) | nkvsets;

                sp3_node_insert(sp, spn, RBT_L_SCAT, weight);
            }
        } else {
            sp3_node_remove(sp, spn, RBT_L_SCAT);
        }

    } else {
        if (nkvsets >= sp->thresh.ispill_kvsets_min && jobs < 3) {
            uint64_t pop_keys = (uint64_t)sp->thresh.ispill_pop_keys << 20;
            uint64_t pop_sz = sp->thresh.ispill_pop_szgb;
            uint64_t alen = cn_ns_alen(&tn->tn_ns) >> 30;
            uint64_t weight;

            /* All interior nodes reside in RBT_RI_ALEN so that they can be
             * spilled regardless of size (e.g., to meet tree leaf targets).
             * If the allocated length is below the minimum spill size and
             * the number of keys exceeds the "pop_keys" threshold then
             * insert using the "pop_sz" threshold to ensure it gets spilled.
             * Spill-by-alen always takes precedence over spill-by-keys.
             */
            if (alen < pop_sz && nkeys > pop_keys) {
                weight = (pop_sz << 32) | nkvsets;
            } else {
                weight = (alen << 32) | (UINT32_MAX - nkvsets);
            }

            /* RBT_RI_ALEN: root and internal nodes sorted by alen */
            sp3_node_insert(sp, spn, RBT_RI_ALEN, weight);
        }
    }

    if (debug_dirty_node(sp)) {

        bool isleaf = cn_node_isleaf(tn);

        slog_info(
            HSE_SLOG_START("cn_dirty_node"),
            HSE_SLOG_FIELD("cnid", "%lu", (ulong)tn->tn_tree->cnid),
            HSE_SLOG_FIELD("lvl", "%u", tn->tn_loc.node_level),
            HSE_SLOG_FIELD("off", "%u", tn->tn_loc.node_offset),
            HSE_SLOG_FIELD("isleaf", "%d", isleaf),
            HSE_SLOG_FIELD("nd_len", "%lu", (ulong)nkvsets_total),
            HSE_SLOG_FIELD("alen", "%lu", (ulong)cn_ns_alen(&tn->tn_ns)),
            HSE_SLOG_FIELD("garbage", "%lu", (ulong)garbage),
            HSE_SLOG_FIELD("scatter", "%u", scatter),
            HSE_SLOG_END);
    }
}

static void
sp3_dirty_node(struct sp3 *sp, struct cn_tree_node *tn)
{
    void *lock;

    rmlock_rlock(&tn->tn_tree->ct_lock, &lock);
    sp3_dirty_node_locked(sp, tn);
    rmlock_runlock(lock);
}

static void
sp3_process_workitem(struct sp3 *sp, struct cn_compaction_work *w)
{
    struct sp3_tree *    spt = tree2spt(w->cw_tree);
    struct cn_tree_node *tn = w->cw_node;
    struct cn_samp_stats diff;
    void *lock;

    assert(spt->spt_job_cnt > 0);
    assert(w->cw_qnum < SP3_QNUM_MAX);
    assert(sp->qinfo[w->cw_qnum].qjobs > 0);
    assert(sp->jobs_started > sp->jobs_finished);

    spt->spt_job_cnt--;

    sp->qinfo[w->cw_qnum].qjobs--;
    sp->jobs_finished++;

    cn_samp_diff(&diff, &w->cw_samp_post, &w->cw_samp_pre);

    if (debug_samp_work(sp)) {
        sp3_log_job_samp(sp, w, "pre", &w->cw_samp_pre);
        sp3_log_job_samp(sp, w, "post", &w->cw_samp_post);
        sp3_log_job_samp(sp, w, "diff", &diff);
        sp3_log_job_samp(sp, w, "estimated", &w->cw_est.cwe_samp);
    }

    sp->samp.r_alen += diff.r_alen;
    sp->samp.r_wlen += diff.r_wlen;
    sp->samp.i_alen += diff.i_alen;
    sp->samp.l_alen += diff.l_alen;
    sp->samp.l_good += diff.l_good;

    sp->samp_wip.i_alen -= w->cw_est.cwe_samp.i_alen;
    sp->samp_wip.l_alen -= w->cw_est.cwe_samp.l_alen;
    sp->samp_wip.l_good -= w->cw_est.cwe_samp.l_good;

    rmlock_rlock(&w->cw_tree->ct_lock, &lock);
    if (w->cw_action == CN_ACTION_SPILL) {

        struct sp3_node *spn;
        uint             fanout = w->cw_tree->ct_cp->fanout;
        uint             i;
        bool             newleaf = false;

        for (i = 0; i < fanout; i++) {
            if (tn->tn_childv[i]) {
                spn = tn2spn(tn->tn_childv[i]);
                if (!spn->spn_initialized) {
                    sp3_node_init(sp, spn);
                    newleaf = true;
                }

                /* [HSE_REVISIT] Skip if node didn't change.
                 */
                sp3_dirty_node_locked(sp, tn->tn_childv[i]);
            }
        }

        /* Unlink parent from all RB trees as this might be the
         * first time it morphed from leaf to internal node.
         */
        if (newleaf)
            sp3_node_unlink(sp, spn);
    }

    sp3_dirty_node_locked(sp, tn);
    rmlock_runlock(lock);

    if (w->cw_debug & CW_DEBUG_PROGRESS)
        sp3_log_progress(w, &w->cw_stats, true);

    if (!tn->tn_parent) {
        u64 dt;

        /* Maintain an average of the root spill's build time - used for throttling.
         */
        dt = w->cw_t3_build - w->cw_t2_prep;
        sp->rspill_dt_prev = (dt + sp->rspill_dt_prev) / 2;
        atomic_set(&sp->rspill_dt, sp->rspill_dt_prev);
    }

    if (debug_samp_work(sp)) {
        sp3_log_samp_each_tree(sp);
        sp3_log_samp_overall(sp);
    }

    sts_job_done(sp->sts, &w->cw_job);
    free(w);
}

static void
sp3_process_ingest(struct sp3 *sp)
{
    struct cn_tree *tree;
    bool            ingested = false;

    list_for_each_entry (tree, &sp->mon_tlist, ct_sched.sp3t.spt_tlink) {

        struct sp3_tree *spt = tree2spt(tree);
        long             alen;
        long             wlen;

        if (atomic_read_acq(&sp->sp_ingest_count) == 0)
            break;

        /* [HSE_REVISIT] Given inopportune concurrency with sp3_op_notify_ingest()
         * there's a small window where alen and wlen could be acquired relatively
         * inconsistently.  The discrepancy will be reflected in samp until after
         * the next ingest in which we can acquire a stable view.
         */
        alen = atomic_read(&spt->spt_ingest_alen);
        wlen = atomic_read(&spt->spt_ingest_wlen);
        if (alen) {
            atomic_dec(&sp->sp_ingest_count);

            atomic_sub(&spt->spt_ingest_alen, alen);
            sp->samp.i_alen += alen;
            sp->samp.r_alen += alen;

            atomic_sub(&spt->spt_ingest_wlen, wlen);
            sp->samp.r_wlen += wlen;

            sp3_dirty_node(sp, tree->ct_root);
            ingested = true;
        }
    }

    if (ingested)
        sp->activity++;

    if (ingested && debug_samp_ingest(sp)) {
        sp3_log_samp_each_tree(sp);
        sp3_log_samp_overall(sp);
    }
}

static void
sp3_process_worklist(struct sp3 *sp)
{
    struct cn_compaction_work *w;
    struct list_head           list;

    INIT_LIST_HEAD(&list);

    /* Move completed work from shared list to private list */
    mutex_lock(&sp->work_list_lock);
    list_splice_tail(&sp->work_list, &list);
    INIT_LIST_HEAD(&sp->work_list);
    mutex_unlock(&sp->work_list_lock);

    while (NULL != (w = list_first_entry_or_null(&list, typeof(*w), cw_sched_link))) {
        list_del(&w->cw_sched_link);
        sp3_process_workitem(sp, w);
        sp->activity++;
    }
}

static void
sp3_process_new_trees(struct sp3 *sp)
{
    struct cn_tree * tree, *tmp;
    struct list_head list;

    INIT_LIST_HEAD(&list);

    /* Move new trees from shared list to private list */
    mutex_lock(&sp->new_tlist_lock);
    list_splice_tail(&sp->new_tlist, &list);
    INIT_LIST_HEAD(&sp->new_tlist);
    mutex_unlock(&sp->new_tlist_lock);

    list_for_each_entry_safe (tree, tmp, &list, ct_sched.sp3t.spt_tlink) {

        struct sp3_tree *    spt = tree2spt(tree);
        struct cn_tree_node *tn;
        struct tree_iter     iter;
        void *lock;

        if (debug_tree_life(sp))
            log_info("sp3 acquire tree cnid %lu", (ulong)tree->cnid);

        rmlock_rlock(&tree->ct_lock, &lock);
        tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);

        while (NULL != (tn = tree_iter_next(tree, &iter))) {
            sp3_node_init(sp, tn2spn(tn));
            sp3_dirty_node_locked(sp, tn);
        }
        rmlock_runlock(lock);

        sp3_log_samp_one_tree(tree);

        sp->samp.r_alen += tree->ct_samp.r_alen;
        sp->samp.r_wlen += tree->ct_samp.r_wlen;
        sp->samp.i_alen += tree->ct_samp.i_alen;
        sp->samp.l_alen += tree->ct_samp.l_alen;
        sp->samp.l_good += tree->ct_samp.l_good;

        sp->lvl_max = max(sp->lvl_max, tree->ct_lvl_max);

        /* Move to the monitor's list. */
        list_del(&spt->spt_tlink);
        list_add(&spt->spt_tlink, &sp->mon_tlist);

        sp->activity++;
    }
}

static void
sp3_prune_trees(struct sp3 *sp)
{
    struct cn_tree *tree, *tmp;

    list_for_each_entry_safe (tree, tmp, &sp->mon_tlist, ct_sched.sp3t.spt_tlink) {

        struct sp3_tree *spt = tree2spt(tree);

        if (atomic_read_acq(&sp->sp_prune_count) == 0)
            break;

        if (!atomic_read(&spt->spt_enabled) && spt->spt_job_cnt == 0) {
            atomic_dec(&sp->sp_prune_count);

            if (debug_tree_life(sp))
                log_info("sp3 release tree cnid %lu", (ulong)tree->cnid);

            sp3_unlink_all_nodes(sp, tree);
            list_del_init(&spt->spt_tlink);

            sp3_log_samp_one_tree(tree);
            sp3_log_samp_overall(sp);

            /* [HSE_REVISIT]
             * Uncomment these asserts after fixing NFSE-3736.
             */
#if 0
#ifdef HSE_BUILD_DEBUG
            assert(sp->samp.i_alen >= tree->ct_samp.i_alen);
            assert(sp->samp.r_alen >= tree->ct_samp.r_alen);
            assert(sp->samp.r_wlen >= tree->ct_samp.r_wlen);
            assert(sp->samp.l_alen >= tree->ct_samp.l_alen);
            assert(sp->samp.l_good >= tree->ct_samp.l_good);
#endif
#endif

            if (sp->samp.i_alen >= tree->ct_samp.i_alen)
                sp->samp.i_alen -= tree->ct_samp.i_alen;
            if (sp->samp.r_alen >= tree->ct_samp.r_alen)
                sp->samp.r_alen -= tree->ct_samp.r_alen;
            if (sp->samp.r_wlen >= tree->ct_samp.r_wlen)
                sp->samp.r_wlen -= tree->ct_samp.r_wlen;
            if (sp->samp.l_alen >= tree->ct_samp.l_alen)
                sp->samp.l_alen -= tree->ct_samp.l_alen;
            if (sp->samp.l_good >= tree->ct_samp.l_good)
                sp->samp.l_good -= tree->ct_samp.l_good;

            sp3_log_samp_overall(sp);

            cn_ref_put(tree->cn);

            sp->activity++;
        }
    }
}

/**
 * sp3_work_progress() - External API: progress update
 * sp3_work_complete() - External API: notify compaction job has completed
 *
 * These aren't what you would normally consider an external
 * interface, but it is a callback resulting from an external event
 * and is executed on an external thread.
 */
static void
sp3_work_complete(struct cn_compaction_work *w)
{
    struct sp3 *sp = w->cw_sched;

    /* Put work on completion list and wake monitor. */
    mutex_lock(&sp->work_list_lock);
    list_add_tail(&w->cw_sched_link, &sp->work_list);
    mutex_unlock(&sp->work_list_lock);

    sp3_monitor_wake(sp);
}

static void
sp3_work_progress(struct cn_compaction_work *w)
{
    struct cn_merge_stats ms;

    if (!(w->cw_debug & CW_DEBUG_PROGRESS))
        return;

    /* compute change in merge stats from previous progress report */
    cn_merge_stats_diff(&ms, &w->cw_stats, &w->cw_stats_prev);
    memcpy(&w->cw_stats_prev, &w->cw_stats, sizeof(w->cw_stats_prev));

    sp3_log_progress(w, &ms, false);
}

static inline void
sp3_comp_thread_name(
    char *              buf,
    size_t              bufsz,
    enum cn_action      action,
    enum cn_comp_rule   rule,
    struct cn_node_loc *loc,
    bool                leaf)
{
    const char *a = "XX";
    const char *r = "XX";
    char        node_type;

    switch (action) {

        case CN_ACTION_NONE:
        case CN_ACTION_END:
            break;

        case CN_ACTION_COMPACT_K:
            a = "kc";
            break;
        case CN_ACTION_COMPACT_KV:
            a = "kv";
            break;
        case CN_ACTION_SPILL:
            a = "sp";
            break;
    }

    switch (rule) {

        case CN_CR_NONE:
        case CN_CR_END:
            break;

        case CN_CR_RSPILL:
            r = "sr";
            break;
        case CN_CR_RTINY:
            r = "tr";
            break;
        case CN_CR_ISPILL:
            r = "si";
            break;
        case CN_CR_ISPILL_ONE:
            r = "s1";
            break;
        case CN_CR_ITINY:
            r = "ti";
            break;
        case CN_CR_ILONG:
            r = "li";
            break;
        case CN_CR_LBIG:
            r = "bn";
            break;
        case CN_CR_LBIG_ONE:
            r = "b1";
            break;
        case CN_CR_LGARB:
            r = "gb";
            break;
        case CN_CR_LLONG:
            r = "lg";
            break;
        case CN_CR_LSHORT_LW:
            r = "lw";
            break;
        case CN_CR_LSHORT_IDLE:
            r = "id";
            break;
        case CN_CR_LSHORT_IDLE_VG:
            r = "iv";
            break;
        case CN_CR_LSCATTER:
            r = "sc";
            break;
    }

    if (loc->node_level == 0)
        node_type = 'r';
    else if (leaf)
        node_type = 'x';
    else
        node_type = 'i';

    snprintf(buf, bufsz, "hse_%c%s_%s_%u%u",
             node_type, a, r, loc->node_level, loc->node_offset);
}

/* This function is the sts job-print callback which is invoked
 * with the sts run-queue lock held and hence must not block.
 */
static int
sp3_job_print(struct sts_job *job, bool hdr, char *buf, size_t bufsz)
{
    struct cn_compaction_work *w = container_of(job, typeof(*w), cw_job);
    int n = 0, m = 0;

    if (hdr) {
        n = snprintf(buf, bufsz,
                     "%3s %6s %5s %7s %-7s %2s %1s %5s %6s %6s %4s"
                     " %3s %5s %3s %4s %6s %6s %6s %6s %1s %4s  %s\n",
                     "ID", "LOC   ", "JOB", "ACTION", "RULE",
                     "Q", "T", "KVSET", "ALEN", "CLEN", "PCAP",
                     "CC", "DGEN", "NK", "NV",
                     "RALEN", "IALEN", "LALEN", "LGOOD",
                     "S", "TIME", "TNAME");

        if (n < 1 || n >= bufsz)
            return n;

        bufsz -= n;
        buf += n;
    }

    m = snprintf(buf, bufsz,
                 "%3lu %u,%-4u %5u %7s %-7s %2u %1u %2u,%-2u %6lu %6lu %4u"
                 " %3u %5lu %3u %4u %6ld %6ld %6ld %6ld %1c %4lu  %s\n",
                 w->cw_tree->cnid,
                 w->cw_node->tn_loc.node_level, w->cw_node->tn_loc.node_offset,
                 sts_job_id_get(&w->cw_job),
                 cn_action2str(w->cw_action), cn_comp_rule2str(w->cw_comp_rule),
                 w->cw_qnum,
                 atomic_read(&w->cw_node->tn_busycnt) >> 16,
                 w->cw_kvset_cnt, (uint)cn_ns_kvsets(&w->cw_ns),
                 cn_ns_alen(&w->cw_ns) >> 20,
                 cn_ns_clen(&w->cw_ns) >> 20,
                 w->cw_ns.ns_pcap,
                 w->cw_compc,
                 w->cw_dgen_lo,
                 w->cw_nk, w->cw_nv,
                 w->cw_est.cwe_samp.r_alen >> 20,
                 w->cw_est.cwe_samp.i_alen >> 20,
                 w->cw_est.cwe_samp.l_alen >> 20,
                 w->cw_est.cwe_samp.l_good >> 20,
                 sts_job_status_get(&w->cw_job),
                 (jclock_ns - w->cw_t0_enqueue) / NSEC_PER_SEC,
                 w->cw_threadname);

    return (m < 1) ? m : (n + m);
}

static void
sp3_submit(struct sp3 *sp, struct cn_compaction_work *w, uint qnum)
{
    struct cn_tree_node *tn = w->cw_node;
    struct sp3_tree *    spt = tree2spt(w->cw_tree);

    assert(qnum < SP3_QNUM_MAX);

    sp3_comp_thread_name(
        w->cw_threadname,
        sizeof(w->cw_threadname),
        w->cw_action,
        w->cw_comp_rule,
        &tn->tn_loc,
        cn_node_isleaf(w->cw_node));

    w->cw_iter_flags = kvset_iter_flag_fullscan;
    w->cw_io_workq = NULL;

    switch (csched_rp_kvset_iter(sp->rp)) {
        case csched_rp_kvset_iter_sync:
            /* synchronous mblock read */
            break;

        case csched_rp_kvset_iter_mcache:
            /* mache maps */
            w->cw_iter_flags |= kvset_iter_flag_mcache;
            break;

        case csched_rp_kvset_iter_async:
        default:
            /* async mblock read */
            w->cw_io_workq = cn_get_io_wq(w->cw_tree->cn);
            break;
    }

    /* Force compaction reads to use mcache if the value blocks for this node reside on
     * the pmem media class. This is not accurate if the mclass policy is changed during
     * subsequent kvs opens, which results in a mix of media classes for the k/vblocks
     * in this node. However, this is not a correctness issue and will recover on its own
     * after a series of compaction operations.
     */
    if (cn_tree_node_mclass(tn, HSE_MPOLICY_DTYPE_VALUE) == HSE_MCLASS_PMEM) {
        w->cw_iter_flags |= kvset_iter_flag_mcache;
        w->cw_io_workq = NULL;
    }

    w->cw_sched = sp;
    w->cw_completion = sp3_work_complete;
    w->cw_progress = sp3_work_progress;
    w->cw_prog_interval = nsecs_to_jiffies(NSEC_PER_SEC);
    w->cw_debug = csched_rp_dbg_comp(sp->rp);
    w->cw_qnum = qnum;

    sp->samp_wip.i_alen += w->cw_est.cwe_samp.i_alen;
    sp->samp_wip.l_alen += w->cw_est.cwe_samp.l_alen;
    sp->samp_wip.l_good += w->cw_est.cwe_samp.l_good;

    spt->spt_job_cnt++;

    assert(!qfull(sp, qnum));
    sp->qinfo[qnum].qjobs++;
    sp->jobs_started++;
    sp->job_id++;
    sp->activity++;

    sts_job_init(&w->cw_job, cn_comp_slice_cb, sp->job_id);
    sts_job_submit(sp->sts, &w->cw_job);

    if (debug_sched(sp)) {
        log_info("%-2lu %u,%-4u j%u q%u n%u t%-2u %s:%-6s  kvsets %u,%-2u  clen %5lu"
                 "  cap %u%%  samp %lu%%%s",
                 w->cw_tree->cnid,
                 w->cw_node->tn_loc.node_level, w->cw_node->tn_loc.node_offset,
                 w->cw_job.sj_id, w->cw_qnum,
                 atomic_read(&w->cw_node->tn_busycnt) >> 16,
                 spt->spt_job_cnt,
                 cn_action2str(w->cw_action), cn_comp_rule2str(w->cw_comp_rule),
                 w->cw_kvset_cnt, (uint)cn_ns_kvsets(&w->cw_ns),
                 cn_ns_clen(&w->cw_ns) >> 20,
                 w->cw_ns.ns_pcap,
                 100 - (cn_ns_clen(&w->cw_ns) * 100 / cn_ns_alen(&w->cw_ns)),
                 sp->samp_reduce ? " samp_reduce" : "");
    }

    if (HSE_LIKELY(!w->cw_debug))
        return;

    if (cn_node_isroot(w->cw_node) && !(w->cw_debug & CW_DEBUG_ROOT))
        return;
    else if (cn_node_isleaf(w->cw_node) && !(w->cw_debug & CW_DEBUG_LEAF))
        return;
    else if (!(w->cw_debug & CW_DEBUG_INTERNAL))
        return;

    slog_info(
        HSE_SLOG_START("cn_comp_start"),
        HSE_SLOG_FIELD("job", "%u", w->cw_job.sj_id),
        HSE_SLOG_FIELD("comp", "%s", cn_action2str(w->cw_action)),
        HSE_SLOG_FIELD("rule", "%s", cn_comp_rule2str(w->cw_comp_rule)),
        HSE_SLOG_FIELD("cnid", "%lu", w->cw_tree->cnid),
        HSE_SLOG_FIELD("lvl", "%u", w->cw_node->tn_loc.node_level),
        HSE_SLOG_FIELD("off", "%u", w->cw_node->tn_loc.node_offset),
        HSE_SLOG_FIELD("leaf", "%u", (uint)cn_node_isleaf(w->cw_node)),
        HSE_SLOG_FIELD("qnum", "%u", w->cw_qnum),
        HSE_SLOG_FIELD("c_nk", "%u", w->cw_nk),
        HSE_SLOG_FIELD("c_nv", "%u", w->cw_nv),
        HSE_SLOG_FIELD("c_kvsets", "%u", w->cw_kvset_cnt),
        HSE_SLOG_FIELD("nd_kvsets", "%lu", (ulong)cn_ns_kvsets(&w->cw_ns)),
        HSE_SLOG_FIELD("nd_cap%%", "%lu", (ulong)w->cw_ns.ns_pcap),
        HSE_SLOG_FIELD("nd_keys", "%lu", (ulong)cn_ns_keys(&w->cw_ns)),
        HSE_SLOG_FIELD(
            "nd_hll%%",
            "%lu",
            (ulong)(
                cn_ns_keys(&w->cw_ns) == 0
                ? 0
                : ((100 * w->cw_ns.ns_keys_uniq) / cn_ns_keys(&w->cw_ns)))),
        HSE_SLOG_FIELD("rdsz_b", "%ld", (long)w->cw_est.cwe_read_sz),
        HSE_SLOG_FIELD("wrsz_b", "%ld", (long)w->cw_est.cwe_write_sz),
        HSE_SLOG_FIELD("i_alen_b", "%ld", (long)w->cw_est.cwe_samp.i_alen),
        HSE_SLOG_FIELD("l_alen_b", "%ld", (long)w->cw_est.cwe_samp.l_alen),
        HSE_SLOG_END);
}

static bool
sp3_check_roots(struct sp3 *sp, uint qnum)
{
    struct sp3_node *spn, *next;
    uint debug;

    debug = csched_rp_dbg_comp(sp->rp);

    /* Each node on the rspill list had at least rspill_kvsets_min kvsets
     * available when we scheduled this work request.
     */
    list_for_each_entry_safe(spn, next, &sp->spn_rlist, spn_rlink) {
        bool have_work;

        if (sp3_work(spn, &sp->thresh, wtype_rspill, debug, &sp->wp))
            return false;

        have_work = sp->wp && sp->wp->cw_action != CN_ACTION_NONE;
        if (have_work) {

            /* Move to end of list to prevent this node
             * from starving other nodes on the list.
             */
            if (!list_is_last(&spn->spn_rlink, &sp->spn_rlist)) {
                list_del(&spn->spn_rlink);
                list_add_tail(&spn->spn_rlink, &sp->spn_rlist);
            }

            sp3_submit(sp, sp->wp, qnum);
            sp->wp = NULL;
            return true;
        }

        /* There are either too many active jobs or insufficient kvsets
         * to spill right now so drop this work request. sp3_dirty_node()
         * will re-assess the situation when the node composition changes.
         */
        list_del_init(&spn->spn_rlink);
    }

    return false;
}

static void
sp3_rb_dump(struct sp3 *sp, uint tx, uint count_max)
{
    struct rb_root *     root;
    struct rb_node *     rbn;
    struct sp3_rbe *     rbe;
    struct sp3_node *    spn;
    struct cn_tree_node *tn;
    uint                 count;

    if (tx >= RBT_MAX)
        return;

    /* spn_rbe must be first element in sp3_node struct in order for
     * '(void *)(rbe - tx)' to map rbe back to the sp3_node struct.
     */
    assert(offsetof(typeof(*spn), spn_rbe) == 0);

    count = 0;
    root = sp->rbt + tx;
    for (rbn = rb_first(root); rbn; rbn = rb_next(rbn)) {

        rbe = rb_entry(rbn, struct sp3_rbe, rbe_node);
        spn = (void *)(rbe - tx);
        tn = spn2tn(spn);

        slog_info(
            HSE_SLOG_START("cn_rbt"),
            HSE_SLOG_FIELD("rbt", "%u", tx),
            HSE_SLOG_FIELD("item", "%u", count),
            HSE_SLOG_FIELD("weight", "%lx", (ulong)rbe->rbe_weight),
            HSE_SLOG_FIELD("cnid", "%lu", (ulong)tn->tn_tree->cnid),
            HSE_SLOG_FIELD("lvl", "%u", tn->tn_loc.node_level),
            HSE_SLOG_FIELD("off", "%u", tn->tn_loc.node_offset),
            HSE_SLOG_FIELD("leaf", "%u", (uint)cn_node_isleaf(tn)),
            HSE_SLOG_FIELD("len", "%ld", (long)cn_ns_kvsets(&tn->tn_ns)),
            HSE_SLOG_FIELD("ialen_b", "%ld", (long)tn->tn_samp.i_alen),
            HSE_SLOG_FIELD("lalen_b", "%ld", (long)tn->tn_samp.l_alen),
            HSE_SLOG_FIELD("lgood_b", "%ld", (long)tn->tn_samp.l_good),
            HSE_SLOG_FIELD("lgarb_b", "%ld", (long)(tn->tn_samp.l_alen - tn->tn_samp.l_good)),
            HSE_SLOG_END);

        if (count++ == count_max)
            break;
    }
}

static void
sp3_tree_shape_log(const struct cn_tree_node *tn, bool bad, const char *category)
{
    uint pcap;

    if (!tn)
        return;

    pcap = cn_node_isleaf(tn) ? tn->tn_ns.ns_pcap : 0;

    slog_info(
        HSE_SLOG_START("cn_tree_shape"),
        HSE_SLOG_FIELD("type", "%s", category),
        HSE_SLOG_FIELD("lvl", "%u", tn->tn_loc.node_level),
        HSE_SLOG_FIELD("off", "%u", tn->tn_loc.node_offset),
        HSE_SLOG_FIELD("status", "%s", bad ? "bad" : "good"),
        HSE_SLOG_FIELD("cnid", "%lu", (ulong)tn->tn_tree->cnid),
        HSE_SLOG_FIELD("nd_kvsets", "%lu", (ulong)cn_ns_kvsets(&tn->tn_ns)),
        HSE_SLOG_FIELD("nd_alen", "%lu", (ulong)cn_ns_alen(&tn->tn_ns)),
        HSE_SLOG_FIELD("pcap", "%u", pcap),
        HSE_SLOG_END);
}

/**
 * sp3_tree_shape_check() - report on tree shape
 * @sp: scheduler context
 *
 * Log a warning message if tree shape transitions from "good" to
 * "bad".  While shape is bad, periodically log messages providing
 * detail about shape and scheduler activity to assist
 * troubleshooting.
 *
 * Notes:
 * - There's nothing scientific about the thresholds for "bad tree"
 *   status, they were simply chosen to be high enough to hopefully
 *   not cause false alarms.
 * - The scheduler does not directly manage all these metrics, which
 *   means a tree might be flagged as bad and the scheduler won't
 *   purposefully fix it (e.g., there's no rule to directly limit the
 *   length of a leaf node).
 * - Largest internal node is not tracked because the scheduler
 *   doesn't manage internal nodes by size.
 */
static void
sp3_tree_shape_check(struct sp3 *sp)
{
    const uint rlen_thresh = 48;
    const uint ilen_thresh = 20;
    const uint llen_thresh = 20;
    const uint lsiz_thresh = 140;

    struct cn_tree_node *rlen_node = 0; /* longest root node */
    struct cn_tree_node *ilen_node = 0; /* longest internal node */
    struct cn_tree_node *llen_node = 0; /* longest leaf node */
    struct cn_tree_node *lsiz_node = 0; /* largest leaf node */

    uint rlen = 0;
    uint ilen = 0;
    uint llen = 0;
    uint lsiz = 0;
    uint lclen = 0;
    bool log = false;
    bool bad;

    struct sp3_node *spn;
    uint lvl_max = 0;

    /* [HSE_REVISIT] This function reads node state and stats without
     * holding the tree lock, so state determination and reporting
     * may be inconsistent (e.g., node composition can chance, leaf
     * nodes can become internal nodes, ...)
     */
    list_for_each_entry(spn, &sp->spn_alist, spn_alink) {
        struct cn_tree_node *tn = spn2tn(spn);
        uint len = cn_ns_kvsets(&tn->tn_ns);

        if (cn_node_isleaf(tn)) {
            uint pcap = tn->tn_ns.ns_pcap;

            if (!llen_node || len > llen) {
                llen_node = tn;
                llen = len;
            }

            if (!lsiz_node || pcap > lsiz) {
                lsiz_node = tn;
                lsiz = pcap;
                lclen = cn_ns_clen(&tn->tn_ns) >> 20;
            }
        } else if (cn_node_isroot(tn)) {
            if (!rlen_node || len > rlen) {
                rlen_node = tn;
                rlen = len;
            }

            lvl_max = max(lvl_max, tn->tn_tree->ct_lvl_max);
        } else {
            if (!ilen_node || len > ilen) {
                ilen_node = tn;
                ilen = len;
            }
        }
    }

    bad = rlen > rlen_thresh || ilen > ilen_thresh || llen > llen_thresh || lsiz > lsiz_thresh;
    sp->lvl_max = lvl_max;

    if (sp->tree_shape_bad != bad) {

        log_info("tree shape changed from %s (samp %.3f rlen %u ilen %u llen %u lsize %um)",
                 bad ? "good to bad" : "bad to good",
                 scale2dbl(sp->samp_curr),
                 rlen, ilen, llen, lclen);

        sp->tree_shape_bad = bad;
        log = true; /* log details below */
    }

    if (log || debug_sched(sp)) {

        sp3_tree_shape_log(rlen_node, rlen > rlen_thresh, "longest_root");
        sp3_tree_shape_log(ilen_node, ilen > ilen_thresh, "longest_internal");
        sp3_tree_shape_log(llen_node, llen > llen_thresh, "longest_leaf");
        sp3_tree_shape_log(lsiz_node, lsiz > lsiz_thresh, "largest_leaf");

        slog_info(
            HSE_SLOG_START("cn_sched"),
            HSE_SLOG_FIELD("samp_lwm", "%.3f", scale2dbl(sp->samp_lwm)),
            HSE_SLOG_FIELD("hwm", "%.3f", scale2dbl(sp->samp_hwm)),
            HSE_SLOG_FIELD("max", "%.3f", scale2dbl(sp->samp_max)),
            HSE_SLOG_FIELD("curr", "%.3f", scale2dbl(sp->samp_targ)),
            HSE_SLOG_FIELD("reduce", "%d", sp->samp_reduce),
            HSE_SLOG_FIELD("lf_pct_targ", "%.3f", scale2dbl(sp->lpct_targ)),
            HSE_SLOG_FIELD("jobs_started", "%u", sp->jobs_started),
            HSE_SLOG_FIELD("jobs_finished", "%u", sp->jobs_finished),
            HSE_SLOG_FIELD("cur_jobs", "%u", sp->jobs_started - sp->jobs_finished),
            HSE_SLOG_FIELD("max_jobs", "%u", sp->jobs_max),
            HSE_SLOG_END);

        sp3_log_samp_each_tree(sp);
        sp3_log_samp_overall(sp);
    }
}

/* spn_rbe must be first element in sp3_node struct in order for
 * '(void *)(rbe - tx)' to map rbe back to the sp3_node struct.
 */
static_assert(offsetof(struct sp3_node, spn_rbe) == 0,
              "spn_rbe must be first field in struct sp3_node");

static bool
sp3_check_rb_tree(struct sp3 *sp, uint tx, u64 threshold, enum sp3_work_type wtype, uint qnum)
{
    struct rb_root *root;
    struct rb_node *rbn;
    uint            debug;

    assert(tx < RBT_MAX);

    debug = csched_rp_dbg_comp(sp->rp);

    root = sp->rbt + tx;
    rbn = rb_first(root);

    while (rbn) {
        struct sp3_rbe * rbe;
        struct sp3_node *spn;
        bool             have_work;

        rbe = rb_entry(rbn, struct sp3_rbe, rbe_node);
        spn = (void *)(rbe - tx);

        if (rbe->rbe_weight < threshold)
            return false;

        if (sp3_work(spn, &sp->thresh, wtype, debug, &sp->wp))
            return false;

        have_work = sp->wp && sp->wp->cw_action != CN_ACTION_NONE;
        if (have_work) {
            sp3_submit(sp, sp->wp, qnum);
            sp->wp = NULL;
            return true;
        }

        rbn = rb_next(rbn);

        /* Work functions that do not produce any work need not
         * be invoked again until the node changes shape.
         */
        sp3_node_remove(sp, spn, tx);
    }

    return false;
}

static void
sp3_qos_check(struct sp3 *sp)
{
    struct cn_tree *tree;
    uint rootmin, rootmax;
    u64 sval;

    if (!sp->throttle_sensor_root)
        return;

    rootmin = sp->thresh.rspill_kvsets_min;
    rootmax = rootmin;
    sval = 0;

    list_for_each_entry (tree, &sp->mon_tlist, ct_sched.sp3t.spt_tlink) {
        struct kvs_rparams *rp = cn_tree_get_rp(tree);
        uint nk = cn_ns_kvsets(&tree->ct_root->tn_ns);

        /* The root node length counts toward the throttle sensor value
         * only if cn maintenance mode is enabled.  Diminish the weight
         * of long, tiny root nodes on the throttle.
         */
        if (cn_ns_clen(&tree->ct_root->tn_ns) < (1ul << 30))
            nk /= 2;

        if (nk > rootmax && !rp->cn_maint_disable)
            rootmax = nk;
    }

    if (rootmax > rootmin) {
        u64 K;
        u64 r = (rootmax - rootmin) * 100;
        u64 nsec = atomic_read(&sp->rspill_dt) / NSEC_PER_SEC;
        u64 min_lat = 16, max_lat = 80;

        /* Since, the throttling system's sensitivty to sensor values over 1000 is non-linear, the
         * sensor value is not incremented at a high rate once it gets over 1000.
         *
         * The mathematical function used here is:
         *
         *   sval = 3KR / (K + R)
         *
         * where,
         *   K is a parameter in the range [500, 600], and
         *   R is the root node length times a hundred
         *
         * The parameter K is determined based on the latency of a root spill, i.e. it's an
         * indicator of the available media bandwidth. K determines the root node length for which
         * the sensor value surpasses 1000. Lower the value of K, higher is this root node length.
         *
         * This was tested for extremes of slow and fast drives and a latency range of 16s to 80s
         * worked well. Map a latency of [16s, 80s] to the range [500, 600]:
         *
         *   K = (100 * nsec / 64) + 475;
         */

        nsec = clamp_t(u64, nsec, min_lat, max_lat);
        K = ((100 * nsec) + (475 * 64)) / 64;
        sval = (K * r * 3) / (K + r);
    }

    throttle_sensor_set(sp->throttle_sensor_root, (uint)sval);

    if (debug_qos(sp) && jclock_ns > sp->qos_log_ttl) {
        sp->qos_log_ttl = jclock_ns + NSEC_PER_SEC;

        slog_info(
            HSE_SLOG_START("cn_qos_sensors"),
            HSE_SLOG_FIELD("root_sensor", "%lu", sval),
            HSE_SLOG_FIELD("root_maxlen", "%u", rootmax),
            HSE_SLOG_FIELD("samp_curr", "%.3f", scale2dbl(sp->samp_curr)),
            HSE_SLOG_FIELD("samp_targ", "%.3f", scale2dbl(sp->samp_targ)),
            HSE_SLOG_FIELD("lpct_targ", "%.3f", scale2dbl(sp->lpct_targ)),
            HSE_SLOG_END);
    }
}

/**
 * sp3_schedule() - try to schedule a single job
 */
static void
sp3_schedule(struct sp3 *sp)
{
    enum job_type {
        jtype_root,
        jtype_ispill,
        jtype_node_len,
        jtype_node_idle,
        jtype_leaf_garbage,
        jtype_leaf_size,
        jtype_leaf_scatter,
        jtype_MAX,
    };

    bool job = false;
    uint rp_leaf_pct;
    uint rr;

    /* This log message should never be emitted (unless someone has reduced
     * csched_qthreads at run time).  Scheduling of new jobs will resume
     * after a sufficient number of jobs complete.
     */
    if (sp->jobs_started - sp->jobs_finished > sp->jobs_max) {
        log_warn("possible job queue accounting bug (%u - %u > %u)",
                 sp->jobs_started, sp->jobs_finished, sp->jobs_max);
        usleep(NSEC_PER_SEC / 3);
        return;
    }

    /* convert rparam to internal scale */
    rp_leaf_pct = sp->inputs.csched_leaf_pct * SCALE / EXT_SCALE;

    for (rr = 0; !job && rr < jtype_MAX; rr++) {
        uint64_t thresh;
        uint qnum;

        /* round robin between job types */
        sp->rr_job_type++;
        if (sp->rr_job_type >= jtype_MAX)
            sp->rr_job_type = 0;

        switch (sp->rr_job_type) {
        case jtype_root:
            qnum = SP3_QNUM_ROOT;
            if (qfull(sp, qnum))
                break;

            /* Implements root node query-shape rule.
             * Uses "root" queue.
             */
            job = sp3_check_roots(sp, qnum);
            break;

        case jtype_ispill:
            qnum = SP3_QNUM_INTERN;
            if (qfull(sp, qnum)) {
                qnum = SP3_QNUM_SHARED;
                if (qfull(sp, qnum))
                    break;
            }

            thresh = (uint64_t)sp->thresh.ispill_pop_szgb << 32;
            if (sp->lpct_targ < rp_leaf_pct)
                thresh = 0;

            /* Service RBT_RI_ALEN red-black tree, which
             * contains both root and internal nodes and
             * keeps leaf_pct above configured value.
             * Implements:
             *   - Root node space amp rule
             *   - Internal node space amp rule
             */
            job = sp3_check_rb_tree(sp, RBT_RI_ALEN, thresh, wtype_ispill, qnum);
            break;

        case jtype_node_len:
            qnum = SP3_QNUM_NODELEN;
            if (qfull(sp, qnum))
                break;

            /* Service RBT_LI_LEN red-black tree.
             * Implements:
             *   - Internal node query-shape rule
             *   - Leaf node query-shape rule
             */
            job = sp3_check_rb_tree(sp, RBT_LI_LEN, 0, wtype_node_len, qnum);
            break;

        case jtype_node_idle:
            qnum = SP3_QNUM_SHARED;
            if (qfull(sp, qnum))
                break;

            /* Service RBT_LI_IDLE red-black tree.
             * Implements:
             *   - Idle node query-shape rule
             */
            if (sp->thresh.llen_idlec > 0) {
                thresh = (UINT32_MAX - (jclock_ns >> 32)) << 32;

                job = sp3_check_rb_tree(sp, RBT_LI_IDLE, thresh, wtype_node_idle, qnum);
            }
            break;

        case jtype_leaf_garbage:
            qnum = SP3_QNUM_LGARB;
            if (qfull(sp, qnum)) {
                qnum = SP3_QNUM_SHARED;
                if (qfull(sp, qnum))
                    break;
            }

            /* Service RBT_L_GARB red-black tree.
             * Implements:
             *   - Leaf node space amp rule
             * Notes:
             *   - Don't check for garbage unless ucomp is active
             *     or if in samp_reduce mode and leaf percent is
             *     somewhat caught up (ie, current leaf pct
             *     (lpct_targ) is within 90% of rparam setting
             *     (rp_leaf_pct)).
             *   - When checking for garbage, if leaf percent is
             *     behind, then bump up threshold so we don't waste
             *     write amp by compacting nodes with a small
             *     amount of garbage (we'd rather wait for
             *     leaf_pct to catch up).
             */
            if (sp->samp_reduce && (100 * sp->lpct_targ > 90 * rp_leaf_pct)) {
                thresh = (sp->lpct_targ < rp_leaf_pct ? 10ul : 0ul) << 32;

                job = sp3_check_rb_tree(sp, RBT_L_GARB, thresh, wtype_leaf_garbage, qnum);
            }
            break;

        case jtype_leaf_size:
            qnum = SP3_QNUM_LSIZE;
            if (qfull(sp, qnum)) {
                qnum = SP3_QNUM_SHARED;
                if (qfull(sp, qnum))
                    break;
            }

            /* Service RBT_L_PCAP red-black tree.
             * - Handles big leaf nodes with or with out garbage.
             * Implements:
             *   - Leaf node size rule
             */
            job = sp3_check_rb_tree(sp, RBT_L_PCAP, 0, wtype_leaf_size, qnum);
            break;

        case jtype_leaf_scatter:
            qnum = SP3_QNUM_SHARED;
            if (qfull(sp, qnum))
                break;

            /* Implements:
             *   - Leaf node scatter rule
             */
            if (sp->thresh.lscatter_pct < 100) {
                thresh = (UINT32_MAX - (jclock_ns >> 32)) << 32;

                job = sp3_check_rb_tree(sp, RBT_L_SCAT, thresh, wtype_leaf_scatter, qnum);
            }
            break;
        }
    }
}

/*
 * sp3_update_samp() - update internal space amp metrics
 *
 * Updates the following members of struct sp3:
 *
 *  sp->samp_curr
 *  sp->samp_targ
 *  sp->lpct_targ
 *  sp->lpct_throttle
 *  sp->samp_reduce
 *  sp->ucomp_*
 */
static void
sp3_update_samp(struct sp3 *sp)
{
    struct cn_samp_stats targ;

    sp3_samp_target(sp, &targ);
    sp->samp_targ = samp_est(&targ, SCALE);
    sp->lpct_targ = samp_pct_leaves(&targ, SCALE);

    sp->samp_curr = samp_est(&sp->samp, SCALE);

    perfc_set(&sp->sched_pc, PERFC_BA_SP3_SAMP, sp->samp_targ);
    perfc_set(&sp->sched_pc, PERFC_BA_SP3_REDUCE, sp->samp_reduce);

    sp3_ucomp_check(sp);

    /* Use low/high water marks to enable/disable garbage collection. */
    if (sp->samp_reduce) {
        if (sp->samp_targ < sp->samp_lwm) {
            sp->samp_reduce = false;
            log_info("sp3 expected samp %u below lwm %u, disable samp reduction",
                     sp->samp_targ * 100 / SCALE,
                     sp->samp_lwm * 100 / SCALE);
        }
    } else {
        if (sp->samp_targ > sp->samp_hwm) {
            sp->samp_reduce = true;
            log_info("sp3 expected samp %u above hwm %u, enable samp reduction",
                     sp->samp_targ * 100 / SCALE,
                     sp->samp_hwm * 100 / SCALE);
        }
    }
}

struct periodic_check {
    u64 interval;
    u64 next;
    u64 prev;
};

static void
sp3_monitor(struct work_struct *work)
{
    struct sp3 *sp = container_of(work, struct sp3, mon_work);

    struct periodic_check chk_qos     = { .interval = NSEC_PER_SEC / 3 };
    struct periodic_check chk_refresh = { .interval = NSEC_PER_SEC * 10 };
    struct periodic_check chk_shape   = { .interval = NSEC_PER_SEC * 15 };

    bool bad_health = false;
    u64 last_activity = 0;

    sp3_refresh_settings(sp);

    while (atomic_read(&sp->running)) {
        uint64_t now = get_time_ns();
        merr_t err;

        mutex_lock(&sp->mon_lock);
        if (!sp->mon_signaled && now < chk_qos.next) {
            int timeout_ms = max_t(int, 10, (chk_qos.next - now) / USEC_PER_SEC);

            cv_timedwait(&sp->mon_cv, &sp->mon_lock, timeout_ms);

            now = get_time_ns();
        }
        sp->mon_signaled = false;
        mutex_unlock(&sp->mon_lock);

        /* The following "process and prune" functions will increment
         * sp->activity to trigger a call (below) to sp3_schedule().
         */
        sp->activity = 0;
        sp3_process_worklist(sp);
        sp3_process_ingest(sp);
        sp3_process_new_trees(sp);
        sp3_prune_trees(sp);

        sp3_update_samp(sp);

        err = kvdb_health_check(sp->health, KVDB_HEALTH_FLAG_ALL);
        if (ev(err)) {
            if (!bad_health)
                log_errx("KVDB %s is in bad health; @@e", err, sp->name);

            bad_health = true;
        }

        if (sp->activity) {
            last_activity = now + NSEC_PER_SEC * 5;
            sp->activity = 0;

            if (!bad_health)
                sp3_schedule(sp);
        }

        if (now > chk_refresh.next) {
            sp3_refresh_settings(sp);
            chk_refresh.next = now + chk_refresh.interval;
        }

        if (now > chk_qos.next) {
            sp3_qos_check(sp);
            chk_qos.next = now + chk_qos.interval;
        }

        if (now > chk_shape.next) {
            sp3_tree_shape_check(sp);
            if (debug_rbtree(sp)) {
                for (uint tx = 0; tx < RBT_MAX; tx++)
                    sp3_rb_dump(sp, tx, 25);
            }
            chk_shape.next = now + chk_shape.interval;
        }

        sp->idle = now > last_activity && sp->jobs_started == sp->jobs_finished;
    }
}

/*****************************************************************
 *
 * External Entry Points
 *
 ****************************************************************/

void
sp3_throttle_sensor(struct csched *handle, struct throttle_sensor *sensor)
{
    struct sp3 *sp = (struct sp3 *)handle;

    if (!sp)
        return;

    sp->throttle_sensor_root = sensor;
}

void
sp3_compact_request(struct csched *handle, int flags)
{
    struct sp3 *sp = (struct sp3 *)handle;

    if (!sp)
        return;

    if (flags & HSE_KVDB_COMPACT_CANCEL) {
        sp3_ucomp_cancel(sp);
    } else if (flags & HSE_KVDB_COMPACT_SAMP_LWM) {
        sp3_ucomp_start(sp);
    } else {
        log_info("invalid user-initiated compaction request: flags 0x%x", flags);
    }
}

void
sp3_compact_status_get(struct csched *handle, struct hse_kvdb_compact_status *status)
{
    struct sp3 *sp = (struct sp3 *)handle;

    if (!sp)
        return;

    status->kvcs_active = sp->ucomp_active;
    status->kvcs_canceled = sp->ucomp_canceled;
    status->kvcs_samp_curr = samp_est(&sp->samp, 100);
    status->kvcs_samp_lwm = sp->samp_lwm * 100 / SCALE;
    status->kvcs_samp_hwm = sp->samp_hwm * 100 / SCALE;
}

/**
 * sp3_notify_ingest() - External API: notify ingest job has completed
 */
void
sp3_notify_ingest(struct csched *handle, struct cn_tree *tree, size_t alen, size_t wlen)
{
    struct sp3 *sp = (struct sp3 *)handle;
    struct sp3_tree *spt = tree2spt(tree);

    if (!sp)
        return;

    atomic_add(&spt->spt_ingest_alen, alen);
    atomic_add(&spt->spt_ingest_wlen, wlen);
    atomic_inc_rel(&sp->sp_ingest_count);

    sp3_monitor_wake(sp);
}

static void
sp3_tree_init(struct sp3_tree *spt)
{
    memset(spt, 0, sizeof(*spt));
    atomic_set(&spt->spt_enabled, 1);
    INIT_LIST_HEAD(&spt->spt_tlink);
}

/**
 * sp3_tree_add() - External API: add tree to scheduler
 */
void
sp3_tree_add(struct csched *handle, struct cn_tree *tree)
{
    struct sp3 *sp = (struct sp3 *)handle;
    struct sp3_tree *spt = tree2spt(tree);

    if (!sp)
        return;

    assert(!sp3_tree_is_managed(tree));

    if (debug_tree_life(sp))
        log_info("sp3 %s cnid %lu", __func__, (ulong)tree->cnid);

    cn_ref_get(tree->cn);

    sp3_tree_init(spt);

    mutex_lock(&sp->new_tlist_lock);
    list_add(&spt->spt_tlink, &sp->new_tlist);
    mutex_unlock(&sp->new_tlist_lock);

    sp3_monitor_wake(sp);
}

/**
 * sp3_tree_remove() - External API: remove tree from scheduler
 */
void
sp3_tree_remove(struct csched *handle, struct cn_tree *tree, bool cancel)
{
    struct sp3 *sp = (struct sp3 *)handle;
    struct sp3_tree *spt = tree2spt(tree);

    if (!sp || !sp3_tree_is_managed(tree))
        return;

    if (debug_tree_life(sp))
        log_info("sp3 %s cnid %lu", __func__, (ulong)tree->cnid);

    /* Disable scheduling for tree.  Monitor will remove the tree
     * out when no more jobs are pending.
     */
    atomic_set(&spt->spt_enabled, 0);
    atomic_inc_rel(&sp->sp_prune_count);

    sp3_monitor_wake(sp);
}

/**
 * sp3_destroy() - External API: SP3 destructor
 */
void
sp3_destroy(struct csched *handle)
{
    struct sp3 *sp = (struct sp3 *)handle;
    uint        tx;

    if (!sp)
        return;

    /* Destroy shouldn't be invoked until all cn trees been removed and
     * all cn refs have been returned wih cn_ref_put.  If that is true
     * then we should have empty lists, rb trees, job counts, etc.
     */
    assert(list_empty(&sp->new_tlist));
    assert(list_empty(&sp->mon_tlist));
    assert(list_empty(&sp->work_list));

    for (tx = 0; tx < RBT_MAX; tx++)
        assert(!rb_first(sp->rbt + tx));

    atomic_set(&sp->running, 0);
    sp3_monitor_wake(sp);

    /* This is like a pthread_join for the monitor thread */
    destroy_workqueue(sp->mon_wq);

    sts_destroy(sp->sts);

    mutex_destroy(&sp->work_list_lock);
    mutex_destroy(&sp->new_tlist_lock);
    mutex_destroy(&sp->mon_lock);
    cv_destroy(&sp->mon_cv);

    perfc_free(&sp->sched_pc);
    free(sp->wp);
    free(sp);
}

/**
 * sp3_create() - External API: constructor
 */
merr_t
sp3_create(
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         kvdb_alias,
    struct kvdb_health * health,
    struct csched      **handle)
{
    const char *restname = "csched";
    char group[128];
    struct sp3 *sp;
    merr_t      err;
    size_t      name_sz, alloc_sz;
    uint        tx;

    INVARIANT(rp && kvdb_alias && handle);

    /* Allocate cache aligned space for struct csched + sp->name */
    name_sz = strlen(restname) + strlen(kvdb_alias) + 2;
    alloc_sz = sizeof(*sp) + name_sz;
    alloc_sz = roundup(alloc_sz, alignof(*sp));

    sp = aligned_alloc(alignof(*sp), alloc_sz);
    if (ev(!sp))
        return merr(ENOMEM);

    memset(sp, 0, alloc_sz);
    sp->ds = ds;
    snprintf(sp->name, name_sz, "%s/%s", restname, kvdb_alias);

    sp->rp = rp;
    sp->health = health;

    mutex_init(&sp->new_tlist_lock);
    mutex_init(&sp->work_list_lock);

    mutex_init(&sp->mon_lock);
    cv_init(&sp->mon_cv, "csched");

    INIT_LIST_HEAD(&sp->mon_tlist);
    INIT_LIST_HEAD(&sp->new_tlist);
    INIT_LIST_HEAD(&sp->work_list);
    INIT_LIST_HEAD(&sp->spn_alist);
    INIT_LIST_HEAD(&sp->spn_rlist);

    for (tx = 0; tx < RBT_MAX; tx++)
        sp->rbt[tx] = RB_ROOT;

    atomic_set(&sp->running, 1);
    atomic_set(&sp->sp_ingest_count, 0);
    atomic_set(&sp->sp_prune_count, 0);

    err = sts_create(sp->name, SP3_QNUM_MAX, sp3_job_print, &sp->sts);
    if (ev(err))
        goto err_exit;

    sp->mon_wq = alloc_workqueue("hse_sp3_monitor", 0, 1, 1);
    if (ev(!sp->mon_wq)) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    snprintf(group, sizeof(group), "kvdb/%s", sp->name);

    perfc_alloc(csched_sp3_perfc, group, "sp3", rp->perfc_level, &sp->sched_pc);

    INIT_WORK(&sp->mon_work, sp3_monitor);
    queue_work(sp->mon_wq, &sp->mon_work);

    slog_info(
        HSE_SLOG_START("cn_threads"),
        HSE_SLOG_FIELD("root", "%u", qthreads(sp, SP3_QNUM_ROOT)),
        HSE_SLOG_FIELD("intern", "%u", qthreads(sp, SP3_QNUM_INTERN)),
        HSE_SLOG_FIELD("nodelen", "%u", qthreads(sp, SP3_QNUM_NODELEN)),
        HSE_SLOG_FIELD("leafgarb", "%u", qthreads(sp, SP3_QNUM_LGARB)),
        HSE_SLOG_FIELD("leafsize", "%u", qthreads(sp, SP3_QNUM_LSIZE)),
        HSE_SLOG_FIELD("shared", "%u", qthreads(sp, SP3_QNUM_SHARED)),
        HSE_SLOG_END);

    *handle = (void *)sp;
    return 0;

err_exit:
    sts_destroy(sp->sts);

    mutex_destroy(&sp->work_list_lock);
    mutex_destroy(&sp->new_tlist_lock);
    mutex_destroy(&sp->mon_lock);
    cv_destroy(&sp->mon_cv);

    free(sp);

    return err;
}

#if HSE_MOCKING
#include "csched_sp3_ut_impl.i"
#endif /* HSE_MOCKING */
