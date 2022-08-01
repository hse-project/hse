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

    struct rb_root rbt[wtype_MAX - 1] HSE_L1D_ALIGNED;

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
    uint             rr_wtype;
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
#define debug_tree_life(_sp)   (csched_rp_dbg_tree_life((_sp)->rp))
#define debug_dirty_node(_sp)  (csched_rp_dbg_dirty_node((_sp)->rp))
#define debug_sched(_sp)       (csched_rp_dbg_sched((_sp)->rp))
#define debug_qos(_sp)         (csched_rp_dbg_qos((_sp)->rp))
#define debug_rbtree(_sp)      (csched_rp_dbg_rbtree((_sp)->rp))
#define debug_tree_shape(_sp)  (csched_rp_dbg_tree_shape((_sp)->rp))

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
samp_pct_garbage(struct cn_samp_stats *s, uint scale)
{
    assert(s->l_alen >= s->l_good);

    return scale * safe_div(s->l_alen - s->l_good, s->l_alen);
}

static void
sp3_node_init(struct sp3 *sp, struct sp3_node *spn)
{
    spn->spn_initialized = true;
    spn->spn_cgen = UINT_MAX;

    for (uint tx = 0; tx < NELEM(spn->spn_rbe); tx++)
        RB_CLEAR_NODE(&spn->spn_rbe[tx].rbe_node);

    INIT_LIST_HEAD(&spn->spn_rlink);
    INIT_LIST_HEAD(&spn->spn_alink);

    /* Append to list of all nodes from all managed trees.
     */
    list_add_tail(&spn->spn_alink, &sp->spn_alist);
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
        SLOG_START("cn_comp_stats"),
        SLOG_FIELD("type", "%s", msg_type),
        SLOG_FIELD("job", "%u", w->cw_job.sj_id),
        SLOG_FIELD("comp", "%s", cn_action2str(w->cw_action)),
        SLOG_FIELD("rule", "%s", cn_rule2str(w->cw_rule)),
        SLOG_FIELD("cnid", "%lu", w->cw_tree->cnid),
        SLOG_FIELD("nodeid", "%lu", w->cw_node->tn_nodeid),
        SLOG_FIELD("leaf", "%u", (uint)cn_node_isleaf(w->cw_node)),
        SLOG_FIELD("pct", "%3.1f", 100 * progress),
        SLOG_FIELD("vrd_eff", "%.3f", vblk_read_efficiency),

        SLOG_FIELD("kblk_alloc_ops", "%ld", ms->ms_kblk_alloc.op_cnt),
        SLOG_FIELD("kblk_alloc_sz", "%ld", ms->ms_kblk_alloc.op_size),
        SLOG_FIELD("kblk_alloc_ns", "%ld", ms->ms_kblk_alloc.op_time),

        SLOG_FIELD("kblk_write_ops", "%ld", ms->ms_kblk_write.op_cnt),
        SLOG_FIELD("kblk_write_sz", "%ld", ms->ms_kblk_write.op_size),
        SLOG_FIELD("kblk_write_ns", "%ld", ms->ms_kblk_write.op_time),

        SLOG_FIELD("vblk_alloc_ops", "%ld", ms->ms_vblk_alloc.op_cnt),
        SLOG_FIELD("vblk_alloc_sz", "%ld", ms->ms_vblk_alloc.op_size),
        SLOG_FIELD("vblk_alloc_ns", "%ld", ms->ms_vblk_alloc.op_time),

        SLOG_FIELD("vblk_write_ops", "%ld", ms->ms_vblk_write.op_cnt),
        SLOG_FIELD("vblk_write_sz", "%ld", ms->ms_vblk_write.op_size),
        SLOG_FIELD("vblk_write_ns", "%ld", ms->ms_vblk_write.op_time),

        SLOG_FIELD("vblk_read1_ops", "%ld", ms->ms_vblk_read1.op_cnt),
        SLOG_FIELD("vblk_read1_sz", "%ld", ms->ms_vblk_read1.op_size),
        SLOG_FIELD("vblk_read1_ns", "%ld", ms->ms_vblk_read1.op_time),

        SLOG_FIELD("vblk_read1wait_ops", "%ld", ms->ms_vblk_read1_wait.op_cnt),
        SLOG_FIELD("vblk_read1wait_ns", "%ld", ms->ms_vblk_read1_wait.op_time),

        SLOG_FIELD("vblk_read2_ops", "%ld", ms->ms_vblk_read2.op_cnt),
        SLOG_FIELD("vblk_read2_sz", "%ld", ms->ms_vblk_read2.op_size),
        SLOG_FIELD("vblk_read2_ns", "%ld", ms->ms_vblk_read2.op_time),

        SLOG_FIELD("vblk_read2wait_ops", "%ld", ms->ms_vblk_read2_wait.op_cnt),
        SLOG_FIELD("vblk_read2wait_ns", "%ld", ms->ms_vblk_read2_wait.op_time),

        SLOG_FIELD("kblk_read_ops", "%ld", ms->ms_kblk_read.op_cnt),
        SLOG_FIELD("kblk_read_sz", "%ld", ms->ms_kblk_read.op_size),
        SLOG_FIELD("kblk_read_ns", "%ld", ms->ms_kblk_read.op_time),

        SLOG_FIELD("kblk_readwait_ops", "%ld", ms->ms_kblk_read_wait.op_cnt),
        SLOG_FIELD("kblk_readwait_ns", "%ld", ms->ms_kblk_read_wait.op_time),

        SLOG_FIELD("vblk_dbl_reads", "%ld", ms->ms_vblk_wasted_reads),

        SLOG_FIELD("queue_us", "%lu", qt),
        SLOG_FIELD("prep_us", "%lu", pt),
        SLOG_FIELD("merge_us", "%lu", bt),
        SLOG_FIELD("commit_us", "%lu", ct),
        SLOG_END);
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

static void
sp3_refresh_thresholds(struct sp3 *sp)
{
    struct sp3_thresholds thresh = {};
    struct sp3_node *spn;
    uint64_t v;

    /* root node spill settings */
    v = sp->rp->csched_rspill_params;
    if (v) {
        thresh.rspill_runlen_max = (v >> 0) & 0xff;
        thresh.rspill_runlen_min = (v >> 8) & 0xff;
        thresh.rspill_sizemb_max = (v >> 16) & 0xffff;
    } else {
        thresh.rspill_runlen_max = SP3_RSPILL_RUNLEN_MAX_DEFAULT;
        thresh.rspill_runlen_min = SP3_RSPILL_RUNLEN_MIN_DEFAULT;
        thresh.rspill_sizemb_max = SP3_RSPILL_SIZEMB_MAX_DEFAULT;
    }

    thresh.rspill_runlen_max = clamp_t(uint8_t, thresh.rspill_runlen_max,
                                       SP3_RSPILL_RUNLEN_MIN, SP3_RSPILL_RUNLEN_MAX);

    thresh.rspill_runlen_min = clamp_t(uint8_t, thresh.rspill_runlen_min,
                                       SP3_RSPILL_RUNLEN_MIN, thresh.rspill_runlen_max);

    thresh.rspill_sizemb_max = clamp_t(uint16_t, thresh.rspill_sizemb_max,
                                       SP3_RSPILL_SIZEMB_MIN, SP3_RSPILL_SIZEMB_MAX);

    /* leaf node compaction settings */
    v = sp->rp->csched_leaf_comp_params;
    if (v) {
        thresh.lcomp_runlen_max = (v >> 0) & 0xff;
        thresh.lcomp_split_pct = (v >> 16) & 0xff;
        thresh.lcomp_split_keys = (v >> 24) & 0xff;
    } else {
        thresh.lcomp_runlen_max = SP3_LCOMP_RUNLEN_MAX;
        thresh.lcomp_split_pct = SP3_LCOMP_SPLIT_PCT;
        thresh.lcomp_split_keys = SP3_LCOMP_SPLIT_KEYS; /* units of 4 million */
    }

    /* leaf node length settings */
    v = sp->rp->csched_leaf_len_params;
    if (v) {
        thresh.llen_runlen_max = (v >> 0) & 0xff;
        thresh.llen_runlen_min = (v >> 8) & 0xff;
        thresh.llen_idlec = (v >> 24) & 0xff;
        thresh.llen_idlem = (v >> 32) & 0xff;
    } else {
        thresh.llen_runlen_max = SP3_LLEN_RUNLEN_MAX_DEFAULT;
        thresh.llen_runlen_min = SP3_LLEN_RUNLEN_MIN_DEFAULT;
        thresh.llen_idlec = SP3_LLEN_IDLEC_DEFAULT;
        thresh.llen_idlem = SP3_LLEN_IDLEM_DEFAULT;
    }

    thresh.llen_runlen_max = clamp_t(uint8_t, thresh.llen_runlen_max,
                                     SP3_LLEN_RUNLEN_MIN, SP3_LLEN_RUNLEN_MAX);

    thresh.llen_runlen_min = clamp_t(uint8_t, thresh.llen_runlen_min,
                                     SP3_LLEN_RUNLEN_MIN, thresh.llen_runlen_max);

    /* vgroup leaf-scatter remediation settings
     */
    thresh.lscat_runlen_max = sp->rp->csched_lscat_runlen_max;
    thresh.lscat_hwm = sp->rp->csched_lscat_hwm;

    /* If thresholds have not changed there's nothing to do.  Otherwise, need to
     * recompute work trees.
     */
    if (!memcmp(&thresh, &sp->thresh, sizeof(thresh)))
        return;

    sp->thresh = thresh;

    list_for_each_entry(spn, &sp->spn_alist, spn_alink) {
        sp3_dirty_node(sp, spn2tn(spn));
    }

    log_info("sp3 thresholds: rspill: min/max/sizemb %u/%u/%u, lcomp: max/pct/keys %u/%u%%/%u,"
             " llen: min/max %u/%u, idlec: %u, idlem: %u, lscat: hwm/max %u/%u",
             thresh.rspill_runlen_min, thresh.rspill_runlen_max, thresh.rspill_sizemb_max,
             thresh.lcomp_runlen_max, thresh.lcomp_split_pct,
             thresh.lcomp_split_keys, thresh.llen_runlen_min, thresh.llen_runlen_max,
             thresh.llen_idlec, thresh.llen_idlem,
             thresh.lscat_hwm, thresh.lscat_runlen_max);
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

    assert(tx < NELEM(spn->spn_rbe));

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

    for (tx = 0; tx < NELEM(spn->spn_rbe); tx++)
        sp3_rb_erase(sp->rbt + tx, spn->spn_rbe + tx);
}

/* Remove all nodes from all rb trees that belong to given cn_tree */
static void
sp3_unlink_all_nodes(struct sp3 *sp, struct cn_tree *tree)
{
    struct cn_tree_node *tn;

    cn_tree_foreach_node(tn, tree) {
        struct sp3_node *spn = tn2spn(tn);

        sp3_node_unlink(sp, spn);

        list_del_init(&spn->spn_rlink);
        list_del_init(&spn->spn_alink);
    }
}

static void
sp3_dirty_node_locked(struct sp3 *sp, struct cn_tree_node *tn)
{
    struct sp3_node *spn = tn2spn(tn);
    uint64_t nkvsets_total, nkvsets;
    uint garbage = 0, jobs;
    uint scatter = 0;

    /* Skip if node hasn't changed since last time we inserted
     * it into the work trees.
     */
    if (spn->spn_cgen == tn->tn_cgen)
        return;

    spn->spn_cgen = tn->tn_cgen;

    jobs = atomic_read_acq(&tn->tn_busycnt);

    nkvsets_total = cn_ns_kvsets(&tn->tn_ns);
    nkvsets = nkvsets_total - (jobs & 0xffffu);
    jobs >>= 16;

    /* We disallow scheduling more than one job of any given type on
     * any given leaf node (technically we could schedule more, but
     * the effects have proven deleterious in practice).
     *
     * Similarly, we never schedule more than three jobs on any given
     * root node (see CSCHED_QTHREADS_DEFAULT for default limits).
     */
    if (cn_node_isleaf(tn)) {
        const uint64_t nkeys = cn_ns_keys(&tn->tn_ns);

        scatter = cn_tree_node_scatter(tn);

        /* Leaf nodes sorted by number of kvsets.
         * We use inverse scatter as a secondary discriminant so as to
         * prefer scatter jobs over kcompactions when scatter is high.
         */
        if (nkvsets >= sp->thresh.llen_runlen_min && jobs < 1) {
            const uint64_t weight = (nkvsets << 32) | (UINT32_MAX - scatter);

            sp3_node_insert(sp, spn, wtype_length, weight);
        } else {
            sp3_node_remove(sp, spn, wtype_length);
        }

        garbage = samp_pct_garbage(&tn->tn_samp, 100);

        /* Leaf nodes sorted by pct garbage.
         * Range: 0 <= rbe_weight <= 100.  If rbe_weight == 3, then
         * node has 3% garbage.
         * We use alen as the secondary discriminant to prefer nodes
         * with higher total bytes of garbage.
         *
         * TODO: The garbage caculation needs help:  It sometimes returns
         * a non-zero result for nodes consisting entirely of unique keys.
         */
        if (garbage > 0 && nkvsets > 1 && jobs < 1) {
            const uint64_t weight = ((uint64_t)garbage << 32) | (cn_ns_alen(&tn->tn_ns) >> 20);

            sp3_node_insert(sp, spn, wtype_garbage, weight);
        } else {
            sp3_node_remove(sp, spn, wtype_garbage);
        }

        /* Leaf nodes sorted by vgroup scatter and garbage.
         */
        if (scatter > 0 && jobs < 1) {
            const uint64_t weight = ((uint64_t)scatter << 32) | garbage;

            sp3_node_insert(sp, spn, wtype_scatter, weight);
        } else {
            sp3_node_remove(sp, spn, wtype_scatter);
        }

        /* Leaf nodes sorted by pct capacity and secondarily by
         * number of keys.  If the node's size doesn't exceed the "split_pct"
         * threshold then we check to see if the number of keys exceeds the
         * "split_keys" threshold.  If so, we insert this node into the tree
         * with "split_pct" capacity to ensure it gets split or compacted.
         */
        if (tn->tn_ns.ns_pcap >= sp->thresh.lcomp_split_pct && jobs < 1) {
            const uint64_t weight = ((uint64_t)tn->tn_ns.ns_pcap << 32) | nkeys;

            sp3_node_insert(sp, spn, wtype_split, weight);
            ev_debug(1);
        } else {
            uint64_t split_keys = (uint64_t)sp->thresh.lcomp_split_keys << 22;
            uint64_t keys_uniq = cn_ns_keys_uniq(&tn->tn_ns);

            if (keys_uniq > split_keys && jobs < 1) {
                const uint64_t weight = ((uint64_t)sp->thresh.lcomp_split_pct << 32) | keys_uniq;

                sp3_node_insert(sp, spn, wtype_split, weight);
                ev_debug(1);
            } else {
                sp3_node_remove(sp, spn, wtype_split);
            }
        }
    } else {

        /* If this root node is ready to spill then ensure it's on the list
         * in FIFO order, retaining its current position if it's already on
         * the list.  List order is otherwise managed by sp3_check_roots().
         */
        if (nkvsets >= sp->thresh.rspill_runlen_min && jobs < 3) {
            if (list_empty(&spn->spn_rlink))
                list_add_tail(&spn->spn_rlink, &sp->spn_rlist);
        } else {
            list_del_init(&spn->spn_rlink);
        }
    }

    /* Nodes sorted by idle check expiration time.
     * Time is a negative offset in 4-second intervals from
     * UINT32_MAX in order to work correctly with the rb-tree
     * weight comparator logic.
     */
    if (nkvsets >= sp->thresh.llen_idlec && sp->thresh.llen_idlem > 0 && jobs < 1) {
        const uint64_t ttl = (sp->thresh.llen_idlem * 60) / 4;
        uint64_t weight = UINT32_MAX - (jclock_ns >> 32) - ttl;

        weight = (weight << 32) | nkvsets;

        sp3_node_insert(sp, spn, wtype_idle, weight);
    } else {
        sp3_node_remove(sp, spn, wtype_idle);
    }

    if (debug_dirty_node(sp)) {
        slog_info(
            SLOG_START("cn_dirty_node"),
            SLOG_FIELD("cnid", "%lu", (ulong)tn->tn_tree->cnid),
            SLOG_FIELD("nodeid", "%-2lu", (ulong)tn->tn_nodeid),
            SLOG_FIELD("kvsets", "%-2lu", (ulong)nkvsets_total),
            SLOG_FIELD("keys", "%lu", (ulong)cn_ns_keys(&tn->tn_ns)),
            SLOG_FIELD("uniq", "%lu", (ulong)cn_ns_keys_uniq(&tn->tn_ns)),
            SLOG_FIELD("tombs", "%lu", (ulong)cn_ns_tombs(&tn->tn_ns)),
            SLOG_FIELD("alen", "%lu", (ulong)cn_ns_alen(&tn->tn_ns)),
            SLOG_FIELD("clen", "%lu", (ulong)cn_ns_clen(&tn->tn_ns)),
            SLOG_FIELD("garbage", "%u", garbage),
            SLOG_FIELD("scatter", "%u", scatter),
            SLOG_END);
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
    struct cn_tree *tree = w->cw_tree;
    struct sp3_tree *spt = tree2spt(tree);
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

    sp->samp.r_alen += diff.r_alen;
    sp->samp.r_wlen += diff.r_wlen;
    sp->samp.i_alen += diff.i_alen;
    sp->samp.l_alen += diff.l_alen;
    sp->samp.l_good += diff.l_good;

    sp->samp_wip.i_alen -= w->cw_est.cwe_samp.i_alen;
    sp->samp_wip.l_alen -= w->cw_est.cwe_samp.l_alen;
    sp->samp_wip.l_good -= w->cw_est.cwe_samp.l_good;

    rmlock_rlock(&tree->ct_lock, &lock);

    /* Verify that the action didn't dislodge the root node
     * from the head of the nodes list.
     */
    assert(tree->ct_root == list_first_entry(&tree->ct_nodes, typeof(*tn), tn_link));

    if (w->cw_action == CN_ACTION_SPILL) {
        struct cn_tree_node *leaf;

        assert(tn == tree->ct_root);

        cn_tree_foreach_leaf(leaf, tree) {
            sp3_dirty_node_locked(sp, leaf);
        }
    }

    if (w->cw_action == CN_ACTION_SPLIT) {
        for (int i = 0; i < 2; i++) {
            struct cn_tree_node *node = w->cw_split.nodev[i];

            if (node) {
                struct sp3_node *spn = tn2spn(node);

                if (!spn->spn_initialized)
                    sp3_node_init(sp, spn);

                sp3_dirty_node_locked(sp, node);
            }
        }
    } else {
        sp3_dirty_node_locked(sp, tn);
    }
    rmlock_runlock(lock);

    if (w->cw_debug & (CW_DEBUG_PROGRESS | CW_DEBUG_FINAL))
        sp3_log_progress(w, &w->cw_stats, true);

    if (cn_node_isroot(tn)) {
        u64 dt;

        /* Maintain an average of the root spill's build time - used for throttling.
         */
        dt = w->cw_t3_build - w->cw_t2_prep;
        sp->rspill_dt_prev = (dt + sp->rspill_dt_prev) / 2;
        atomic_set(&sp->rspill_dt, sp->rspill_dt_prev);
    }

    sts_job_done(&w->cw_job);
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
        void *lock;

        if (debug_tree_life(sp))
            log_info("sp3 acquire tree cnid %lu", (ulong)tree->cnid);

        rmlock_rlock(&tree->ct_lock, &lock);
        cn_tree_foreach_node(tn, tree) {
            sp3_node_init(sp, tn2spn(tn));
            sp3_dirty_node_locked(sp, tn);
        }
        rmlock_runlock(lock);

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

static void
sp3_comp_thread_name(
    char *              buf,
    size_t              bufsz,
    enum cn_action      action,
    enum cn_rule        rule,
    uint64_t            nodeid)
{
    const char *a = "XX";
    const char *r = "XX";

    switch (action) {
    case CN_ACTION_NONE:
        a = "no";
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

    case CN_ACTION_SPLIT:
        a = "s2";
        break;
    }

    switch (rule) {
    case CN_RULE_NONE:
        r = "xx";
        break;
    case CN_RULE_INGEST:
        r = "s0";
        break;
    case CN_RULE_RSPILL:
        r = "sr";
        break;
    case CN_RULE_TSPILL:
        r = "st";
        break;
    case CN_RULE_ZSPILL:
        r = "sz";
        break;
    case CN_RULE_SPLIT:
        r = "s2";
        break;
    case CN_RULE_GARBAGE:
        r = "gb";
        break;
    case CN_RULE_LENGTHK:
        r = "lk";
        break;
    case CN_RULE_LENGTHV:
        r = "lv";
        break;
    case CN_RULE_INDEXF:
        r = "fi";
        break;
    case CN_RULE_INDEXP:
        r = "pi";
        break;
    case CN_RULE_IDLE_INDEX:
        r = "ii";
        break;
    case CN_RULE_IDLE_SIZE:
        r = "is";
        break;
    case CN_RULE_IDLE_TOMB:
        r = "it";
        break;
    case CN_RULE_SCATTERF:
        r = "fs";
        break;
    case CN_RULE_SCATTERP:
        r = "ps";
        break;
    }

    snprintf(buf, bufsz, "hse_%s_%s_%lu", a, r, nodeid);
}

/* This function is the sts job-print callback which is invoked
 * with the sts run-queue lock held and hence must not block.
 * priv is a pointer to a 64-byte block for our private use,
 * zeroed before the first call.  job is set to NULL on the
 * last call to allow us to clean up any lingering state.
 */
static int
sp3_job_print(struct sts_job *job, void *priv, char *buf, size_t bufsz)
{
    struct cn_compaction_work *w = container_of(job, typeof(*w), cw_job);
    struct job_print_state {
        int jobwidth;
        bool hdr;
    } *jps = priv;
    int n = 0, m = 0;
    char tmbuf[32];
    ulong tm;

    if (!job) {
        return (jps->hdr) ? snprintf(buf, bufsz, "\n") : 0;
    }

    if (!jps->hdr) {
        jps->jobwidth = snprintf(NULL, 0, "%4u", sts_job_id_get(&w->cw_job) * 10);

        n = snprintf(buf, bufsz,
                     "%3s %5s %*s %7s %-7s"
                     " %2s %1s %5s %6s %6s %4s"
                     " %4s %5s %3s %3s %4s"
                     " %6s %6s %6s %6s"
                     " %8s %4s %s\n",
                     "ID", "NODE", jps->jobwidth, "JOB", "ACTION", "RULE",
                     "Q", "T", "KVSET", "ALEN", "CLEN", "PCAP",
                     "CC", "DGEN", "NH", "NK", "NV",
                     "RALEN", "IALEN", "LALEN", "LGOOD",
                     "WMESG", "TIME", "TNAME");

        if (n < 1 || n >= bufsz)
            return n;

        jps->hdr = true;
        bufsz -= n;
        buf += n;
    }

    tm = (jclock_ns - w->cw_t0_enqueue) / NSEC_PER_SEC;
    snprintf(tmbuf, sizeof(tmbuf), "%lu:%02lu", (tm / 60) % 60, tm % 60);

    m = snprintf(buf, bufsz,
                 "%3lu %5lu %*u %7s %-7s"
                 " %2u %1u %2u,%-2u %6lu %6lu %4u"
                 " %4u %5lu %3u %3u %4u"
                 " %6ld %6ld %6ld %6ld"
                 " %8.8s %4s %s\n",
                 w->cw_tree->cnid,
                 w->cw_node->tn_nodeid,
                 jps->jobwidth, sts_job_id_get(&w->cw_job),
                 cn_action2str(w->cw_action), cn_rule2str(w->cw_rule),
                 w->cw_qnum,
                 atomic_read(&w->cw_node->tn_busycnt) >> 16,
                 w->cw_kvset_cnt, (uint)cn_ns_kvsets(&w->cw_ns),
                 cn_ns_alen(&w->cw_ns) >> 20,
                 cn_ns_clen(&w->cw_ns) >> 20,
                 w->cw_ns.ns_pcap,
                 w->cw_compc,
                 w->cw_dgen_lo,
                 w->cw_nh, w->cw_nk, w->cw_nv,
                 w->cw_est.cwe_samp.r_alen >> 20,
                 w->cw_est.cwe_samp.i_alen >> 20,
                 w->cw_est.cwe_samp.l_alen >> 20,
                 w->cw_est.cwe_samp.l_good >> 20,
                 sts_job_wmesg_get(&w->cw_job),
                 tmbuf, w->cw_threadname);

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
        w->cw_rule,
        tn->tn_nodeid);

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

    if (debug_sched(sp) || (w->cw_debug & CW_DEBUG_START)) {

        const struct cn_node_stats *ns = &w->cw_ns;
        ulong hll_pct = cn_ns_keys(ns) ? ((100 * ns->ns_keys_uniq) / cn_ns_keys(ns)) : 0;
        uint busycnt = atomic_read(&w->cw_node->tn_busycnt) >> 16;

        slog_info(
            SLOG_START("cn_comp_start"),
            SLOG_FIELD("job", "%u", w->cw_job.sj_id),
            SLOG_FIELD("jcnt", "%u", spt->spt_job_cnt),
            SLOG_FIELD("bcnt", "%u", busycnt),
            SLOG_FIELD("qnum", "%u", w->cw_qnum),
            SLOG_FIELD("reduce", "%d", sp->samp_reduce),
            SLOG_FIELD("cnid", "%lu", w->cw_tree->cnid),
            SLOG_FIELD("comp", "%s", cn_action2str(w->cw_action)),
            SLOG_FIELD("rule", "%s", cn_rule2str(w->cw_rule)),
            SLOG_FIELD("nodeid", "%lu", w->cw_node->tn_nodeid),
            SLOG_FIELD("c_nk", "%u", w->cw_nk),
            SLOG_FIELD("c_nv", "%u", w->cw_nv),
            SLOG_FIELD("c_kvsets", "%u", w->cw_kvset_cnt),
            SLOG_FIELD("nd_kvsets", "%lu", (ulong)cn_ns_kvsets(ns)),
            SLOG_FIELD("nd_keys", "%lu", (ulong)cn_ns_keys(ns)),
            SLOG_FIELD("nd_hll%%", "%lu", hll_pct),
            SLOG_FIELD("nd_clen_mb", "%lu", (ulong)cn_ns_clen(ns) >> MB_SHIFT),
            SLOG_FIELD("samp", "%u", cn_ns_samp(ns)),
            SLOG_END);
    }
}

static bool
sp3_check_roots(struct sp3 *sp, uint qnum)
{
    struct sp3_node *spn, *next;
    uint debug;

    debug = csched_rp_dbg_comp(sp->rp);

    /* Each node on the rspill list had at least rspill_runlen_min kvsets
     * available when we scheduled this work request.
     */
    list_for_each_entry_safe(spn, next, &sp->spn_rlist, spn_rlink) {
        bool have_work;

        if (sp3_work(spn, wtype_root, &sp->thresh, debug, &sp->wp))
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

    if (tx >= NELEM(sp->rbt))
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
            SLOG_START("cn_rbt"),
            SLOG_FIELD("rbt", "%u", tx),
            SLOG_FIELD("item", "%u", count),
            SLOG_FIELD("weight", "%lx", (ulong)rbe->rbe_weight),
            SLOG_FIELD("cnid", "%lu", (ulong)tn->tn_tree->cnid),
            SLOG_FIELD("nodeid", "%lu", (ulong)tn->tn_nodeid),
            SLOG_FIELD("leaf", "%u", (uint)cn_node_isleaf(tn)),
            SLOG_FIELD("len", "%ld", (long)cn_ns_kvsets(&tn->tn_ns)),
            SLOG_FIELD("ialen_b", "%ld", (long)tn->tn_samp.i_alen),
            SLOG_FIELD("lalen_b", "%ld", (long)tn->tn_samp.l_alen),
            SLOG_FIELD("lgood_b", "%ld", (long)tn->tn_samp.l_good),
            SLOG_FIELD("lgarb_b", "%ld", (long)(tn->tn_samp.l_alen - tn->tn_samp.l_good)),
            SLOG_END);

        if (count++ == count_max)
            break;
    }
}

static void
sp3_tree_shape_log(const struct cn_tree_node *tn, bool bad, const char *category)
{
    ulong hll_pct;
    const struct cn_node_stats *ns;

    if (!tn)
        return;

    ns = &tn->tn_ns;
    hll_pct = cn_ns_keys(ns) ? ((100 * ns->ns_keys_uniq) / cn_ns_keys(ns)) : 0;

    slog_info(
        SLOG_START("cn_tree_shape"),
        SLOG_FIELD("type", "%s", category),
        SLOG_FIELD("status", "%s", bad ? "bad" : "good"),
        SLOG_FIELD("cnid", "%lu", (ulong)tn->tn_tree->cnid),
        SLOG_FIELD("nodeid", "%lu", (ulong)tn->tn_nodeid),
        SLOG_FIELD("nd_kvsets", "%lu", (ulong)cn_ns_kvsets(ns)),
        SLOG_FIELD("nd_alen_mb", "%lu", (ulong)cn_ns_alen(ns) >> MB_SHIFT),
        SLOG_FIELD("nd_wlen_mb", "%lu", (ulong)cn_ns_alen(ns) >> MB_SHIFT),
        SLOG_FIELD("nd_clen_mb", "%lu", (ulong)cn_ns_clen(ns) >> MB_SHIFT),
        SLOG_FIELD("nd_hll%%", "%lu", hll_pct),
        SLOG_FIELD("nd_samp", "%u", cn_ns_samp(ns)),
        SLOG_END);
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
    bool log = debug_tree_shape(sp);
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

    if (log) {
        sp3_tree_shape_log(rlen_node, rlen > rlen_thresh, "longest_root");
        sp3_tree_shape_log(llen_node, llen > llen_thresh, "longest_leaf");
        sp3_tree_shape_log(lsiz_node, lsiz > lsiz_thresh, "largest_leaf");
    }
}

/* spn_rbe must be first element in sp3_node struct in order for
 * '(void *)(rbe - tx)' to map rbe back to the sp3_node struct.
 */
static_assert(offsetof(struct sp3_node, spn_rbe) == 0,
              "spn_rbe must be first field in struct sp3_node");

static bool
sp3_check_rb_tree(struct sp3 *sp, enum sp3_work_type wtype, uint64_t threshold, uint qnum)
{
    struct rb_root *root;
    struct rb_node *rbn;
    uint            debug;

    assert(wtype < NELEM(sp->rbt));

    debug = csched_rp_dbg_comp(sp->rp);

    root = sp->rbt + wtype;
    rbn = rb_first(root);

    while (rbn) {
        struct sp3_rbe * rbe;
        struct sp3_node *spn;
        bool             have_work;

        rbe = rb_entry(rbn, struct sp3_rbe, rbe_node);
        spn = (void *)(rbe - wtype);

        if (rbe->rbe_weight < threshold)
            return false;

        if (sp3_work(spn, wtype, &sp->thresh, debug, &sp->wp))
            return false;

        /* Remove node from future consideration of this job type
         * until put back on the RBT by sp3_dirty_node().
         */
        rbn = rb_next(rbn);
        sp3_node_remove(sp, spn, wtype);

        have_work = sp->wp && sp->wp->cw_action != CN_ACTION_NONE;
        if (have_work) {
            sp3_submit(sp, sp->wp, qnum);
            sp->wp = NULL;
            return true;
        }
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

    rootmin = sp->thresh.rspill_runlen_max;
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
            nk /= 3;

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
            SLOG_START("cn_qos_sensors"),
            SLOG_FIELD("root_sensor", "%lu", sval),
            SLOG_FIELD("root_maxlen", "%u", rootmax),
            SLOG_FIELD("samp_curr", "%.3f", scale2dbl(sp->samp_curr)),
            SLOG_FIELD("samp_targ", "%.3f", scale2dbl(sp->samp_targ)),
            SLOG_FIELD("lpct_targ", "%.3f", scale2dbl(sp->lpct_targ)),
            SLOG_END);
    }
}

/**
 * sp3_schedule() - try to schedule a single job
 */
static void
sp3_schedule(struct sp3 *sp)
{
    bool job = false;

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

    for (uint rr = 0; rr < wtype_MAX && !job; rr++) {
        uint rp_leaf_pct, qnum;
        uint64_t thresh;

        /* round robin between job types */
        sp->rr_wtype = (sp->rr_wtype + 1) % wtype_MAX;

        switch (sp->rr_wtype) {
        case wtype_root:
            qnum = SP3_QNUM_ROOT;
            if (qfull(sp, qnum))
                break;

            job = sp3_check_roots(sp, qnum);
            break;

        case wtype_length:
            qnum = SP3_QNUM_LENGTH;
            if (qfull(sp, qnum))
                break;

            job = sp3_check_rb_tree(sp, sp->rr_wtype, 0, qnum);
            break;

        case wtype_idle:
            qnum = SP3_QNUM_SHARED;
            if (qfull(sp, qnum))
                break;

            thresh = (UINT32_MAX - (jclock_ns >> 32)) << 32;

            job = sp3_check_rb_tree(sp, sp->rr_wtype, thresh, qnum);
            break;

        case wtype_garbage:
            qnum = SP3_QNUM_GARBAGE;
            if (qfull(sp, qnum)) {
                qnum = SP3_QNUM_SHARED;
                if (qfull(sp, qnum))
                    break;
            }

            /* convert rparam to internal scale */
            rp_leaf_pct = (uint)sp->inputs.csched_leaf_pct * SCALE / EXT_SCALE;

            /* Implements:
             *   - Leaf node space amp rule
             * Notes:
             *   - Check for garbage if ucomp is active OR samp_reduce mode is enabled
             *     and leaf percent is somewhat caught up (ie, current leaf pct (lpct_targ)
             *     is within 90% of rparam setting (rp_leaf_pct)).
             *   - When checking for garbage, if leaf percent is behind, then bump up
             *     the threshold so we don't waste write amp compacting nodes with
             *     low garbage (we'd rather wait for leaf_pct to catch up).
             *   - If neither ucomp nor samp_reduce is active then check for nodes
             *     with excessively high garbage (e.g., 90% is roughly 10x garbage,
             *     93% is roughly 15x garbage, 95% is roughly 20x garbage, ...)
             */
            if (sp->samp_reduce && (100 * sp->lpct_targ > 90 * rp_leaf_pct)) {
                thresh = (sp->lpct_targ < rp_leaf_pct ? 10ul : 0ul) << 32;
            } else {
                thresh = 93ul << 32;
            }
            job = sp3_check_rb_tree(sp, sp->rr_wtype, thresh, qnum);
            break;

        case wtype_scatter:
            qnum = SP3_QNUM_SCATTER;
            if (qfull(sp, qnum)) {
                qnum = SP3_QNUM_SHARED;
                if (qfull(sp, qnum))
                    break;
            }

            thresh = (uint64_t)sp->thresh.lscat_hwm << 32;

            job = sp3_check_rb_tree(sp, sp->rr_wtype, thresh, qnum);
            break;

        case wtype_split:
            qnum = SP3_QNUM_SPLIT;
            if (qfull(sp, qnum))
                break;

            job = sp3_check_rb_tree(sp, sp->rr_wtype, 0, qnum);
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
    struct periodic_check chk_sched   = { .interval = NSEC_PER_SEC * 3 };
    struct periodic_check chk_refresh = { .interval = NSEC_PER_SEC * 10 };
    struct periodic_check chk_shape   = { .interval = NSEC_PER_SEC * 15 };

    bool bad_health = false;
    u64 last_activity = 0;

    sp3_refresh_settings(sp);

    while (atomic_read(&sp->running)) {
        uint64_t now = get_time_ns();
        merr_t err;

        mutex_lock(&sp->mon_lock);
        end_stats_work();

        if (!sp->mon_signaled && now < chk_qos.next) {
            int timeout_ms = max_t(int, 10, (chk_qos.next - now) / USEC_PER_SEC);

            cv_timedwait(&sp->mon_cv, &sp->mon_lock, timeout_ms, "spmonslp");

            now = get_time_ns();
        }

        begin_stats_work();
        sp->mon_signaled = false;
        mutex_unlock(&sp->mon_lock);

        /* The following "process and prune" functions will increment
         * sp->activity to trigger a call (below) to sp3_schedule().
         */
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

        if (now > chk_sched.next || sp->activity) {
            if (sp->activity) {
                last_activity = now + NSEC_PER_SEC * 5;
                sp->activity = 0;
            }

            if (!bad_health)
                sp3_schedule(sp);

            chk_sched.next = now + chk_sched.interval;
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
                for (uint tx = 0; tx < NELEM(sp->rbt); tx++)
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

    for (tx = 0; tx < NELEM(sp->rbt); tx++)
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
    alloc_sz = roundup(alloc_sz, __alignof__(*sp));

    sp = aligned_alloc(__alignof__(*sp), alloc_sz);
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
    cv_init(&sp->mon_cv);

    INIT_LIST_HEAD(&sp->mon_tlist);
    INIT_LIST_HEAD(&sp->new_tlist);
    INIT_LIST_HEAD(&sp->work_list);
    INIT_LIST_HEAD(&sp->spn_alist);
    INIT_LIST_HEAD(&sp->spn_rlist);

    for (tx = 0; tx < NELEM(sp->rbt); tx++)
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

    INIT_WORK(&sp->mon_work, sp3_monitor);
    queue_work(sp->mon_wq, &sp->mon_work);

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
