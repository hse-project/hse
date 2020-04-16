/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_csched_sp3

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/token_bucket.h>
#include <hse_util/string.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "csched_ops.h"
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
 *    - Ingest threads, created in c0/c1.
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
 *    - We do not count CNDB mlogs or c1 mlogs or any other mlogs.
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
#define RBT_L_PCAP 1  /* leaf nodes sorted by pct capacity */
#define RBT_L_GARB 2  /* leaf nodes sorted by garbage */
#define RBT_LI_LEN 3  /* internal and leaf nodes, sorted by #kvsets */
#define RBT_L_SCAT 4  /* leaf nodes sorted by vblock scatter */

static const char *const rbt_name[] = {
    "ri_size", "l_size", "l_garb", "li_len", "l_scat",
};

struct sp3_qinfo {
    uint qjobs;
    uint qjobs_max;
};

static inline bool
qfull(struct sp3_qinfo *qi)
{
    return qi->qjobs >= qi->qjobs_max;
}

/**
 * struct sp3 - kvdb scheduler policy
 * @ops:
 * @ds:           to access mpool qos
 * @rp:           kvb run-time params
 * @name:         name for logging and data tree
 * @sts:          short term scheduler
 * @cv:           monitor thread conditional var
 * @mutex:        mutex used with @cv
 * @wqueue:       monitor thread workqueue
 * @wstruct:      monitor thread work struct
 * @mon_tlist:    monitored trees
 * @destruct:     sp3_destroy called
 * @new_tlist:        list of new trees
 * @new_tlist_lock:   lock for list of new trees
 * @samp_reduce:      if true, compact while samp > LWM
 * @comp_flags:       compaction flags for an active compaction request
 * @comp_request:     whether a compaction request is active
 */
struct sp3 {
    /* Accessed only by monitor thread */
    struct csched_ops        ops;
    struct mpool *           ds;
    struct kvdb_rparams *    rp;
    char *                   name;
    struct sts *             sts;
    struct work_struct       wstruct;
    struct workqueue_struct *wqueue;
    struct list_head         mon_tlist;
    struct sp3_thresholds    thresh;
    struct throttle_sensor * throttle_sensor;
    struct kvdb_health      *health;

    struct rb_root rbt[RBT_MAX];

    struct sp3_qinfo qinfo[SP3_NUM_QUEUES];
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

    u64 iowrite_limit_burst;
    u64 iowrite_limit_rate;

    atomic64_t wbyte_spill_rt;

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
    uint lpct_curr;
    uint lpct_targ;
    uint lpct_throttle;

    /* Throttle sensors */
    uint sensor_lpct;

    u64 qos_prv_log;

    /* Tree shape report */
    u64  tree_shape_last_report;
    bool tree_shape_bad;
    uint lvl_max;

    u64                  leaf_pop_size;
    struct cn_samp_stats samp;
    struct cn_samp_stats samp_wip;
    struct perfc_set     sched_pc;

    /* Accessed by monitor and infrequently by open/close threads */
    __aligned(SMP_CACHE_BYTES) struct mutex new_tlist_lock;
    struct list_head new_tlist;
    atomic_t         destruct;

    /* Accessed by monitor, open/close, ingest and jobs threads */
    __aligned(SMP_CACHE_BYTES) struct mutex mutex;
    struct cv cv;

    /* Accessed monitor and infrequently by job threads */
    __aligned(SMP_CACHE_BYTES) struct mutex work_list_lock;
    struct list_head work_list;

    /* Accessed by monitor and job threads */
    __aligned(SMP_CACHE_BYTES) struct tbkt tbkt;

    /* Accessed by forced compactions and monitor */
    __aligned(SMP_CACHE_BYTES) int comp_flags;
    bool comp_request;
};

/* external to internal handle */
#define h2sp(_hdl) container_of(_hdl, struct sp3, ops)

/* cn_tree 2 sp3_tree */
#define tree2spt(_tree) (&(_tree)->ct_sched.sp3t)

/* Scale of kvdb rparms */
#define EXT_SCALE 100

/* Internal scale, to get better precision with scalar math.
 * ONE is defined simply for readability in
 * expressions such as '(1 + r) / r'.
 */
#define SCALE 10000
#define ONE SCALE

/* Easy-ish access to run-time parameters */
#define debug_samp_work(_sp) (csched_rp_dbg_samp_work((_sp)->rp))
#define debug_samp_ingest(_sp) (csched_rp_dbg_samp_ingest((_sp)->rp))
#define debug_tree_life(_sp) (csched_rp_dbg_tree_life((_sp)->rp))
#define debug_dirty_node(_sp) (csched_rp_dbg_dirty_node((_sp)->rp))
#define debug_sched(_sp) (csched_rp_dbg_sched((_sp)->rp))
#define debug_qos(_sp) (csched_rp_dbg_qos((_sp)->rp))
#define debug_rbtree(_sp) (csched_rp_dbg_rbtree((_sp)->rp))

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
throttle_pct_leaves(struct cn_samp_stats *s, uint scale)
{
    s64 i_size;
    s64 total_size;

    i_size = s->i_alen - s->r_alen + s->r_wlen;
    total_size = i_size + s->l_alen;

    return scale * safe_div(s->l_alen, total_size);
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

    uint tx;
    uint ttl;

    spn->spn_initialized = 1;

    for (tx = 0; tx < RBT_MAX; tx++)
        RB_CLEAR_NODE(&spn->spn_rbe[tx].rbe_node);

    tn = spn2tn(spn);
    ttl = sp->rp ? sp->rp->csched_node_min_ttl : 13;
    spn->spn_ttl = (ttl << tn->tn_loc.node_level);
}

static void
sp3_monitor_wake(struct sp3 *sp)
{
    /* Signal monitor thread (our cv_signal requres lock to be held). */
    mutex_lock(&sp->mutex);
    cv_signal(&sp->cv);
    mutex_unlock(&sp->mutex);
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

    hse_slog(
        HSE_NOTICE,
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

    hse_slog(
        HSE_NOTICE,
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

    hse_slog(
        HSE_NOTICE,
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

        HSE_SLOG_FIELD("kblk_write_async_ops", "%ld", ms->ms_kblk_write_async.op_cnt),
        HSE_SLOG_FIELD("kblk_write_async_sz", "%ld", ms->ms_kblk_write_async.op_size),
        HSE_SLOG_FIELD("kblk_write_async_ns", "%ld", ms->ms_kblk_write_async.op_time),

        HSE_SLOG_FIELD("kblk_flush_ops", "%ld", ms->ms_kblk_flush.op_cnt),
        HSE_SLOG_FIELD("kblk_flush_ns", "%ld", ms->ms_kblk_flush.op_time),

        HSE_SLOG_FIELD("vblk_alloc_ops", "%ld", ms->ms_vblk_alloc.op_cnt),
        HSE_SLOG_FIELD("vblk_alloc_sz", "%ld", ms->ms_vblk_alloc.op_size),
        HSE_SLOG_FIELD("vblk_alloc_ns", "%ld", ms->ms_vblk_alloc.op_time),

        HSE_SLOG_FIELD("vblk_write_ops", "%ld", ms->ms_vblk_write.op_cnt),
        HSE_SLOG_FIELD("vblk_write_sz", "%ld", ms->ms_vblk_write.op_size),
        HSE_SLOG_FIELD("vblk_write_ns", "%ld", ms->ms_vblk_write.op_time),

        HSE_SLOG_FIELD("vblk_write_async_ops", "%ld", ms->ms_vblk_write_async.op_cnt),
        HSE_SLOG_FIELD("vblk_write_async_sz", "%ld", ms->ms_vblk_write_async.op_size),
        HSE_SLOG_FIELD("vblk_write_async_ns", "%ld", ms->ms_vblk_write_async.op_time),

        HSE_SLOG_FIELD("vblk_flush_ops", "%ld", ms->ms_vblk_flush.op_cnt),
        HSE_SLOG_FIELD("vblk_flush_ns", "%ld", ms->ms_vblk_flush.op_time),

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
    hse_slog(
        HSE_NOTICE,
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

/*****************************************************************
 *
 * Space amp parameters
 *
 ****************************************************************/

#define SP3_PARAM_DEF(NAME, DFLT_VAL, MIN_VAL, MAX_VAL)                       \
    {                                                                         \
        .name = #NAME, .rp_offset = offsetof(struct kvdb_rparams, NAME),      \
        .sp_offset = offsetof(struct sp3, inputs.NAME), .min_val = (MIN_VAL), \
        .max_val = (MAX_VAL), .dflt_val = (DFLT_VAL)                          \
    }

struct sp3_param_def {
    const char *name;
    size_t      rp_offset;
    size_t      sp_offset;
    u64         min_val;
    u64         max_val;
    u64         dflt_val;
};

static const struct sp3_param_def sp3_params[] = { SP3_PARAM_DEF(csched_samp_max, 150, 100, 999),
                                                   SP3_PARAM_DEF(csched_lo_th_pct, 25, 5, 95),
                                                   SP3_PARAM_DEF(csched_hi_th_pct, 75, 5, 95),
                                                   SP3_PARAM_DEF(csched_leaf_pct, 90, 1, 99) };

static void
sp3_refresh_samp(struct sp3 *sp)
{
    const uint np = NELEM(sp3_params);
    bool       changed = false;
    uint       i;
    u64        samp, lwm, hwm, leaf, r;
    u64        good_max, good_min;
    u64        good_hwm, good_lwm;
    u64        samp_hwm, samp_lwm;
    u64        range;

    for (i = 0; i < np; i++) {

        u64 *rp_ptr = (void *)sp->rp + sp3_params[i].rp_offset;
        u64 *sp_ptr = (void *)sp + sp3_params[i].sp_offset;
        u64  new_val = *rp_ptr;

        if (!new_val)
            new_val = sp3_params[i].dflt_val;

        if (*sp_ptr == new_val)
            continue;

        new_val = clamp_t(u64, new_val, sp3_params[i].min_val, sp3_params[i].max_val);

        hse_log(
            HSE_NOTICE "sp3 kvdb_rparam %s changed from %lu to %lu",
            sp3_params[i].name,
            (ulong)*sp_ptr,
            (ulong)new_val);

        *sp_ptr = new_val;
        changed = true;
    }

    if (!changed)
        return;

    hse_log(
        HSE_NOTICE "sp3 new samp input params:"
                   " samp %lu, lwm_pct %lu, hwm_pct %lu, leaf_pct %lu",
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

    hse_log(
        HSE_NOTICE "sp3 samp derived params:"
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
    u64                   v;

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
        } else {
            thresh.ispill_kvsets_max = 12;
            thresh.ispill_kvsets_min = 1;
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
        } else {
            thresh.lcomp_kvsets_max = 12;
            thresh.lcomp_kvsets_min = 2;
            thresh.lcomp_pop_pct = 80;
        }
        thresh.lcomp_kvsets_min = max(thresh.lcomp_kvsets_min, SP3_LCOMP_KVSETS_MIN);
    }

    /* leaf node length settings */
    v = sp->rp->csched_leaf_len_params;
    if (v != U64_MAX) {
        if (v) {
            thresh.llen_runlen_max = (v >> 0) & 0xff;
            thresh.llen_runlen_min = (v >> 8) & 0xff;
            thresh.llen_kvcompc = (v >> 16) & 0xff;
            thresh.llen_idlec = (v >> 24) & 0xff;
            thresh.llen_idlem = (v >> 32) & 0xff;
        } else {
            thresh.llen_runlen_max = 8;
            thresh.llen_runlen_min = 4;
            thresh.llen_kvcompc = -1;
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

    sp->thresh = thresh;

    hse_log(
        HSE_NOTICE "sp3 thresholds:"
                   " rspill: min/max %u/%u,"
                   " ispill: min/max %u/%u,"
                   " lcomp: min/max/pop %u/%u/%u%%,"
                   " llen: min/max %u/%u,"
                   " kvcompc: %u,"
                   " idlec: %u,"
                   " idlem: %u,"
                   " lscatter_pct: %u%%",
        thresh.rspill_kvsets_min,
        thresh.rspill_kvsets_max,

        thresh.ispill_kvsets_min,
        thresh.ispill_kvsets_max,

        thresh.lcomp_kvsets_min,
        thresh.lcomp_kvsets_max,
        thresh.lcomp_pop_pct,

        thresh.llen_runlen_min,
        thresh.llen_runlen_max,

        thresh.llen_kvcompc,
        thresh.llen_idlec,
        thresh.llen_idlem,

        thresh.lscatter_pct);
}

static void
sp3_refresh_worker_counts(struct sp3 *sp)
{
    uint i;
    uint workers;

    sp->jobs_max = 0;

    for (i = 0; i < SP3_NUM_QUEUES; i++) {
        workers = sts_wcnt_get_target(sp->sts, i);
        sp->qinfo[i].qjobs_max = workers;
        sp->jobs_max += workers;
    }

    /* shared workers */
    sp->jobs_max += sts_wcnt_get_target(sp->sts, SP3_NUM_QUEUES);
}

static void
sp3_refresh_rate_limiters(struct sp3 *sp)
{
    u64 burst = sp->rp->csched_wr_burst_sz;
    u64 rate = sp->rp->csched_wr_rate_max;

    if (burst == sp->iowrite_limit_burst && rate == sp->iowrite_limit_rate)
        return;

    hse_log(
        HSE_NOTICE "sp3: set maintenance write limits:"
                   " burst %lu MiB, rate %lu MiB",
        (ulong)burst,
        (ulong)rate);

    sp->iowrite_limit_burst = burst;
    sp->iowrite_limit_rate = rate;

    tbkt_reinit(&sp->tbkt, burst << 20, rate << 20);
}

static void
sp3_refresh_settings(struct sp3 *sp)
{
    sp3_refresh_samp(sp);
    sp3_refresh_thresholds(sp);
    sp3_refresh_worker_counts(sp);
    sp3_refresh_rate_limiters(sp);
}

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
    assert(NELEM(spn->spn_rbe) == RBT_MAX);

    rbe->rbe_weight = weight;
    sp3_rb_insert(root, rbe);
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
    while (NULL != (tn = tree_iter_next(tree, &iter)))
        sp3_node_unlink(sp, tn2spn(tn));
}

static void
sp3_dirty_node(struct sp3 *sp, struct cn_tree_node *tn)
{
    struct sp3_node *spn = tn2spn(tn);
    u64              n_kvsets = cn_ns_kvsets(&tn->tn_ns);
    u64              alen = cn_ns_alen(&tn->tn_ns);
    uint             garbage;

    uint scatter = 0;

    sp3_node_unlink(sp, spn);

    if (tn->tn_parent != NULL) {
        /* RBT_LI_LEN: internal and leaf nodes sorted by #kvsets*/
        sp3_node_insert(sp, spn, RBT_LI_LEN, n_kvsets);
    }

    garbage = samp_pct_garbage(&tn->tn_samp, 100);

    if (cn_node_isleaf(tn)) {

        /* RBT_L_GARB: leaf nodes sorted by garbage */
        sp3_node_insert(sp, spn, RBT_L_GARB, garbage);

        /* RBT_L_PCAP: leaf nodes sorted by pct capacity */
        sp3_node_insert(sp, spn, RBT_L_PCAP, tn->tn_ns.ns_pcap);

        if (sp->thresh.lscatter_pct < 100) {
            spn->spn_timeout = get_time_ns() + spn->spn_ttl * NSEC_PER_SEC;

            scatter = sp3_node_scatter_score_compute(spn);
            sp3_node_insert(sp, spn, RBT_L_SCAT, scatter);
        }
    } else {
        /* RBT_RI_ALEN: root and internal nodes sorted by alen */
        sp3_node_insert(sp, spn, RBT_RI_ALEN, alen);
    }

    if (debug_dirty_node(sp)) {

        bool isleaf = cn_node_isleaf(tn);

        hse_slog(
            HSE_NOTICE,
            HSE_SLOG_START("cn_dirty_node"),
            HSE_SLOG_FIELD("cnid", "%lu", (ulong)tn->tn_tree->cnid),
            HSE_SLOG_FIELD("lvl", "%u", tn->tn_loc.node_level),
            HSE_SLOG_FIELD("off", "%u", tn->tn_loc.node_offset),
            HSE_SLOG_FIELD("isleaf", "%d", isleaf),
            HSE_SLOG_FIELD("nd_len", "%lu", (ulong)n_kvsets),
            HSE_SLOG_FIELD("alen", "%lu", (ulong)alen),
            HSE_SLOG_FIELD("garbage", "%lu", (ulong)garbage),
            HSE_SLOG_FIELD("scatter", "%u", scatter),
            HSE_SLOG_END);
    }
}

static void
sp3_process_workitem(struct sp3 *sp, struct cn_compaction_work *w)
{
    struct sp3_tree *    spt = tree2spt(w->cw_tree);
    struct cn_tree_node *tn = w->cw_node;
    struct cn_samp_stats diff;

    assert(spt->spt_job_cnt > 0);
    assert(w->cw_job.sj_qnum < SP3_NUM_QUEUES);
    assert(sp->qinfo[w->cw_job.sj_qnum].qjobs > 0);
    assert(sp->jobs_started > sp->jobs_finished);

    spt->spt_job_cnt--;
    sp->qinfo[w->cw_job.sj_qnum].qjobs--;
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

    if (w->cw_action == CN_ACTION_SPILL) {

        struct sp3_node *spn;
        uint             fanout = w->cw_tree->ct_cp->cp_fanout;
        uint             i;

        for (i = 0; i < fanout; i++) {
            if (tn->tn_childv[i]) {
                spn = tn2spn(tn->tn_childv[i]);
                if (!spn->spn_initialized)
                    sp3_node_init(sp, spn);
                sp3_dirty_node(sp, tn->tn_childv[i]);
            }
        }
    }

    if (w->cw_node->tn_loc.node_level > 0 || (w->cw_debug & CW_DEBUG_ROOT))
        sp3_log_progress(w, &w->cw_stats, true);

    sp3_dirty_node(sp, tn);

    free(w);

    if (debug_samp_work(sp)) {
        sp3_log_samp_each_tree(sp);
        sp3_log_samp_overall(sp);
    }
}

static void
sp3_process_ingest(struct sp3 *sp)
{
    struct cn_tree *tree;
    bool            ingested = false;

    list_for_each_entry (tree, &sp->mon_tlist, ct_sched.sp3t.spt_tlink) {

        struct sp3_tree *spt = tree2spt(tree);
        int              v;
        long             alen;
        long             wlen;

        v = atomic_read(&spt->spt_ingest_count);
        atomic_sub(v, &spt->spt_ingest_count);

        alen = atomic64_read(&spt->spt_ingest_alen);
        wlen = atomic64_read(&spt->spt_ingest_wlen);
        if (alen) {

            atomic64_sub(alen, &spt->spt_ingest_alen);
            sp->samp.i_alen += alen;
            sp->samp.r_alen += alen;

            atomic64_sub(wlen, &spt->spt_ingest_wlen);
            sp->samp.r_wlen += wlen;

            sp3_dirty_node(sp, tree->ct_root);
            ingested = true;
        }
    }

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
    uint                       count = 0;

    INIT_LIST_HEAD(&list);

    /* Move completed work from shared list to private list */
    mutex_lock(&sp->work_list_lock);
    list_splice_tail(&sp->work_list, &list);
    INIT_LIST_HEAD(&sp->work_list);
    mutex_unlock(&sp->work_list_lock);

    while (NULL != (w = list_first_entry_or_null(&list, typeof(*w), cw_sched_link))) {
        list_del(&w->cw_sched_link);
        sp3_process_workitem(sp, w);
        count++;
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

        if (debug_tree_life(sp))
            hse_log(HSE_NOTICE "sp3 acquire tree cnid %lu", (ulong)tree->cnid);

        tree_iter_init(tree, &iter, TRAVERSE_TOPDOWN);
        while (NULL != (tn = tree_iter_next(tree, &iter))) {
            sp3_node_init(sp, tn2spn(tn));
            sp3_dirty_node(sp, tn);
        }

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
    }
}

static void
sp3_prune_trees(struct sp3 *sp)
{
    struct cn_tree *tree, *tmp;

    list_for_each_entry_safe (tree, tmp, &sp->mon_tlist, ct_sched.sp3t.spt_tlink) {

        struct sp3_tree *spt = tree2spt(tree);
        int              enabled = atomic_read(&spt->spt_enabled);

        if (!enabled && spt->spt_job_cnt == 0) {

            if (debug_tree_life(sp))
                hse_log(HSE_NOTICE "sp3 release tree cnid %lu", (ulong)tree->cnid);

            sp3_unlink_all_nodes(sp, tree);
            list_del_init(&spt->spt_tlink);

            sp3_log_samp_one_tree(tree);
            sp3_log_samp_overall(sp);

            assert(sp->samp.i_alen >= tree->ct_samp.i_alen);
            assert(sp->samp.r_alen >= tree->ct_samp.r_alen);
            assert(sp->samp.r_wlen >= tree->ct_samp.r_wlen);
            assert(sp->samp.l_alen >= tree->ct_samp.l_alen);
            assert(sp->samp.l_good >= tree->ct_samp.l_good);

            sp->samp.i_alen -= tree->ct_samp.i_alen;
            sp->samp.r_alen -= tree->ct_samp.r_alen;
            sp->samp.r_wlen -= tree->ct_samp.r_wlen;
            sp->samp.l_alen -= tree->ct_samp.l_alen;
            sp->samp.l_good -= tree->ct_samp.l_good;

            sp3_log_samp_overall(sp);

            cn_ref_put(tree->cn);
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

    /* compute change in merge stats from previous progress report */
    cn_merge_stats_diff(&ms, &w->cw_stats, &w->cw_stats_prev);
    memcpy(&w->cw_stats_prev, &w->cw_stats, sizeof(w->cw_stats_prev));

    if ((w->cw_debug & CW_DEBUG_PROGRESS) &&
        (w->cw_node->tn_loc.node_level > 0 || (w->cw_debug & CW_DEBUG_ROOT))) {
        sp3_log_progress(w, &ms, false);
    }
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

        case CN_CR_SPILL:
            r = "sn";
            break;
        case CN_CR_SPILL_ONE:
            r = "s1";
            break;
        case CN_CR_SPILL_TINY:
            r = "st";
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
        case CN_CR_LLONG_SCATTER:
            r = "ls";
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

    snprintf(buf, bufsz, "%c%s_%s_%u%u", node_type, a, r, loc->node_level, loc->node_offset);
}

static void
sp3_submit(struct sp3 *sp, struct cn_compaction_work *w, uint qnum, uint rbt_idx)
{
    struct cn_tree_node *tn = w->cw_node;
    struct sp3_tree *    spt = tree2spt(w->cw_tree);

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

    /* Use mcache for root spills to efficiently handle c1 vblocks. */
    if (cn_node_isroot(tn)) {
        w->cw_iter_flags |= kvset_iter_flag_mcache;
        w->cw_io_workq = NULL;
    }

    w->cw_sched = sp;
    w->cw_completion = sp3_work_complete;
    w->cw_progress = sp3_work_progress;
    w->cw_prog_interval = NSEC_PER_SEC;
    w->cw_debug = csched_rp_dbg_comp(sp->rp);

    sp->samp_wip.i_alen += w->cw_est.cwe_samp.i_alen;
    sp->samp_wip.l_alen += w->cw_est.cwe_samp.l_alen;
    sp->samp_wip.l_good += w->cw_est.cwe_samp.l_good;

    spt->spt_job_cnt++;
    sp->qinfo[qnum].qjobs++;
    sp->jobs_started++;

    w->cw_job.sj_id = sp->job_id++;

    sts_job_init(&w->cw_job, cn_comp_slice_cb, cn_comp_cancel_cb, qnum, w->cw_tree->cnid);

    if (w->cw_node->tn_loc.node_level > 0 || (w->cw_debug & CW_DEBUG_ROOT)) {

        const char *rbt = rbt_idx < RBT_MAX ? rbt_name[rbt_idx] : "root";

        hse_slog(
            HSE_NOTICE,
            HSE_SLOG_START("cn_comp_start"),
            HSE_SLOG_FIELD("job", "%u", w->cw_job.sj_id),
            HSE_SLOG_FIELD("comp", "%s", cn_action2str(w->cw_action)),
            HSE_SLOG_FIELD("rule", "%s", cn_comp_rule2str(w->cw_comp_rule)),
            HSE_SLOG_FIELD("cnid", "%lu", w->cw_tree->cnid),
            HSE_SLOG_FIELD("lvl", "%u", w->cw_node->tn_loc.node_level),
            HSE_SLOG_FIELD("off", "%u", w->cw_node->tn_loc.node_offset),
            HSE_SLOG_FIELD("leaf", "%u", (uint)cn_node_isleaf(w->cw_node)),
            HSE_SLOG_FIELD("rbt", "%s", rbt),
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
                    cn_ns_keys(&w->cw_ns) == 0 ? 0 : ((100 * w->cw_ns.ns_keys_uniq) /
                                                      cn_ns_keys(&w->cw_ns)))),
            HSE_SLOG_FIELD("rdsz_b", "%ld", (long)w->cw_est.cwe_read_sz),
            HSE_SLOG_FIELD("wrsz_b", "%ld", (long)w->cw_est.cwe_write_sz),
            HSE_SLOG_FIELD("i_alen_b", "%ld", (long)w->cw_est.cwe_samp.i_alen),
            HSE_SLOG_FIELD("l_alen_b", "%ld", (long)w->cw_est.cwe_samp.l_alen),
            HSE_SLOG_END);
    }

    sts_job_submit(sp->sts, &w->cw_job);
}

static bool
sp3_check_roots(struct sp3 *sp)
{
    uint            debug;
    struct cn_tree *tree;
    uint            lvl_max = 0;

    debug = csched_rp_dbg_comp(sp->rp);

    list_for_each_entry (tree, &sp->mon_tlist, ct_sched.sp3t.spt_tlink) {

        bool have_work;
        uint qnum;

        lvl_max = max(lvl_max, tree->ct_lvl_max);

        if (sp3_work(tn2spn(tree->ct_root), &sp->thresh, wtype_rspill, debug, &qnum, &sp->wp))
            return false;

        have_work = sp->wp && sp->wp->cw_action != CN_ACTION_NONE;
        if (have_work) {
            struct sp3_tree *spt = tree2spt(tree);

            /* Move to end of list to prevent this node
             * from starving other nodes on the list. */
            list_del(&spt->spt_tlink);
            list_add_tail(&spt->spt_tlink, &sp->mon_tlist);

            sp3_submit(sp, sp->wp, qnum, RBT_MAX);
            sp->wp = NULL;
            return true;
        }
    }

    sp->lvl_max = lvl_max;

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

        hse_slog(
            HSE_NOTICE,
            HSE_SLOG_START("cn_rbt"),
            HSE_SLOG_FIELD("rbt", "%s", rbt_name[tx]),
            HSE_SLOG_FIELD("item", "%u", count),
            HSE_SLOG_FIELD("weight", "%ld", (long)rbe->rbe_weight),
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

    hse_slog(
        HSE_NOTICE,
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

    bool rlen_bad = false;
    bool ilen_bad = false;
    bool llen_bad = false;
    bool lsiz_bad = false;

    struct cn_tree *tree;
    struct rb_node *rbn;
    bool            log = false;
    bool            bad;
    uint            tx;

    /* Find longest root node */
    list_for_each_entry (tree, &sp->mon_tlist, ct_sched.sp3t.spt_tlink) {

        struct cn_tree_node *tn = tree->ct_root;
        uint                 len = cn_ns_kvsets(&tn->tn_ns);

        if (!rlen_node || len > cn_ns_kvsets(&rlen_node->tn_ns)) {
            rlen_node = tn;
            rlen_bad = len > rlen_thresh;
        }
    }

    /* All non-root nodes are on the RBT_LI_LEN red/black tree.
     * Walk the entire tree to get longest and largest internal
     * and leaf nodes.
     */
    tx = RBT_LI_LEN;
    for (rbn = rb_first(sp->rbt + tx); rbn; rbn = rb_next(rbn)) {

        struct sp3_rbe *     rbe = rb_entry(rbn, struct sp3_rbe, rbe_node);
        struct sp3_node *    spn = (void *)(rbe - tx);
        struct cn_tree_node *tn = spn2tn(spn);

        uint pcap = tn->tn_ns.ns_pcap;
        uint len = cn_ns_kvsets(&tn->tn_ns);

        if (cn_node_isleaf(tn)) {

            if (!llen_node || len > cn_ns_kvsets(&llen_node->tn_ns)) {
                llen_node = tn;
                llen_bad = len > llen_thresh;
            }

            if (!lsiz_node || pcap > lsiz_node->tn_ns.ns_pcap) {
                lsiz_node = tn;
                lsiz_bad = pcap > lsiz_thresh;
            }

        } else {

            if (!ilen_node || len > cn_ns_kvsets(&ilen_node->tn_ns)) {
                ilen_node = tn;
                ilen_bad = len > ilen_thresh;
            }
        }
    }

    bad = rlen_bad || ilen_bad || llen_bad || lsiz_bad;

    if (sp->tree_shape_bad != bad) {

        if (bad)
            hse_log(HSE_WARNING "tree shape changed from good to bad");
        else
            hse_log(HSE_NOTICE "tree shape changed from bad to good");

        sp->tree_shape_bad = bad;
        log = true; /* log details below */
    }

    if (log || debug_sched(sp)) {

        sp3_tree_shape_log(rlen_node, rlen_bad, "longest_root");
        sp3_tree_shape_log(ilen_node, ilen_bad, "longest_internal");
        sp3_tree_shape_log(llen_node, llen_bad, "longest_leaf");
        sp3_tree_shape_log(lsiz_node, lsiz_bad, "largest_leaf");

        hse_slog(
            HSE_NOTICE,
            HSE_SLOG_START("cn_sched"),
            HSE_SLOG_FIELD("samp_lwm", "%.3f", scale2dbl(sp->samp_lwm)),
            HSE_SLOG_FIELD("hwm", "%.3f", scale2dbl(sp->samp_hwm)),
            HSE_SLOG_FIELD("max", "%.3f", scale2dbl(sp->samp_max)),
            HSE_SLOG_FIELD("curr", "%.3f", scale2dbl(sp->samp_targ)),
            HSE_SLOG_FIELD("reduce", "%d", sp->samp_reduce),
            HSE_SLOG_FIELD("lf_pct_targ", "%.3f", scale2dbl(sp->lpct_targ)),
            HSE_SLOG_FIELD("lf_pct_curr", "%.3f", scale2dbl(sp->lpct_throttle)),
            HSE_SLOG_FIELD("jobs_started", "%u", sp->jobs_started),
            HSE_SLOG_FIELD("jobs_finished", "%u", sp->jobs_finished),
            HSE_SLOG_FIELD("cur_jobs", "%u", sp->jobs_started - sp->jobs_finished),
            HSE_SLOG_FIELD("max_jobs", "%u", sp->jobs_max),
            HSE_SLOG_END);

        sp3_log_samp_each_tree(sp);
        sp3_log_samp_overall(sp);

        sp->tree_shape_last_report = get_time_ns();
    }
}

static bool
sp3_check_rb_tree(struct sp3 *sp, uint tx, u64 threshold, enum sp3_work_type wtype)
{
    struct rb_root *root;
    struct rb_node *rbn;
    uint            debug;

    assert(tx < RBT_MAX);

    debug = csched_rp_dbg_comp(sp->rp);

    root = sp->rbt + tx;

    for (rbn = rb_first(root); rbn; rbn = rb_next(rbn)) {

        struct sp3_rbe * rbe;
        struct sp3_node *spn;
        bool             have_work;
        uint             qnum;

        assert((void *)spn == (void *)&spn->spn_rbe[0]);
        rbe = rb_entry(rbn, struct sp3_rbe, rbe_node);
        spn = (void *)(rbe - tx);

        if (rbe->rbe_weight < threshold)
            return false;

        if (sp3_work(spn, &sp->thresh, wtype, debug, &qnum, &sp->wp))
            return false;

        have_work = sp->wp && sp->wp->cw_action != CN_ACTION_NONE;
        if (have_work) {
            sp3_submit(sp, sp->wp, qnum, tx);
            sp->wp = NULL;
            return true;
        }
    }

    return false;
}

static void
sp3_qos_check(struct sp3 *sp)
{
    struct cn_samp_stats targ;

    u64  cur_time_ns;
    bool log;

    cur_time_ns = get_time_ns();

    log = debug_qos(sp) && cur_time_ns > sp->qos_prv_log + NSEC_PER_SEC;
    if (log)
        sp->qos_prv_log = cur_time_ns;

    /* Leaf percent throttle sensor -- based on leaf percentage,
     * but only after we have a non-trivial amount of data.
     */
    sp3_samp_target(sp, &targ);
    if (targ.i_alen + targ.l_alen > (128ull << 30)) {

        uint lpct = sp->lpct_throttle;
        uint N = THROTTLE_SENSOR_SCALE;
        uint sval, cutoff;

        /* Convert csched_leaf_pct rparam to internal scale.
         * Example rparam value is 90, which represents a
         * cutoff of 90% (in the following expressions, read
         * 'SCALE' as 100% and cutoff as 90%).  Set the sensor
         * based on leaf percent as follows:
         *
         *   Leaf Pct    Sensor Value
         *   --------    ------------
         *      100        2000  2*N
         *       95        1500  Linear between N and 2*N
         *       90        1000  1*N (N==1000), cutoff
         *       45         500  Linear between 0 and 1000)
         *        0           0
         */

        cutoff = sp->inputs.csched_leaf_pct * SCALE / EXT_SCALE;

        if (lpct < cutoff)

            sval = 2 * N - (N * lpct / cutoff);

        else if (lpct < SCALE)

            sval = N * (SCALE - lpct) / (SCALE - cutoff);
        else
            sval = 0;

        sp->sensor_lpct = sval;
    }

    /* Use leaf percent... */
    if (sp->throttle_sensor)
        throttle_sensor_set(sp->throttle_sensor, sp->sensor_lpct);

    if (log) {
        hse_slog(
            HSE_NOTICE,
            HSE_SLOG_START("cn_qos_sensors"),
            HSE_SLOG_FIELD("lpct_sensor", "%u", sp->sensor_lpct),
            HSE_SLOG_FIELD("samp_curr", "%.3f", scale2dbl(sp->samp_curr)),
            HSE_SLOG_FIELD("samp_targ", "%.3f", scale2dbl(sp->samp_targ)),
            HSE_SLOG_FIELD("lpct_curr", "%.3f", scale2dbl(sp->lpct_curr)),
            HSE_SLOG_FIELD("lpct_targ", "%.3f", scale2dbl(sp->lpct_targ)),
            HSE_SLOG_FIELD("lpct_throttle", "%.3f", scale2dbl(sp->lpct_throttle)),
            HSE_SLOG_END);
    }
}

/**
 * sp3_schedule() - try to schedule a single job
 * Returns true if a job was scheduled, false otherwise.
 */
static bool
sp3_schedule(struct sp3 *sp)
{
    enum job_type {
        jtype_root,
        jtype_ispill,
        jtype_node_len,
        jtype_leaf_garbage,
        jtype_leaf_size,
        jtype_leaf_scatter,
        jtype_MAX,
    };

    u64               node_len_max;
    bool              job = false;
    struct sp3_qinfo *qi;
    bool              shared_full;
    uint              rp_leaf_pct;
    uint              rr;

    /* convert rparam to internal scale */
    rp_leaf_pct = sp->inputs.csched_leaf_pct * SCALE / EXT_SCALE;

    node_len_max = sp->rp->csched_node_len_max ?: SP3_LLEN_RUNLEN_MIN;
    shared_full = sts_wcnt_get_idle(sp->sts, SP3_NUM_QUEUES) == 0;

    for (rr = 0; !job && rr < jtype_MAX; rr++) {

        /* round robin between job types */
        sp->rr_job_type++;
        if (sp->rr_job_type >= jtype_MAX)
            sp->rr_job_type = 0;

        switch (sp->rr_job_type) {

            case jtype_root:
                /* Implements root node query-shape rule.
             * Uses "intern" queue.
             */
                qi = sp->qinfo + SP3_QNUM_INTERN;
                if (qfull(qi) && shared_full)
                    break;
                job = sp3_check_roots(sp);
                break;

            case jtype_ispill:
                /* Service RBT_RI_ALEN red-black tree, which
             * contains both root and internal nodes.
             * Keeps leaf_pct above configured value.
             * Implements:
             *   - Root node space amp rule
             *   - Internal node space amp rule
             */
                qi = sp->qinfo + SP3_QNUM_INTERN;
                if (qfull(qi) && shared_full)
                    break;
                if (sp->lpct_targ < rp_leaf_pct)
                    job = sp3_check_rb_tree(sp, RBT_RI_ALEN, 0, wtype_ispill);
                break;

            case jtype_node_len:
                /* Service RBT_LI_LEN red-black tree.
             * Implements:
             *   - Internal node query-shape rule
             *   - Leaf node query-shape rule
             */
                qi = sp->qinfo + SP3_QNUM_INTERN;
                if (qfull(qi) && shared_full)
                    break;
                job = sp3_check_rb_tree(sp, RBT_LI_LEN, node_len_max, wtype_node_len);
                break;

            case jtype_leaf_garbage:
                /* Service RBT_L_GARB red-black tree.
             * Implements:
             *   - Leaf node space amp rule
             * Notes:
             *   - These are big jobs, so do not use shared
             *     workers to limit the number of concurrent
             *     big jobs to the number dedicated workers.
             */
                qi = sp->qinfo + SP3_QNUM_LEAF;
                if (qfull(qi))
                    break;
                if (sp->samp_reduce && (100 * sp->lpct_targ > 90 * rp_leaf_pct)) {
                    uint thresh = 0;

                    if (sp->lpct_targ < rp_leaf_pct)
                        thresh = 100 - sp->lpct_targ;

                    job = sp3_check_rb_tree(sp, RBT_L_GARB, thresh, wtype_leaf_garbage);
                }
                break;

            case jtype_leaf_size:
                /* Service RBT_L_PCAP red-black tree.
             * - Handles big leaf nodes with or with out garbage.
             * - NOTE: These are big jobs, so do not use shared
             *   workers.
             * Implements:
             *   - Leaf node size rule
             */
                qi = sp->qinfo + SP3_QNUM_LEAFBIG;
                if (qfull(qi))
                    break;
                job = sp3_check_rb_tree(sp, RBT_L_PCAP, 100, wtype_leaf_size);
                break;

            case jtype_leaf_scatter:
                /* Implements:
             *   - Leaf node scatter rule
             * [HSE_REVISIT]: Node length is currently not factored
             * into this metric.
             */
                if (sp->thresh.lscatter_pct == 100)
                    break;
                qi = sp->qinfo + SP3_QNUM_LSCAT;
                if (qfull(qi) && shared_full)
                    break;
                job = sp3_check_rb_tree(sp, RBT_L_SCAT, SP3_LSCAT_THRESH_MIN, wtype_leaf_scatter);
                break;
        }
    }

    return job;
}

/*
 * sp3_update_samp() - update internal space amp metrics
 *
 * Updates the following members of struct sp3:
 *
 *  sp->samp_curr
 *  sp->samp_targ
 *  sp->lpct_targ
 *  sp->lpct_curr
 *  sp->lpct_throttle
 *  sp->samp_reduce
 *  sp->comp_request
 *  sp->comp_flags
 */
static void
sp3_update_samp(struct sp3 *sp)
{
    struct cn_samp_stats targ;

    sp3_samp_target(sp, &targ);
    sp->samp_targ = samp_est(&targ, SCALE);
    sp->lpct_targ = samp_pct_leaves(&targ, SCALE);

    sp->samp_curr = samp_est(&sp->samp, SCALE);
    sp->lpct_curr = samp_pct_leaves(&sp->samp, SCALE);

    /* The leaf percent computation for throttling uses the written
     * length of root node k/vblocks instead of allocated length.
     */
    sp->lpct_throttle = throttle_pct_leaves(&sp->samp, SCALE);

    perfc_set(&sp->sched_pc, PERFC_BA_SP3_SAMP, sp->samp_targ);
    perfc_set(&sp->sched_pc, PERFC_BA_SP3_REDUCE, sp->samp_reduce);

    /* Detect completion of external compaction requests */
    if (sp->comp_request && sp->jobs_started == sp->jobs_finished) {
        if (sp->comp_flags & HSE_KVDB_COMP_FLAG_SAMP_LWM &&
            samp_est(&sp->samp, 100) < sp->samp_lwm) {
            sp->samp_reduce = false;
            sp->comp_request = false;
            sp->comp_flags = 0;
        }
    }

    /* Use low/high water marks to enable/disable garbage collection. */
    if (sp->samp_reduce) {
        if (sp->samp_targ < sp->samp_lwm) {
            sp->samp_reduce = false;
            hse_log(
                HSE_NOTICE "sp3 expected samp"
                           " %u below lwm %u,"
                           " disable samp reduction",
                sp->samp_targ * 100 / SCALE,
                sp->samp_lwm * 100 / SCALE);
        }
    } else {
        if (sp->samp_targ > sp->samp_hwm) {
            sp->samp_reduce = true;
            hse_log(
                HSE_NOTICE "sp3 expected samp"
                           " %u above hwm %u,"
                           " enable samp reduction",
                sp->samp_targ * 100 / SCALE,
                sp->samp_hwm * 100 / SCALE);
        }
    }
}

static bool
sp3_compact(struct sp3 *sp)
{
    uint   cur_jobs;
    bool   scheduled_new_job = false;
    merr_t err;

    assert(sp->jobs_started >= sp->jobs_finished);
    cur_jobs = sp->jobs_started - sp->jobs_finished;

    err = kvdb_health_check(sp->health, KVDB_HEALTH_FLAG_ALL);
    if (ev(err)) {
        hse_log(HSE_ERR "KVDB is in bad health. Need a restart");
        return false;
    }

    if (cur_jobs < sp->jobs_max)
        scheduled_new_job = sp3_schedule(sp);

    return scheduled_new_job;
}

struct periodic_check {
    u64 interval;
    u64 next;
    u64 prev;
};

static void
sp3_monitor(struct work_struct *work)
{
    struct sp3 *sp = container_of(work, struct sp3, wstruct);

    const int long_timeout_ms = 100;
    const int short_timeout_ms = 20;

    struct periodic_check chk_qos;
    struct periodic_check chk_refresh;
    struct periodic_check chk_shape;

    bool busy = false;
    u64  now;

    now = get_time_ns();

    chk_qos.interval = NSEC_PER_SEC / 5;
    chk_refresh.interval = 10 * NSEC_PER_SEC;
    chk_shape.interval = 15 * NSEC_PER_SEC;

    chk_qos.next = now + chk_qos.interval;
    chk_refresh.next = now + chk_refresh.interval;
    chk_shape.next = now + chk_shape.interval;

    sp3_refresh_settings(sp);

    while (!atomic_read(&sp->destruct)) {

        mutex_lock(&sp->mutex);
        cv_timedwait(&sp->cv, &sp->mutex, busy ? short_timeout_ms : long_timeout_ms);
        mutex_unlock(&sp->mutex);

        now = get_time_ns();

        sp3_process_worklist(sp);
        sp3_process_ingest(sp);
        sp3_process_new_trees(sp);
        sp3_prune_trees(sp);

        sp3_update_samp(sp);

        busy = sp3_compact(sp);

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
    }
}

/*****************************************************************
 *
 * External Entry Points
 *
 ****************************************************************/

static struct tbkt *
sp3_op_tbkt_maint_get(struct csched_ops *handle)
{
    return &h2sp(handle)->tbkt;
}

static void
sp3_op_throttle_sensor(struct csched_ops *handle, struct throttle_sensor *sensor)
{
    struct sp3 *sp = h2sp(handle);

    sp->throttle_sensor = sensor;
}

static void
sp3_op_compact_request(struct csched_ops *handle, int flags)
{
    struct sp3 *sp = h2sp(handle);

    if (sp->comp_request && !(flags & HSE_KVDB_COMP_FLAG_CANCEL))
        return;

    if (flags & HSE_KVDB_COMP_FLAG_CANCEL) {
        sp->comp_request = false;
    } else if (flags & HSE_KVDB_COMP_FLAG_SAMP_LWM) {
        sp->comp_request = true;
        sp->samp_reduce = true;
    }

    sp->comp_flags = flags;
}

static void
sp3_op_compact_status(struct csched_ops *handle, struct hse_kvdb_compact_status *status)
{
    struct sp3 *sp = h2sp(handle);

    status->kvcs_active = sp->comp_request;
    status->kvcs_samp_curr = samp_est(&sp->samp, 100);
    status->kvcs_samp_lwm = sp->samp_lwm * 100 / SCALE;
    status->kvcs_samp_hwm = sp->samp_hwm * 100 / SCALE;
}

/**
 * sp3_op_notify_ingest() - External API: notify ingest job has completed
 */
static void
sp3_op_notify_ingest(struct csched_ops *handle, struct cn_tree *tree, size_t alen, size_t wlen)
{
    struct sp3 *     sp = h2sp(handle);
    struct sp3_tree *spt = tree2spt(tree);

    atomic64_add(alen, &spt->spt_ingest_alen);
    atomic64_add(wlen, &spt->spt_ingest_wlen);
    atomic_inc(&spt->spt_ingest_count);

    sp3_monitor_wake(sp);
}

static void
sp3_tree_init(struct sp3_tree *spt)
{
    memset(spt, 0, sizeof(*spt));
    atomic_set(&spt->spt_enabled, 1);
}

/**
 * sp3_op_tree_add() - External API: add tree to scheduler
 */
static void
sp3_op_tree_add(struct csched_ops *handle, struct cn_tree *tree)
{
    struct sp3 *     sp = h2sp(handle);
    struct sp3_tree *spt = tree2spt(tree);

    assert(!sp3_tree_is_managed(tree));

    if (debug_tree_life(sp))
        hse_log(HSE_NOTICE "sp3 %s cnid %lu", __func__, (ulong)tree->cnid);

    cn_ref_get(tree->cn);

    sp3_tree_init(spt);

    mutex_lock(&sp->new_tlist_lock);
    list_add(&spt->spt_tlink, &sp->new_tlist);
    mutex_unlock(&sp->new_tlist_lock);

    sp3_monitor_wake(sp);
}

/**
 * sp3_op_tree_remove() - External API: remove tree from scheduler
 */
static void
sp3_op_tree_remove(struct csched_ops *handle, struct cn_tree *tree, bool cancel)
{
    struct sp3 *     sp = h2sp(handle);
    struct sp3_tree *spt = tree2spt(tree);

    if (!sp3_tree_is_managed(tree))
        return;

    if (debug_tree_life(sp))
        hse_log(HSE_NOTICE "sp3 %s cnid %lu", __func__, (ulong)tree->cnid);

    /* Disable scheduling for tree.  Monitor will remove the tree
     * out when no more jobs are pending.
     */
    atomic_set(&spt->spt_enabled, 0);

    sp3_monitor_wake(sp);
}

/**
 * sp3_op_destroy() - External API: SP3 destructor
 */
static void
sp3_op_destroy(struct csched_ops *handle)
{
    struct sp3 *sp = h2sp(handle);
    uint        tx;

    if (ev(!handle))
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

    atomic_set(&sp->destruct, 1);
    sp3_monitor_wake(sp);

    /* This is like a pthread_join for the monitor thread */
    destroy_workqueue(sp->wqueue);

    sts_destroy(sp->sts);

    cv_destroy(&sp->cv);

    mutex_destroy(&sp->work_list_lock);
    mutex_destroy(&sp->new_tlist_lock);
    mutex_destroy(&sp->mutex);

    free(sp->wp);

    perfc_ctrseti_free(&sp->sched_pc);

    free_aligned(sp);
}

/**
 * sp3_create() - External API: constructor
 */
merr_t
sp3_create(
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         mp,
    struct kvdb_health * health,
    struct csched_ops ** handle)
{
    struct sp3 *sp;
    merr_t      err;
    size_t      name_sz, alloc_sz;
    uint        tx;

    assert(rp);
    assert(mp);
    assert(handle);

    if (!rp->csched_qthreads)
        rp->csched_qthreads = CSCHED_QTHREADS_DEFAULT;

    hse_slog(
        HSE_NOTICE,
        HSE_SLOG_START("cn_threads"),
        HSE_SLOG_FIELD("intern", "%lu", (rp->csched_qthreads >> (8 * SP3_QNUM_INTERN)) & 0xff),
        HSE_SLOG_FIELD("leaf", "%lu", (rp->csched_qthreads >> (8 * SP3_QNUM_LEAF)) & 0xff),
        HSE_SLOG_FIELD("leafbig", "%lu", (rp->csched_qthreads >> (8 * SP3_QNUM_LEAFBIG)) & 0xff),
        HSE_SLOG_FIELD("leafscat", "%lu", (rp->csched_qthreads >> (8 * SP3_QNUM_LSCAT)) & 0xff),
        HSE_SLOG_FIELD("shared", "%lu", (rp->csched_qthreads >> (8 * SP3_NUM_QUEUES)) & 0xff),
        HSE_SLOG_END);

    /* Allocate cache aligned space for struct csched + sp->name */
    name_sz = strlen(mp) + 1;
    alloc_sz = sizeof(*sp) + name_sz;
    sp = alloc_aligned(alloc_sz, SMP_CACHE_BYTES, GFP_KERNEL);
    if (ev(!sp))
        return merr(ENOMEM);

    memset(sp, 0, alloc_sz);

    sp->ds = ds;
    sp->name = (void *)(sp + 1);
    strlcpy(sp->name, mp, name_sz);

    sp->rp = rp;
    sp->health = health;

    mutex_init(&sp->new_tlist_lock);
    mutex_init(&sp->work_list_lock);

    cv_init(&sp->cv, "csched");

    tbkt_init(&sp->tbkt, 0, 0);

    INIT_LIST_HEAD(&sp->mon_tlist);
    INIT_LIST_HEAD(&sp->new_tlist);
    INIT_LIST_HEAD(&sp->work_list);

    for (tx = 0; tx < RBT_MAX; tx++)
        sp->rbt[tx] = RB_ROOT;

    atomic_set(&sp->destruct, 0);

    err = sts_create(sp->rp, sp->name, SP3_NUM_QUEUES, &sp->sts);
    if (ev(err))
        goto err_exit;

    sp->wqueue = alloc_workqueue("sp3_monitor", 0, 1);
    if (ev(!sp->wqueue)) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    INIT_WORK(&sp->wstruct, sp3_monitor);
    queue_work(sp->wqueue, &sp->wstruct);

    sts_resume(sp->sts);

    sp->ops.cs_destroy = sp3_op_destroy;
    sp->ops.cs_notify_ingest = sp3_op_notify_ingest;
    sp->ops.cs_throttle_sensor = sp3_op_throttle_sensor;
    sp->ops.cs_compact_request = sp3_op_compact_request;
    sp->ops.cs_compact_status = sp3_op_compact_status;
    sp->ops.cs_tree_add = sp3_op_tree_add;
    sp->ops.cs_tree_remove = sp3_op_tree_remove;
    sp->ops.cs_tbkt_maint_get = sp3_op_tbkt_maint_get;

    if (perfc_ctrseti_alloc(
            COMPNAME, sp->name, csched_sp3_perfc, PERFC_EN_SP3, "sp3", &sp->sched_pc))
        hse_log(HSE_ERR "cannot alloc sp3 perf counters");

    *handle = &sp->ops;
    return 0;

err_exit:
    sts_destroy(sp->sts);

    cv_destroy(&sp->cv);

    mutex_destroy(&sp->work_list_lock);
    mutex_destroy(&sp->new_tlist_lock);
    mutex_destroy(&sp->mutex);

    free_aligned(sp);

    return err;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "csched_sp3_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
