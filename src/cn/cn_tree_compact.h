/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_COMPACT_H
#define HSE_KVDB_CN_CN_TREE_COMPACT_H

#include <hse_util/atomic.h>
#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/workqueue.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/sched_sts.h>

#include "cn_metrics.h"
#include "kcompact.h"

/* MTF_MOCK_DECL(cn_tree_compact) */

struct cn_tree;
struct cn_tree_node;
struct kv_iterator;
struct kvset_list_entry;
struct kvset_mblocks;
struct kvset;

enum cn_action {
    CN_ACTION_NONE = 0,
    CN_ACTION_COMPACT_K,
    CN_ACTION_COMPACT_KV,
    CN_ACTION_SPILL,
    CN_ACTION_END,
};

enum cn_comp_rule {
    CN_CR_NONE = 0,
    CN_CR_SPILL,          /* normal spill */
    CN_CR_SPILL_ONE,      /* spill a single kvset b/c it was large */
    CN_CR_SPILL_TINY,     /* spill many small kvsets */
    CN_CR_LBIG,           /* big leaf (near pop threshold) */
    CN_CR_LBIG_ONE,       /* big leaf, compact one kvset */
    CN_CR_LGARB,          /* leaf garbage (reducing space amp) */
    CN_CR_LLONG,          /* long leaf */
    CN_CR_LLONG_SCATTER,  /* long leaf, with high vblk scatter */
    CN_CR_LSHORT_LW,      /* short leaf, light weight */
    CN_CR_LSHORT_IDLE,    /* short leaf, idle */
    CN_CR_LSHORT_IDLE_VG, /* short leaf, idle, vblk groups */
    CN_CR_LSCATTER,       /* leaf vblk scatter */
    CN_CR_END,
};

static inline const char *
cn_action2str(enum cn_action action)
{
    switch (action) {

        case CN_ACTION_NONE:
        case CN_ACTION_END:
            break;

        case CN_ACTION_COMPACT_K:
            return "kcomp";
        case CN_ACTION_COMPACT_KV:
            return "kvcomp";
        case CN_ACTION_SPILL:
            return "spill";
    }

    return "unknown_action";
}

static inline const char *
cn_comp_rule2str(enum cn_comp_rule rule)
{
    switch (rule) {

        case CN_CR_NONE:
        case CN_CR_END:
            break;

        case CN_CR_SPILL:
            return "spill";
        case CN_CR_SPILL_ONE:
            return "spill_one";
        case CN_CR_SPILL_TINY:
            return "spill_tiny";
        case CN_CR_LBIG:
            return "big";
        case CN_CR_LBIG_ONE:
            return "big_one";
        case CN_CR_LGARB:
            return "garbage";
        case CN_CR_LLONG:
            return "long";
        case CN_CR_LLONG_SCATTER:
            return "longscat";
        case CN_CR_LSHORT_LW:
            return "short_lw";
        case CN_CR_LSHORT_IDLE:
            return "idle";
        case CN_CR_LSHORT_IDLE_VG:
            return "idle_vg";
        case CN_CR_LSCATTER:
            return "scatter";
    }

    return "unknown_rule";
}

#define CW_DEBUG_ROOT 0x01 /* include ingest and root spills */
#define CW_DEBUG_PROGRESS 0x02

typedef void (*cn_work_callback)(struct cn_compaction_work *w);

/**
 * struct cn_work_est - compaction work estimate
 * @cwe_samp: estimate of this jobs effect on space amp
 * @cwe_read_sz:  estimate of number of bytes read by this job
 * @cwe_write_sz: estimate of number of bytes written by this job
 */
struct cn_work_est {
    struct cn_samp_stats cwe_samp;
    s64                  cwe_read_sz;  /* must be signed */
    s64                  cwe_write_sz; /* must be signed */
    u64                  cwe_keys;
};

/**
 * struct cn_compaction_work - control structure for cn tree compaction
 *
 * @cw_work:         for linking into workqueues
 * @cw_tree:         cn tree
 * @cw_node:         node within cn tree
 * @cw_mark:         oldest kvset to be compacted
 * @cw_kvset_cnt:    number of kvsets to be compacted
 * @cw_action:       spill, k-compact, or kv-compact
 * @cw_rspill_link:  for adding struct to root node's list of completed spills
 * @cw_rspill_done:  if set, then root spill compaction work is done
 * @cw_rspill_busy:  if set, then root spill compaction work is done and the
 *                       tree is being updated with this work
 * @cw_dgen_hi:      the dgen of the newest kvset to be compacted
 * @cw_dgen_lo:      the dgen of the oldest kvset to be compacted
 * @cw_active_count: for tracking the number of active "root" or "other" threads
 * @cw_horizon:      sequence number horizon to use while compacting
 * @cw_debug:        enables debug stats
 * @cw_outc:         number of output kvsets
 * @cw_outv:         outputs (mblock ids used to make output kvsets)
 * @cw_inputv:       number of input kvsets
 * @cw_vbmap:        tracks vblocks that are transferred from intput to output
 *                       kvsets during k-compaction
 * @cw_hash_shift:   used to determine output child when spilling
 * @cw_drop_tombv:   if true, then tombstones can be dropped in the merge loop
 * @cw_work_txid:    the cndb transaction id
 * @cw_commitc:      keeps track of how many output mblocks have been committed
 * @cw_keep_vblks:   indicates whether or not vblocks should be deleted or
 *                   if they should transferred from input kvsets to
 *                   output kvets (e.g., in k-compaction).
 * @cw_tagv:         uniquely identify kvsets for cndb journal
 * @cw_stats:        debug stats
 * @cw_t0_enqueue:   debug stats
 * @cw_t1_qtime:     debug stats
 * @cw_t2_prep:      debug stats
 * @cw_t3_build:     debug stats
 * @cw_t4_commit:    debug stats
 * @cw_t5_update:    debug stats
 */
struct cn_compaction_work {

    /* initialized in cn_compaction() */
    struct work_struct       cw_work;
    u64                      cw_horizon;
    uint                     cw_iter_flags;
    uint                     cw_debug;
    bool                     cw_canceled;
    merr_t                   cw_err;
    struct workqueue_struct *cw_io_workq;
    struct perfc_set *       cw_pc;
    atomic_t *               cw_cancel_request;
    struct mpool *           cw_ds;
    struct kvs_rparams *     cw_rp;
    struct kvs_cparams *     cw_cp;

    /* initialized in constructor (cn_tree_find_compaction_candidate) */
    struct cn_tree *         cw_tree;
    struct cn_tree_node *    cw_node;
    struct kvset_list_entry *cw_mark;
    struct cn_node_stats     cw_ns;
    uint                     cw_kvset_cnt;
    uint                     cw_nk;
    uint                     cw_nv;
    uint                     cw_compc;
    uint                     cw_pfx_len;
    enum cn_action           cw_action;
    enum cn_comp_rule        cw_comp_rule;
    bool                     cw_have_token;
    bool                     cw_rspill_conc;
    struct list_head         cw_rspill_link;
    atomic_t                 cw_rspill_done;
    atomic_t                 cw_rspill_busy;
    u64                      cw_dgen_hi;
    u64                      cw_dgen_lo;
    atomic_t *               cw_bonus;

    /* For scheduler */
    struct sts_job        cw_job;
    cn_work_callback      cw_completion;
    cn_work_callback      cw_progress;
    void *                cw_sched;
    struct list_head      cw_sched_link;
    struct cn_samp_stats  cw_samp_pre;
    struct cn_samp_stats  cw_samp_post;
    struct cn_work_est    cw_est;
    struct cn_merge_stats cw_stats;
    struct cn_merge_stats cw_stats_prev;

    /* Progress tracking */
    u64 cw_prog_interval;

    /* initialized in cn_tree_prepare_compaction () */
    uint                  cw_outc;
    struct kvset_mblocks *cw_outv;
    struct kv_iterator ** cw_inputv;
    struct kvset_vblk_map cw_vbmap;
    u32                   cw_hash_shift;
    bool *                cw_drop_tombv;

    /* initialized in cn_compaction_worker() */
    u64                   cw_work_txid;
    uint                  cw_commitc;
    bool                  cw_keep_vblks;
    u64 *                 cw_tagv;
    struct kvset_builder *cw_child[CN_FANOUT_MAX];

    /* used in cleanup if debug enabled */
    u64  cw_t0_enqueue;
    u64  cw_t1_qtime;
    u64  cw_t2_prep;
    u64  cw_t3_build;
    u64  cw_t4_commit;
    char cw_threadname[16];
};

/* MTF_MOCK */
void
cn_tree_ingest_update(
    struct cn_tree *tree,
    struct kvset *  kvset,
    void *          ptomb,
    uint            ptlen,
    u64             ptseq);

/* MTF_MOCK */
void
cn_tree_capped_compact(struct cn_tree *tree);

/* MTF_MOCK */
bool
cn_node_comp_token_get(struct cn_tree_node *tn);

/* MTF_MOCK */
void
cn_node_comp_token_put(struct cn_tree_node *tn);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_tree_compact_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
