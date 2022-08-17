
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_CN_TREE_COMPACT_H
#define HSE_KVDB_CN_CN_TREE_COMPACT_H

#include <hse_util/atomic.h>
#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/workqueue.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/csched.h>
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
    CN_ACTION_SPLIT,
};

static inline const char *
cn_action2str(enum cn_action action)
{
    switch (action) {
    case CN_ACTION_NONE:
        return "none";
    case CN_ACTION_COMPACT_K:
        return "kcomp";
    case CN_ACTION_COMPACT_KV:
        return "kvcomp";
    case CN_ACTION_SPILL:
        return "spill";
    case CN_ACTION_SPLIT:
        return "split";
    }

    return "invalid";
}

/* compaction work debug flags */
enum {
    CW_DEBUG_START    = 0x01, /* enable cn_comp_start log messages */
    CW_DEBUG_PROGRESS = 0x02, /* enable cn_comp_stats type=progress log messages */
    CW_DEBUG_FINAL    = 0x04, /* enable cn_comp_stats type=final log messages */
    CW_DEBUG_SPLIT    = 0x08  /* enable cn_comp_stats type=split log messages */
};

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
 * @cw_debug:        enables debug stats
 * @cw_resched:      csched should reschedule sp3_work() if true
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
 * @cw_outc:         number of output kvsets
 * @cw_outv:         outputs (mblock ids used to make output kvsets)
 * @cw_inputv:       number of input kvsets
 * @cw_vbmap:        tracks vblocks that are transferred from intput to output
 *                       kvsets during k-compaction
 * @cw_drop_tombs:   if true, then tombstones can be dropped in the merge loop
 * @cw_work_txid:    the cndb transaction id
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
    struct work_struct       cw_work;
    u64                      cw_horizon;
    uint                     cw_iter_flags;
    uint                     cw_debug;
    bool                     cw_canceled;
    bool                     cw_resched;
    uint8_t                  cw_qnum;
    merr_t                   cw_err;
    struct workqueue_struct *cw_io_workq;
    struct perfc_set *       cw_pc;
    atomic_int              *cw_cancel_request;
    struct mpool *           cw_mp;
    struct kvs_rparams *     cw_rp;
    struct kvs_cparams *     cw_cp;

    uint64_t                 cw_sgen;
    struct cn_tree *         cw_tree;
    struct cn_tree_node *    cw_node;
    struct kvset_list_entry *cw_mark;
    struct cn_node_stats     cw_ns;
    uint                     cw_kvset_cnt;
    uint32_t                 cw_nh;
    uint32_t                 cw_nk;
    uint32_t                 cw_nv;
    uint                     cw_compc;
    uint32_t                 cw_input_vgroups;
    uint                     cw_pfx_len;
    enum cn_action           cw_action;
    enum cn_rule             cw_rule;
    bool                     cw_have_token;
    struct list_head         cw_rspill_link;
    atomic_int               cw_rspill_commit_in_progress;
    u64                      cw_dgen_hi;
    u64                      cw_dgen_lo;

    /* For scheduler */
    struct sts_job        cw_job;
    cn_work_callback      cw_checkpoint;
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

    uint                     cw_outc;
    bool                     cw_drop_tombs;
    uint64_t                *cw_kvsetidv;
    struct kvset_mblocks    *cw_outv;
    struct kv_iterator     **cw_inputv;
    struct cn_tree_node    **cw_output_nodev;
    struct vgmap           **cw_vgmap; /* used during k-compact and split */
    struct kvset_vblk_map    cw_vbmap; /* used only during k-compact */
    bool                     cw_keep_vblks;

    /* Used only for node split */
    struct {
        void                 *key;       /* split key for this node */
        struct blk_list      *commit;    /* mblocks to commit - a list per output kvset */
        struct blk_list      *purge;     /* mblocks to purge - a list per source kvset */
        uint64_t             *dgen;      /* dgen array - one entry per output kvset */
        uint32_t             *compc;     /* compc array - one entry per output kvset */
        struct cn_tree_node  *nodev[2];  /* node split output nodes */
        uint                  klen;      /* split key length */
    } cw_split;

    /* used in cleanup if debug enabled */
    u64  cw_t0_enqueue;
    u64  cw_t1_qtime;
    u64  cw_t2_prep;
    u64  cw_t3_build;
    u64  cw_t4_commit;
    u64  cw_t5_finish;
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

#if HSE_MOCKING
#include "cn_tree_compact_ut.h"
#endif /* HSE_MOCKING */

#endif
