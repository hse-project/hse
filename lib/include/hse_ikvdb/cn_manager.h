/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_CN_MANAGER_H
#define HSE_IKVS_CN_MANAGER_H

#include <error/merr.h>

#include <hse_ikvdb/cn.h>

/*
 * This interface exposes too many CN internals.  As such, it is only
 * use for CN Version1 (i.e., not the new "treeish" CN).
 */
struct cn_manager;
struct kvset;
struct kvblock;

struct cn_block_iterator_context {
    void *             blob;
    struct cn_manager *cnm;
    struct kvset *     kvset;
    struct kvblock *   kvb;
    s32                index;
    s32                kvset_index;
    s32                kvb_index;
    bool               kvset_end;
    bool               cn_end;
};

/**
 * struct cn_compaction_manual - Describes a manual CN compaction
 * @cp_max_steps: max number of merge steps
 * @cp_min_input_kvsets: min number of kvsets needed before compacting
 * @cp_max_input_kvsets: max number of input kvsets for a single merge step
 * @cp_max_concurrency: max number of concurrent merges
 */
struct cn_compaction_manual {
    u32 cp_max_steps;
    u32 cp_min_input_kvsets;
    u32 cp_max_input_kvsets;
    u32 cp_max_concurrency;
};

struct cn_manager_ops {

    int (*cn_run_manual_compaction)(struct cn_manager *cnm, struct cn_compaction_manual *steps_in);

    void (*cn_get_manual_compaction_status)(struct cn_manager *cnm, u64 *num_steps_pending);

    void (*cn_foreach_block)(
        struct cn_manager *cn_manager,
        void (*callback)(struct cn_block_iterator_context *),
        void *blob);
};

struct cn_manager {
    struct cn_manager_ops *ops;
    struct cn *            cn;
    struct mpool *         mpool;
};

merr_t
cn_manager_open(struct cn_manager **manager_out, struct cn *cn);

merr_t
cn_manager_close(struct cn_manager *manager);

#endif
