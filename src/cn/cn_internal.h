/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_INTERNAL_H
#define HSE_KVS_CN_INTERNAL_H

struct cn_tree;
struct mpool;
struct kvs_rparams;
struct cndb;
struct ikvdb;
struct kvdb_health;
struct csched;

#include <hse_util/atomic.h>
#include <hse_util/workqueue.h>
#include <hse_util/inttypes.h>
#include <hse_util/mutex.h>
#include <hse_util/token_bucket.h>
#include <hse_util/perfc.h>

#include <hse/hse_limits.h>

struct cn {
    struct cn_tree *  cn_tree;
    struct perfc_set  cn_pc_get;
    struct cn_kvdb *  cn_kvdb;
    struct cn_tstate *cn_tstate;
    struct mpool *    cn_dataset;
    struct cndb *     cn_cndb;
    struct tbkt *     cn_tbkt_maint;
    u64               cn_cnid;
    u64               cn_hash;

    __aligned(SMP_CACHE_BYTES) atomic64_t cn_ingest_dgen;

    atomic_t cn_refcnt;
    bool     cn_closing;
    bool     cn_replay;

    /* for asynchronous mblock I/O */
    struct workqueue_struct *cn_io_wq;

    /* perf counters */
    struct perfc_set cn_pc_ingest;
    struct perfc_set cn_pc_spill;
    struct perfc_set cn_pc_kcompact;
    struct perfc_set cn_pc_kvcompact;

    uint             cn_pc_shape_next;
    struct perfc_set cn_pc_shape_rnode;
    struct perfc_set cn_pc_shape_inode;
    struct perfc_set cn_pc_shape_lnode;
    struct perfc_set cn_pc_capped;
    struct perfc_set cn_pc_mclass;

    /* for maintenance work */
    struct workqueue_struct *cn_maint_wq;
    struct work_struct       cn_maintenance_work;
    atomic_t                 cn_maint_cancel;
    bool                     cn_maintenance_stop;

    struct kvs_rparams *  rp;
    struct kvs_cparams *  cp;
    struct ikvdb *        ikvdb;
    struct csched *       csched;
    struct kvdb_health *  cn_kvdb_health;
    struct mclass_policy *cn_mpolicy;

    u32 cn_cflags;

    char cn_mpname[HSE_KVS_NAME_LEN_MAX];
    char cn_kvsname[HSE_KVS_NAME_LEN_MAX];

    struct mpool_params cn_mpool_params;
};

#endif
