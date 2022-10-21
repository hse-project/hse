/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_INTERNAL_H
#define HSE_KVS_CN_INTERNAL_H

struct cn_tree;
struct kvs_rparams;
struct cndb;
struct ikvdb;
struct kvdb_health;
struct csched;

#include <hse_util/atomic.h>
#include <hse_util/workqueue.h>
#include <hse_util/inttypes.h>
#include <hse_util/token_bucket.h>
#include <hse_util/perfc.h>

#include <hse/limits.h>
#include <hse/mpool/mpool.h>

struct cn {
    struct cn_tree *  cn_tree;
    struct perfc_set  cn_pc_get;
    struct cn_kvdb *  cn_kvdb;
    struct mpool *    cn_dataset;
    struct cndb *     cn_cndb;
    struct tbkt *     cn_tbkt_maint;
    u64               cn_cnid;

    atomic_ulong cn_ingest_dgen;

    atomic_int cn_refcnt;
    bool       cn_replay;

    /* for asynchronous mblock I/O */
    struct workqueue_struct *cn_io_wq;

    /* perf counters */
    struct perfc_set cn_pc_ingest;
    struct perfc_set cn_pc_spill;
    struct perfc_set cn_pc_kcompact;
    struct perfc_set cn_pc_kvcompact;
    struct perfc_set cn_pc_split;
    struct perfc_set cn_pc_join;

    uint             cn_pc_shape_next;
    struct perfc_set cn_pc_shape_rnode;
    struct perfc_set cn_pc_shape_lnode;
    struct perfc_set cn_pc_capped;

    /* for maintenance work */
    struct workqueue_struct *cn_maint_wq;
    struct delayed_work      cn_maint_dwork;
    atomic_int               cn_maint_cancel;
    bool                     cn_maint_running;

    struct kvs_rparams *  rp;
    struct kvs_cparams *  cp;
    struct ikvdb *        ikvdb;
    struct csched *       csched;
    struct kvdb_health *  cn_kvdb_health;
    struct mclass_policy *cn_mpolicy;

    u32 cn_cflags;

    const char *cn_kvdb_alias;
    const char *cn_kvs_name;

    struct mpool_props cn_mpool_props;
};

#endif
