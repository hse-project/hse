/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>
#include <hse_test_support/mapi_alloc_tester.h>

#include <hse_util/hse_err.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/csched_rp.h>
#include <hse_ikvdb/cn.h>

#include "../csched_ops.h"
#include "../csched_sp3.h"
#include "../csched_sp3_work.h"
#include "../cn_tree_create.h"
#include "../cn_tree_internal.h"
#include "../cn_tree_compact.h"
#include "../kvset.h"

#include "mock_kvset.h"

struct kvdb_health   health;
struct cn_kvdb       cn_kvdb;
struct kvdb_rparams *kvdb_rp, kvdb_rparams;
struct kvs_rparams * kvs_rp, kvs_rparams;
const char *         mp;
struct mpool *       ds;
struct cndb *        cndb;

#define MiB(x) ((ulong)(x) << 20)
#define GiB(x) ((ulong)(x) << 30)

#define DELAY_MS (250)

/*****************************************************************
 *
 * Support code to fabricate kvset meta data:
 *
 *   - Uses globals (not thread-safe).
 *   - Creates kvsets with fixed number of kblocks and vblocks.
 *   - Uses counter for mblock ids.
 */
struct kvset_meta km;
struct kvs_block  km_kblocks[4];
struct kvs_block  km_vblocks[4];
u64               mbid = 123456;

static struct kvset_meta *
init_kvset_meta(u64 dgen)
{
    int i;

    memset(&km, 0, sizeof(km));
    memset(&km_kblocks, 0, sizeof(km_kblocks));
    memset(&km_vblocks, 0, sizeof(km_vblocks));

    km.km_kblk_list.n_blks = NELEM(km_kblocks);
    km.km_vblk_list.n_blks = NELEM(km_vblocks);

    km.km_kblk_list.blks = km_kblocks;
    km.km_vblk_list.blks = km_vblocks;

    for (i = 0; i < km.km_kblk_list.n_blks; i++)
        km_kblocks[i].bk_blkid = mbid++;

    for (i = 0; i < km.km_vblk_list.n_blks; i++)
        km_vblocks[i].bk_blkid = mbid++;

    km.km_vused = 1000;
    km.km_dgen = dgen;

    return &km;
}

/*****************************************************************
 *
 * Support routines for building cn trees.
 *   - Uses globals (not thread-safe).
 *
 */
struct test_tree {
    struct cn_tree *tree;
    u64             dgen;
    uint            fbits;
    uint            fout;
    uint            pfx_len;
    uint            cnid;
    uint            tag;
};

#define MAX_TREES 100
struct test_tree ttv[MAX_TREES];
uint             ttc;

void
init_trees(void)
{
    memset(ttv, 0, sizeof(ttv));
    ttv->dgen = 1000;
    ttc = 0;
}

void
destroy_trees(void)
{
    uint i;

    for (i = 0; i < ttc; i++)
        cn_tree_destroy(ttv[i].tree);
    init_trees();
}

struct kvs_cparams cp;

struct test_tree *
new_tree(uint fanout)
{
    uint              pfx_len = 0;
    merr_t            err;
    struct test_tree *tt;
    uint              fbits;

    fbits = 1;
    while (fbits < 10 && (1 << fbits) != fanout)
        fbits++;

    if ((1 << fbits) != fanout)
        return 0;

    if (ttc == MAX_TREES)
        return 0;

    tt = ttv + ttc;

    cp.cp_fanout = fanout, cp.cp_pfx_len = pfx_len,

    err = cn_tree_create(&tt->tree, NULL, 0, &cp, &health, kvs_rp);
    if (err)
        return 0;

    tt->fbits = fbits;
    tt->fout = fanout;
    tt->pfx_len = pfx_len;

    tt->cnid = 1000 + ttc;
    tt->tag = 2000 + ttc;

    ttc++;

    return tt;
}

merr_t
new_kvsets(struct test_tree *tt, int n_kvsets, int lvl, int off)
{
    struct kvset *kvset;
    merr_t        err = 0;
    int           i;
    int           start_off, end_off;

    if (off == -1) {
        start_off = 0;
        end_off = (1 << (tt->fbits * lvl)) - 1;
    } else {
        start_off = off;
        end_off = off;
    }

    for (off = start_off; off <= end_off; off++) {

        for (i = 0; i < n_kvsets; i++) {

            err = kvset_create(tt->tree, tt->tag, init_kvset_meta(ttv->dgen--), &kvset);
            if (err)
                return err;

            err = cn_tree_insert_kvset(tt->tree, kvset, lvl, off);
            if (err) {
                kvset_put_ref(kvset);
                return err;
            }
        }
    }

    return err;
}

/*****************************************************************
 *
 * Mocks
 *
 */
void
job_done(struct cn_compaction_work *w, int cancel)
{
    hse_log(
        HSE_NOTICE "job %s: cnid=%lu loc=(%u,%u)",
        cancel ? "canceled" : "complete",
        w->cw_tree->cnid,
        w->cw_node->tn_loc.node_level,
        w->cw_node->tn_loc.node_offset);

    if (w->cw_have_token)
        cn_node_comp_token_put(w->cw_node);

    if (w->cw_completion)
        w->cw_completion(w);
    else
        mapi_safe_free(w);
}

void
job_cancel_cb(struct sts_job *job)
{
    job_done(container_of(job, struct cn_compaction_work, cw_job), 1);
}

void
job_cb(struct sts_job *job)
{
    job_done(container_of(job, struct cn_compaction_work, cw_job), 0);
}

void
sts_job_submit_mock(struct sts *self, struct sts_job *job)
{
    mtfm_sched_sts_sts_job_submit_fp real_fn;

    real_fn = mtfm_sched_sts_sts_job_submit_getreal();

    job->sj_job_fn = job_cb;
    job->sj_cancel_fn = job_cancel_cb;

    real_fn(self, job);
}

merr_t
sp3_work_mock(
    struct sp3_node *           spn,
    struct sp3_thresholds *     thresh,
    enum sp3_work_type          wtype,
    uint                        debug,
    uint *                      qnum_out,
    struct cn_compaction_work **w_out)
{
    struct cn_tree_node *      tn;
    struct cn_compaction_work *w;
    struct kvset_list_entry *  le;
    uint                       i;
    const char *               comptype = 0;

    *w_out = 0;
    *qnum_out = 0;
    tn = spn2tn(spn);

    /* no work */
    if (cn_ns_kvsets(&tn->tn_ns) < 4)
        return 0;

    w = mapi_safe_malloc(sizeof(*w));
    if (!w)
        return merr(ENOMEM);

    memset(w, 0, sizeof(*w));

    /* count how many kvsets and remember the oldest */
    w->cw_mark = list_last_entry(&tn->tn_kvset_list, typeof(*le), le_link);
    w->cw_kvset_cnt = cn_ns_kvsets(&tn->tn_ns);

    if (!tn->tn_parent) {

        w->cw_action = CN_ACTION_SPILL;
        *qnum_out = SP3_QNUM_INTERN;
        comptype = "rspill";

    } else {
        if (!cn_node_comp_token_get(tn))
            goto no_work;

        if (cn_node_isleaf(tn)) {
            w->cw_action = CN_ACTION_COMPACT_KV;
            *qnum_out = SP3_QNUM_LEAF;
            comptype = "kv_compact";
        } else {
            w->cw_action = CN_ACTION_SPILL;
            *qnum_out = SP3_QNUM_INTERN;
            comptype = "ispill";
        }
    }

    w->cw_dgen_lo = kvset_get_dgen(w->cw_mark->le_kvset);
    le = w->cw_mark;
    for (i = 0; i < w->cw_kvset_cnt; i++) {
        w->cw_dgen_hi = kvset_get_dgen(le->le_kvset);
        w->cw_nk += kvset_get_num_kblocks(le->le_kvset);
        w->cw_nv += kvset_get_num_vblocks(le->le_kvset);
        le = list_prev_entry(le, le_link);
    }

    w->cw_debug = 1;
    w->cw_tree = tn->tn_tree;
    w->cw_node = tn;
    w->cw_ds = tn->tn_tree->ds;
    w->cw_rp = tn->tn_tree->rp;
    w->cw_pfx_len = tn->tn_tree->ct_cp->cp_pfx_len;

    hse_log(
        HSE_DEBUG "%s(cnid=%lu loc=(%u,%u), action=%s",
        __func__,
        tn->tn_tree->cnid,
        tn->tn_loc.node_level,
        tn->tn_loc.node_offset,
        comptype);

    *w_out = w;
    return 0;

no_work:
    mapi_safe_free(w);
    *w_out = 0;
    return 0;
}

void
cn_node_stats_get_mock(const struct cn_tree_node *tn, struct cn_node_stats *s)
{
    memset(s, 0, sizeof(*s));

    s->ns_keys_uniq = 100 * 1000;
    s->ns_scatter = 10;
}

void
mock_init(void)
{
    mapi_inject_clear();

    mock_kvset_set();

    mapi_inject_ptr(mapi_idx_cn_get_io_wq, NULL);

    mapi_inject(mapi_idx_cn_ref_get, 0);
    mapi_inject(mapi_idx_cn_ref_put, 0);

    MOCK_SET_FN(csched_sp3_work, sp3_work, sp3_work_mock);

    MOCK_SET_FN(sched_sts, sts_job_submit, sts_job_submit_mock);

    MOCK_SET_FN(cn_tree_internal, cn_node_stats_get, cn_node_stats_get_mock);
}

/*****************************************************************
 *
 * Pre/Post Routines
 *
 */
int
pre_collection(struct mtf_test_info *info)
{
    hse_log_set_verbose(true);
    hse_log_set_pri(HSE_DEBUG_VAL);
    return 0;
}

static void
reset_state(void)
{
    memset(&health, 0, sizeof(health));

    memset(&cn_kvdb, 0, sizeof(cn_kvdb));

    kvdb_rparams = kvdb_rparams_defaults();
    kvdb_rp = &kvdb_rparams;

    kvdb_rp->csched_debug_mask = U64_MAX;

    kvs_rparams = kvs_rparams_defaults();
    kvs_rp = &kvs_rparams;

    init_trees();
}

static int
pre_test(struct mtf_test_info *ti)
{
    mp = "baton";
    reset_state();
    mock_init();

    return 0;
}

void
add_tree(struct cn_tree *tree, struct csched_ops *ops)
{
    u64 cnt;
    u32 api;

    api = mapi_idx_cn_ref_get;
    cnt = mapi_calls(api);

    ops->cs_tree_add(ops, tree);

    while (mapi_calls(api) == cnt)
        msleep(20);
}

void
remove_tree(struct cn_tree *tree, struct csched_ops *ops)
{
    u64 cnt;
    u32 api;

    api = mapi_idx_cn_ref_put;
    cnt = mapi_calls(api);

    ops->cs_tree_remove(ops, tree, false);

    while (mapi_calls(api) == cnt)
        msleep(20);
}

/*****************************************************************
 *
 * Unit tests
 *
 */

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

MTF_DEFINE_UTEST_PRE(test, t_sp3_create, pre_test)
{
    struct csched_ops *ops;
    merr_t             err;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);
    ops->cs_destroy(0);
    ops->cs_destroy(ops);

    kvdb_rp->csched_qthreads = 1;
    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);
    ops->cs_destroy(ops);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_create_nomem, pre_test)
{
    struct csched_ops *ops = 0;
    merr_t             err = merr(EBUG);
    int                rc;

    mapi_inject(mapi_idx_sts_perfc_alloc, 0);
    mapi_inject(mapi_idx_sts_perfc_free, 0);
    mapi_inject(mapi_idx_perfc_ctrseti_alloc, 0);

    void run(struct mtf_test_info * lcl_ti, uint i, uint j)
    {
        err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
        if (i == j)
            ASSERT_EQ(err, 0);
        else
            ASSERT_EQ(merr_errno(err), ENOMEM);
    }

    void clean(struct mtf_test_info * lcl_ti)
    {
        /* Note: parent function local vars are preserved from
         * previous call to run().
         */
        if (!err)
            ops->cs_destroy(ops);
        ops = 0;
    }

    rc = mapi_alloc_tester(lcl_ti, run, clean);
    ASSERT_EQ(rc, 0);

    mapi_inject_unset(mapi_idx_sts_perfc_alloc);
    mapi_inject_unset(mapi_idx_sts_perfc_free);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_create_fail, pre_test)
{
    struct csched_ops *ops;
    merr_t             err;

    mapi_inject(mapi_idx_sts_create, 1234);
    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 1234);
    mapi_inject_unset(mapi_idx_sts_create);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_empty_tree, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched_ops *ops;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    add_tree(tt->tree, ops);

    msleep(DELAY_MS);

    remove_tree(tt->tree, ops);

    destroy_trees();
    ops->cs_destroy(ops);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_many_empty_trees, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched_ops *ops;
    uint               num_trees = 50;
    uint               fanouts[] = { 2, 4, 8, 16 };
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);

    for (i = 0; i < num_trees; i++) {
        tt = new_tree(fanouts[i % NELEM(fanouts)]);
        ASSERT_NE(tt, NULL);
    }

    for (i = 0; i < num_trees; i++)
        add_tree(ttv[i].tree, ops);

    msleep(DELAY_MS);

    for (i = 0; i < num_trees; i++)
        remove_tree(ttv[i].tree, ops);

    destroy_trees();

    ops->cs_destroy(ops);
}

#define SP3_NODE_LEN_THRESH 32

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_small_tree_with_work, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched_ops *ops;
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 0, 0);
    ASSERT_EQ(err, 0);

    for (i = 0; i < ttc; i++)
        add_tree(ttv[i].tree, ops);

    msleep(DELAY_MS);

    for (i = 0; i < ttc; i++)
        remove_tree(ttv[i].tree, ops);

    destroy_trees();

    ops->cs_destroy(ops);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_medium_tree_with_work, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched_ops *ops;
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 0, 0);
    ASSERT_EQ(err, 0);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 1, -1);
    ASSERT_EQ(err, 0);

    for (i = 0; i < ttc; i++)
        add_tree(ttv[i].tree, ops);

    msleep(DELAY_MS);

    for (i = 0; i < ttc; i++)
        remove_tree(ttv[i].tree, ops);

    destroy_trees();

    ops->cs_destroy(ops);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_big_tree_with_work, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched_ops *ops;
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 0, 0);
    ASSERT_EQ(err, 0);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 2, 1, -1);
    ASSERT_EQ(err, 0);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 3, 2, -1);
    ASSERT_EQ(err, 0);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 4, 3, -1);
    ASSERT_EQ(err, 0);

    for (i = 0; i < ttc; i++)
        add_tree(ttv[i].tree, ops);

    msleep(DELAY_MS);

    for (i = 0; i < ttc; i++)
        remove_tree(ttv[i].tree, ops);

    destroy_trees();

    ops->cs_destroy(ops);
}

MTF_END_UTEST_COLLECTION(test);
