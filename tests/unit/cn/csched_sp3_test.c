/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>
#include <mock/alloc_tester.h>

#include <error/merr.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/csched_rp.h>
#include <hse_ikvdb/cn.h>

#include <cn/csched_sp3.h>
#include <cn/csched_sp3_work.h>
#include <cn/cn_tree_create.h>
#include <cn/cn_tree_internal.h>
#include <cn/cn_tree_compact.h>
#include <cn/kvset.h>

#include <mocks/mock_kvset.h>

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

    cp.pfx_len = pfx_len;

    err = cn_tree_create(&tt->tree, NULL, 0, &cp, &health, kvs_rp);
    if (err)
        return 0;

    tt->fbits = fbits;
    tt->fout = fanout;
    tt->pfx_len = pfx_len;

    tt->cnid = 1000 + ttc;
    tt->tag = 2000 + ttc;

    ttc++;

    for (int i = 0; i < fanout; i++) {
        struct cn_tree_node *tn;

        tn = cn_node_alloc(tt->tree, i + 1);
        if (!tn)
            return NULL;

        list_add_tail(&tn->tn_link, &tt->tree->ct_nodes);
    }

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

            err = kvset_open(tt->tree, tt->tag, init_kvset_meta(ttv->dgen--), &kvset);
            if (err)
                return err;

            err = cn_tree_insert_kvset(tt->tree, kvset, lvl + off);
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
    log_info(
        "job %s: cnid=%lu nodeid=%lu",
        cancel ? "canceled" : "complete",
        w->cw_tree->cnid,
        w->cw_node->tn_nodeid);

    if (w->cw_have_token)
        cn_node_comp_token_put(w->cw_node);

    if (w->cw_completion)
        w->cw_completion(w);
    else
        mapi_safe_free(w);
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

    real_fn(self, job);
}

merr_t
sp3_work_mock(
    struct sp3_node            *spn,
    enum sp3_work_type          wtype,
    struct sp3_thresholds      *thresh,
    uint                        debug,
    struct cn_compaction_work **w_out)
{
    struct cn_tree_node *      tn;
    struct cn_compaction_work *w;
    struct kvset_list_entry *  le;
    uint                       i;
    const char *               comptype = 0;

    *w_out = 0;
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

    if (cn_node_isroot(tn)) {

        w->cw_action = CN_ACTION_SPILL;
        comptype = "rspill";

    } else {
        if (!cn_node_comp_token_get(tn))
            goto no_work;

        w->cw_action = CN_ACTION_COMPACT_KV;
        comptype = "kv_compact";
    }

    w->cw_dgen_lo = kvset_get_dgen(w->cw_mark->le_kvset);
    le = w->cw_mark;
    for (i = 0; i < w->cw_kvset_cnt; i++) {
        w->cw_dgen_hi = kvset_get_dgen(le->le_kvset);
        w->cw_nh++; /* Only ever one hblock per kvset */
        w->cw_nk += kvset_get_num_kblocks(le->le_kvset);
        w->cw_nv += kvset_get_num_vblocks(le->le_kvset);
        le = list_prev_entry(le, le_link);
    }

    w->cw_debug = 1;
    w->cw_tree = tn->tn_tree;
    w->cw_node = tn;
    w->cw_mp = tn->tn_tree->mp;
    w->cw_rp = tn->tn_tree->rp;
    w->cw_pfx_len = tn->tn_tree->ct_cp->pfx_len;

    log_debug("cnid=%lu nodeid=%lu, action=%s",
              tn->tn_tree->cnid, tn->tn_nodeid, comptype);

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
}

/* Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
struct mapi_injection inject_list[] = {
    { mapi_idx_cn_get_io_wq, MAPI_RC_PTR, NULL },
    { mapi_idx_cn_ref_get, MAPI_RC_SCALAR, 0 },
    { mapi_idx_cn_ref_put, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvset_get_vgroups, MAPI_RC_SCALAR, 0 },
    { -1 },
};

void
mock_init(void)
{
    mapi_inject_clear();

    mock_kvset_set();

    mapi_inject_list_set(inject_list);

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
add_tree(struct cn_tree *tree, struct csched *cs)
{
    u64 cnt;
    u32 api;

    api = mapi_idx_cn_ref_get;
    cnt = mapi_calls(api);

    sp3_tree_add(cs, tree);

    while (mapi_calls(api) == cnt)
        usleep(20 * 1000);
}

void
remove_tree(struct cn_tree *tree, struct csched *cs)
{
    u64 cnt;
    u32 api;

    api = mapi_idx_cn_ref_put;
    cnt = mapi_calls(api);

    sp3_tree_remove(cs, tree, false);

    while (mapi_calls(api) == cnt)
        usleep(20 * 1000);
}

/*****************************************************************
 *
 * Unit tests
 *
 */

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

MTF_DEFINE_UTEST_PRE(test, t_sp3_create, pre_test)
{
    struct csched *cs;
    merr_t err;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 0);
    sp3_destroy(0);
    sp3_destroy(cs);

    kvdb_rp->csched_qthreads = 1;
    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 0);
    sp3_destroy(cs);
}

#ifndef __clang__
MTF_DEFINE_UTEST_PRE(test, t_sp3_create_nomem, pre_test)
{
    struct csched *cs = NULL;
    merr_t err = merr(EBUG);
    int rc;

    mapi_inject(mapi_idx_perfc_alloc_impl, 0);

    void run(struct mtf_test_info * lcl_ti, uint i, uint j)
    {
        err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
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
            sp3_destroy(cs);
        cs = NULL;
    }

    rc = mapi_alloc_tester(lcl_ti, run, clean);
    ASSERT_EQ(rc, 0);

    mapi_inject_unset(mapi_idx_perfc_alloc_impl);
}
#endif

MTF_DEFINE_UTEST_PRE(test, t_sp3_create_fail, pre_test)
{
    struct csched *cs;
    merr_t err;

    mapi_inject(mapi_idx_sts_create, 1234);
    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 1234);
    mapi_inject_unset(mapi_idx_sts_create);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_empty_tree, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched     *cs;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    add_tree(tt->tree, cs);

    usleep(DELAY_MS * 1000);

    remove_tree(tt->tree, cs);

    destroy_trees();
    sp3_destroy(cs);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_many_empty_trees, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched     *cs;
    uint               num_trees = 50;
    uint               fanouts[] = { 2, 4, 8, 16 };
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 0);

    for (i = 0; i < num_trees; i++) {
        tt = new_tree(fanouts[i % NELEM(fanouts)]);
        ASSERT_NE(tt, NULL);
    }

    for (i = 0; i < num_trees; i++)
        add_tree(ttv[i].tree, cs);

    usleep(DELAY_MS * 1000);

    for (i = 0; i < num_trees; i++)
        remove_tree(ttv[i].tree, cs);

    destroy_trees();

    sp3_destroy(cs);
}

#define SP3_NODE_LEN_THRESH 32

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_small_tree_with_work, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched     *cs;
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 0, 0);
    ASSERT_EQ(err, 0);

    for (i = 0; i < ttc; i++)
        add_tree(ttv[i].tree, cs);

    usleep(DELAY_MS * 1000);

    for (i = 0; i < ttc; i++)
        remove_tree(ttv[i].tree, cs);

    destroy_trees();

    sp3_destroy(cs);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_medium_tree_with_work, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched     *cs;
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 0, 0);
    ASSERT_EQ(err, 0);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 1, -1);
    ASSERT_EQ(err, 0);

    for (i = 0; i < ttc; i++)
        add_tree(ttv[i].tree, cs);

    usleep(DELAY_MS * 1000);

    for (i = 0; i < ttc; i++)
        remove_tree(ttv[i].tree, cs);

    destroy_trees();

    sp3_destroy(cs);
}

MTF_DEFINE_UTEST_PRE(test, t_sp3_one_big_tree_with_work, pre_test)
{
    merr_t             err;
    struct test_tree * tt;
    struct csched     *cs;
    uint               i;

    err = sp3_create(NULL, kvdb_rp, mp, &health, &cs);
    ASSERT_EQ(err, 0);

    tt = new_tree(4);
    ASSERT_NE(tt, NULL);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 1, 0, 0);
    ASSERT_EQ(err, 0);

    err = new_kvsets(tt, SP3_NODE_LEN_THRESH + 2, 1, -1);
    ASSERT_EQ(err, 0);

    for (i = 0; i < ttc; i++)
        add_tree(ttv[i].tree, cs);

    usleep(DELAY_MS * 1000);

    for (i = 0; i < ttc; i++)
        remove_tree(ttv[i].tree, cs);

    destroy_trees();

    sp3_destroy(cs);
}

MTF_END_UTEST_COLLECTION(test);
