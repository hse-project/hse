/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/conditions.h>
#include <mtf/framework.h>
#include <mock/api.h>

#include <hse_util/inttypes.h>
#include <hse_util/logging.h>
#include <hse_util/atomic.h>

#include <mpool/mpool.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvs_rparams.h>

#include <cn/blk_list.h>
#include <cn/cn_internal.h>
#include <cn/cn_tree.h>
#include <cn/cn_tree_create.h>
#include <cn/cn_tree_internal.h>
#include <cn/cn_mblocks.h>
#include <cn/kvset.h>

static struct mpool *mock_ds = (void *)-1;

static struct kvdb_health mock_health;

static u64 mblk_id = 1000000;

struct injections {
    u64 rc;
    u32 api;
};

struct injections injections[] = {

    /* kvset */
    { 0, mapi_idx_kvset_open },
    { 0, mapi_idx_kvset_put_ref },
    { 0, mapi_idx_kvset_get_ref },
    { 0, mapi_idx_kvset_delete_log_record },
    { 0, mapi_idx_kvset_mark_mblocks_for_delete },
    { 0, mapi_idx_kvset_get_hlog },
    { 123, mapi_idx_kvset_get_dgen },

    /* cndb */
    { 0, mapi_idx_cndb_record_txstart },
    { 0, mapi_idx_cndb_kvsetid_mint },
    { 0, mapi_idx_cndb_record_kvset_add },
    { 0, mapi_idx_cndb_record_kvset_del },
    { 0, mapi_idx_cndb_record_kvset_add_ack },
    { 0, mapi_idx_cndb_record_kvset_del_ack },
    { 0, mapi_idx_cndb_record_nak },

    /* hlog */
    { 0, mapi_idx_hlog_create },
    { 0, mapi_idx_hlog_destroy },
    { 0, mapi_idx_hlog_union },
    { 0, mapi_idx_hlog_reset },
    { 0, mapi_idx_hlog_card },

    /* cn */
    { 0, mapi_idx_cn_get_flags },
    { 0, mapi_idx_cn_get_sched },
    { 0, mapi_idx_cn_tree_ingest_update },

    /* csched */
    { 0, mapi_idx_csched_notify_ingest },

    /* ikvdb */
    { 0, mapi_idx_ikvdb_get_csched },

    /* mblocks */
    { 0, mapi_idx_mpool_mblock_commit },
    { 0, mapi_idx_mpool_mblock_delete },
};

const struct kvset_stats fake_kvset_stats = {
    .kst_keys = 10000,
    .kst_kvsets = 1,

    .kst_hblks = 1,
    .kst_kblks = 1,
    .kst_vblks = 1,

    .kst_halen = 32 * 1024 * 1024,
    .kst_hwlen = 30 * 1024 * 1024,

    .kst_kalen = 32 * 1024 * 1024,
    .kst_kwlen = 30 * 1024 * 1024,

    .kst_valen = 32 * 1024 * 1024,
    .kst_vwlen = 30 * 1024 * 1024,
    .kst_vulen = 10 * 1024 * 1024,
};

const struct kvset_stats *
_kvset_statsp(const struct kvset *ks)
{
    return &fake_kvset_stats;
}

void
_kvset_stats(const struct kvset *ks, struct kvset_stats *stats)
{
    *stats = fake_kvset_stats;
}

int
setup(struct mtf_test_info *info)
{
    return 0;
}

int
teardown(struct mtf_test_info *info)
{
    return 0;
}

void
enable_mocks(void)
{
    int i;

    for (i = 0; i < NELEM(injections); i++)
        mapi_inject(injections[i].api, injections[i].rc);

    MOCK_SET(kvset, _kvset_statsp);
    MOCK_SET(kvset, _kvset_stats);
}

int
test_pre(struct mtf_test_info *info)
{
    enable_mocks();
    return 0;
}

void
free_mblks(struct kvset_mblocks *p, uint nsets)
{
    uint i;

    for (i = 0; i < nsets; ++i) {
        blk_list_free(&p[i].kblks);
        blk_list_free(&p[i].vblks);
    }
}

void
init_mblks(struct kvset_mblocks *p, uint nsets, uint *nk, uint *nv)
{
    uint i, j;

    *nk = 3;
    *nv = 5;

    memset(p, 0, nsets * sizeof(*p));

    for (i = 0; i < nsets; ++i) {
        p[i].hblk.bk_blkid = mblk_id++;

        blk_list_init(&p[i].kblks);
        for (j = 0; j < *nk; j++)
            blk_list_append(&p[i].kblks, mblk_id++);

        blk_list_init(&p[i].vblks);
        for (j = 0; j < *nv; j++)
            blk_list_append(&p[i].vblks, mblk_id++);
    }
}

/* ------------------------------------------------------------
 * Unit tests
 */

MTF_BEGIN_UTEST_COLLECTION_PREPOST(cn_ingest_test, setup, teardown);

MTF_DEFINE_UTEST_PRE(cn_ingest_test, commit_delete, test_pre)
{
    struct kvset_mblocks m[4];
    uint                 n_kvsets = NELEM(m);

    u32    k, v;
    merr_t err;

    /*
     * Test cn_mblocks_commit w/ cndb_txn_txc set to succeed
     */
    init_mblks(m, n_kvsets, &k, &v);
    mapi_calls_clear(mapi_idx_mpool_mblock_commit);
    err = cn_mblocks_commit(mock_ds, n_kvsets, m, CN_MUT_OTHER);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(mapi_calls(mapi_idx_mpool_mblock_commit), n_kvsets * (1 + k + v)); /* 1 for hblock */
    free_mblks(m, n_kvsets);

    init_mblks(m, n_kvsets, &k, &v);
    mapi_calls_clear(mapi_idx_mpool_mblock_commit);
    err = cn_mblocks_commit(mock_ds, n_kvsets, m, CN_MUT_KCOMPACT);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(mapi_calls(mapi_idx_mpool_mblock_commit), n_kvsets * (1 + k)); /* kcompact ==> does not commit vblks, 1 for hblock */
    free_mblks(m, n_kvsets);

    /* Test cn_mblocks_destroy with kcompact == false.
     * Should delete kblocks and vblocks.
     */
    init_mblks(m, n_kvsets, &k, &v);
    mapi_calls_clear(mapi_idx_mpool_mblock_delete);
    cn_mblocks_destroy(mock_ds, n_kvsets, m, 0);
    ASSERT_EQ(mapi_calls(mapi_idx_mpool_mblock_delete), n_kvsets * (1 + k + v)); /* 1 for hblock */
    free_mblks(m, n_kvsets);

    /* Test cn_mblocks_destroy with kcompact == true.
     * Should delete kblocks but not vblocks.
     */
    init_mblks(m, n_kvsets, &k, &v);
    mapi_calls_clear(mapi_idx_mpool_mblock_delete);
    cn_mblocks_destroy(mock_ds, n_kvsets, m, 1);
    ASSERT_EQ(mapi_calls(mapi_idx_mpool_mblock_delete), n_kvsets * (1 + k)); /* 1 for hblock */
    free_mblks(m, n_kvsets);
}

MTF_DEFINE_UTEST_PRE(cn_ingest_test, worker, test_pre)
{
    struct kvset_mblocks m[1];
    uint                 n_kvsets = NELEM(m);

    u32                k, v;
    merr_t             err;
    struct cn          cn = {};
    struct kvs_rparams rp;

    struct cn *           cnv[1] = { &cn };
    struct kvset_mblocks *mbv[1] = { &m[0] };
    struct kvs_cparams    cp;
    uint64_t kvsetidv[1] = { 1 };

    rp = kvs_rparams_defaults();
    cn.rp = &rp;
    cn.cn_dataset = mock_ds;
    atomic_set(&cn.cn_ingest_dgen, 41);

    cp.pfx_len = 0;
    cp.sfx_len = 0;
    err = cn_tree_create(&cn.cn_tree, NULL, 0, &cp, &mock_health, &rp);
    ASSERT_EQ(err, 0);

    /* The kblocks contain no keys, so the ingest should fail.
     */
    init_mblks(m, n_kvsets, &k, &v);
    err = cn_ingestv(cnv, mbv, kvsetidv, NELEM(cnv), U64_MAX, U64_MAX, NULL, NULL);
    ASSERT_NE(0, err);
    free_mblks(m, n_kvsets);

    cn_tree_destroy(cn.cn_tree);
}

MTF_DEFINE_UTEST_PRE(cn_ingest_test, fail_cleanup, test_pre)
{
    struct kvset_mblocks m[1];
    uint                 n_kvsets = NELEM(m);

    u32                k, v;
    merr_t             err;
    struct cn          cn = {};
    struct kvs_rparams rp;
    struct kvs_cparams cp;

    struct cn *           cnv[1] = { &cn };
    struct kvset_mblocks *mbv[1] = { &m[0] };
    uint64_t kvsetidv[1] = { 1 };

    rp = kvs_rparams_defaults();
    cn.rp = &rp;
    cn.cn_dataset = mock_ds;
    atomic_set(&cn.cn_ingest_dgen, 41);

    cp.pfx_len = 0;
    cp.sfx_len = 0;
    err = cn_tree_create(&cn.cn_tree, NULL, 0, &cp, &mock_health, &rp);
    ASSERT_EQ(err, 0);

    /* kvset create failure */
    init_mblks(m, n_kvsets, &k, &v);
    mapi_inject(mapi_idx_kvset_open, merr(EBADF));
    err = cn_ingestv(cnv, mbv, kvsetidv, NELEM(cnv), U64_MAX, U64_MAX, NULL, NULL);
    ASSERT_EQ(merr_errno(err), EBADF);
    mapi_inject(mapi_idx_kvset_open, 0);
    free_mblks(m, n_kvsets);

    cn_tree_destroy(cn.cn_tree);
}

MTF_END_UTEST_COLLECTION(cn_ingest_test);
