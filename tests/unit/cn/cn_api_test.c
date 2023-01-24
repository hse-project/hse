/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/test/mtf/framework.h>
#include <hse/ikvdb/kvs.h>
#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/cn_kvdb.h>
#include <hse/ikvdb/kvdb_health.h>
#include <hse/mpool/mpool.h>

#include "cn/cn_internal.h"
#include "cn/cn_tree.h"
#include "cn/cn_tree_compact.h"
#include "kvdb/kvdb_kvs.h"

static struct kvdb_health mock_health;

int
init(struct mtf_test_info *info)
{
    return 0;
}

int
pre(struct mtf_test_info *info)
{
    mapi_inject_clear();

    mapi_inject_ptr(mapi_idx_ikvdb_get_mclass_policy, (void *)5);
    mapi_inject(mapi_idx_cndb_cn_instantiate, 0);
    mapi_inject(mapi_idx_cndb_nodeid_mint, 1);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(cn_api, init);

MTF_DEFINE_UTEST_PRE(cn_api, basic, pre)
{
    void *tree;
    merr_t err;
    uint64_t cnid;
    struct cn *cn;
    uint32_t cn_flags;
    struct kvs_buf vbuf;
    struct cn_kvdb *cn_kvdb;
    struct kvdb_kvs kk = { 0 };
    struct kvs_cparams cp = { 0 };
    struct mpool *ds = (void *)-1;
    struct cndb *cndb = (void *)-1;
    uint64_t dummy_ikvdb[32] = { 0 };

    enum key_lookup_res res;
    struct kvs_rparams *rp_out;
    struct kvs_ktuple   kt = { 0 };
    struct kvs_rparams  rp = { 0 };

    kt.kt_data = "123";
    kt.kt_len = 3;

    kk.kk_parent = (void *)&dummy_ikvdb;
    kk.kk_cparams = &cp;

    mapi_inject(mapi_idx_ikvdb_get_csched, 0);
    mapi_inject(mapi_idx_mpool_props_get, 0);
    mapi_inject(mapi_idx_mpool_mclass_props_get, ENOENT);

    err = cn_kvdb_create(4, 4, &cn_kvdb);
    ASSERT_EQ(0, err);

    err = cn_open(cn_kvdb, ds, &kk, cndb, 0, &rp, "mp", "kvs", &mock_health, 0, &cn);
    ASSERT_EQ(err, 0);
    ASSERT_NE(cn, NULL);

    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    rp_out = cn_get_rp(cn);
    ASSERT_EQ(&rp, rp_out);

    cn_flags = cn_get_flags(cn);
    ASSERT_EQ(0, cn_flags);

    cnid = cn_get_cnid(cn);
    ASSERT_EQ(0, cnid);

    (void)cn_get_cancel(cn);
    (void)cn_get_io_wq(cn);
    (void)cn_get_sched(cn);
    (void)cn_get_cndb(cn);
    (void)cn_get_perfc(cn, CN_ACTION_COMPACT_K);
    (void)cn_get_perfc(cn, CN_ACTION_COMPACT_KV);
    (void)cn_get_perfc(cn, CN_ACTION_SPILL);
    (void)cn_get_perfc(cn, CN_ACTION_NONE);

    err = cn_get(cn, &kt, 0, &res, &vbuf);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(res, NOT_FOUND);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    cn_kvdb_destroy(cn_kvdb);
}

MTF_END_UTEST_COLLECTION(cn_api);
