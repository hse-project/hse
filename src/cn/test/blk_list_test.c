/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/conditions.h>
#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvs_rparams.h>

#include "../blk_list.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct mpool *ds = (struct mpool *)0xface;

#define BLK_ID 0x1234

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

int
pre(struct mtf_test_info *info)
{
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    mapi_inject(mapi_idx_mpool_mblock_commit, 0);
    mapi_inject(mapi_idx_mpool_mblock_abort, 0);
    return 0;
}

int
post(struct mtf_test_info *info)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(blk_list_test, setup, teardown);

MTF_DEFINE_UTEST_PREPOST(blk_list_test, t_blk_list_init_free, pre, post)
{
    struct blk_list b;

    blk_list_init(&b);
    blk_list_free(&b);
    blk_list_free(0);
}

MTF_DEFINE_UTEST_PREPOST(blk_list_test, t_blk_list_append, pre, post)
{
    int             i, add;
    merr_t          err;
    struct blk_list b;
    u64             blkid = BLK_ID;
    u64             blkid_start;

    blk_list_init(&b);

    add = BLK_LIST_PRE_ALLOC + 10;
    blkid_start = blkid;
    for (i = 0; i < add; i++) {
        err = blk_list_append(&b, blkid++);
        ASSERT_EQ(err, 0);
    }
    ASSERT_EQ(b.n_blks, add);
    for (i = 0; i < add; i++)
        ASSERT_EQ(b.blks[i].bk_blkid, blkid_start + i);

    /* A common pattern is to reset blk count to reuse a blk_list
     * without having to re-allocate the array of mblock IDs.
     */
    b.n_blks = 0;

    add = 2 * BLK_LIST_PRE_ALLOC + 10;
    blkid_start = blkid;
    for (i = 0; i < add; i++) {
        err = blk_list_append(&b, blkid++);
        ASSERT_EQ(err, 0);
    }
    ASSERT_EQ(b.n_blks, add);
    for (i = 0; i < add; i++)
        ASSERT_EQ(b.blks[i].bk_blkid, blkid_start + i);

    blk_list_free(&b);

    /*
     * Test some failure paths.
     */
    mapi_inject(mapi_idx_malloc, 0);
    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_NE(err, 0);
    mapi_inject_unset(mapi_idx_malloc);

    /* Append one, expect success, then inject allocation failure.
     * Append more until we hit the allocation failure, which should be
     * when the blk_list needs to grow.
     */
    blk_list_init(&b);

    add = BLK_LIST_PRE_ALLOC + 10;
    err = blk_list_append(&b, blkid++);
    ASSERT_EQ(err, 0);
    mapi_inject(mapi_idx_malloc, 0);
    for (i = 0; i < add; i++) {
        err = blk_list_append(&b, blkid++);
        if (err)
            break;
    }
    /* verify we broke out of loop with error */
    ASSERT_NE(err, 0);
    mapi_inject_unset(mapi_idx_malloc);
    blk_list_free(&b);
}

MTF_DEFINE_UTEST_PREPOST(blk_list_test, t_commit_mblock, pre, post)
{
    merr_t          err;
    struct blk_list b;
    u32             api;

    /* commit with handle */
    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_EQ(err, 0);
    err = commit_mblock(ds, &b.blks[0]);
    ASSERT_EQ(err, 0);
    blk_list_free(&b);

    /* commit with failure */
    api = mapi_idx_mpool_mblock_commit;
    mapi_inject(api, merr(EINVAL));
    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_EQ(err, 0);
    err = commit_mblock(ds, &b.blks[0]);
    ASSERT_NE(err, 0);
    blk_list_free(&b);
    mapi_inject(api, 0);
}

MTF_DEFINE_UTEST_PREPOST(blk_list_test, t_delete_mblock, pre, post)
{
    merr_t          err;
    struct blk_list b;
    u32             api;

    /* delete with handle */
    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_EQ(err, 0);
    err = delete_mblock(ds, &b.blks[0]);
    ASSERT_EQ(err, 0);
    blk_list_free(&b);

    /* delete with handle and with mpool_mblock_delete failure */
    api = mapi_idx_mpool_mblock_delete;
    mapi_inject(api, merr(EINVAL));
    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_EQ(err, 0);
    err = delete_mblock(ds, &b.blks[0]);
    ASSERT_NE(err, 0);
    blk_list_free(&b);
    mapi_inject(api, 0);

    /* delete without handle */
    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_EQ(err, 0);
    err = delete_mblock(ds, &b.blks[0]);
    ASSERT_EQ(err, 0);
    blk_list_free(&b);
}

MTF_DEFINE_UTEST_PREPOST(blk_list_test, t_abort_mblocks, pre, post)
{
    int             i, N = 5;
    merr_t          err;
    struct blk_list b;
    u32             api;

    abort_mblocks(ds, 0);

    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_EQ(err, 0);
    abort_mblocks(ds, &b);
    blk_list_free(&b);

    blk_list_init(&b);
    for (i = 0; i < N; i++) {
        err = blk_list_append(&b, BLK_ID + i);
        ASSERT_EQ(err, 0);
    }
    abort_mblocks(ds, &b);
    blk_list_free(&b);

    api = mapi_idx_mpool_mblock_abort;
    mapi_inject(api, merr(EINVAL));
    blk_list_init(&b);
    err = blk_list_append(&b, BLK_ID);
    ASSERT_EQ(err, 0);
    abort_mblocks(ds, &b);
    blk_list_free(&b);
    mapi_inject(api, 0);
}

MTF_END_UTEST_COLLECTION(blk_list_test);
