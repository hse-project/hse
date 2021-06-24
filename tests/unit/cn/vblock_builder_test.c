/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mapi_alloc_tester.h>

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/logging.h>
#include <hse_util/page.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvs_rparams.h>

#include <hse/hse_limits.h>

#include <cn/vblock_builder.h>
#include <cn/blk_list.h>

#include <mocks/mock_mpool.h>

struct kvs_rparams kvsrp;
int                salt;
void *             workbuf;

#define WORKBUF_SIZE (2 * HSE_KVS_VLEN_MAX)

#define VBB_CREATE_ARGS &vbb, (void *)0, NULL, 1

static int
add_entry(
    struct mtf_test_info * lcl_ti,
    struct vblock_builder *vbb,
    uint                   value_len,
    int                    expected_errno);

static int
add_entries(
    struct mtf_test_info * lcl_ti,
    struct vblock_builder *vbb,
    uint                   n_entries,
    uint                   vlen,
    int                    expected_errno);

static int
fill_exact(
    struct mtf_test_info * lcl_ti,
    struct vblock_builder *vbb,
    uint                   space,
    int                    expected_errno);

struct mclass_policy mocked_mpolicy = {
    .mc_name = "capacity_only",
};

/*----------------------------------------------------------------------------
 * Call at start of each MTF_DEFINE_UTEST
 */
int
test_setup(struct mtf_test_info *lcl_ti)
{
    mock_mpool_set();

    mapi_inject_ptr(mapi_idx_cn_get_rp, &kvsrp);
    mapi_inject_ptr(mapi_idx_cn_get_mclass_policy, &mocked_mpolicy);

    mapi_inject(mapi_idx_cn_get_cnid, 1001);
    mapi_inject(mapi_idx_cn_get_dataset, 0);
    mapi_inject(mapi_idx_cn_get_flags, 0);
    mapi_inject(mapi_idx_cn_pc_mclass_get, 0);

    return 0;
}

/*----------------------------------------------------------------------------
 * One-time Setup and Teardown
 */
int
initial_setup(struct mtf_test_info *lcl_ti)
{
    u32 i, j, k;

    hse_openlog("vblock_builder_test", 1);

    workbuf = mapi_safe_malloc(WORKBUF_SIZE);
    ASSERT_TRUE_RET(workbuf, -1);

    for (i = 0; i < WORKBUF_SIZE; i++)
        ((u8 *)workbuf)[i] = i;

    kvsrp = kvs_rparams_defaults();

    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++)
            for (k = 0; k < HSE_MPOLICY_MEDIA_CNT; k++) {
                if (k == 0)
                    mocked_mpolicy.mc_table[i][j][k] = HSE_MPOLICY_MEDIA_CAPACITY;
                else
                    mocked_mpolicy.mc_table[i][j][k] = HSE_MPOLICY_MEDIA_INVALID;
            }

    return 0;
}

int
final_teardown(struct mtf_test_info *lcl_ti)
{
    mock_mpool_unset();
    free(workbuf);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(test, initial_setup, final_teardown);

/* Test: successful creation of vblock builder. */
MTF_DEFINE_UTEST_PRE(test, t_vbb_create1, test_setup)
{
    struct vblock_builder *vbb;
    merr_t                 err;
    int                    i;

    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++) {
        vbb_set_agegroup(vbb, i);
        ASSERT_EQ(vbb_get_agegroup(vbb), i);
    }

    vbb_destroy(vbb);
}

/* Test: vbb_destroy NULL ptr. */
MTF_DEFINE_UTEST_PRE(test, t_vbb_destroy1, test_setup)
{
    vbb_destroy(NULL);
}

/* Test: vbb_create, allocation failure */
MTF_DEFINE_UTEST_PRE(test, t_vbb_create_fail_nomem, test_setup)
{
    struct vblock_builder *vbb;

    merr_t err = 0;
    int    rc;

    void run(struct mtf_test_info * lcl_ti, uint i, uint j)
    {
        err = vbb_create(VBB_CREATE_ARGS);
        if (i == j)
            ASSERT_EQ(err, 0);
        else
            ASSERT_EQ(merr_errno(err), ENOMEM);
    }

    void clean(struct mtf_test_info * lcl_ti)
    {
        if (!err)
            vbb_destroy(vbb);
    }

    rc = mapi_alloc_tester(lcl_ti, run, clean);
    ASSERT_EQ(rc, 0);
}

/* Test: vbb_finish w/ no values. */
MTF_DEFINE_UTEST_PRE(test, t_vbb_finish_empty1, test_setup)
{
    struct vblock_builder *vbb;
    struct blk_list        blks;
    merr_t                 err = 0;

    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = vbb_finish(vbb, &blks);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(blks.n_blks, 0);
    blk_list_free(&blks);

    vbb_destroy(vbb);
}

/* Test: vbb_finish w/ vblock that is exactly full. */
MTF_DEFINE_UTEST_PRE(test, t_vbb_finish_exact, test_setup)
{
    struct vblock_builder *vbb;
    struct blk_list        blks;
    merr_t                 err = 0;

    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = fill_exact(lcl_ti, vbb, 0, 0);
    ASSERT_EQ(err, 0);

    err = vbb_finish(vbb, &blks);
    ASSERT_EQ(err, 0);
    ASSERT_GE(blks.n_blks, 1);

    blk_list_free(&blks);
    vbb_destroy(vbb);
}

/* Test: vbb_add_entry, mblock allocation failure */
MTF_DEFINE_UTEST_PRE(test, t_vbb_add_entry_fail_mblock_alloc, test_setup)
{
    uint                   api;
    merr_t                 err = 0;
    struct vblock_builder *vbb = 0;

    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    api = mapi_idx_mpool_mblock_alloc;
    mapi_inject(api, 999);

    err = add_entry(lcl_ti, vbb, 123, 999);
    ASSERT_EQ(err, 0);

    mapi_inject_unset(api);

    vbb_destroy(vbb);
}

/* Test: vbb_add_entry, memory allocation failure.
 * Code path (must be first entry added to vblock):
 *   vbb_add_entry -> _vblock_start ->  blk_list_append -> malloc;
 */
MTF_DEFINE_UTEST_PRE(test, t_vbb_add_entry_fail_nomem, test_setup)
{
    uint                   api;
    merr_t                 err = 0;
    struct vblock_builder *vbb = 0;

    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    api = mapi_idx_malloc;
    mapi_inject_once_ptr(api, 1, 0);

    err = add_entry(lcl_ti, vbb, 123, ENOMEM);
    ASSERT_EQ(err, 0);

    mapi_inject_unset(api);

    vbb_destroy(vbb);
}

/* Test: vbb_add_entry w/ vblock that is exactly full. */
MTF_DEFINE_UTEST_PRE(test, t_vbb_add_entry_exact, test_setup)
{
    struct vblock_builder *vbb;
    struct blk_list        blks;
    merr_t                 err = 0;

    /*
     * Fill and finish to verify we get 1 vblock
     */
    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = fill_exact(lcl_ti, vbb, 0, 0);
    ASSERT_EQ(err, 0);

    err = vbb_finish(vbb, &blks);
    ASSERT_EQ(err, 0);
    ASSERT_GE(blks.n_blks, 1);

    blk_list_free(&blks);
    vbb_destroy(vbb);

    /*
     * Repeat but add one more 1-byte value
     * and verify 2 vblocks.  Throw in the INGEST
     * flag to cover different code branches.
     */
    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = fill_exact(lcl_ti, vbb, 0, 0);
    ASSERT_EQ(err, 0);

    err = add_entry(lcl_ti, vbb, 1, 0); /* one extra */
    ASSERT_EQ(err, 0);

    err = vbb_finish(vbb, &blks);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(blks.n_blks, 2); /* verify 1 vblock */

    blk_list_free(&blks);
    vbb_destroy(vbb);
}

/* Test: vbb_add_entry, mblock write error
 * Code paths:
 *  1. vbb_add_entry -> _vblock_write -> mpool_mblock_write;
 *  2. vbb_add_entry -> _vblock_finish -> _vblock_write -> mpool_mblock_write
 *  3. vbb_add_entry -> _vblock_write -> mpool_mblock_write;
 *  4. vbb_add_entry -> _vblock_finish -> _vblock_write -> mpool_mblock_write;
 */
MTF_DEFINE_UTEST_PRE(test, t_vbb_add_entry_fail_mblock_write, test_setup)
{
    uint                   api;
    merr_t                 err = 0;
    struct vblock_builder *vbb = 0;

    /*
     * Case 1: vbb_add_entry -> _vblock_write -> mpool_mblock_write;
     */
    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    api = mapi_idx_mpool_mblock_write;
    mapi_inject(api, 666);

    err = fill_exact(lcl_ti, vbb, 0, 666);
    ASSERT_EQ(err, 0);

    mapi_inject_unset(api);

    vbb_destroy(vbb);

    /*
     * Case 2: vbb_add_entry -> _vblock_finish ->
     * _vblock_write -> mpool_mblock_write;
     */
    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = fill_exact(lcl_ti, vbb, 100, 0); /* leave 100 bytes space */
    ASSERT_EQ(err, 0);

    api = mapi_idx_mpool_mblock_write;
    mapi_inject(api, 666);

    /* add 200, forcing call to _vblock_finish(), which should fail */
    err = add_entry(lcl_ti, vbb, 200, 666);
    ASSERT_EQ(err, 0);

    mapi_inject_unset(api);

    vbb_destroy(vbb);

    /*
     * Case 3: vbb_add_entry -> _vblock_write -> mpool_mblock_write
     */
    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    api = mapi_idx_mpool_mblock_write;
    mapi_inject(api, 666);

    err = fill_exact(lcl_ti, vbb, 0, 666);
    ASSERT_EQ(err, 0);

    mapi_inject_unset(api);

    vbb_destroy(vbb);

    /*
     * Case 4: vbb_add_entry -> _vblock_finish ->
     * _vblock_write -> mpool_mblock_write;
     */
    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = fill_exact(lcl_ti, vbb, 100, 0); /* leave 100 bytes space */
    ASSERT_EQ(err, 0);

    api = mapi_idx_mpool_mblock_write;
    mapi_inject(api, 666);

    /* add 200, forcing call to _vblock_finish(), which should fail */
    err = add_entry(lcl_ti, vbb, 200, 666);
    ASSERT_EQ(err, 0);

    mapi_inject_unset(api);

    vbb_destroy(vbb);
}

/* Test: vbb_finish fail mode */
MTF_DEFINE_UTEST_PRE(test, t_vbb_finish_fail_mblock_write, test_setup)
{
    uint                   api;
    merr_t                 err = 0;
    struct vblock_builder *vbb = 0;
    struct blk_list        blks;

    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = add_entry(lcl_ti, vbb, 123, 0);
    ASSERT_EQ(err, 0);

    api = mapi_idx_mpool_mblock_write;
    mapi_inject(api, 666);

    err = vbb_finish(vbb, &blks);
    ASSERT_EQ(merr_errno(err), 666);

    mapi_inject_unset(api);

    vbb_destroy(vbb);
}

static int
check_err(struct mtf_test_info *lcl_ti, merr_t err, int expected_errno)
{
    switch (expected_errno) {
        case -2:
            /* no check, just return */
            return err;
        case -1:
            /* any error */
            ASSERT_TRUE_RET(err, -1);
            break;
        case 0:
            /* no error */
            ASSERT_EQ_RET(err, 0, -1);
            break;
        default:
            /* specific error */
            ASSERT_EQ_RET(merr_errno(err), expected_errno, -1);
    }

    return 0;
}

static int
add_entry(struct mtf_test_info *lcl_ti, struct vblock_builder *vbb, uint vlen, int expected_errno)
{
    merr_t err;
    uint   vboff = -1;
    uint   vbidx = -1;
    u64    vbid = (u64)-1;

    /* Use salt to compute an offset into the
     * workbuf so values aren't all identical.
     */
    unsigned base = (7 * salt++) % (WORKBUF_SIZE - vlen - 1);

    err = vbb_add_entry(vbb, workbuf + base, vlen, &vbid, &vbidx, &vboff);
    if (!err) {
        ASSERT_TRUE_RET(vboff != -1, -1);
        ASSERT_TRUE_RET(vbidx != -1, -1);
    }

    return check_err(lcl_ti, err, expected_errno);
}

static int
add_entries(
    struct mtf_test_info * lcl_ti,
    struct vblock_builder *vbb,
    uint                   n_entries,
    uint                   vlen,
    int                    expected_errno)
{
    uint i;
    int  err = 0;

    for (i = 0; !err && i < n_entries; i++)
        err = add_entry(lcl_ti, vbb, vlen, -2);

    return check_err(lcl_ti, err, expected_errno);
}

static int
fill_exact(struct mtf_test_info *lcl_ti, struct vblock_builder *vbb, uint space, int expected_errno)
{
    merr_t err = 0;
    uint   vlen_max = HSE_KVS_VLEN_MAX;
    uint   avail = kvsrp.vblock_size - PAGE_SIZE - space;
    uint   vlen;

    while (avail > 0) {
        vlen = min(avail, vlen_max);
        err = add_entry(lcl_ti, vbb, vlen, -2);
        if (err)
            break;
        avail -= vlen;
    }
    return check_err(lcl_ti, err, expected_errno);
}

enum test_case {
    tc_finish,
    tc_destroy,
};

int
run_test_case(struct mtf_test_info *lcl_ti, enum test_case tc, size_t n_vblocks)
{
    struct vblock_builder *vbb = 0;

    const size_t mblock_size = kvsrp.vblock_size;
    const size_t vblock_hdr_size = PAGE_SIZE;
    const size_t avail_mblock_size = mblock_size - vblock_hdr_size;
    const size_t vlen = 50 * 1000;
    const size_t values_per_mblock = avail_mblock_size / vlen;
    const size_t add_count = n_vblocks * values_per_mblock;

    ASSERT_LE_RET(vlen, HSE_KVS_VLEN_MAX, -1);

    u32             i;
    merr_t          err;
    struct blk_list blks;

    mapi_calls_clear(mapi_idx_mpool_mblock_alloc);
    mapi_calls_clear(mapi_idx_mpool_mblock_write);
    mapi_calls_clear(mapi_idx_mpool_mblock_abort);
    mapi_calls_clear(mapi_idx_mpool_mblock_commit);
    mapi_calls_clear(mapi_idx_mpool_mblock_delete);

    hse_log(
        HSE_INFO "Creating vbb: size %zu = hdr %zu"
                 " + %zu values x %zu bytes/value + %ld leftover",
        mblock_size,
        PAGE_SIZE,
        values_per_mblock,
        vlen,
        (long)(mblock_size - PAGE_SIZE - values_per_mblock * vlen));

    err = vbb_create(VBB_CREATE_ARGS);
    ASSERT_EQ_RET(err, 0, 1);

    hse_log(HSE_INFO "Adding %zu values, expect %zu vblocks to be created", add_count, n_vblocks);

    if (add_entries(lcl_ti, vbb, add_count, vlen, 0))
        return 1;

    switch (tc) {

        case tc_finish:

            err = vbb_finish(vbb, &blks);
            ASSERT_EQ_RET(0, err, 1);
            ASSERT_EQ_RET(blks.n_blks, n_vblocks, 1);
            for (i = 0; i < n_vblocks; i++)
                ASSERT_EQ_RET(blks.blks[i].bk_blkid, MPM_MBLOCK_ID_BASE + i, 1);
            blk_list_free(&blks);

            vbb_destroy(vbb);

            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_alloc), n_vblocks, 1);
            ASSERT_GT_RET(mapi_calls(mapi_idx_mpool_mblock_write), 0, 1);
            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_abort), 0, 1);
            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_commit), 0, 1);
            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_delete), 0, 1);
            break;

        case tc_destroy:

            vbb_destroy(vbb);

            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_alloc), n_vblocks, 1);
            ASSERT_GT_RET(mapi_calls(mapi_idx_mpool_mblock_write), 0, 1);
            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_abort), n_vblocks, 1);
            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_commit), 0, 1);
            ASSERT_EQ_RET(mapi_calls(mapi_idx_mpool_mblock_delete), 0, 1);
            break;
    }

    return 0;
}

MTF_DEFINE_UTEST_PRE(test, t_finish_with_1_vblock, test_setup)
{
    run_test_case(lcl_ti, tc_finish, 1);
}

MTF_DEFINE_UTEST_PRE(test, t_finish_with_2_vblock, test_setup)
{
    run_test_case(lcl_ti, tc_finish, 2);
}

MTF_DEFINE_UTEST_PRE(test, t_finish_with_3_vblock, test_setup)
{
    run_test_case(lcl_ti, tc_finish, 3);
}

MTF_DEFINE_UTEST_PRE(test, t_destroy_with_1_vblock, test_setup)
{
    run_test_case(lcl_ti, tc_destroy, 1);
}

MTF_DEFINE_UTEST_PRE(test, t_destroy_with_2_vblock, test_setup)
{
    run_test_case(lcl_ti, tc_destroy, 2);
}

MTF_DEFINE_UTEST_PRE(test, t_destroy_with_3_vblock, test_setup)
{
    run_test_case(lcl_ti, tc_destroy, 3);
}

MTF_END_UTEST_COLLECTION(test);
