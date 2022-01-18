/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/alloc_tester.h>

#include <hse_util/hse_err.h>
#include <hse_util/logging.h>

#include <hse/limits.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/mclass_policy.h>

#include <cn/kblock_builder.h>
#include <cn/omf.h>
#include <cn/blk_list.h>
#include <cn/bloom_reader.h>

#include <mocks/mock_mpool.h>

const struct kvs_rparams mocked_rp_default = {
    .cn_bloom_create = 1,
};

const struct kvs_cparams mocked_cp_default = {
    .fanout = 16,
    .pfx_len = 0,
    .pfx_pivot = 0,
    .sfx_len = 0,
};

struct mclass_policy mocked_mpolicy = {
    .mc_name = "capacity_only",
};

struct kvs_rparams mocked_rp;
struct kvs_cparams mocked_cp;

u8    key_buf_pfxed[HSE_KVS_KEY_LEN_MAX];
void *key_buf;
void *kmd_buf;
int   salt;

#define BIG_KLEN 1000
#define BIG_KMDLEN 100000

#define WORK_BUF_SIZE (100 * 1024)

#define KBB_CREATE_ARGS &kbb, (void *)-1, 0

struct kbb_key_stats key_stats = { .nvals = 3, .ntombs = 1, .tot_vlen = 144 };

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
add_ptomb(
    struct mtf_test_info * lcl_ti,
    struct kblock_builder *kbb,
    uint                   klen,
    uint                   kmdlen,
    int                    expected_errno)
{
    merr_t      err;
    const void *kdata;
    const void *kmd;

    struct kbb_key_stats ptomb_stats = { .nptombs = 1, .tot_vlen = 0 };

    ASSERT_LE_RET(klen, WORK_BUF_SIZE, -1);
    ASSERT_LE_RET(kmdlen, WORK_BUF_SIZE, -1);

    /* Use salt to compute an offset into the
     * key_buf so values aren't all identical.
     */
    kdata = key_buf + ((7 * salt++) % (WORK_BUF_SIZE - klen - 1));
    kmd = kmd_buf + ((7 * salt++) % (WORK_BUF_SIZE - kmdlen - 1));

    struct key_obj ko;

    key2kobj(&ko, kdata, klen);
    err = kbb_add_ptomb(kbb, &ko, kmd, kmdlen, &ptomb_stats);
    return check_err(lcl_ti, err, expected_errno);
}

static int
add_entry(
    struct mtf_test_info * lcl_ti,
    struct kblock_builder *kbb,
    uint                   klen,
    uint                   pfx_len,
    uint                   kmdlen,
    int                    expected_errno)
{
    merr_t      err;
    const void *kdata;
    const void *kmd;

    ASSERT_LE_RET(klen, WORK_BUF_SIZE, -1);
    ASSERT_LE_RET(kmdlen, WORK_BUF_SIZE, -1);

    /* Use salt to compute an offset into the
     * key_buf so values aren't all identical.
     */
    if (pfx_len) {
        kdata = key_buf;
        memcpy(key_buf_pfxed, kdata, pfx_len);
        kdata = key_buf + ((7 * salt++) % (WORK_BUF_SIZE - klen - 1));
        memcpy(key_buf_pfxed + pfx_len, kdata, klen);
        kdata = key_buf_pfxed;
    } else {
        kdata = key_buf + ((7 * salt++) % (WORK_BUF_SIZE - klen - 1));
    }

    kmd = kmd_buf + ((7 * salt++) % (WORK_BUF_SIZE - kmdlen - 1));

    struct key_obj ko;

    key2kobj(&ko, kdata, pfx_len + klen);
    err = kbb_add_entry(kbb, &ko, kmd, kmdlen, &key_stats);
    return check_err(lcl_ti, err, expected_errno);
}

static int
add_entries(
    struct mtf_test_info * lcl_ti,
    struct kblock_builder *kbb,
    uint                   kcnt,
    uint                   klen,
    uint                   pfx_len,
    uint                   kmdlen,
    int                    expected_errno)
{
    merr_t err = 0;
    uint   i;

    log_info("Add entries: %u keys * (%u klen + %u kmd) = %u bytes",
             kcnt, klen, kmdlen, kcnt * (klen + kmdlen));

    for (i = 0; !err && i < kcnt; i++)
        err = add_entry(lcl_ti, kbb, klen, pfx_len, kmdlen, -2);

    return check_err(lcl_ti, err, expected_errno);
}

/*----------------------------------------------------------------------------
 * Call at start of each MTF_DEFINE_UTEST
 */
int
test_setup(struct mtf_test_info *lcl_ti)
{
    /* setup mpool mock */
    mock_mpool_set();

    mocked_rp = mocked_rp_default;
    mocked_cp = mocked_cp_default;

    mapi_inject_ptr(mapi_idx_cn_get_rp, &mocked_rp);
    mapi_inject_ptr(mapi_idx_cn_get_cparams, &mocked_cp);
    mapi_inject_ptr(mapi_idx_cn_get_mclass_policy, &mocked_mpolicy);

    mapi_inject(mapi_idx_cn_get_cnid, 1001);
    mapi_inject(mapi_idx_cn_get_dataset, 0);
    mapi_inject(mapi_idx_cn_get_flags, 0);

    return 0;
}

/*----------------------------------------------------------------------------
 * One-time Setup and Teardown
 */
int
initial_setup(struct mtf_test_info *lcl_ti)
{
    int i, j;

    key_buf = mapi_safe_malloc(WORK_BUF_SIZE);
    ASSERT_TRUE_RET(key_buf, -1);

    kmd_buf = mapi_safe_malloc(WORK_BUF_SIZE);
    ASSERT_TRUE_RET(kmd_buf, -1);

    for (i = 0; i < WORK_BUF_SIZE; i++) {
        ((u8 *)key_buf)[i] = i;
        ((u8 *)kmd_buf)[i] = ~i;
    }

    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++)
        for (j = 0; j < HSE_MPOLICY_DTYPE_CNT; j++)
            mocked_mpolicy.mc_table[i][j] = HSE_MCLASS_CAPACITY;

    return 0;
}

int
final_teardown(struct mtf_test_info *lcl_ti)
{
    mock_mpool_unset();
    free(key_buf);
    free(kmd_buf);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(test, initial_setup, final_teardown);

/*****************************************************************
 *
 * Interface_Under_Test: kbb_create()
 *
 *****************************************************************/

/* Test: successful creation of kblock builder. */
MTF_DEFINE_UTEST_PRE(test, t_kbb_create1, test_setup)
{
    merr_t                 err;
    struct kblock_builder *kbb;
    int                    i;

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    for (i = 0; i < HSE_MPOLICY_AGE_CNT; i++) {
        err = kbb_set_agegroup(kbb, i);
        ASSERT_EQ(0, merr_errno(err));
        ASSERT_EQ(kbb_get_agegroup(kbb), i);
    }

    kbb_destroy(kbb);
}

#ifndef __clang__
/* Test: kbb_create failures w/ ENOMEM */
MTF_DEFINE_UTEST_PRE(test, t_kbb_create_fail_nomem, test_setup)
{
    struct kblock_builder *kbb;

    merr_t err = 0;
    int    rc;

    /* kbb_create requires 6 memory allocations. Expose each one and
     * verify we tested them all.
     */
    void run(struct mtf_test_info * lcl_ti, uint i, uint j)
    {
        err = kbb_create(KBB_CREATE_ARGS);
        if (i == j)
            ASSERT_EQ(err, 0);
        else
            ASSERT_EQ(merr_errno(err), ENOMEM);
    }

    void clean(struct mtf_test_info * lcl_ti)
    {
        if (!err)
            kbb_destroy(kbb);
    }

    rc = mapi_alloc_tester(lcl_ti, run, clean);
    ASSERT_EQ(rc, 0);
}
#endif

/* Test: simple kbb_add_entry success case */
MTF_DEFINE_UTEST_PRE(test, t_kbb_add_entry_success, test_setup)
{
    merr_t                 err;
    struct kblock_builder *kbb;
    uint                   klen = 100;
    uint                   kmdlen = 9;

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = add_entry(lcl_ti, kbb, klen, 0, kmdlen, 0);
    ASSERT_EQ(err, 0);

    kbb_destroy(kbb);
}

/* Test: kbb_add_entry out of memory
 */
MTF_DEFINE_UTEST_PRE(test, t_kbb_add_entry_nomem, test_setup)
{
    uint                   api;
    merr_t                 err;
    struct kblock_builder *kbb;
    uint                   klen = 10;
    uint                   kmdlen = 10;

    api = mapi_idx_malloc;

    /* Code path under test
     * --------------------
     *   - kbb_add_entry -> kblock_add_entry -> hash_set_add -> kmalloc;
     * This path occurs when adding first key.
     */
    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);
    mapi_inject_once_ptr(api, 1, 0);
    err = add_entry(lcl_ti, kbb, klen, 0, kmdlen, ENOMEM);
    ASSERT_EQ(err, 0);
    mapi_inject_unset(api);
    kbb_destroy(kbb);

    /* Code path under test
     * --------------------
     *  - wbb_kmd_append -> alloc_page_aligned;
     *
     * This path occurs when adding N-th key, N > 1.
     * Use an extremely large kmdlen to get the append to fail.
     */
    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);
    err = add_entries(lcl_ti, kbb, 1, klen, 2, kmdlen, 0);
    ASSERT_EQ(err, 0);
    mapi_inject_once_ptr(api, 1, 0);
    err = add_entries(lcl_ti, kbb, 1000, klen, 2, BIG_KMDLEN, ENOMEM);
    ASSERT_EQ(err, 0);
    mapi_inject_unset(api);
    kbb_destroy(kbb);
}

/* Test: kbb_add_entry mblock alloc fails
 */
MTF_DEFINE_UTEST_PRE(test, t_kbb_add_entry_fail_mblock_alloc, test_setup)
{
    u32                    api;
    merr_t                 err;
    struct kblock_builder *kbb;

    api = mapi_idx_mpool_mblock_alloc;

    /* Code path under test
     * --------------------
     * - kbb_add_entry -> kblock_finish -> mpool_mblock_alloc
     */
    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    mapi_inject(api, 666);
    err = add_entries(lcl_ti, kbb, 10 * 1000, BIG_KLEN, 0, BIG_KMDLEN, 666);
    ASSERT_EQ(err, 0);
    mapi_inject_unset(api);

    kbb_destroy(kbb);
}

MTF_DEFINE_UTEST_PRE(test, t_kbb_finish, test_setup)
{
    uint                   i, api;
    merr_t                 err = 0;
    struct kblock_builder *kbb = 0;
    struct blk_list        blks;

    /* with bloom */
    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = add_entry(lcl_ti, kbb, 123, 0, 9, 0);
    ASSERT_EQ(err, 0);

    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_EQ(err, 0);

    blk_list_free(&blks);
    kbb_destroy(kbb);

    /* without bloom */
    mocked_rp.cn_bloom_create = 0;

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = add_entry(lcl_ti, kbb, 123, 0, 9, 0);
    ASSERT_EQ(err, 0);

    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_EQ(err, 0);

    blk_list_free(&blks);
    kbb_destroy(kbb);

    /* mutliple kblocks per kvset */
    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    api = mapi_idx_mpool_mblock_alloc;
    mapi_calls_clear(api);
    for (i = 0; i < 100 * 1000; i++) {
        err = add_entry(lcl_ti, kbb, BIG_KLEN, 0, BIG_KMDLEN, 0);
        ASSERT_EQ(err, 0);
        if (mapi_calls(api) == 2)
            break;
    }
    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_EQ(err, 0);

    blk_list_free(&blks);
    kbb_destroy(kbb);
}

/* [HSE_REVISIT] make a table fo this */
static int
get_max_keys(struct mtf_test_info *lcl_ti, uint klen, uint kmdlen)
{
    struct kblock_builder *kbb = 0;
    uint                   i, api;

    kbb_create(KBB_CREATE_ARGS);

    api = mapi_idx_mpool_mblock_alloc;
    mapi_calls_clear(api);
    for (i = 0; i < 100 * 1000; i++) {
        add_entry(lcl_ti, kbb, klen, 0, kmdlen, 0);
        if (mapi_calls(api) == 1)
            break;
    }

    kbb_destroy(kbb);
    return i;
}

/*
 * With fixed mblock size per media class, the kblock contents cannot exceed
 * KBLOCK_MAX_SIZE. Commenting this test until we arrive at a solution to
 * handle this.
 */
MTF_DEFINE_UTEST_PRE(test, t_kbb_finish_with_ptombs, test_setup)
{
    uint                   i, api;
    merr_t                 err = 0;
    struct kblock_builder *kbb = 0;
    struct blk_list        blks;
    uint                   entries_per_kb;

    /* only ptomb with bloom */
    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = add_ptomb(lcl_ti, kbb, 123, 9, 0);
    ASSERT_EQ(err, 0);

    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_EQ(err, 0);

    blk_list_free(&blks);
    kbb_destroy(kbb);

    /* only ptomb without bloom */
    mocked_rp.cn_bloom_create = 0;

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = add_ptomb(lcl_ti, kbb, 123, 9, 0);
    ASSERT_EQ(err, 0);

    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_EQ(err, 0);

    blk_list_free(&blks);
    kbb_destroy(kbb);

    /* ptombs causing kblock to be larger than KBLOCK_MAX_SIZE */

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    entries_per_kb = get_max_keys(lcl_ti, BIG_KLEN, BIG_KMDLEN);

    api = mapi_idx_mpool_mblock_alloc;
    mapi_calls_clear(api);
    for (i = 0; i < entries_per_kb; i++) {
        err = add_entry(lcl_ti, kbb, BIG_KLEN, 0, BIG_KMDLEN, 0);
        ASSERT_EQ(err, 0);
        if (mapi_calls(api) == 1)
            break;
    }

    for (i = 0; i < 2000; i++) {
        err = add_ptomb(lcl_ti, kbb, BIG_KLEN, 9, 0);
        ASSERT_EQ(err, 0);
    }

    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_EQ(err, 0);

    blk_list_free(&blks);
    kbb_destroy(kbb);
}

/* Test: kbb_finish handling of various errors */
MTF_DEFINE_UTEST_PRE(test, t_kbb_finish_fail, test_setup)
{
    uint api[] = { mapi_idx_wbb_freeze, mapi_idx_mpool_mblock_alloc, mapi_idx_mpool_mblock_write };
    uint i, num_allocs;
    merr_t                 err = 0;
    struct kblock_builder *kbb = 0;
    struct blk_list        blks;

    for (i = 0; i < NELEM(api); i++) {

        err = kbb_create(KBB_CREATE_ARGS);
        ASSERT_EQ(err, 0);

        err = add_entry(lcl_ti, kbb, 123, 0, 9, 0);
        ASSERT_EQ(err, 0);

        mapi_inject(api[i], 100 + i);

        err = kbb_finish(kbb, &blks, 0, 0);
        ASSERT_EQ(merr_errno(err), 100 + i);

        mapi_inject_unset(api[i]);

        kbb_destroy(kbb);
    }

    /* expose memory allocation failures */
    num_allocs = 3;
    for (i = 0; i <= num_allocs; i++) {
        err = kbb_create(KBB_CREATE_ARGS);
        ASSERT_EQ(err, 0);

        err = add_entry(lcl_ti, kbb, 123, 0, 9, 0);
        ASSERT_EQ(err, 0);

        mapi_inject_once_ptr(mapi_idx_malloc, 1 + i, 0);

        err = kbb_finish(kbb, &blks, 0, 0);
        if (i == num_allocs) {
            ASSERT_EQ(err, 0);
            blk_list_free(&blks);
        } else {
            ASSERT_EQ(merr_errno(err), ENOMEM);
        }

        mapi_inject_unset(mapi_idx_malloc);

        kbb_destroy(kbb);
    }
}

/* Test: kbb_destroy. */
MTF_DEFINE_UTEST_PRE(test, t_kbb_destroy_nullptr, test_setup)
{
    kbb_destroy(0);
}

int
fill_test(struct mtf_test_info *lcl_ti, uint kcnt, uint klen, uint kmdlen)
{
    struct kblock_builder *kbb = 0;
    merr_t                 err = 0;
    uint                   ac, wc, cc;

    ac = mapi_calls(mapi_idx_mpool_mblock_alloc);
    wc = mapi_calls(mapi_idx_mpool_mblock_write);
    cc = mapi_calls(mapi_idx_mpool_mblock_commit);

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ_RET(err, 0, err);

    err = add_entries(lcl_ti, kbb, kcnt, klen, 2, kmdlen, 0);
    ASSERT_EQ_RET(err, 0, err);

    kbb_destroy(kbb);

    ac = mapi_calls(mapi_idx_mpool_mblock_alloc) - ac;
    wc = mapi_calls(mapi_idx_mpool_mblock_write) - wc;
    cc = mapi_calls(mapi_idx_mpool_mblock_commit) - cc;

    log_info("--> mblock stats: allocated %u, writes %u, committed %u", ac, wc, cc);

    return 0;
}

/* kbb_finish w/ no keys */
MTF_DEFINE_UTEST_PRE(test, t_kbb_finish_empty1, test_setup)
{
    merr_t                 err = 0;
    struct kblock_builder *kbb = 0;
    struct blk_list        blks;

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(blks.n_blks, 0);

    /* finish when already finished */
    err = kbb_finish(kbb, &blks, 0, 0);
    ASSERT_NE(err, 0);

    kbb_destroy(kbb);
}

MTF_DEFINE_UTEST_PRE(test, t_kbb_fill, test_setup)
{
    uint other = 4; /* minimum bloom + lfe overhead */
    uint i, j;
    uint klen, kmdlen;

    uint klens[] = { 4, 10, 18, 23, 100, 500, 999, 1000 };
    uint kmdlens[] = { 5, 9, 100 };
    uint nkeys;

    for (i = 0; i < NELEM(klens); i++) {
        klen = klens[i];
        for (j = 0; j < NELEM(kmdlens); j++) {
            kmdlen = kmdlens[j];
            nkeys = KBLOCK_MAX_SIZE / (klen + kmdlen + other);
            fill_test(lcl_ti, nkeys, klen, kmdlen);
        }
    }
}

MTF_DEFINE_UTEST_PRE(test, t_hash_set, test_setup)
{
    struct kblock_builder *kbb = 0;

    merr_t err = 0;
    uint   klen = 1;
    uint   kcnt = 16 * 1024; /* matches HSP_HASH_MAX_KEYS */
    uint   kmdlen = 9;

    err = kbb_create(KBB_CREATE_ARGS);
    ASSERT_EQ(err, 0);

    err = add_entries(lcl_ti, kbb, kcnt + 1, klen, 0, kmdlen, 0);
    ASSERT_EQ(err, 0);

    kbb_destroy(kbb);
}

MTF_END_UTEST_COLLECTION(test)
