/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <mocks/mock_mpool.h>

#include <cn/blk_list.h>
#include <cn/hblock_builder.h>
#include <cn/omf.h>

#include <hse_ikvdb/blk_list.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/mclass_policy.h>
#include <hse_util/alloc.h>
#include <hse_util/assert.h>
#include <hse_util/base.h>
#include <hse/error/merr.h>
#include <hse_util/key_util.h>
#include <hse_util/page.h>
#include <hse_util/hlog.h>
#include <hse_util/keycmp.h>

#include <cn/kvset.h>

#define WORK_BUF_SIZE (100 * 1024)

uint8_t *hlog;
static struct vgmap *vgmap;

void *key_buf;
void *kmd_buf;
int   salt;

struct mclass_policy mocked_mpolicy = {
    .mc_name = "capacity_only",
};

int
collection_pre(struct mtf_test_info *lcl_ti)
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

    hlog = aligned_alloc(PAGE_SIZE, HLOG_SIZE);
    if (!hlog)
        return ENOMEM;

    vgmap = vgmap_alloc(1);
    if (!vgmap)
        return ENOMEM;

    return 0;
}

int
collection_post(struct mtf_test_info *lcl_ti)
{
    free(key_buf);
    free(kmd_buf);

    vgmap_free(vgmap);

    return 0;
}

int
test_pre(struct mtf_test_info *info)
{
    mock_mpool_set();

    mapi_inject_ptr(mapi_idx_cn_get_mclass_policy, &mocked_mpolicy);

    mapi_inject(mapi_idx_cn_get_cnid, 1001);
    mapi_inject(mapi_idx_cn_get_dataset, 0);
    mapi_inject(mapi_idx_cn_get_flags, 0);

    return 0;
}

int
test_post(struct mtf_test_info *info)
{
    mock_mpool_unset();

    return 0;
}

merr_t
add_ptomb(
    struct hblock_builder *hbb,
    uint klen,
    uint kmdlen,
    const void **pfx)
{
    const void *kmd;
    const void *kdata;
    struct key_obj ko;

    struct key_stats key_stats = { .nptombs = 1 };

    INVARIANT(klen < WORK_BUF_SIZE);
    INVARIANT(kmdlen < WORK_BUF_SIZE);

    /* Use salt to compute an offset into the
     * key_buf so values aren't all identical.
     */
    kdata = key_buf + ((7 * salt++) % (WORK_BUF_SIZE - klen - 1));
    kmd = kmd_buf + ((7 * salt++) % (WORK_BUF_SIZE - kmdlen - 1));

    key2kobj(&ko, kdata, klen);

    if (pfx)
        *pfx = kdata;

    return hbb_add_ptomb(hbb, &ko, kmd, kmdlen, &key_stats);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(hblock_builder_test, collection_pre, collection_post)

MTF_DEFINE_UTEST_PREPOST(hblock_builder_test, add_ptomb_success, test_pre, test_post)
{
    merr_t err;
    struct hblock_hdr_omf *hdr;
    struct hblock_builder *bld;
    struct mpool *mpool = (void *)-1;
    struct cn *cn = (void *)-1;
    struct iovec iov[1];
    uint64_t mbid;
    const void *pfx, *pfx_min, *pfx_max;
    size_t pfx_min_len = 0, pfx_max_len = 0;

    char *buf = aligned_alloc(PAGE_SIZE, HBLOCK_HDR_PAGES * PAGE_SIZE);
    hdr = (struct hblock_hdr_omf *)buf;

    iov[0].iov_base = buf;
    iov[0].iov_len = HBLOCK_HDR_PAGES * PAGE_SIZE;

    /* Test no ptombs */

    err = hbb_create(&bld, cn, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = hbb_finish(bld, &mbid, vgmap, NULL, NULL, 0, 1, 1, 3, 0, hlog, NULL, NULL, 0);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_read(mpool, mbid, iov, NELEM(iov), 0);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(0, omf_hbh_min_seqno(hdr));
    ASSERT_EQ(1, omf_hbh_max_seqno(hdr));
    ASSERT_EQ(0, omf_hbh_num_ptombs(hdr));
    ASSERT_EQ(1, omf_hbh_num_kblocks(hdr));
    ASSERT_EQ(3, omf_hbh_num_vblocks(hdr));

    hbb_destroy(bld);

    /* Test one ptomb */

    err = hbb_create(&bld, cn, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = add_ptomb(bld, HSE_KVS_PFX_LEN_MAX, 9, &pfx);
    ASSERT_EQ(0, merr_errno(err));

    err = hbb_finish(bld, &mbid, vgmap, NULL, NULL, 0, 1, 1, 3, 1, hlog, NULL, NULL, 0);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_read(mpool, mbid, iov, NELEM(iov), 0);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(0, omf_hbh_min_seqno(hdr));
    ASSERT_EQ(1, omf_hbh_max_seqno(hdr));
    ASSERT_EQ(1, omf_hbh_num_ptombs(hdr));
    ASSERT_EQ(1, omf_hbh_num_kblocks(hdr));
    ASSERT_EQ(3, omf_hbh_num_vblocks(hdr));
    ASSERT_EQ(0, keycmp(pfx, 9, (void *)hdr + HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX, 9));
    ASSERT_EQ(0, keycmp(pfx, 9, (void *)hdr + HBLOCK_HDR_LEN - HSE_KVS_PFX_LEN_MAX, 9));

    hbb_destroy(bld);

    /* Test hundreds ptomb
     *
     * The goal here is to get a wbtree internal node to be created.
     */

    pfx_min = NULL;
    pfx_max = NULL;

    err = hbb_create(&bld, cn, NULL);
    ASSERT_EQ(0, merr_errno(err));

    for (int i = 10; i < 200; i++) {
        const size_t pfx_len = i % HSE_KVS_PFX_LEN_MAX;
        err = add_ptomb(bld, i % HSE_KVS_PFX_LEN_MAX, 10, &pfx);
        ASSERT_EQ(0, merr_errno(err));

        if (!pfx_min) {
            pfx_min = pfx;
            pfx_min_len = pfx_len;
        }

        if (!pfx_max) {
            pfx_max = pfx;
            pfx_max_len = pfx_len;
        }

        if (keycmp(pfx, pfx_len, pfx_min, pfx_min_len) < 0) {
            pfx_min = pfx;
            pfx_min_len = pfx_len;
        }

        if (keycmp(pfx, pfx_len, pfx_min, pfx_min_len) > 0) {
            pfx_max = pfx;
            pfx_max_len = pfx_len;
        }
    }

    err = hbb_finish(bld, &mbid, vgmap, NULL, NULL, 0, 1, 1, 3, 190, hlog, NULL, NULL, 0);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_read(mpool, mbid, iov, NELEM(iov), 0);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(0, omf_hbh_min_seqno(hdr));
    ASSERT_EQ(1, omf_hbh_max_seqno(hdr));
    ASSERT_EQ(190, omf_hbh_num_ptombs(hdr));
    ASSERT_EQ(1, omf_hbh_num_kblocks(hdr));
    ASSERT_EQ(3, omf_hbh_num_vblocks(hdr));
    ASSERT_EQ(0, keycmp(pfx_max, pfx_max_len, (void *)hdr + HBLOCK_HDR_LEN -
        2 * HSE_KVS_PFX_LEN_MAX, pfx_max_len));
    ASSERT_EQ(0, keycmp(pfx_min, pfx_min_len, (void *)hdr + HBLOCK_HDR_LEN - HSE_KVS_PFX_LEN_MAX,
        pfx_min_len));

    hbb_destroy(bld);

    free(buf);
}

MTF_DEFINE_UTEST_PREPOST(hblock_builder_test, finish_null_hlog, test_pre, test_post)
{
    merr_t err;
    struct hblock_builder *bld;
    struct cn *cn = (void *)-1;
    uint64_t mbid;

    err = hbb_create(&bld, cn, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = hbb_finish(bld, &mbid, vgmap, NULL, NULL, 0, 1, 1, 3, 0, NULL, NULL, NULL, 0);
    ASSERT_EQ(EINVAL, merr_errno(err));

    hbb_destroy(bld);
}

MTF_END_UTEST_COLLECTION(hblock_builder_test)
