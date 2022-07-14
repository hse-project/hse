/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <mtf/framework.h>

#include <cn/hblock_builder.h>
#include <cn/hblock_reader.h>
#include <cn/kvs_mblk_desc.h>
#include <cn/omf.h>
#include <cn/wbt_reader.h>

#include <hse_util/hlog.h>
#include <hse_util/hse_err.h>
#include <hse_util/keycmp.h>
#include <hse_util/page.h>

#include <mpool/mpool_structs.h>

#include <mocks/mock_mpool.h>

/* 1 header page, HLOG_PGC hlog pages, 3 ptree pages */
#define FAKE_BLOCK_SIZE ((HBLOCK_HDR_PAGES + HLOG_PGC + 3) * PAGE_SIZE)
#define PFX_MAX "BBBB"
#define PFX_MAX_LEN 4
#define PFX_MIN "AAAA"
#define PFX_MIN_LEN 4

struct hdr {
    struct hblock_hdr_omf *hblk_hdr;

    uint8_t data[HBLOCK_HDR_LEN];
};

const uint8_t fake_mblock_buf[FAKE_BLOCK_SIZE];

int
test_pre(struct mtf_test_info *info)
{
    mock_mpool_set();

    return 0;
}

int
test_post(struct mtf_test_info *info)
{
    mock_mpool_unset();

    return 0;
}

void
init_hdr(struct hdr *hdr)
{
    memset(hdr->data, 0, sizeof(hdr->data));

    hdr->hblk_hdr = (struct hblock_hdr_omf *)hdr->data;

    omf_set_hbh_magic(hdr->hblk_hdr, HBLOCK_HDR_MAGIC);
    omf_set_hbh_version(hdr->hblk_hdr, HBLOCK_HDR_VERSION);
    /* fake seqnos */
    omf_set_hbh_min_seqno(hdr->hblk_hdr, 11);
    omf_set_hbh_max_seqno(hdr->hblk_hdr, 101);
    omf_set_hbh_num_ptombs(hdr->hblk_hdr, 22);
    omf_set_hbh_num_kblocks(hdr->hblk_hdr, 0);
    omf_set_hbh_num_vblocks(hdr->hblk_hdr, 0);
    omf_set_hbh_vgmap_off_pg(hdr->hblk_hdr, 1);
    omf_set_hbh_vgmap_len_pg(hdr->hblk_hdr, 1);
    omf_set_hbh_hlog_off_pg(hdr->hblk_hdr, 2);
    omf_set_hbh_hlog_len_pg(hdr->hblk_hdr, HLOG_PGC);
    omf_set_hbh_ptree_data_off_pg(hdr->hblk_hdr, 2 + HLOG_PGC);
    omf_set_hbh_ptree_data_len_pg(hdr->hblk_hdr, 3);

    omf_set_wbt_magic(&hdr->hblk_hdr->hbh_ptree_hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(&hdr->hblk_hdr->hbh_ptree_hdr, WBT_TREE_VERSION);
    omf_set_wbt_root(&hdr->hblk_hdr->hbh_ptree_hdr, 0);
    omf_set_wbt_leaf(&hdr->hblk_hdr->hbh_ptree_hdr, 0);
    omf_set_wbt_leaf_cnt(&hdr->hblk_hdr->hbh_ptree_hdr, 0);

    memcpy((void *)hdr->hblk_hdr + HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX, PFX_MAX, PFX_MAX_LEN);
    memcpy((void *)hdr->hblk_hdr + HBLOCK_HDR_LEN - HSE_KVS_PFX_LEN_MAX, PFX_MIN, PFX_MIN_LEN);
}

MTF_BEGIN_UTEST_COLLECTION(hblock_reader_test)

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, madvise_wbt_int_nodes_success, test_pre, test_post)
{
    merr_t err;
    struct hdr hdr;
    struct mpool *mpool = (void *)-1;
    struct kvs_mblk_desc blk_desc;
    struct wbt_desc wbt_desc;
    uint64_t blkid;

    init_hdr(&hdr);

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    hbr_madvise_wbt_int_nodes(&blk_desc, &wbt_desc, MADV_WILLNEED);

    wbt_desc.wbd_n_pages = 0;
    wbt_desc.wbd_leaf_cnt = 0;
    hbr_madvise_wbt_int_nodes(&blk_desc, &wbt_desc, MADV_WILLNEED);

    mpool_mcache_munmap(blk_desc.map);

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, madvise_kmd_success, test_pre, test_post)
{
    merr_t err;
    struct hdr hdr;
    struct mpool *mpool = (void *)-1;
    struct kvs_mblk_desc blk_desc;
    struct wbt_desc wbt_desc;
    uint64_t blkid;

    init_hdr(&hdr);

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    hbr_madvise_kmd(&blk_desc, &wbt_desc, MADV_WILLNEED);

    wbt_desc.wbd_n_pages = 0;
    wbt_desc.wbd_leaf_cnt = 0;
    hbr_madvise_kmd(&blk_desc, &wbt_desc, MADV_WILLNEED);

    mpool_mcache_munmap(blk_desc.map);

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, madvise_wbt_leaf_nodes_success, test_pre, test_post)
{
    merr_t err;
    struct hdr hdr;
    struct mpool *mpool = (void *)-1;
    struct kvs_mblk_desc blk_desc;
    struct wbt_desc wbt_desc;
    uint64_t blkid;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    hbr_madvise_wbt_leaf_nodes(&blk_desc, &wbt_desc, MADV_WILLNEED);

    wbt_desc.wbd_n_pages = 0;
    wbt_desc.wbd_leaf_cnt = 0;
    hbr_madvise_wbt_leaf_nodes(&blk_desc, &wbt_desc, MADV_WILLNEED);

    mpool_mcache_munmap(blk_desc.map);

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, read_desc_error, test_pre, test_post)
{
    merr_t err;
    struct mpool *mpool = (void *)-1;
    struct mpool_mcache_map *map = (void *)-1;
    const uint64_t blkid = 0xffff;
    struct kvs_mblk_desc desc;
    struct mblock_props props;

    mapi_inject_ptr(mapi_idx_mpool_mcache_getbase, NULL);

    err = hbr_read_desc(mpool, map, &props, blkid, &desc);
    ASSERT_NE(0, merr_errno(err));

    mapi_inject_unset(mapi_idx_mpool_mcache_getbase);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, read_desc_success, test_pre, test_post)
{
    merr_t err;
    struct mpool *mpool = (void *)-1;
    struct mpool_mcache_map *map;
    struct hdr hdr;
    uint64_t blkid;
    struct kvs_mblk_desc desc;
    struct mblock_props props;
    struct hblk_metrics metrics;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blkid, &map);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_props_get(mpool, blkid, &props);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    err = mpm_mblock_write(blkid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = hbr_read_desc(mpool, map, &props, blkid, &desc);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(HBLOCK_HDR_MAGIC, omf_hbh_magic(desc.map_base));
    ASSERT_EQ(0, keycmp(desc.map_base + HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX, PFX_MAX_LEN,
        PFX_MAX, PFX_MAX_LEN));
    ASSERT_EQ(0, keycmp(desc.map_base + HBLOCK_HDR_LEN - HSE_KVS_PFX_LEN_MAX, PFX_MIN_LEN,
        PFX_MIN, PFX_MIN_LEN));

    err = hbr_read_metrics(&desc, &metrics);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(props.mpr_write_len, metrics.hm_size);
    ASSERT_EQ(22, metrics.hm_nptombs);

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, read_ptree_region_desc_error, test_pre, test_post)
{
    merr_t err, expected;
    struct mpool *mpool = (void *)-1;
    struct hdr hdr;
    struct kvs_mblk_desc blk_desc = {};
    struct wbt_desc wbt_desc;
    uint64_t blkid;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    expected = __LINE__;
    mapi_inject(mapi_idx_mpool_mcache_getpages, expected);
    err = hbr_read_ptree_region_desc(&blk_desc, &wbt_desc);
    ASSERT_EQ(expected, merr_errno(err));

    mapi_inject_unset(mapi_idx_mpool_mcache_getpages);

    expected = __LINE__;
    mapi_inject(mapi_idx_wbtr_read_desc, expected);
    err = hbr_read_ptree_region_desc(&blk_desc, &wbt_desc);
    ASSERT_EQ(expected, merr_errno(err));

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, read_ptree_region_desc_success, test_pre, test_post)
{
    merr_t err;
    struct mpool *mpool = (void *)-1;
    struct hdr hdr;
    struct kvs_mblk_desc blk_desc = {};
    struct wbt_desc wbt_desc;
    uint64_t blkid;
    uint64_t min_seqno, max_seqno;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    mapi_inject(mapi_idx_wbtr_read_desc, 0);

    err = hbr_read_ptree_region_desc(&blk_desc, &wbt_desc);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(omf_hbh_ptree_data_off_pg(hdr.hblk_hdr), wbt_desc.wbd_first_page);
    ASSERT_EQ(omf_hbh_ptree_data_len_pg(hdr.hblk_hdr), wbt_desc.wbd_n_pages);

    mapi_inject_unset(mapi_idx_wbtr_read_desc);

    err = hbr_read_seqno_range(&blk_desc, &min_seqno, &max_seqno);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(omf_hbh_min_seqno(hdr.hblk_hdr), min_seqno);
    ASSERT_EQ(omf_hbh_max_seqno(hdr.hblk_hdr), max_seqno);

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, read_seqno_range_desc_error, test_pre, test_post)
{
    merr_t err, expected;
    struct mpool *mpool = (void *)-1;
    struct hdr hdr;
    struct kvs_mblk_desc blk_desc = {};
    uint64_t blkid;
    uint64_t min_seqno, max_seqno;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    expected = __LINE__;
    mapi_inject(mapi_idx_mpool_mcache_getpages, expected);

    err = hbr_read_seqno_range(&blk_desc, &min_seqno, &max_seqno);
    ASSERT_EQ(expected, merr_errno(err));

    mapi_inject_unset(mapi_idx_mpool_mcache_getpages);

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, read_seqno_range_success, test_pre, test_post)
{
    merr_t err;
    struct mpool *mpool = (void *)-1;
    struct hdr hdr;
    struct kvs_mblk_desc blk_desc = {};
    uint64_t blkid;
    uint64_t min_seqno, max_seqno;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = hbr_read_seqno_range(&blk_desc, &min_seqno, &max_seqno);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(omf_hbh_min_seqno(hdr.hblk_hdr), min_seqno);
    ASSERT_EQ(omf_hbh_max_seqno(hdr.hblk_hdr), max_seqno);

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, corrupt_magic, test_pre, test_post)
{
    merr_t err;
    struct mpool *mpool = (void *)-1;
    struct hdr hdr;
    struct kvs_mblk_desc blk_desc = {};
    struct wbt_desc wbt_desc;
    uint64_t blkid;
    uint64_t min_seqno, max_seqno;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    omf_set_hbh_magic(hdr.hblk_hdr, ~HBLOCK_HDR_MAGIC);
    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = hbr_read_ptree_region_desc(&blk_desc, &wbt_desc);
    ASSERT_EQ(EPROTO, merr_errno(err));

    err = hbr_read_seqno_range(&blk_desc, &min_seqno, &max_seqno);
    ASSERT_EQ(EPROTO, merr_errno(err));

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, corrupt_version, test_pre, test_post)
{
    merr_t err;
    struct mpool *mpool = (void *)-1;
    struct hdr hdr;
    struct kvs_mblk_desc blk_desc = {};
    struct wbt_desc wbt_desc;
    uint64_t blkid;
    uint64_t min_seqno, max_seqno;

    err = mpm_mblock_alloc(FAKE_BLOCK_SIZE, &blkid);
    ASSERT_EQ(0, merr_errno(err));
    blk_desc.mbid = blkid;

    err = mpm_mblock_write(blkid, fake_mblock_buf, 0, FAKE_BLOCK_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mcache_mmap(mpool, 1, &blk_desc.mbid, &blk_desc.map);
    ASSERT_EQ(0, merr_errno(err));

    init_hdr(&hdr);
    omf_set_hbh_version(hdr.hblk_hdr, ~HBLOCK_HDR_VERSION);
    err = mpm_mblock_write(blk_desc.mbid, hdr.data, 0, HBLOCK_HDR_PAGES * PAGE_SIZE);
    ASSERT_EQ(0, merr_errno(err));

    err = hbr_read_ptree_region_desc(&blk_desc, &wbt_desc);
    ASSERT_EQ(EPROTO, merr_errno(err));

    err = hbr_read_seqno_range(&blk_desc, &min_seqno, &max_seqno);
    ASSERT_EQ(EPROTO, merr_errno(err));

    err = mpool_mblock_delete(mpool, blkid);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(hblock_reader_test)
