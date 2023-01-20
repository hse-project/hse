/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>
#include <sys/mman.h>

#include <mtf/framework.h>

#include "cn/hblock_builder.h"
#include "cn/hblock_reader.h"
#include "cn/kvs_mblk_desc.h"
#include "cn/omf.h"
#include "cn/wbt_reader.h"
#include "cn/vgmap.h"
#include "cn/kvset.h"

#include <hse/util/hlog.h>
#include <hse/error/merr.h>
#include <hse/util/keycmp.h>
#include <hse/util/page.h>

/* 1 header page, HLOG_PGC hlog pages, 3 ptree pages */
#define FAKE_HBLOCK_SIZE ((HBLOCK_HDR_PAGES + HLOG_PGC + 3) * PAGE_SIZE)
#define PFX_MAX "BBBB"
#define PFX_MAX_LEN 4
#define PFX_MIN "AAAA"
#define PFX_MIN_LEN 4


size_t madvise_advice;
size_t madvise_off;
size_t madvise_len;
uint8_t hblock[FAKE_HBLOCK_SIZE];
struct kvs_mblk_desc mblk;

const struct hblk_metrics met = {
    .hm_size = 0,
    .hm_nptombs = 1,
};

const struct hblock_hdr_omf hbh_ro = {
    .hbh_magic = HBLOCK_HDR_MAGIC,
    .hbh_version = HBLOCK_HDR_VERSION,

    .hbh_min_seqno = 11,
    .hbh_max_seqno = 101,

    .hbh_num_ptombs = 22,
    .hbh_num_kblocks = 1,
    .hbh_num_vblocks = 4,

    .hbh_vgmap_off_pg = 1,
    .hbh_vgmap_len_pg = 1,

    .hbh_hlog_off_pg = 2,
    .hbh_hlog_len_pg = HLOG_PGC,

    .hbh_ptree_data_off_pg = 2 + HLOG_PGC,
    .hbh_ptree_data_len_pg = 3,

    .hbh_max_pfx_off = HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX,
    .hbh_max_pfx_len = PFX_MAX_LEN,

    .hbh_min_pfx_off = HBLOCK_HDR_LEN - 1 * HSE_KVS_PFX_LEN_MAX,
    .hbh_min_pfx_len = PFX_MIN_LEN,

    .hbh_ptree_hdr = {
        .wbt_magic = WBT_TREE_MAGIC,
        .wbt_version = WBT_TREE_VERSION,
        .wbt_root = 20,
        .wbt_leaf = 0,
        .wbt_leaf_cnt = 10,
        .wbt_kmd_pgc = 5
    },
};

void
init_hblock(struct hblock_hdr_omf *hbh)
{
    struct vgroup_map_omf *vgm = (void *)hbh + PAGE_SIZE * hbh_ro.hbh_vgmap_off_pg;

    omf_set_hbh_magic(hbh, hbh_ro.hbh_magic);
    omf_set_hbh_version(hbh, hbh_ro.hbh_version);

    omf_set_hbh_min_seqno(hbh, hbh_ro.hbh_min_seqno);
    omf_set_hbh_max_seqno(hbh, hbh_ro.hbh_max_seqno);
    omf_set_hbh_num_ptombs(hbh, hbh_ro.hbh_num_ptombs);
    omf_set_hbh_num_kblocks(hbh, hbh_ro.hbh_num_kblocks);
    omf_set_hbh_num_vblocks(hbh, hbh_ro.hbh_num_vblocks);
    omf_set_hbh_vgmap_off_pg(hbh, hbh_ro.hbh_vgmap_off_pg);
    omf_set_hbh_vgmap_len_pg(hbh, hbh_ro.hbh_vgmap_len_pg);
    omf_set_hbh_hlog_off_pg(hbh, hbh_ro.hbh_hlog_off_pg);
    omf_set_hbh_hlog_len_pg(hbh, hbh_ro.hbh_hlog_len_pg);
    omf_set_hbh_ptree_data_off_pg(hbh, hbh_ro.hbh_ptree_data_off_pg);
    omf_set_hbh_ptree_data_len_pg(hbh, hbh_ro.hbh_ptree_data_len_pg);

    omf_set_wbt_magic(&hbh->hbh_ptree_hdr,    hbh_ro.hbh_ptree_hdr.wbt_magic);
    omf_set_wbt_version(&hbh->hbh_ptree_hdr,  hbh_ro.hbh_ptree_hdr.wbt_version);
    omf_set_wbt_root(&hbh->hbh_ptree_hdr,     hbh_ro.hbh_ptree_hdr.wbt_root);
    omf_set_wbt_leaf(&hbh->hbh_ptree_hdr,     hbh_ro.hbh_ptree_hdr.wbt_leaf);
    omf_set_wbt_leaf_cnt(&hbh->hbh_ptree_hdr, hbh_ro.hbh_ptree_hdr.wbt_leaf_cnt);
    omf_set_wbt_kmd_pgc(&hbh->hbh_ptree_hdr,  hbh_ro.hbh_ptree_hdr.wbt_kmd_pgc);

    omf_set_vgm_magic(vgm, VGROUP_MAP_MAGIC);
    omf_set_vgm_version(vgm, VGROUP_MAP_VERSION);
    omf_set_vgm_count(vgm, 2);

    memcpy((void *)hbh + HBLOCK_HDR_LEN - 2 * HSE_KVS_PFX_LEN_MAX, PFX_MAX, PFX_MAX_LEN);
    memcpy((void *)hbh + HBLOCK_HDR_LEN - HSE_KVS_PFX_LEN_MAX, PFX_MIN, PFX_MIN_LEN);
}

merr_t
mock_mblk_madvise_pages(const struct kvs_mblk_desc *md, size_t pg_off, size_t pg_cnt, int advice)
{
    madvise_off = pg_off * PAGE_SIZE;
    madvise_len = pg_cnt * PAGE_SIZE;
    madvise_advice = advice;
    return 0;
}

int
test_pre(struct mtf_test_info *info)
{
    memset(hblock, 0, sizeof(hblock));
    memset(&mblk, 0, sizeof(mblk));

    mblk.map_base = hblock;

    mblk.alen_pages = FAKE_HBLOCK_SIZE / PAGE_SIZE;
    mblk.wlen_pages = FAKE_HBLOCK_SIZE / PAGE_SIZE;
    mblk.mbid = 123;
    mblk.mclass = 1;

    init_hblock(mblk.map_base);

    madvise_off = 12345;
    madvise_len = 12345;
    madvise_advice = 12345;

    MOCK_SET_FN(mblk_desc, mblk_madvise_pages, mock_mblk_madvise_pages);

    return 0;
}

int
test_post(struct mtf_test_info *info)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(hblock_reader_test)

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_read_metrics, test_pre, test_post)
{
    merr_t err;
    struct hblk_metrics s;

    err = hbr_read_metrics(&mblk, &s);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_read_ptree_region_desc, test_pre, test_post)
{
    merr_t err;
    struct wbt_desc s;

    err = hbr_read_ptree_region_desc(&mblk, &s);
    ASSERT_EQ(err, 0);

    ASSERT_EQ(s.wbd_first_page, hbh_ro.hbh_ptree_data_off_pg);
    ASSERT_EQ(s.wbd_n_pages,    hbh_ro.hbh_ptree_data_len_pg);

    ASSERT_EQ(s.wbd_version,    hbh_ro.hbh_ptree_hdr.wbt_version);
    ASSERT_EQ(s.wbd_root,       hbh_ro.hbh_ptree_hdr.wbt_root);
    ASSERT_EQ(s.wbd_leaf,       hbh_ro.hbh_ptree_hdr.wbt_leaf);
    ASSERT_EQ(s.wbd_leaf_cnt,   hbh_ro.hbh_ptree_hdr.wbt_leaf_cnt);
    ASSERT_EQ(s.wbd_kmd_pgc,    hbh_ro.hbh_ptree_hdr.wbt_kmd_pgc);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_read_seqno_range, test_pre, test_post)
{
    merr_t err;
    uint64_t min_seqno, max_seqno;

    err = hbr_read_seqno_range(&mblk, &min_seqno, &max_seqno);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(min_seqno, hbh_ro.hbh_min_seqno);
    ASSERT_EQ(max_seqno, hbh_ro.hbh_max_seqno);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_read_vgroup_cnt, test_pre, test_post)
{
    merr_t err;
    uint32_t nvgroups;

    err = hbr_read_vgroup_cnt(&mblk, &nvgroups);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(nvgroups, 2);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_read_vgroup_map, test_pre, test_post)
{
    merr_t err;
    bool use_vgmap;
    struct vgmap *vgmap;
    uint32_t nvgroups;

    err = hbr_read_vgroup_cnt(&mblk, &nvgroups);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(nvgroups, 2);

    vgmap = vgmap_alloc(nvgroups);
    ASSERT_NE(vgmap, NULL);

    err = hbr_read_vgroup_map(&mblk, vgmap, &use_vgmap);
    ASSERT_EQ(err, 0);
    ASSERT_FALSE(use_vgmap);

    free(vgmap);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_read_ptree, test_pre, test_post)
{
    merr_t err;
    uint8_t *ptree;
    uint32_t ptree_pgc;
    struct wbt_desc s;

    err = hbr_read_ptree_region_desc(&mblk, &s);
    ASSERT_EQ(err, 0);

    hbr_read_ptree(&mblk, &s, &ptree, &ptree_pgc);
    ASSERT_EQ(ptree, mblk.map_base + s.wbd_first_page * PAGE_SIZE);
    ASSERT_EQ(ptree_pgc, s.wbd_n_pages);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_madvise_kmd, test_pre, test_post)
{
    merr_t err;
    struct wbt_desc s;
    uint32_t pg, pg_cnt;
    int adv = __LINE__;

    err = hbr_read_ptree_region_desc(&mblk, &s);
    ASSERT_EQ(err, 0);

    pg = s.wbd_first_page + s.wbd_root + 1;
    pg_cnt = s.wbd_kmd_pgc;

    hbr_madvise_kmd(&mblk, &s, adv);

    ASSERT_EQ(madvise_advice, adv);
    ASSERT_EQ(madvise_off, PAGE_SIZE * pg);
    ASSERT_EQ(madvise_len, PAGE_SIZE * pg_cnt);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_madvise_wbt_leaf_nodes, test_pre, test_post)
{
    merr_t err;
    struct wbt_desc s;
    uint32_t pg, pg_cnt;
    int adv = __LINE__;

    err = hbr_read_ptree_region_desc(&mblk, &s);
    ASSERT_EQ(err, 0);

    pg = s.wbd_first_page;
    pg_cnt = s.wbd_leaf_cnt;

    hbr_madvise_wbt_leaf_nodes(&mblk, &s, adv);

    ASSERT_EQ(madvise_advice, adv);
    ASSERT_EQ(madvise_off, PAGE_SIZE * pg);
    ASSERT_EQ(madvise_len, PAGE_SIZE * pg_cnt);
}

MTF_DEFINE_UTEST_PREPOST(hblock_reader_test, t_hbr_madvise_wbt_int_nodes, test_pre, test_post)
{
    merr_t err;
    struct wbt_desc s;
    uint32_t pg, pg_cnt;
    int adv = __LINE__;

    err = hbr_read_ptree_region_desc(&mblk, &s);
    ASSERT_EQ(err, 0);

    pg = s.wbd_first_page + s.wbd_leaf_cnt;
    pg_cnt = s.wbd_n_pages - s.wbd_leaf_cnt - s.wbd_kmd_pgc;

    hbr_madvise_wbt_int_nodes(&mblk, &s, adv);

    ASSERT_EQ(madvise_advice, adv);
    ASSERT_EQ(madvise_off, PAGE_SIZE * pg);
    ASSERT_EQ(madvise_len, PAGE_SIZE * pg_cnt);

}

MTF_END_UTEST_COLLECTION(hblock_reader_test)
