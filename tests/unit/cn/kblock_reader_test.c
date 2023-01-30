/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <sys/mman.h>

#include <hse/test/mtf/framework.h>

#include <hse/logging/logging.h>
#include <hse/util/bloom_filter.h>
#include <hse/util/page.h>

#include "cn/omf.h"
#include "cn/kblock_reader.h"
#include "cn/bloom_reader.h"
#include "cn/wbt_internal.h"
#include "cn/wbt_reader.h"
#include "cn/cn_metrics.h"

/* 1 header page + 4 wbtree pages + 3 bloom pages */
#define FAKE_WBTREE_DOFF_PG  1
#define FAKE_WBTREE_DLEN_PG  4

#define FAKE_BLOOM_DOFF_PG   5
#define FAKE_BLOOM_DLEN_PG   3

#define FAKE_KBLOCK_SIZE ((1 + 4 + 3) * PAGE_SIZE)

size_t madvise_advice;
size_t madvise_off;
size_t madvise_len;
uint8_t kblock[FAKE_KBLOCK_SIZE];
struct kvs_mblk_desc mblk;

#define NUM_KEYS         1178
#define NUM_TOMBSTONES    100
#define TOT_KEY_BYTES    (NUM_KEYS * 20)
#define TOT_VAL_BYTES    (NUM_KEYS * 100)
#define TOT_KVLEN        (NUM_KEYS * 200)
#define TOT_VUSED_BYTES  ((NUM_KEYS * 100) - 100)
#define TOT_VGARB_BYTES   0

#define HOFF_ALIGN  8
#define WBT_HOFF ((sizeof(struct kblock_hdr_omf) + HOFF_ALIGN) & ~(HOFF_ALIGN - 1))
#define BLM_HOFF (WBT_HOFF + ((sizeof(struct wbt_hdr_omf) + HOFF_ALIGN) & ~(HOFF_ALIGN - 1)))

const struct kblk_metrics met = {
    .num_keys = NUM_KEYS,
    .num_tombstones = NUM_TOMBSTONES,
    .tot_key_bytes = TOT_KEY_BYTES,
    .tot_val_bytes = TOT_VAL_BYTES,
    .tot_kvlen = TOT_KVLEN,
    .tot_vused_bytes = TOT_VUSED_BYTES,
    .tot_wbt_pages = FAKE_WBTREE_DLEN_PG,
    .tot_blm_pages = FAKE_BLOOM_DLEN_PG,
};

const struct kblock_hdr_omf kbhro = {
    .kbh_magic = KBLOCK_HDR_MAGIC,
    .kbh_version = KBLOCK_HDR_VERSION,

    .kbh_hlog_doff_pg = 0,
    .kbh_hlog_dlen_pg = 0,

    .kbh_entries = NUM_KEYS,
    .kbh_tombs = NUM_TOMBSTONES,
    .kbh_key_bytes = TOT_KEY_BYTES,
    .kbh_val_bytes = TOT_VAL_BYTES,
    .kbh_kvlen = TOT_KVLEN,
    .kbh_vused_bytes = TOT_VUSED_BYTES,
    .kbh_vgarb_bytes = TOT_VGARB_BYTES,

    .kbh_min_koff = PAGE_SIZE - 100,
    .kbh_max_koff = PAGE_SIZE - 50,
    .kbh_min_klen = 20,
    .kbh_max_klen = 21,

    .kbh_wbt_hoff = WBT_HOFF,
    .kbh_wbt_hlen = sizeof(struct wbt_hdr_omf),
    .kbh_wbt_doff_pg = FAKE_WBTREE_DOFF_PG,
    .kbh_wbt_dlen_pg = FAKE_WBTREE_DLEN_PG,

    .kbh_blm_hoff = BLM_HOFF,
    .kbh_blm_hlen = sizeof(struct bloom_hdr_omf),
    .kbh_blm_doff_pg = FAKE_BLOOM_DOFF_PG,
    .kbh_blm_dlen_pg = FAKE_BLOOM_DLEN_PG,
};

void
init_kblock(struct kblock_hdr_omf *kbh)
{
    struct wbt_hdr_omf *wbt = (void *)kbh + WBT_HOFF;
    struct bloom_hdr_omf *bh = (void *)kbh + BLM_HOFF;

    omf_set_kbh_magic(kbh, kbhro.kbh_magic);
    omf_set_kbh_version(kbh, kbhro.kbh_version);

    omf_set_kbh_hlog_doff_pg(kbh, kbhro.kbh_hlog_doff_pg);
    omf_set_kbh_hlog_dlen_pg(kbh, kbhro.kbh_hlog_dlen_pg);

    omf_set_kbh_entries(kbh, kbhro.kbh_entries);
    omf_set_kbh_tombs(kbh, kbhro.kbh_tombs);
    omf_set_kbh_key_bytes(kbh, kbhro.kbh_key_bytes);
    omf_set_kbh_val_bytes(kbh, kbhro.kbh_val_bytes);
    omf_set_kbh_kvlen(kbh, kbhro.kbh_kvlen);
    omf_set_kbh_vused_bytes(kbh, kbhro.kbh_vused_bytes);
    omf_set_kbh_vgarb_bytes(kbh, kbhro.kbh_vgarb_bytes);

    omf_set_kbh_min_koff(kbh, kbhro.kbh_min_koff - 100);
    omf_set_kbh_min_klen(kbh, kbhro.kbh_min_klen);
    omf_set_kbh_max_koff(kbh, kbhro.kbh_max_koff - 50);
    omf_set_kbh_max_klen(kbh, kbhro.kbh_max_klen);

    /* NOTE: fake wbtree is supposed to be at pages 3..12 */
    omf_set_kbh_wbt_hoff(kbh, kbhro.kbh_wbt_hoff);
    omf_set_kbh_wbt_hlen(kbh, kbhro.kbh_wbt_hlen);
    omf_set_kbh_wbt_doff_pg(kbh, kbhro.kbh_wbt_doff_pg);
    omf_set_kbh_wbt_dlen_pg(kbh, kbhro.kbh_wbt_dlen_pg);

    /* NOTE: fake bloom filter at pages 1..2 */
    omf_set_kbh_blm_hoff(kbh, kbhro.kbh_blm_hoff);
    omf_set_kbh_blm_hlen(kbh, kbhro.kbh_blm_hlen);
    omf_set_kbh_blm_doff_pg(kbh, kbhro.kbh_blm_doff_pg);
    omf_set_kbh_blm_dlen_pg(kbh, kbhro.kbh_blm_dlen_pg);

    /* wbtree header */
    omf_set_wbt_magic(wbt, WBT_TREE_MAGIC);
    omf_set_wbt_version(wbt, WBT_TREE_VERSION);
    omf_set_wbt_root(wbt, 2);
    omf_set_wbt_leaf(wbt, 1);
    omf_set_wbt_leaf_cnt(wbt, 1);
    omf_set_wbt_kmd_pgc(wbt, 1);

    /* bloom header */
    omf_set_bh_magic(bh, BLOOM_OMF_MAGIC);
    omf_set_bh_version(bh, BLOOM_OMF_VERSION);
    omf_set_bh_bitmapsz(bh, 128);
    omf_set_bh_modulus(bh, 11);
    omf_set_bh_bktshift(bh, 8);
    omf_set_bh_rotl(bh, 8);
    omf_set_bh_n_hashes(bh, 4);
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
pre(struct mtf_test_info *info)
{
    memset(kblock, 0, sizeof(kblock));
    memset(&mblk, 0, sizeof(mblk));

    mblk.map_base = kblock;

    mblk.alen_pages = FAKE_KBLOCK_SIZE / PAGE_SIZE;
    mblk.wlen_pages = FAKE_KBLOCK_SIZE / PAGE_SIZE;
    mblk.mbid = 123;
    mblk.mclass = 1;

    init_kblock(mblk.map_base);

    madvise_off = 12345;
    madvise_len = 12345;
    madvise_advice = 12345;

    MOCK_SET_FN(mblk_desc, mblk_madvise_pages, mock_mblk_madvise_pages);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(kblock_reader);

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_read_wbt_region_desc, pre)
{
    merr_t err;
    struct wbt_desc wbt;

    err = kbr_read_wbt_region_desc(&mblk, &wbt);
    ASSERT_EQ(0, err);
    ASSERT_EQ(wbt.wbd_first_page, kbhro.kbh_wbt_doff_pg);
    ASSERT_EQ(wbt.wbd_n_pages, kbhro.kbh_wbt_dlen_pg);
}

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_read_blm_region_desc, pre)
{
    merr_t err;
    struct bloom_desc blm;

    err = kbr_read_blm_region_desc(&mblk, &blm);
    ASSERT_EQ(0, err);
    ASSERT_EQ(blm.bd_first_page, kbhro.kbh_blm_doff_pg);
    ASSERT_EQ(blm.bd_n_pages, kbhro.kbh_blm_dlen_pg);
    ASSERT_EQ(blm.bd_bitmap, mblk.map_base + PAGE_SIZE * blm.bd_first_page);
}

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_read_metrics, pre)
{
    merr_t err;
    struct kblk_metrics met;

    err = kbr_read_metrics(&mblk, &met);
    ASSERT_EQ(0, err);
    ASSERT_EQ(met.num_keys, kbhro.kbh_entries);
    ASSERT_EQ(met.num_tombstones, kbhro.kbh_tombs);
    ASSERT_EQ(met.tot_key_bytes, kbhro.kbh_key_bytes);
    ASSERT_EQ(met.tot_val_bytes, kbhro.kbh_val_bytes);
    ASSERT_EQ(met.tot_kvlen, kbhro.kbh_kvlen);
    ASSERT_EQ(met.tot_vused_bytes, kbhro.kbh_vused_bytes);
    ASSERT_EQ(met.tot_wbt_pages, kbhro.kbh_wbt_dlen_pg);
    ASSERT_EQ(met.tot_blm_pages, kbhro.kbh_blm_dlen_pg);

}

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_read_invalid_version, pre)
{
    merr_t err;
    struct wbt_desc wbt;
    struct kblk_metrics met;
    struct bloom_desc blm;
    struct kblock_hdr_omf *kbh = mblk.map_base;

    omf_set_kbh_version(kbh, kbhro.kbh_version + 1);

    err = kbr_read_wbt_region_desc(&mblk, &wbt);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kbr_read_blm_region_desc(&mblk, &blm);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kbr_read_metrics(&mblk, &met);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_madvise_kmd, pre)
{
    merr_t err;
    int adv;
    uint32_t pg_off, pg_cnt;
    struct wbt_desc wbt;

    err = kbr_read_wbt_region_desc(&mblk, &wbt);
    ASSERT_EQ(0, err);

    adv = __LINE__;
    pg_off = wbt.wbd_first_page + wbt.wbd_root + 1;
    pg_cnt = wbt.wbd_kmd_pgc;

    kbr_madvise_kmd(&mblk, &wbt, adv);

    ASSERT_EQ(madvise_advice, adv);
    ASSERT_EQ(madvise_off, PAGE_SIZE * pg_off);
    ASSERT_EQ(madvise_len, PAGE_SIZE * pg_cnt);
}

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_madvise_wbt_leaf_nodes, pre)
{
    merr_t err;
    int adv;
    uint32_t pg_off, pg_cnt;
    struct wbt_desc wbt;

    err = kbr_read_wbt_region_desc(&mblk, &wbt);
    ASSERT_EQ(0, err);

    adv = __LINE__;
    pg_off = wbt.wbd_first_page;
    pg_cnt = wbt.wbd_leaf_cnt;

    kbr_madvise_wbt_leaf_nodes(&mblk, &wbt, adv);

    ASSERT_EQ(madvise_advice, adv);
    ASSERT_EQ(madvise_off, PAGE_SIZE * pg_off);
    ASSERT_EQ(madvise_len, PAGE_SIZE * pg_cnt);
}

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_madvise_wbt_int_nodes, pre)
{
    merr_t err;
    int adv;
    uint32_t pg_off, pg_cnt;
    struct wbt_desc wbt;

    err = kbr_read_wbt_region_desc(&mblk, &wbt);
    ASSERT_EQ(0, err);

    adv = __LINE__;
    pg_off = wbt.wbd_first_page + wbt.wbd_leaf_cnt;
    pg_cnt = wbt.wbd_n_pages - wbt.wbd_leaf_cnt - wbt.wbd_kmd_pgc;

    kbr_madvise_wbt_int_nodes(&mblk, &wbt, adv);

    ASSERT_EQ(madvise_advice, adv);
    ASSERT_EQ(madvise_off, PAGE_SIZE * pg_off);
    ASSERT_EQ(madvise_len, PAGE_SIZE * pg_cnt);
}

MTF_DEFINE_UTEST_PRE(kblock_reader, t_kbr_madvise_bloom, pre)
{
    merr_t err;
    int adv;
    uint32_t pg_off, pg_cnt;
    struct bloom_desc blm;

    err = kbr_read_blm_region_desc(&mblk, &blm);
    ASSERT_EQ(0, err);

    adv = __LINE__;
    pg_off = blm.bd_first_page;
    pg_cnt = blm.bd_n_pages;

    kbr_madvise_bloom(&mblk, &blm, adv);

    ASSERT_EQ(madvise_advice, adv);
    ASSERT_EQ(madvise_off, PAGE_SIZE * pg_off);
    ASSERT_EQ(madvise_len, PAGE_SIZE * pg_cnt);
}

MTF_END_UTEST_COLLECTION(kblock_reader)
