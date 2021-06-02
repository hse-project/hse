/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/logging.h>
#include <hse_util/page.h>
#include <hse_util/bloom_filter.h>

#include <hse_ikvdb/kvs_rparams.h>

#include <cn/omf.h>
#include <cn/kblock_reader.h>
#include <cn/bloom_reader.h>
#include <cn/wbt_internal.h>
#include <cn/wbt_reader.h>
#include <cn/cn_metrics.h>

#include <mocks/mock_mpool.h>

int
test_collection_setup(struct mtf_test_info *info)
{
    hse_openlog("kblock_reader_test", 1);
    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    mock_mpool_unset();
    return 0;
}

int
pre(struct mtf_test_info *info)
{
    mock_mpool_set();
    return 0;
}

struct kb_hdr {
    struct kblock_hdr_omf *kb_hdr;
    struct wbt_hdr_omf *   wbt_hdr;
    struct bloom_hdr_omf * blm_hdr;
    struct wbt_hdr_omf *   pt_hdr;
    u8                     data[4096];
};

/* 1 header page + 2 bloom pages +10 wbtree pages */
#define FAKE_KBLOCK_SIZE ((1 + 2 + 10) * PAGE_SIZE)

/* an empty buffer for writing to mblocks */
const char fake_kblock_buf[FAKE_KBLOCK_SIZE];

void
init_kb_hdr(struct kb_hdr *kb)
{
    u32 align = 8;
    u32 wbt_off = (sizeof(struct kblock_hdr_omf) + align) & ~(align - 1);
    u32 blm_off = wbt_off + ((sizeof(struct wbt_hdr_omf) + align) & ~(align - 1));
    u32 pt_off = blm_off + ((sizeof(struct bloom_hdr_omf) + align) & ~(align - 1));

    memset(kb->data, 0, 4096);
    kb->kb_hdr = (struct kblock_hdr_omf *)(kb->data);
    kb->wbt_hdr = (struct wbt_hdr_omf *)(kb->data + wbt_off);
    kb->blm_hdr = (struct bloom_hdr_omf *)(kb->data + blm_off);
    kb->pt_hdr = (struct wbt_hdr_omf *)(kb->data + pt_off);

    omf_set_kbh_magic(kb->kb_hdr, KBLOCK_HDR_MAGIC);
    omf_set_kbh_version(kb->kb_hdr, KBLOCK_HDR_VERSION);
    omf_set_kbh_entries(kb->kb_hdr, 1173);
    omf_set_kbh_tombs(kb->kb_hdr, 87);
    omf_set_kbh_key_bytes(kb->kb_hdr, 13789);
    omf_set_kbh_val_bytes(kb->kb_hdr, 83787);
    omf_set_kbh_wbt_hoff(kb->kb_hdr, wbt_off);

    /* NOTE: fake bloom filter at pages 1..2 */
    omf_set_kbh_blm_hlen(kb->kb_hdr, sizeof(struct bloom_hdr_omf));
    omf_set_kbh_blm_doff_pg(kb->kb_hdr, 1);
    omf_set_kbh_blm_dlen_pg(kb->kb_hdr, 2);

    /* NOTE: fake wbtree is supposed to be at pages 3..12 */
    omf_set_kbh_wbt_hlen(kb->kb_hdr, sizeof(struct wbt_hdr_omf));
    omf_set_kbh_wbt_doff_pg(kb->kb_hdr, 3);
    omf_set_kbh_wbt_dlen_pg(kb->kb_hdr, 10);
    omf_set_kbh_blm_hoff(kb->kb_hdr, blm_off);

    omf_set_kbh_pt_hoff(kb->kb_hdr, pt_off);

    /* NOTE: fake ptree is supposed to be at pages 13..15 */
    omf_set_kbh_pt_hlen(kb->kb_hdr, sizeof(struct wbt_hdr_omf));
    omf_set_kbh_pt_doff_pg(kb->kb_hdr, 13);
    omf_set_kbh_pt_dlen_pg(kb->kb_hdr, 3);

    /* fake seqnos */
    omf_set_kbh_min_seqno(kb->kb_hdr, 11);
    omf_set_kbh_max_seqno(kb->kb_hdr, 101);

    omf_set_wbt_magic(kb->wbt_hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(kb->wbt_hdr, WBT_TREE_VERSION);
    omf_set_wbt_root(kb->wbt_hdr, 0);
    omf_set_wbt_leaf(kb->wbt_hdr, 0);
    omf_set_wbt_leaf_cnt(kb->wbt_hdr, 0);

    omf_set_bh_magic(kb->blm_hdr, BLOOM_OMF_MAGIC);
    omf_set_bh_version(kb->blm_hdr, BLOOM_OMF_VERSION);

    omf_set_bh_modulus(kb->blm_hdr, 11730);
    omf_set_bh_bktshift(kb->blm_hdr, BF_BKTSHIFT);
    omf_set_bh_rotl(kb->blm_hdr, BF_ROTL);
    omf_set_bh_n_hashes(kb->blm_hdr, 7);
    omf_set_bh_bitmapsz(kb->blm_hdr, ALIGN((omf_bh_modulus(kb->blm_hdr) / CHAR_BIT), PAGE_SIZE));

    omf_set_wbt_magic(kb->pt_hdr, WBT_TREE_MAGIC);
    omf_set_wbt_version(kb->pt_hdr, WBT_TREE_VERSION);
    omf_set_wbt_root(kb->pt_hdr, 0);
    omf_set_wbt_leaf(kb->pt_hdr, 0);
    omf_set_wbt_leaf_cnt(kb->pt_hdr, 0);
}

merr_t
write_kb_hdr(struct kb_hdr *kb, struct kvs_mblk_desc *blkdesc)
{
    return mpm_mblock_write(blkdesc->mb_id, kb->data, 0, PAGE_SIZE);
}

int
check_read_hdrs(
    struct kb_hdr *       kb,
    struct kvs_mblk_desc *blkdesc,
    int                   wbt_errno,
    int                   blm_errno,
    int                   pt_errno,
    int                   seq_errno)
{
    merr_t            err;
    struct wbt_desc   wb_desc, pt_desc;
    struct bloom_desc blm_desc;
    u64               seqno_min, seqno_max;

    write_kb_hdr(kb, blkdesc);

    err = kbr_read_wbt_region_desc(blkdesc, &wb_desc);
    VERIFY_EQ_RET(merr_errno(err), wbt_errno, 1);

    err = kbr_read_blm_region_desc(blkdesc, &blm_desc);
    VERIFY_EQ_RET(merr_errno(err), blm_errno, 1);

    err = kbr_read_pt_region_desc(blkdesc, &pt_desc);
    VERIFY_EQ_RET(merr_errno(err), pt_errno, 1);

    err = kbr_read_seqno_range(blkdesc, &seqno_min, &seqno_max);
    VERIFY_EQ_RET(merr_errno(err), seq_errno, 1);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    kblock_reader_test,
    test_collection_setup,
    test_collection_teardown);

MTF_DEFINE_UTEST_PRE(kblock_reader_test, t_kbr_get_kblock_desc, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map = (struct mpool_mcache_map *)0x123;
    u32                      map_idx = 3;
    u64                      kbid = 0xffff;
    struct kvs_mblk_desc     desc;

    /* force success w/o having an actual mblock */
    mapi_inject_ptr(mapi_idx_mpool_mcache_getbase, (void *)1);
    err = kbr_get_kblock_desc(ds, map, map_idx, kbid, &desc);
    ASSERT_EQ(err, 0);

    /* force fail */
    mapi_inject_ptr(mapi_idx_mpool_mcache_getbase, 0);
    err = kbr_get_kblock_desc(ds, map, map_idx, kbid, &desc);
    ASSERT_NE(err, 0);
}

MTF_DEFINE_UTEST_PRE(kblock_reader_test, basic_wbt_blm_test, pre)
{
    merr_t               err;
    struct mpool *       mp_ds = (void *)-1;
    struct wbt_desc      wb_desc, pt_desc;
    struct bloom_desc    blm_desc;
    struct kb_hdr        kb;
    struct kblk_metrics  metrics;
    struct kvs_mblk_desc blkdesc;
    u64                  blkid;
    u8 *                 blm_pages;

    memset(&blkdesc, 0, sizeof(blkdesc));

    err = mpm_mblock_alloc(FAKE_KBLOCK_SIZE, &blkid);
    ASSERT_EQ(0, err);
    blkdesc.mb_id = blkid;

    err = mpm_mblock_write(blkid, fake_kblock_buf, 0, FAKE_KBLOCK_SIZE);
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(mp_ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(0, err);

    init_kb_hdr(&kb);
    err = write_kb_hdr(&kb, &blkdesc);
    ASSERT_EQ(err, 0);

    err = kbr_read_wbt_region_desc(&blkdesc, &wb_desc);
    ASSERT_EQ(0, err);
    ASSERT_EQ(omf_kbh_wbt_doff_pg(kb.kb_hdr), wb_desc.wbd_first_page);
    ASSERT_EQ(omf_kbh_wbt_dlen_pg(kb.kb_hdr), wb_desc.wbd_n_pages);

    err = kbr_read_pt_region_desc(&blkdesc, &pt_desc);
    ASSERT_EQ(0, err);
    ASSERT_EQ(omf_kbh_pt_doff_pg(kb.kb_hdr), pt_desc.wbd_first_page);
    ASSERT_EQ(omf_kbh_pt_dlen_pg(kb.kb_hdr), pt_desc.wbd_n_pages);

    u64 seqno_min, seqno_max;

    err = kbr_read_seqno_range(&blkdesc, &seqno_min, &seqno_max);
    ASSERT_EQ(0, err);
    ASSERT_EQ(omf_kbh_min_seqno(kb.kb_hdr), seqno_min);
    ASSERT_EQ(omf_kbh_max_seqno(kb.kb_hdr), seqno_max);

    err = kbr_read_blm_region_desc(&blkdesc, &blm_desc);
    ASSERT_EQ(0, err);
    ASSERT_EQ(omf_kbh_blm_doff_pg(kb.kb_hdr), blm_desc.bd_first_page);
    ASSERT_EQ(omf_kbh_blm_dlen_pg(kb.kb_hdr), blm_desc.bd_n_pages);

    /* BLOOM_LOOKUP_MCACHE will return base address of the bloom
     * blocks in the mcache map.
     */
    blm_pages = NULL;
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_MCACHE, &blm_desc, &blm_pages);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, blm_pages);
    kbr_free_blm_pages(&blkdesc, BLOOM_LOOKUP_MCACHE, blm_pages);

    blm_pages = NULL;
    mapi_inject_once(mapi_idx_mpool_mcache_getpages, 1, EBUG);
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_MCACHE, &blm_desc, &blm_pages);
    ASSERT_NE(0, err);
    ASSERT_EQ(NULL, blm_pages);

    /* BLOOM_LOOKUP_BUFFER will return a ptr to a buffer
     * which contains the bloom blocks read from the mblock.
     */
    blm_pages = NULL;
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_BUFFER, &blm_desc, &blm_pages);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, blm_pages);
    kbr_free_blm_pages(&blkdesc, BLOOM_LOOKUP_BUFFER, blm_pages);

    blm_pages = (void *)(-1);
    mapi_inject_once_ptr(mapi_idx_alloc_aligned, 1, NULL);
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_BUFFER, &blm_desc, &blm_pages);
    ASSERT_NE(0, err);
    ASSERT_EQ(NULL, blm_pages);

    blm_pages = (void *)(-1);
    mapi_inject_once(mapi_idx_mpool_mblock_read, 1, EBUG);
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_BUFFER, &blm_desc, &blm_pages);
    ASSERT_NE(0, err);
    ASSERT_EQ(NULL, blm_pages);

    err = kbr_read_metrics(&blkdesc, &metrics);

    ASSERT_EQ(0, err);
    ASSERT_EQ(omf_kbh_entries(kb.kb_hdr), metrics.num_keys);
    ASSERT_EQ(omf_kbh_tombs(kb.kb_hdr), metrics.num_tombstones);
    ASSERT_EQ(omf_kbh_key_bytes(kb.kb_hdr), metrics.tot_key_bytes);
    ASSERT_EQ(omf_kbh_val_bytes(kb.kb_hdr), metrics.tot_val_bytes);

    /* BLOOM_LOOKUP_NONE should succeed, but return NULL blm_pages.
     */
    blm_pages = (void *)(-1);
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_NONE, &blm_desc, &blm_pages);
    ASSERT_EQ(0, err);
    ASSERT_EQ(NULL, blm_pages);

    blm_desc.bd_n_pages = 0;
    blm_pages = (void *)(-1);
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_NONE, &blm_desc, &blm_pages);
    ASSERT_EQ(0, err);
    ASSERT_EQ(NULL, blm_pages);

    kbr_free_blm_pages(&blkdesc, BLOOM_LOOKUP_NONE, NULL);
    kbr_free_blm_pages(&blkdesc, BLOOM_LOOKUP_NONE, (void *)(-1));

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PRE(kblock_reader_test, t_kbr_madvise_bloom, pre)
{
    merr_t               err;
    struct mpool *       mp_ds = (void *)-1;
    struct kb_hdr        kb;
    struct kvs_mblk_desc blkdesc;
    struct bloom_desc    blm_desc;
    u64                  blkid;

    memset(&blkdesc, 0, sizeof(blkdesc));

    err = mpm_mblock_alloc(FAKE_KBLOCK_SIZE, &blkid);
    ASSERT_EQ(0, err);
    blkdesc.mb_id = blkid;

    err = mpm_mblock_write(blkid, fake_kblock_buf, 0, FAKE_KBLOCK_SIZE);
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(mp_ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(0, err);

    init_kb_hdr(&kb);
    err = write_kb_hdr(&kb, &blkdesc);
    ASSERT_EQ(err, 0);

    err = kbr_read_blm_region_desc(&blkdesc, &blm_desc);
    ASSERT_EQ(err, 0);

    /* once w/ forced error */
    mapi_inject_once(mapi_idx_mpool_mcache_madvise, 1, EINVAL);
    kbr_madvise_bloom(&blkdesc, &blm_desc, MADV_NORMAL);

    /* once w/o error */
    kbr_madvise_bloom(&blkdesc, &blm_desc, MADV_NORMAL);

    blm_desc.bd_n_pages = 0;
    kbr_madvise_bloom(&blkdesc, &blm_desc, MADV_NORMAL);

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PRE(kblock_reader_test, t_kbr_madvise_wbt_leaf_nodes, pre)
{
    merr_t               err;
    struct mpool *       mp_ds = (void *)-1;
    struct kb_hdr        kb = {};
    struct kvs_mblk_desc blkdesc = {};
    struct wbt_desc      wb_desc = {};
    u64                  blkid = 0;

    err = mpm_mblock_alloc(FAKE_KBLOCK_SIZE, &blkid);
    ASSERT_EQ(0, err);
    blkdesc.mb_id = blkid;

    err = mpm_mblock_write(blkid, fake_kblock_buf, 0, FAKE_KBLOCK_SIZE);
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(mp_ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(0, err);

    init_kb_hdr(&kb);
    err = write_kb_hdr(&kb, &blkdesc);
    ASSERT_EQ(err, 0);

    err = kbr_read_wbt_region_desc(&blkdesc, &wb_desc);
    ASSERT_EQ(err, 0);

    /* once w/ forced error */
    mapi_inject_once(mapi_idx_mpool_mcache_madvise, 1, EINVAL);
    kbr_madvise_wbt_leaf_nodes(&blkdesc, &wb_desc, MADV_NORMAL);

    /* once w/o error */
    kbr_madvise_wbt_leaf_nodes(&blkdesc, &wb_desc, MADV_NORMAL);

    wb_desc.wbd_leaf_cnt = 0;
    kbr_madvise_wbt_leaf_nodes(&blkdesc, &wb_desc, MADV_NORMAL);

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PRE(kblock_reader_test, t_kbr_madvise_wbt_int_nodes, pre)
{
    merr_t               err;
    struct mpool *       mp_ds = (void *)-1;
    struct kb_hdr        kb = {};
    struct kvs_mblk_desc blkdesc = {};
    struct wbt_desc      wb_desc = {};
    u64                  blkid = 0;

    err = mpm_mblock_alloc(FAKE_KBLOCK_SIZE, &blkid);
    ASSERT_EQ(0, err);
    blkdesc.mb_id = blkid;

    err = mpm_mblock_write(blkid, fake_kblock_buf, 0, FAKE_KBLOCK_SIZE);
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(mp_ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(0, err);

    init_kb_hdr(&kb);
    err = write_kb_hdr(&kb, &blkdesc);
    ASSERT_EQ(err, 0);

    err = kbr_read_wbt_region_desc(&blkdesc, &wb_desc);
    ASSERT_EQ(err, 0);

    /* once w/ forced error */
    mapi_inject_once(mapi_idx_mpool_mcache_madvise, 1, EINVAL);
    kbr_madvise_wbt_int_nodes(&blkdesc, &wb_desc, MADV_NORMAL);

    /* once w/o error */
    kbr_madvise_wbt_int_nodes(&blkdesc, &wb_desc, MADV_NORMAL);

    wb_desc.wbd_n_pages = 0;
    wb_desc.wbd_leaf_cnt = 0;
    kbr_madvise_wbt_int_nodes(&blkdesc, &wb_desc, MADV_NORMAL);

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PRE(kblock_reader_test, t_kbr_cache_pt_leaf_nodes, pre)
{
    merr_t               err;
    struct mpool *       mp_ds = (void *)-1;
    struct kb_hdr        kb = {};
    struct kvs_mblk_desc blkdesc = {};
    struct wbt_desc      wb_desc = {};
    u64                  blkid = 0;

    err = mpm_mblock_alloc(FAKE_KBLOCK_SIZE, &blkid);
    ASSERT_EQ(0, err);
    blkdesc.mb_id = blkid;

    err = mpm_mblock_write(blkid, fake_kblock_buf, 0, FAKE_KBLOCK_SIZE);
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(mp_ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(0, err);

    init_kb_hdr(&kb);
    err = write_kb_hdr(&kb, &blkdesc);
    ASSERT_EQ(err, 0);

    mapi_inject(mapi_idx_mpool_mcache_getpages, EBUG);
    err = kbr_read_pt_region_desc(&blkdesc, &wb_desc);
    ASSERT_EQ(EBUG, merr_errno(err));
    mapi_inject_unset(mapi_idx_mpool_mcache_getpages);

    u64 seqno_min, seqno_max;

    mapi_inject(mapi_idx_mpool_mcache_getpages, EBUG);
    err = kbr_read_seqno_range(&blkdesc, &seqno_min, &seqno_max);
    ASSERT_EQ(EBUG, merr_errno(err));
    mapi_inject_unset(mapi_idx_mpool_mcache_getpages);

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PRE(kblock_reader_test, t_corrupt_header, pre)
{
    merr_t               err;
    struct kvs_mblk_desc blkdesc;
    struct kb_hdr        kb;
    struct mpool *       mp_ds = (void *)-1;
    u64                  blkid;

    memset(&blkdesc, 0, sizeof(blkdesc));

    err = mpm_mblock_alloc(FAKE_KBLOCK_SIZE, &blkid);
    ASSERT_EQ(err, 0);
    blkdesc.mb_id = blkid;

    err = mpm_mblock_write(blkid, fake_kblock_buf, 0, FAKE_KBLOCK_SIZE);
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(mp_ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(err, 0);

    /* verify we can read w/o corruption */
    init_kb_hdr(&kb);
    err = check_read_hdrs(&kb, &blkdesc, 0, 0, 0, 0);
    ASSERT_EQ(err, 0);

    /* corrupt kblock hdr magic */
    init_kb_hdr(&kb);
    omf_set_kbh_magic(kb.kb_hdr, omf_kbh_magic(kb.kb_hdr) + 1);
    err = check_read_hdrs(&kb, &blkdesc, EINVAL, EINVAL, EINVAL, EINVAL);
    ASSERT_EQ(err, 0);

    /* corrupt kblock hdr version */
    init_kb_hdr(&kb);
    omf_set_kbh_version(kb.kb_hdr, omf_kbh_version(kb.kb_hdr) + 1);
    err = check_read_hdrs(&kb, &blkdesc, EINVAL, EINVAL, EINVAL, EINVAL);
    ASSERT_EQ(err, 0);

    /* corrupt wbt hdr magic */
    init_kb_hdr(&kb);
    omf_set_wbt_magic(kb.wbt_hdr, omf_wbt_magic(kb.wbt_hdr) + 1);
    err = check_read_hdrs(&kb, &blkdesc, EINVAL, 0, 0, 0);
    ASSERT_EQ(err, 0);

    /* corrupt wbt hdr version */
    init_kb_hdr(&kb);
    omf_set_wbt_version(kb.wbt_hdr, omf_wbt_version(kb.wbt_hdr) + 1);
    err = check_read_hdrs(&kb, &blkdesc, EINVAL, 0, 0, 0);
    ASSERT_EQ(err, 0);

    /* corrupt blm hdr magic */
    init_kb_hdr(&kb);
    omf_set_bh_magic(kb.blm_hdr, omf_bh_magic(kb.blm_hdr) + 1);
    err = check_read_hdrs(&kb, &blkdesc, 0, EINVAL, 0, 0);
    ASSERT_EQ(err, 0);

    /* corrupt blm hdr version */
    /* check should succeed, but with blooms disabled */
    init_kb_hdr(&kb);
    omf_set_bh_version(kb.blm_hdr, omf_bh_version(kb.blm_hdr) + 1);
    err = check_read_hdrs(&kb, &blkdesc, 0, 0, 0, 0);
    ASSERT_EQ(err, 0);

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(err, 0);
}

MTF_DEFINE_UTEST_PRE(kblock_reader_test, basic_kblock_error_test, pre)
{
    merr_t               err, force_err;
    struct mpool *       mp_ds = (void *)-1;
    struct kb_hdr        kb;
    struct wbt_desc      wb_desc;
    struct bloom_desc    blm_desc;
    struct kvs_mblk_desc blkdesc;
    u64                  blkid;
    u8 *                 blm_pages;

    memset(&blkdesc, 0, sizeof(blkdesc));

    err = mpm_mblock_alloc(FAKE_KBLOCK_SIZE, &blkid);
    ASSERT_EQ(0, err);
    blkdesc.mb_id = blkid;

    err = mpm_mblock_write(blkid, fake_kblock_buf, 0, FAKE_KBLOCK_SIZE);
    ASSERT_EQ(0, err);

    init_kb_hdr(&kb);
    err = write_kb_hdr(&kb, &blkdesc);
    ASSERT_EQ(err, 0);

    err = mpool_mcache_mmap(mp_ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(0, err);

    force_err = __LINE__;
    mapi_inject_ptr(mapi_idx_mpool_mcache_getpages, (void *)force_err);
    err = kbr_read_wbt_region_desc(&blkdesc, &wb_desc);
    ASSERT_EQ(force_err, err);
    mapi_inject_unset(mapi_idx_mpool_mcache_getpages);

    err = kbr_read_wbt_region_desc(&blkdesc, &wb_desc);
    ASSERT_EQ(0, err);

    force_err = __LINE__;
    mapi_inject_ptr(mapi_idx_mpool_mcache_getpages, (void *)force_err);
    err = kbr_read_blm_region_desc(&blkdesc, &blm_desc);
    ASSERT_EQ(force_err, err);
    mapi_inject_unset(mapi_idx_mpool_mcache_getpages);

    err = kbr_read_blm_region_desc(&blkdesc, &blm_desc);
    ASSERT_EQ(0, err);

    /* BLOOM_LOOKUP_MCACHE will return base address of the bloom
     * blocks in the mcache map.
     */
    blm_pages = NULL;
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_MCACHE, &blm_desc, &blm_pages);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, blm_pages);
    kbr_free_blm_pages(&blkdesc, BLOOM_LOOKUP_MCACHE, blm_pages);

    /* BLOOM_LOOKUP_BUFFER will return a ptr to a buffer
     * which contains the bloom blocks read from the mblock.
     */
    blm_pages = NULL;
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_BUFFER, &blm_desc, &blm_pages);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(blm_pages != 0);
    kbr_free_blm_pages(&blkdesc, BLOOM_LOOKUP_BUFFER, blm_pages);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    blm_pages = NULL;
    err = kbr_read_blm_pages(&blkdesc, BLOOM_LOOKUP_BUFFER, &blm_desc, &blm_pages);
    ASSERT_EQ(merr_errno(err), ENOMEM);

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(err, 0);
}

MTF_END_UTEST_COLLECTION(kblock_reader_test)
