/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <sys/mman.h>

#include <mtf/framework.h>

#include <hse/logging/logging.h>
#include <hse_util/page.h>

#include <cn/vblock_reader.h>
#include <cn/omf.h>

#include <mocks/mock_mpool.h>

struct workqueue_struct *vbr_wq;

int
test_collection_setup(struct mtf_test_info *info)
{
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

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    vblock_reader_test,
    test_collection_setup,
    test_collection_teardown);

static void
set_props(struct mblock_props *props, u64 blkid, uint vlen)
{
    memset(props, 0, sizeof(*props));
    props->mpr_objid = blkid;
    props->mpr_write_len = vlen;
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_desc_read, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf vbftr;
    u64                      blkid;
    struct mblock_props      props;
    uint                     vgroups = 0;
    u64                      argv[1];
    uint                     vbsz = 2 * PAGE_SIZE;

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(0, err);

    omf_set_vbf_magic(&vbftr, VBLOCK_FOOTER_MAGIC);
    omf_set_vbf_version(&vbftr, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(&vbftr, get_time_ns());
    set_props(&props, blkid, vbsz);

    err = mpm_mblock_write(blkid, (void *)&vbftr, PAGE_SIZE, sizeof(vbftr));
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(ds, 1, &blkid, &map);
    ASSERT_EQ(0, err);

    argv[0] = 0xdeadbeefdeadbeef;

    err = vbr_desc_read(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(0, err);
    ASSERT_EQ(blkid, vblk_desc.vbd_mblkdesc.mbid);
    ASSERT_EQ(0, vblk_desc.vbd_off);
    ASSERT_EQ(vbsz - VBLOCK_FOOTER_LEN, vblk_desc.vbd_len);
    ASSERT_EQ(0, vgroups);
    ASSERT_EQ(1, atomic_read(&vblk_desc.vbd_vgidx));
    ASSERT_EQ(argv[0], 0xdeadbeefdeadbeef);

    mpool_mcache_munmap(map);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_desc_update, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf vbftr;
    u64                      blkid;
    struct mblock_props      props;
    uint                     vgroups = 0;
    u64                      argv[2];
    uint                     vbsz = 2 * PAGE_SIZE;

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(0, err);

    omf_set_vbf_magic(&vbftr, VBLOCK_FOOTER_MAGIC);
    omf_set_vbf_version(&vbftr, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(&vbftr, get_time_ns());
    set_props(&props, blkid, vbsz);

    err = mpm_mblock_write(blkid, (void *)&vbftr, PAGE_SIZE, sizeof(vbftr));
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(ds, 1, &blkid, &map);
    ASSERT_EQ(0, err);

    argv[0] = 0xdeadbeefdeadbeef;
    err = vbr_desc_update(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, vgroups);
    ASSERT_EQ(1, atomic_read(&vblk_desc.vbd_vgidx));
    ASSERT_EQ(argv[0], vblk_desc.vbd_vgroup);

    argv[0] += 1;
    err = vbr_desc_update(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, vgroups);
    ASSERT_EQ(2, atomic_read(&vblk_desc.vbd_vgidx));
    ASSERT_NE(argv[0], vblk_desc.vbd_vgroup);
    ASSERT_EQ(argv[1], vblk_desc.vbd_vgroup);

    argv[0] = argv[1];
    argv[1] += 1;
    err = vbr_desc_update(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, vgroups);
    ASSERT_EQ(1, atomic_read(&vblk_desc.vbd_vgidx));
    ASSERT_EQ(argv[0], vblk_desc.vbd_vgroup);
    ASSERT_NE(argv[1], vblk_desc.vbd_vgroup);

    mpool_mcache_munmap(map);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_desc_read_errors, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf vbftr;
    u64                      blkid;
    struct mblock_props      props;
    uint                     vgroups = 0;
    u64                      argv[1];
    uint                     vbsz = 2 * PAGE_SIZE;

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(0, err);

    omf_set_vbf_magic(&vbftr, VBLOCK_FOOTER_MAGIC);
    omf_set_vbf_version(&vbftr, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(&vbftr, get_time_ns());
    set_props(&props, blkid, vbsz);

    err = mpm_mblock_write(blkid, (void *)&vbftr, PAGE_SIZE, sizeof(vbftr));
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(ds, 1, &blkid, &map);
    ASSERT_EQ(0, err);

    /* vbr_desc_reaad -> mpool_mblock_getbase error */
    mapi_inject_ptr(mapi_idx_mpool_mcache_getbase, 0);
    err = vbr_desc_read(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_NE(err, 0);
    mapi_inject_unset(mapi_idx_mpool_mcache_getbase);

    mpool_mcache_munmap(map);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_detect_bad_magic, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf vbftr;
    u64                      blkid;
    struct mblock_props      props;
    uint                     vbsz = 2 * PAGE_SIZE;

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(0, err);

    omf_set_vbf_magic(&vbftr, -1);
    omf_set_vbf_version(&vbftr, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(&vbftr, get_time_ns());
    set_props(&props, blkid, vbsz);

    err = mpm_mblock_write(blkid, (void *)&vbftr, PAGE_SIZE, sizeof(vbftr));
    ASSERT_EQ(0, err);

    err = mpool_mcache_mmap(ds, 1, &blkid, &map);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(ds, map, 0, NULL, NULL, &props, &vblk_desc);
    ASSERT_EQ(EPROTO, merr_errno(err));

    mpool_mcache_munmap(map);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_detect_bad_version, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf vbftr;
    u64                      blkid;
    struct mblock_props      props;
    uint                     vgroups = 0;
    u64                      argv[1];
    int                      i;
    uint                     vbsz = 2 * PAGE_SIZE;

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(0, err);

    for (i = -1; i <= VBLOCK_FOOTER_VERSION + 1; i++) {
        if (i != VBLOCK_FOOTER_VERSION) {
            omf_set_vbf_magic(&vbftr, VBLOCK_FOOTER_MAGIC);
            /* vbf_version is wrong, and should be detected in vbr_desc_read */
            omf_set_vbf_version(&vbftr, i);
            omf_set_vbf_vgroup(&vbftr, get_time_ns());
            set_props(&props, blkid, vbsz);

            err = mpm_mblock_write(blkid, (void *)&vbftr, PAGE_SIZE, sizeof(vbftr));
            ASSERT_EQ(0, err);

            err = mpool_mcache_mmap(ds, 1, &blkid, &map);
            ASSERT_EQ(0, err);

            err = vbr_desc_read(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
            ASSERT_EQ(EPROTO, merr_errno(err));

            mpool_mcache_munmap(map);
        }
    }
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_value, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf *ftr;
    u64                      blkid;
    uint                     i, vlen = 123, n_entries = 19;
    u8 *                     vblk;
    size_t                   vbsz;
    const void *             val;
    uint                     vboff;
    struct mblock_props      props;
    uint                     vgroups = 0;
    u64                      argv[1];

    vbsz = 2 * PAGE_SIZE + n_entries * vlen;

    vblk = mapi_safe_malloc(vbsz);
    ASSERT_TRUE(vblk != 0);
    memset(vblk, 0, vbsz);

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(err, 0);

    for (i = 0; i < vbsz; i++)
        vblk[i] = i;

    ftr = (struct vblock_footer_omf *)(vblk + vbsz - PAGE_SIZE);
    omf_set_vbf_magic(ftr, VBLOCK_FOOTER_MAGIC);
    omf_set_vbf_version(ftr, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(ftr, get_time_ns());
    set_props(&props, blkid, vbsz);

    err = mpm_mblock_write(blkid, vblk, 0, vbsz);
    ASSERT_EQ(err, 0);

    err = mpool_mcache_mmap(ds, 1, &blkid, &map);
    ASSERT_EQ(err, 0);

    err = vbr_desc_read(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(err, 0);

    /* Now, for the actual test */
    vboff = 2 * vlen;
    val = vbr_value(&vblk_desc, vboff, vlen);
    ASSERT_NE(val, NULL);

    mpool_mcache_munmap(map);

    mapi_safe_free(vblk);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_read_ahead, pre)
{
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf *ftr;
    u64                      blkid;
    u32                      i, vlen = 123, n_entries = 19;
    u8 *                     vblk;
    size_t                   vbsz;
    u32                      ra_len;
    struct mblock_props      props;
    off_t                    off;
    size_t                   len;
    struct ra_hist           rahv[1] = { { 0 } };
    uint                     vgroups = 0;
    u64                      argv[1];

    vbsz = 2 * PAGE_SIZE + n_entries * vlen;

    vblk = mapi_safe_malloc(vbsz);
    ASSERT_TRUE(vblk != 0);
    memset(vblk, 0, vbsz);

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(err, 0);

    for (i = 0; i < vbsz; i++)
        vblk[i] = i;

    ftr = (struct vblock_footer_omf *)(vblk + vbsz - PAGE_SIZE);
    omf_set_vbf_magic(ftr, VBLOCK_FOOTER_MAGIC);
    omf_set_vbf_version(ftr, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(ftr, get_time_ns());
    set_props(&props, blkid, vbsz);

    err = mpm_mblock_write(blkid, vblk, 0, vbsz);
    ASSERT_EQ(err, 0);

    err = mpool_mcache_mmap(ds, 1, &blkid, &map);
    ASSERT_EQ(err, 0);

    ra_len = 4096;
    len = 17;

    err = vbr_desc_read(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(err, 0);

    /* read forward (normal path in vbr_readahead) */
    for (off = 1000; off < 5000; off += len) {
        vbr_readahead(&vblk_desc, off, len, 0, ra_len, 1, rahv, NULL);
        ASSERT_EQ(rahv->vgidx, atomic_read(&vblk_desc.vbd_vgidx));
    }

    /* jump read forward (normal path in vbr_readahead) */
    off = 1234567;
    vbr_readahead(&vblk_desc, off, len, 0, ra_len, 1, rahv, NULL);
    ASSERT_EQ(rahv->vgidx, atomic_read(&vblk_desc.vbd_vgidx));

    /* read nothing */
    vbr_readahead(&vblk_desc, off, len, 0, ra_len, 1, rahv, NULL);
    ASSERT_EQ(rahv->vgidx, atomic_read(&vblk_desc.vbd_vgidx));

    /* read backward (same desc) */
    for (off = 5000; off > 1000; off -= len) {
        vbr_readahead(&vblk_desc, off, len, VBR_REVERSE, ra_len, 1, rahv, NULL);
        ASSERT_EQ(rahv->vgidx, atomic_read(&vblk_desc.vbd_vgidx));
    }

    /* new descriptor (to reset read ahead state).
       read forward, but inject failure */
    err = vbr_desc_read(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(err, 0);

    mapi_inject_once(mapi_idx_mpool_mcache_madvise, 1, 123);
    vbr_readahead(&vblk_desc, 200, 10, 0, ra_len, 1, rahv, NULL);

    mpool_mcache_munmap(map);

    mapi_safe_free(vblk);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_madvise_async, pre)
{
    struct workqueue_struct *vbr_wq;
    merr_t                   err;
    struct mpool *           ds = (void *)-1;
    struct mpool_mcache_map *map;
    struct vblock_desc       vblk_desc;
    struct vblock_footer_omf *ftr;
    u64                      blkid;
    u32                      i, vlen = 1024, n_entries = 1024;
    u8 *                     vblk;
    size_t                   vbsz;
    u32                      ra_len;
    struct mblock_props      props;
    struct ra_hist           rahv[8] = { { 0 } };
    uint                     vgroups = 0;
    u64                      argv[1];
    int                      rc;

    vbr_wq = alloc_workqueue("vbr", 0, 0, 0);
    ASSERT_NE(NULL, vbr_wq);

    vbsz = 2 * PAGE_SIZE + n_entries * vlen;

    vblk = mapi_safe_malloc(vbsz);
    ASSERT_TRUE(vblk != 0);
    memset(vblk, 0, vbsz);

    err = mpm_mblock_alloc(vbsz, &blkid);
    ASSERT_EQ(err, 0);

    for (i = 0; i < vbsz; i++)
        vblk[i] = i;

    ftr = (struct vblock_footer_omf *)(vblk + vbsz - PAGE_SIZE);
    omf_set_vbf_magic(ftr, VBLOCK_FOOTER_MAGIC);
    omf_set_vbf_version(ftr, VBLOCK_FOOTER_VERSION);
    omf_set_vbf_vgroup(ftr, get_time_ns());
    set_props(&props, blkid, vbsz);

    err = mpm_mblock_write(blkid, vblk, 0, vbsz);
    ASSERT_EQ(err, 0);

    err = mpool_mcache_mmap(ds, 1, &blkid, &map);
    ASSERT_EQ(err, 0);

    ra_len = 128 * 1024;

    err = vbr_desc_read(ds, map, 0, &vgroups, argv, &props, &vblk_desc);
    ASSERT_EQ(err, 0);

    for (i = 0; i < NELEM(rahv); ++i) {
        vbr_readahead(&vblk_desc, ra_len * i, ra_len, 0, ra_len, NELEM(rahv), rahv, vbr_wq);
    }

    flush_workqueue(vbr_wq);
    ASSERT_EQ(0, atomic_read(&vblk_desc.vbd_refcnt));

    rc = vbr_madvise_async(&vblk_desc, 0, ra_len, MADV_WILLNEED, NULL);
    ASSERT_EQ(false, rc);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    rc = vbr_madvise_async(&vblk_desc, 0, ra_len, MADV_WILLNEED, vbr_wq);
    ASSERT_EQ(false, rc);

    rc = vbr_madvise_async(&vblk_desc, 0, ra_len, MADV_WILLNEED, vbr_wq);
    ASSERT_EQ(true, rc);

    destroy_workqueue(vbr_wq);
    ASSERT_EQ(0, atomic_read(&vblk_desc.vbd_refcnt));

    mpool_mcache_munmap(map);

    mapi_safe_free(vblk);
}

MTF_END_UTEST_COLLECTION(vblock_reader_test)
