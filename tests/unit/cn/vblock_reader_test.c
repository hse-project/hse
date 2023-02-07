/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>
#include <sys/mman.h>

#include <hse/test/mtf/framework.h>

#include <hse/logging/logging.h>
#include <hse/util/page.h>

#include "cn/vblock_reader.h"
#include "cn/omf.h"

struct workqueue_struct *vbr_wq;

int
pre(struct mtf_test_info *info)
{
    return 0;
}

uint64_t blkid_counter = 1000;
uint8_t mblock_data[8<<20];
struct kvs_mblk_desc mblk;

merr_t
mock_mblk_init(size_t alen, uint64_t *blkid)
{
    if (alen > sizeof(mblock_data))
        return merr(EINVAL);

    *blkid = blkid_counter++;

    memset(mblock_data, 0, sizeof(mblock_data));
    memset(&mblk, 0, sizeof(mblk));

    mblk.map_base = mblock_data;
    mblk.wlen_pages = 0;
    mblk.alen_pages = (alen + PAGE_SIZE - 1) / PAGE_SIZE;
    mblk.mbid = *blkid;
    mblk.mclass = 1;

    return 0;
}

merr_t
mock_mblk_write(void *src, size_t off, size_t len)
{
    uint32_t wlen_pages = (off + len + PAGE_SIZE - 1) / PAGE_SIZE;

    if (wlen_pages > mblk.alen_pages)
        return merr(EINVAL);

    memcpy(mblk.map_base + off, src, len);

    if (wlen_pages > mblk.wlen_pages)
        mblk.wlen_pages = wlen_pages;

    return 0;
}

merr_t
mock_mblk_setup_impl(size_t value_bytes, uint32_t magic, uint32_t version)
{
    struct vblock_footer_omf vbf = { 0 };
    size_t footer_offset;
    size_t alen;
    merr_t err;
    uint64_t id;

    if (!value_bytes)
        return merr(EINVAL);

    footer_offset = ALIGN(value_bytes, PAGE_SIZE);
    alen = footer_offset + VBLOCK_FOOTER_PAGES;

    err = mock_mblk_init(alen, &id);
    if (err)
        return err;

    omf_set_vbf_magic(&vbf, magic);
    omf_set_vbf_version(&vbf, version);
    omf_set_vbf_min_klen(&vbf, 17);
    omf_set_vbf_max_klen(&vbf, 18);
    omf_set_vbf_vgroup(&vbf, 19);

    err = mock_mblk_write(&vbf, footer_offset, sizeof(vbf));

    return err;
}


merr_t
mock_mblk_setup(size_t value_bytes)
{
    return mock_mblk_setup_impl(value_bytes, VBLOCK_FOOTER_MAGIC, VBLOCK_FOOTER_VERSION);
}

merr_t
mock_mblk_setup_magic(size_t value_bytes, uint32_t magic)
{
    return mock_mblk_setup_impl(value_bytes, magic, VBLOCK_FOOTER_VERSION);
}

merr_t
mock_mblk_setup_version(size_t value_bytes, uint32_t version)
{
    return mock_mblk_setup_impl(value_bytes, VBLOCK_FOOTER_MAGIC, version);
}



MTF_BEGIN_UTEST_COLLECTION(vblock_reader_test);

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_desc_read, pre)
{
    merr_t                   err;
    struct vblock_desc       vblk_desc;
    size_t                   value_bytes;

    value_bytes = 12345;

    err = mock_mblk_setup(value_bytes);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(&mblk, &vblk_desc);
    ASSERT_EQ(0, err);

    ASSERT_EQ(mblk.mbid, vblk_desc.vbd_mblkdesc->mbid);
    ASSERT_EQ(0, vblk_desc.vbd_off);
    ASSERT_EQ(17, vblk_desc.vbd_min_klen);
    ASSERT_EQ(18, vblk_desc.vbd_max_klen);
    ASSERT_EQ(19, vblk_desc.vbd_vgroup);
    ASSERT_EQ(ALIGN(value_bytes, PAGE_SIZE), vblk_desc.vbd_alen);
    ASSERT_EQ(ALIGN(value_bytes, PAGE_SIZE), vblk_desc.vbd_wlen);
    ASSERT_EQ(1, atomic_read(&vblk_desc.vbd_vgidx));
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_desc_update, pre)
{
    merr_t                   err;
    struct vblock_desc       vblk_desc;
    uint                     vgroups = 0;
    uint64_t                 argv[2];

    err = mock_mblk_setup(8323);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(&mblk, &vblk_desc);
    ASSERT_EQ(0, err);

    argv[0] = 0xdeadbeefdeadbeef;
    err = vbr_desc_update_vgidx(&vblk_desc, &vgroups, argv);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, vgroups);
    ASSERT_EQ(1, atomic_read(&vblk_desc.vbd_vgidx));
    ASSERT_EQ(argv[0], vblk_desc.vbd_vgroup);

    argv[0] += 1;
    err = vbr_desc_update_vgidx(&vblk_desc, &vgroups, argv);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, vgroups);
    ASSERT_EQ(2, atomic_read(&vblk_desc.vbd_vgidx));
    ASSERT_NE(argv[0], vblk_desc.vbd_vgroup);
    ASSERT_EQ(argv[1], vblk_desc.vbd_vgroup);

    argv[0] = argv[1];
    argv[1] += 1;
    err = vbr_desc_update_vgidx(&vblk_desc, &vgroups, argv);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, vgroups);
    ASSERT_EQ(1, atomic_read(&vblk_desc.vbd_vgidx));
    ASSERT_EQ(argv[0], vblk_desc.vbd_vgroup);
    ASSERT_NE(argv[1], vblk_desc.vbd_vgroup);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_detect_bad_magic, pre)
{
    struct vblock_desc vblk_desc;
    merr_t err;

    err = mock_mblk_setup_magic(1436, 1);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(&mblk, &vblk_desc);
    ASSERT_EQ(EPROTO, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_detect_bad_version, pre)
{
    struct vblock_desc vblk_desc;
    merr_t err;

    err = mock_mblk_setup_version(1436, -1);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(&mblk, &vblk_desc);
    ASSERT_EQ(EPROTO, merr_errno(err));
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_value, pre)
{
    struct vblock_desc vblk_desc;
    merr_t err;
    void *val;

    err = mock_mblk_setup(1964);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(&mblk, &vblk_desc);
    ASSERT_EQ(err, 0);

    /* Now, for the actual test */
    val = vbr_value(&vblk_desc, 117, 20);
    ASSERT_EQ(val, mblk.map_base + 117);
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_read_ahead, pre)
{
    merr_t                   err;
    struct vblock_desc       vblk_desc;
    uint32_t                 ra_len;
    off_t                    off;
    size_t                   len;
    struct ra_hist           rahv[1] = { { 0 } };

    err = mock_mblk_setup(4000000);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(&mblk, &vblk_desc);
    ASSERT_EQ(err, 0);

    ra_len = 4096;
    len = 17;

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
}

MTF_DEFINE_UTEST_PRE(vblock_reader_test, t_vbr_madvise_async, pre)
{
    struct workqueue_struct *vbr_wq;
    merr_t                   err;
    struct vblock_desc       vblk_desc;
    uint32_t                 ra_len;
    struct ra_hist           rahv[8] = { 0 };
    int                      rc;

    err = mock_mblk_setup(4000000);
    ASSERT_EQ(0, err);

    err = vbr_desc_read(&mblk, &vblk_desc);
    ASSERT_EQ(err, 0);

    vbr_wq = alloc_workqueue("vbr", 0, 0, 0);
    ASSERT_NE(NULL, vbr_wq);

    ra_len = 128 * 1024;

    for (uint i = 0; i < NELEM(rahv); ++i)
        vbr_readahead(&vblk_desc, ra_len * i, ra_len, 0, ra_len, NELEM(rahv), rahv, vbr_wq);

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
}

MTF_END_UTEST_COLLECTION(vblock_reader_test)
