/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include <bsd/string.h>
#include <sys/stat.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/omf_version.h>
#include <hse/mpool/mpool.h>
#include <hse/util/minmax.h>
#include <hse/util/page.h>

#include <hse/test/mock/api.h>
#include <hse/test/mtf/framework.h>
#include <hse/test/support/random_buffer.h>

#include "common.h"
#include "mblock_file.h"
#include "mblock_fset.h"
#include "mpool_internal.h"

MTF_BEGIN_UTEST_COLLECTION_PRE(mblock_test, mpool_collection_pre)

MTF_DEFINE_UTEST_PREPOST(mblock_test, mblock_abc, mpool_test_pre, mpool_test_post)
{
    struct mpool *mp;
    struct mblock_props props = {};
    struct mpool_info info = {};
    uint64_t mbid, mbid1, bpalloc, apalloc;
    merr_t err;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_alloc(NULL, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_COUNT, 0, &mbid, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, NULL, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid, NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(0, err);

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, merr_errno(err));
    bpalloc = allocated_bytes_summation(&info);

    /* Test mblock pre-allocation */
    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, MPOOL_MBLOCK_PREALLOC, &mbid, &props);
    ASSERT_EQ(0, merr_errno(err));
    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, merr_errno(err));
    apalloc = allocated_bytes_summation(&info);
    ASSERT_GE(apalloc - bpalloc, MPOOL_MBLOCK_SIZE_DEFAULT);

    /* Test if mblock delete releases pre-allocated space */
    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));
    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, merr_errno(err));
    apalloc = allocated_bytes_summation(&info);
    ASSERT_EQ(bpalloc, apalloc);

    /* Test if mblock delete releases pre-allocated space */
    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, MPOOL_MBLOCK_PREALLOC, &mbid, &props);
    ASSERT_EQ(0, merr_errno(err));
    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_write_len, 0);
    ASSERT_EQ(props.mpr_alloc_cap, MPOOL_MBLOCK_SIZE_DEFAULT);

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));
    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, merr_errno(err));
    apalloc = allocated_bytes_summation(&info);
    ASSERT_EQ(bpalloc, apalloc);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclass, HSE_MCLASS_CAPACITY);
    ASSERT_EQ(props.mpr_write_len, 0);

    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_LT(allocated_bytes_summation(&info), 70 << 20);
    ASSERT_LT(used_bytes_summation(&info), 70 << 20);
    ASSERT_EQ(
        0, strncmp(capacity_path, info.mclass[HSE_MCLASS_CAPACITY].mi_path, sizeof(capacity_path)));

    err = mpool_mblock_commit(NULL, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid + 1);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    memset(&props, 0, sizeof(props));

    err = mpool_mblock_props_get(NULL, mbid, &props);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid + 1, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclass, HSE_MCLASS_CAPACITY);
    ASSERT_EQ(props.mpr_write_len, 0);

    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_LT(allocated_bytes_summation(&info), 70 << 20);
    ASSERT_LT(used_bytes_summation(&info), 70 << 20);
    ASSERT_EQ(
        0, strncmp(capacity_path, info.mclass[HSE_MCLASS_CAPACITY].mi_path, sizeof(capacity_path)));

    err = mpool_mblock_delete(mp, 0);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_delete(NULL, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid + 1);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, merr_errno(err));

    setup_mclass(HSE_MCLASS_STAGING);

    err = mpool_mclass_add(HSE_MCLASS_STAGING, &tcparams);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclass, HSE_MCLASS_STAGING);
    ASSERT_EQ(props.mpr_write_len, 0);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclass, HSE_MCLASS_STAGING);
    ASSERT_EQ(props.mpr_write_len, 0);
    ASSERT_EQ(props.mpr_alloc_cap, 0);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclass, HSE_MCLASS_STAGING);
    ASSERT_EQ(props.mpr_write_len, 0);
    ASSERT_EQ(props.mpr_alloc_cap, 0);

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid, &props);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    for (int i = 1; i < MPOOL_MCLASS_FILECNT_DEFAULT; i++) {
        mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid1, NULL);
        mpool_mblock_delete(mp, mbid1);
    }

    err = mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid1, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_NE(mbid, mbid1);
    ASSERT_EQ(mbid & MBID_BLOCK_MASK, mbid1 & MBID_BLOCK_MASK);
    ASSERT_NE(
        (mbid & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT, (mbid1 & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT);

    /* This cannot be detected, unfortunately... */
    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid1, &props);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid1);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid, &props);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, merr_errno(err));

    for (int i = 1; i < MPOOL_MCLASS_FILECNT_DEFAULT; i++) {
        mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid1, NULL);
        mpool_mblock_delete(mp, mbid1);
    }

    err = mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid1, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_NE(mbid, mbid1);
    ASSERT_EQ(mbid & MBID_BLOCK_MASK, mbid1 & MBID_BLOCK_MASK);
    ASSERT_NE(
        (mbid & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT, (mbid1 & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT);

    err = mpool_mblock_commit(mp, mbid1);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid1, &props);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(HSE_MCLASS_STAGING, props.mpr_mclass);

    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_LT(allocated_bytes_summation(&info), 140 << 20);
    ASSERT_LT(used_bytes_summation(&info), 140 << 20);
    ASSERT_EQ(
        0, strncmp(capacity_path, info.mclass[HSE_MCLASS_CAPACITY].mi_path, sizeof(capacity_path)));
    ASSERT_EQ(
        0, strncmp(staging_path, info.mclass[HSE_MCLASS_STAGING].mi_path, sizeof(staging_path)));

    err = mpool_mblock_delete(mp, mbid1);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, merr_errno(err));

    setup_mclass(HSE_MCLASS_PMEM);

    err = mpool_mclass_add(HSE_MCLASS_PMEM, &tcparams);
    if (err)
        ASSERT_EQ(ENOTSUP, merr_errno(err));

    unset_mclass(HSE_MCLASS_STAGING);
    unset_mclass(HSE_MCLASS_PMEM);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_STAGING, 0, &mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_alloc(mp, HSE_MCLASS_PMEM, 0, &mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, merr_errno(err));

    mpool_destroy(mtf_kvdb_home, &tdparams);
}

static merr_t
mblock_rw(struct mpool *mp, uint64_t mbid, void *buf, size_t len, uint64_t boff, bool is_write)
{
    struct iovec *iov;
    int iovc;
    char *pos;
    size_t left;
    int i;
    merr_t err;
    int uaoff = (int)((uint64_t)buf & (PAGE_SIZE - 1));

    iovc = (len + uaoff + PAGE_SIZE - 1) / PAGE_SIZE;

    iov = calloc(iovc, sizeof(struct iovec));
    if (!iov)
        return merr(ENOMEM);

    left = len;
    pos = buf;
    i = 0;
    iovc = 0;

    /* Is the caller's buffer page aligned? */
    if ((uintptr_t)pos & (uint64_t)(PAGE_SIZE - 1)) {
        /* First iovec not page aligned */
        int small;

        assert(uaoff); /* Sanity: uaoff nonzero if buf non-aligned */

        small = PAGE_SIZE - uaoff;
        iov[i].iov_base = pos;
        iov[i].iov_len = small;

        pos += small;
        left -= small;

        i++;
        iovc++;
    }

    while (left) {
        size_t curlen = min_t(size_t, left, PAGE_SIZE);

        iov[i].iov_base = pos;
        iov[i].iov_len = curlen;

        left -= curlen;
        pos += PAGE_SIZE;

        i++;
        iovc++;
    }

    if (is_write)
        err = mpool_mblock_write(mp, mbid, iov, iovc);
    else
        err = mpool_mblock_read(mp, mbid, iov, iovc, boff);

    free(iov);

    return err;
}

MTF_DEFINE_UTEST_PREPOST(mblock_test, mblock_io, mpool_test_pre, mpool_test_post)
{
    struct mpool *mp;
    struct mblock_props props = {};
    struct mpool_info info = {};

    uint64_t mbid;
    merr_t err;
    int rc;
    char *buf, *bufx, *badbuf;
    bool write = true;
    size_t mbsz = 32 << 20, wlen;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(0, err);

    /* Get an aligned buffer that is bigger than we need */
    rc = posix_memalign((void **)&buf, PAGE_SIZE, 2 * mbsz);
    ASSERT_EQ(0, rc);

    /* Get a non-aligned buffer that is bigger than we need */
    bufx = badbuf = malloc(2 * mbsz);
    if ((ulong)badbuf & (PAGE_SIZE - 1)) /* make sure badbuf not aligned */
        badbuf = (void *)((ulong)badbuf + 32);

    /* Writes with bogus length should fail */
    write = true;
    err = mblock_rw(mp, mbid, buf, mbsz + PAGE_SIZE, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, mbsz - 17, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, mbsz + 17, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* Writes with bogus alignment should fail */
    err = mblock_rw(mp, mbid, badbuf, mbsz, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, badbuf, mbsz - PAGE_SIZE, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, badbuf, mbsz + PAGE_SIZE, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, badbuf, mbsz - 17, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, badbuf, mbsz + 17, 0, write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    wlen = 1 << 20;
    err = mblock_rw(mp, mbid, buf, wlen, 0, write);
    ASSERT_EQ(0, err);

    err = mblock_rw(mp, mbid, buf, 0, 0, write);
    ASSERT_EQ(0, err);

    /* Reading from an uncommitted mblock is allowed. */
    err = mblock_rw(mp, mbid, buf, wlen, 0, !write);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_info_get(mp, &info);
    ASSERT_EQ(0, err);
    ASSERT_GE(allocated_bytes_summation(&info), wlen + (64 << 20));
    ASSERT_GE(used_bytes_summation(&info), wlen + (64 << 20));
    ASSERT_EQ(
        0, strncmp(capacity_path, info.mclass[HSE_MCLASS_CAPACITY].mi_path, sizeof(capacity_path)));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclass, HSE_MCLASS_CAPACITY);
    ASSERT_EQ(props.mpr_write_len, wlen);

    err = mblock_rw(mp, mbid, buf, mbsz + PAGE_SIZE, 0, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, mbsz, PAGE_SIZE, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* Read beyond written length should fail. */
    err = mblock_rw(mp, mbid, buf, mbsz, 0, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, wlen + 17, 0, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, wlen - 17, 0, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, wlen, PAGE_SIZE, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, wlen + 17, PAGE_SIZE, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, wlen - 17, PAGE_SIZE, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, badbuf, wlen, 0, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, badbuf, wlen + 17, 0, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, badbuf, wlen - 17, 0, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, wlen / 2, PAGE_SIZE - 17, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_rw(mp, mbid, buf, wlen / 2, 0, !write);
    ASSERT_EQ(0, err);

    err = mblock_rw(mp, mbid, buf, wlen / 2, PAGE_SIZE, !write);
    ASSERT_EQ(0, err);

    err = mblock_rw(mp, mbid, buf, wlen, 0, !write);
    ASSERT_EQ(0, err);

    err = mblock_rw(mp, mbid, buf, 0, 0, !write);
    ASSERT_EQ(0, err);

    /* Appending a committed mblock doesn't fail, but this incorrect usage
     * causes inconsistency in wlen which is flagged during props_get/delete.
     */
    err = mblock_rw(mp, mbid, buf, wlen, 0, write);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    /* Test IO without O_DIRECT */
    trparams.mclass[HSE_MCLASS_CAPACITY].dio_disable = true;
    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(0, err);

    wlen = 1 << 20;
    err = mblock_rw(mp, mbid, buf, wlen, 0, write);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mblock_rw(mp, mbid, buf, wlen, 0, !write);
    ASSERT_EQ(0, err);

    trparams.mclass[HSE_MCLASS_CAPACITY].dio_disable = false;

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(buf);
    free(bufx);
}

MTF_DEFINE_UTEST_PREPOST(mblock_test, mblock_invalid_args, mpool_test_pre, mpool_test_post)
{
    struct mpool *mp;
    struct mblock_fset *mbfsp;
    struct media_class *mc;
    struct mblock_file_params *params = (struct mblock_file_params *)0x1234;
    struct mblock_file *mbfp = (struct mblock_file *)0x1234;
    struct iovec *iov = (struct iovec *)0x1234;

    uint64_t mbid, bad_mbid = 0xffffffff;
    merr_t err;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(0, err);

    mc = mpool_mclass_handle(mp, HSE_MCLASS_CAPACITY);
    mbfsp = mclass_fset(mc);

    /* mblock_fset.c */
    err = mblock_fset_open(NULL, 32, 1 << 20, 0, &mbfsp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_open(mc, 32, 1 << 20, 0, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    mblock_fset_close(NULL);

    err = mblock_fset_alloc(NULL, 0, 1, &mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_alloc(mbfsp, 0, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_alloc(mbfsp, 0, 2, &mbid);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_fset_commit(NULL, &mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_commit(mbfsp, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_commit(mbfsp, &bad_mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_commit(mbfsp, &mbid, 2);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_fset_delete(NULL, &mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_delete(mbfsp, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_delete(mbfsp, &bad_mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_delete(mbfsp, &mbid, 2);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_fset_find(NULL, &mbid, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_find(mbfsp, NULL, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_find(mbfsp, &bad_mbid, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_find(mbfsp, &mbid, 2, NULL);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_fset_read(NULL, mbid, iov, 1, 0);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_read(mbfsp, bad_mbid, iov, 1, 0);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_write(NULL, mbid, iov, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_write(NULL, bad_mbid, iov, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* mblock_file.c */
    err = mblock_file_open(NULL, mc, params, 0, MBLOCK_METAHDR_VERSION, &mbfp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_open(mbfsp, NULL, params, 0, MBLOCK_METAHDR_VERSION, &mbfp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_open(mbfsp, mc, NULL, 0, MBLOCK_METAHDR_VERSION, &mbfp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_open(mbfsp, mc, params, 0, MBLOCK_METAHDR_VERSION, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    mblock_file_close(NULL);

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);
}

MTF_DEFINE_UTEST_PREPOST(mblock_test, mblock_clone, mpool_test_pre, mpool_test_post)
{
    struct mpool *mp;
    struct mblock_props props = { 0 };

    uint64_t mbid, tgt_mbid;
    merr_t err;
    int rc;
    char *wbuf, *rbuf, *zbuf;
    bool write = true;
    size_t bufsz = 32 * MB;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(0, err);

    rc = posix_memalign((void **)&wbuf, PAGE_SIZE, (bufsz * 2) + MB);
    ASSERT_EQ(0, rc);
    rbuf = wbuf + bufsz;
    zbuf = rbuf + bufsz;

    randomize_buffer(wbuf, bufsz, 131);
    randomize_buffer(rbuf, bufsz, 149);
    memset(zbuf, 0, MB);

    err = mblock_rw(mp, mbid, wbuf, bufsz, 0, write);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(props.mpr_write_len, 32 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, props.mpr_write_len);

    err = mblock_rw(mp, mbid, rbuf, bufsz, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf, rbuf, bufsz));

    err = mpool_mblock_clone(mp, mbid, 0, 4 * MB, &tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, tgt_mbid, &props);
    ASSERT_EQ(props.mpr_write_len, 4 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, props.mpr_write_len);

    randomize_buffer(rbuf, MB, 151);
    err = mblock_rw(mp, tgt_mbid, rbuf, 4 * MB, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf, rbuf, 4 * MB));

    err = mblock_rw(mp, tgt_mbid, rbuf, 1 * MB, 4 * MB, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    randomize_buffer(rbuf, MB, 163);
    err = mblock_rw(mp, tgt_mbid, rbuf, 4 * MB, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf, rbuf, 4 * MB));

    err = mpool_mblock_delete(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_clone(mp, mbid, 16 * MB, 4 * MB, &tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, tgt_mbid, &props);
    ASSERT_EQ(props.mpr_write_len, 20 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, 4 * MB);

    randomize_buffer(rbuf, bufsz, 173);
    err = mblock_rw(mp, tgt_mbid, rbuf, 20 * MB, 0, !write);
    ASSERT_EQ(0, err);
    for (int i = 0; i < 16; i++)
        ASSERT_EQ(0, memcmp(zbuf, rbuf + i * MB, MB));
    ASSERT_EQ(0, memcmp(wbuf + 16 * MB, rbuf + 16 * MB, 4 * MB));

    err = mblock_rw(mp, tgt_mbid, rbuf, 1 * MB, 20 * MB, !write);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_delete(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_clone(mp, mbid, 0, 16 * MB, &tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, tgt_mbid, &props);
    ASSERT_EQ(props.mpr_write_len, 16 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, 16 * MB);

    randomize_buffer(rbuf, bufsz, 181);
    err = mblock_rw(mp, tgt_mbid, rbuf, 16 * MB, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf, rbuf, 16 * MB));

    err = mpool_mblock_delete(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_clone(mp, mbid, 16 * MB, 0, &tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, tgt_mbid, &props);
    ASSERT_EQ(props.mpr_write_len, 32 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, 16 * MB);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, tgt_mbid, &props);
    ASSERT_EQ(props.mpr_write_len, 32 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, 16 * MB);

    randomize_buffer(rbuf, bufsz, 181);
    err = mblock_rw(mp, tgt_mbid, rbuf, 32 * MB, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf + 16 * MB, rbuf + 16 * MB, 16 * MB));
    for (int i = 0; i < 16; i++)
        ASSERT_EQ(0, memcmp(zbuf, rbuf + i * MB, MB));

    err = mpool_mblock_delete(mp, tgt_mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_clone(NULL, mbid, 0, bufsz, &tgt_mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_clone(mp, mbid, 0, bufsz, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_clone(mp, mbid, -1, bufsz, &tgt_mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_clone(mp, mbid, 0, bufsz + 1, &tgt_mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_clone(mp, mbid, 1, bufsz, &tgt_mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_clone(mp, mbid, 0, 1, &tgt_mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(wbuf);
}

MTF_DEFINE_UTEST_PREPOST(mblock_test, mblock_punch_test, mpool_test_pre, mpool_test_post)
{
    struct mblock_props props = { 0 };
    struct mpool *mp;
    uint64_t mbid;
    merr_t err;
    int rc;
    char *wbuf, *rbuf, *zbuf;
    bool write = true;
    size_t bufsz = 32 * MB, wlen, punchedb;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(0, err);

    rc = posix_memalign((void **)&wbuf, PAGE_SIZE, (bufsz * 2) + MB);
    ASSERT_EQ(0, rc);
    rbuf = wbuf + bufsz;
    zbuf = rbuf + bufsz;

    randomize_buffer(wbuf, bufsz, 131);
    randomize_buffer(rbuf, bufsz, 149);
    memset(zbuf, 0, MB);

    err = mblock_rw(mp, mbid, wbuf, bufsz, 0, write);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 32 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, props.mpr_write_len);

    err = mblock_rw(mp, mbid, rbuf, bufsz, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf, rbuf, bufsz));

    err = mpool_mblock_punch(mp, mbid, 0, 4096);
    ASSERT_EQ(0, err);
    punchedb = 4096;
    memset(wbuf, 0, punchedb);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 32 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, 32 * MB - punchedb);

    err = mpool_mblock_punch(mp, mbid, 0, 2 * 4096);
    ASSERT_EQ(0, err);
    punchedb += 4096;
    memset(wbuf, 0, punchedb);

    err = mblock_rw(mp, mbid, rbuf, punchedb, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(zbuf, rbuf, punchedb));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 32 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, 32 * MB - punchedb);

    err = mpool_mblock_punch(mp, mbid, MB, MB);
    ASSERT_EQ(0, err);
    memset(wbuf + MB, 0, MB);
    punchedb += MB;

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 32 * MB);
    ASSERT_EQ(props.mpr_alloc_cap, 32 * MB - punchedb);

    wlen = props.mpr_write_len;
    err = mpool_mblock_punch(mp, mbid, wlen - 4096, 0);
    ASSERT_EQ(0, err);
    memset(wbuf + wlen - 4096, 0, 4096);
    punchedb += 4096;

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 32 * MB - 4096);
    ASSERT_EQ(props.mpr_alloc_cap, 32 * MB - punchedb);

    wlen = props.mpr_write_len;
    err = mpool_mblock_punch(mp, mbid, wlen - 4096, 4096);
    ASSERT_EQ(0, err);
    memset(wbuf + wlen - 4096, 0, 4096);
    punchedb += 4096;

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 32 * MB - 2 * 4096);
    ASSERT_EQ(props.mpr_alloc_cap, 32 * MB - punchedb);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 32 * MB - 2 * 4096);
    ASSERT_EQ(props.mpr_alloc_cap, 32 * MB - punchedb);

    randomize_buffer(rbuf, bufsz, 157);
    wlen = props.mpr_write_len;
    err = mblock_rw(mp, mbid, rbuf, wlen, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf, rbuf, wlen));

    err = mpool_mblock_punch(mp, mbid, wlen - 4096, 4097);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(mp, mbid, wlen - 4095, 4096);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(mp, mbid, 1, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(NULL, mbid, 0, bufsz);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(mp, mbid, -1, bufsz);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(mp, mbid, 0, bufsz + 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(mp, mbid, bufsz, bufsz);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(mp, mbid, wlen - 4096, 2 * 4096);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_punch(mp, mbid, 0, 0);
    ASSERT_EQ(0, err);
    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 0);
    ASSERT_EQ(props.mpr_alloc_cap, 0);

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, MPOOL_MBLOCK_PREALLOC, &mbid, NULL);
    ASSERT_EQ(0, err);
    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, 0);
    ASSERT_EQ(props.mpr_alloc_cap, 32 * MB);

    randomize_buffer(wbuf, bufsz, 177);
    err = mblock_rw(mp, mbid, wbuf, bufsz / 2, 0, write);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_punch(mp, mbid, 0, bufsz / 4);
    ASSERT_EQ(0, err);
    memset(wbuf, 0, bufsz / 4);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, bufsz / 2);
    ASSERT_EQ(props.mpr_alloc_cap, (3 * bufsz) / 4);

    err = mpool_mblock_punch(mp, mbid, props.mpr_write_len - MB, MB);
    ASSERT_EQ(0, err);
    memset(wbuf + props.mpr_write_len - MB, 0, MB);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, bufsz / 2 - MB);
    ASSERT_EQ(props.mpr_alloc_cap, bufsz / 4 - MB);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_write_len, bufsz / 2 - MB);
    ASSERT_EQ(props.mpr_alloc_cap, bufsz / 4 - MB);

    randomize_buffer(rbuf, bufsz, 177);
    wlen = props.mpr_write_len;
    err = mblock_rw(mp, mbid, rbuf, wlen, 0, !write);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, memcmp(wbuf, rbuf, wlen));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(wbuf);
}

MTF_END_UTEST_COLLECTION(mblock_test);
