/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/hse_err.h>
#include <hse_util/minmax.h>

#include "common.h"

#include <mpool/mpool.h>
#include <mblock_file.h>
#include <mblock_fset.h>
#include <mpool_internal.h>

MTF_BEGIN_UTEST_COLLECTION_PREPOST(mblock_test, mpool_test_pre, mpool_test_post)

MTF_DEFINE_UTEST(mblock_test, mblock_abc)
{
    char staging_path[PATH_MAX];
    struct mpool *mp;
    struct mblock_props props = {};
    struct mpool_stats  stats = {};
    uint64_t      mbid, mbid1;
    merr_t        err;
    int           rc;

    err = mpool_open("mp1", NULL, O_CREAT, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(NULL, MP_MED_CAPACITY, &mbid, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_COUNT, &mbid, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_CAPACITY, NULL, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid, NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_CAPACITY, &mbid, NULL);
    ASSERT_EQ(0, err);

    err = mpool_mblock_abort(NULL, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_abort(mp, mbid + 1);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_CAPACITY, &mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclassp, MP_MED_CAPACITY);
    ASSERT_EQ(props.mpr_write_len, 0);

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, 64 << 20);
    ASSERT_LT(stats.mps_used, 64 << 20);
    ASSERT_EQ(1, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(storage_path, stats.mps_path[MP_MED_CAPACITY], strlen(storage_path)));

    err = mpool_mblock_commit(NULL, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid + 1);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    memset(&props, 0, sizeof(props));

    err = mpool_mblock_props_get(NULL, mbid, &props);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid + 1, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclassp, MP_MED_CAPACITY);
    ASSERT_EQ(props.mpr_write_len, 0);

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, 64 << 20);
    ASSERT_LT(stats.mps_used, 64 << 20);
    ASSERT_EQ(1, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(storage_path, stats.mps_path[MP_MED_CAPACITY], strlen(storage_path)));

    err = mpool_mblock_delete(NULL, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid + 1);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    strlcpy(staging_path, storage_path, sizeof(staging_path));
    strlcat(staging_path, "/staging", sizeof(staging_path) - strlen(staging_path));
    setenv("HSE_STAGING_PATH", (const char *)staging_path, 1);

    rc = mkdir(staging_path, S_IRWXU | S_IRWXG | S_IROTH | S_IWOTH);
    ASSERT_EQ(0, rc);

    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclassp, MP_MED_STAGING);
    ASSERT_EQ(props.mpr_write_len, 0);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclassp, MP_MED_STAGING);
    ASSERT_EQ(props.mpr_write_len, 0);

    /* deleting an uncommitted mblock returns EINVAL */
    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclassp, MP_MED_STAGING);
    ASSERT_EQ(props.mpr_write_len, 0);

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid, &props);
    ASSERT_EQ(0, err);

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(0, err);

    for (int i = 1; i < MBLOCK_FSET_FILES_DEFAULT; i++) {
        mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid1, NULL);
        mpool_mblock_abort(mp, mbid1);
    }

    err = mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid1, &props);
    ASSERT_EQ(0, err);
    ASSERT_NE(mbid, mbid1);
    ASSERT_EQ(mbid & MBID_BLOCK_MASK, mbid1 & MBID_BLOCK_MASK);
    ASSERT_NE((mbid & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT,
               (mbid1 & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT);

    /* This cannot be detected, unfortunately... */
    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid1, &props);
    ASSERT_EQ(0, err);

    err = mpool_mblock_abort(mp, mbid1);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid, &props);
    ASSERT_EQ(0, err);

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(0, err);

    for (int i = 1; i < MBLOCK_FSET_FILES_DEFAULT; i++) {
        mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid1, NULL);
        mpool_mblock_abort(mp, mbid1);
    }

    err = mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid1, &props);
    ASSERT_EQ(0, err);
    ASSERT_NE(mbid, mbid1);
    ASSERT_EQ(mbid & MBID_BLOCK_MASK, mbid1 & MBID_BLOCK_MASK);
    ASSERT_NE((mbid & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT,
               (mbid1 & MBID_UNIQ_MASK) >> MBID_UNIQ_SHIFT);

    err = mpool_mblock_commit(mp, mbid1);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mblock_props_get(mp, mbid1, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(MP_MED_STAGING, props.mpr_mclassp);

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, 64 << 20);
    ASSERT_LT(stats.mps_used, 64 << 20);
    ASSERT_EQ(1, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(storage_path, stats.mps_path[MP_MED_CAPACITY], strlen(storage_path)));
    ASSERT_EQ(0, strncmp(staging_path, stats.mps_path[MP_MED_STAGING], strlen(staging_path)));

    err = mpool_mblock_delete(mp, mbid1);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    unsetenv("HSE_STAGING_PATH");
    err = mpool_open("mp1", NULL, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mblock_alloc(mp, MP_MED_STAGING, &mbid, &props);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_destroy(mp);
    ASSERT_EQ(0, err);
}

static merr_t
mblock_rw(
    struct mpool *mp,
    uint64_t      mbid,
    void         *buf,
    size_t        len,
    u64           boff,
    bool          is_write)
{
    struct iovec *iov;
    int           iovc;
    char         *pos;
    size_t        left;
    int           i;
    merr_t        err;
    int           uaoff = (int)((u64)buf & (PAGE_SIZE - 1));

    iovc = (len + uaoff + PAGE_SIZE - 1) / PAGE_SIZE;

    iov = calloc(iovc, sizeof(struct iovec));
    if (!iov)
        return merr(ENOMEM);

    left = len;
    pos = buf;
    i = 0;
    iovc = 0;

    /* Is the caller's buffer page aligned? */
    if ((u64)pos & (u64)(PAGE_SIZE - 1)) {
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
        iov[i].iov_len  = curlen;

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

MTF_DEFINE_UTEST(mblock_test, mblock_io)
{
    struct mpool        *mp;
    struct mblock_props  props = {};
    struct mpool_stats   stats = {};

    uint64_t mbid;
    merr_t   err;
    int      rc;
    char    *buf, *bufx, *badbuf;
    bool     write = true;
    size_t   mbsz = 32 << 20, wlen;

    setenv("HSE_STORAGE_PATH", (const char *)storage_path, 1);
    err = mpool_open("mp1", NULL, O_CREAT, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, MP_MED_CAPACITY, &mbid, NULL);
    ASSERT_EQ(0, err);

    /* Get an aligned buffer that is bigger than we need */
    rc = posix_memalign((void **)&buf, PAGE_SIZE, 2 * mbsz);
    ASSERT_EQ(0, rc);

    /* Get a non-aligned buffer that is bigger than we need */
    bufx = badbuf = malloc(2 * mbsz);
    if ((ulong)badbuf & (PAGE_SIZE - 1))  /* make sure badbuf not aligned */
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

    wlen = 8 << 10;
    err = mblock_rw(mp, mbid, buf, wlen, 0, write);
    ASSERT_EQ(0, err);

    err = mblock_rw(mp, mbid, buf, 0, 0, write);
    ASSERT_EQ(0, err);

    err = mpool_stats_get(mp, &stats);
    ASSERT_EQ(0, err);
    ASSERT_LT(stats.mps_allocated, 64 << 20);
    ASSERT_LT(stats.mps_used, 64 << 20);
    ASSERT_EQ(1, stats.mps_mblock_cnt);
    ASSERT_EQ(0, strncmp(storage_path, stats.mps_path[MP_MED_CAPACITY], strlen(storage_path)));

    /* Reading from an uncommitted mblock is allowed. */
    err = mblock_rw(mp, mbid, buf, wlen, 0, !write);
    ASSERT_EQ(0, err);

    err = mpool_mblock_commit(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_mblock_props_get(mp, mbid, &props);
    ASSERT_EQ(0, err);
    ASSERT_EQ(props.mpr_objid, mbid);
    ASSERT_EQ(props.mpr_mclassp, MP_MED_CAPACITY);
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

    err = mpool_destroy(mp);
    ASSERT_EQ(0, err);

    free(buf);
    free(bufx);
}

MTF_DEFINE_UTEST(mblock_test, mblock_invalid_args)
{
    struct mpool *mp;
    struct mpool_mclass_stats stats = {};
    struct mblock_fset *mbfsp;
    struct media_class *mc;
    struct mblock_file_params *params = (struct mblock_file_params *)0x1234;
    struct mblock_file *mbfp = (struct mblock_file *)0x1234;
    struct mblock_file_stats mbstats = {};
    struct iovec *iov = (struct iovec *)0x1234;

    char    *addr = (char *)0x1234;
    uint64_t mbid, bad_mbid = 0xffffffff;
    merr_t   err;

    setenv("HSE_STORAGE_PATH", (const char *)storage_path, 1);
    err = mpool_open("mp1", NULL, O_CREAT, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, MP_MED_CAPACITY, &mbid, NULL);
    ASSERT_EQ(0, err);

    mc = mpool_mclass_handle(mp, MP_MED_CAPACITY);
    mbfsp = mclass_fset(mc);

    /* mblock_fset.c */
    err = mblock_fset_open(NULL, 32, 1 << 20, 0, &mbfsp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_open(mc, 32, 1 << 20, 0, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    mblock_fset_close(NULL);

    err = mblock_fset_alloc(NULL, 1, &mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_alloc(mbfsp, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_alloc(mbfsp, 2, &mbid);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_fset_commit(NULL, &mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_commit(mbfsp, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_commit(mbfsp, &bad_mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_commit(mbfsp, &mbid, 2);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_fset_abort(NULL, &mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_abort(mbfsp, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_abort(mbfsp, &bad_mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_abort(mbfsp, &mbid, 2);
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

    err = mblock_fset_stats_get(NULL, &stats);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_stats_get(mbfsp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* mblock_file.c */
    err = mblock_file_open(NULL, mc, params, 0, addr, &mbfp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_open(mbfsp, NULL, params, 0, addr, &mbfp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_open(mbfsp, mc, NULL, 0, addr, &mbfp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_open(mbfsp, mc, params, 0, NULL, &mbfp);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_open(mbfsp, mc, params, 0, addr, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    mblock_file_close(NULL);

    err = mblock_file_alloc(NULL, 1, &mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_alloc(mbfp, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_alloc(mbfp, 2, &mbid);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_file_find(NULL, &mbid, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_find(mbfp, NULL, 1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_find(mbfp, &mbid, 2, NULL);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_file_commit(NULL, &mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_commit(mbfp, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_commit(mbfp, &mbid, 2);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_file_abort(NULL, &mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_abort(mbfp, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_abort(mbfp, &mbid, 2);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_file_delete(NULL, &mbid, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_delete(mbfp, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_delete(mbfp, &mbid, 2);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mblock_file_read(NULL, mbid, iov, 1, 0);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_read(mbfp, mbid, NULL, 1, 0);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_write(NULL, mbid, iov, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_write(mbfp, mbid, NULL, 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_stats_get(NULL, &mbstats);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_file_stats_get(mbfp, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_abort(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_destroy(mp);
    ASSERT_EQ(0, err);
}

MTF_END_UTEST_COLLECTION(mblock_test);
