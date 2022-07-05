/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>
#include <support/random_buffer.h>

#include <hse_util/hse_err.h>
#include <hse_util/minmax.h>
#include <hse_util/page.h>

#include <mpool/mpool.h>
#include <mblock_file.h>
#include <mblock_fset.h>
#include <mpool_internal.h>

#include "common.h"

MTF_BEGIN_UTEST_COLLECTION_PRE(mcache_test, mpool_collection_pre)

static merr_t
mblock_write_test(struct mpool *mp, uint64_t mbid, void *buf, size_t len)
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

    while (left) {
        size_t curlen = min_t(size_t, left, PAGE_SIZE);

        iov[i].iov_base = pos;
        iov[i].iov_len = curlen;

        left -= curlen;
        pos += PAGE_SIZE;

        i++;
        iovc++;
    }

    err = mpool_mblock_write(mp, mbid, iov, iovc);

    free(iov);

    return err;
}

MTF_DEFINE_UTEST_PREPOST(mcache_test, mcache_api, mpool_test_pre, mpool_test_post)
{
    struct mpool            *mp;
    struct mpool_mcache_map *map;

    uint64_t mbidv[32];
    merr_t   err;
    int      rc, i;
    size_t   bufsz;
    char    *buf, *addr;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    bufsz = 32 * PAGE_SIZE;
    rc = posix_memalign((void **)&buf, PAGE_SIZE, bufsz);
    ASSERT_EQ(0, rc);

    randomize_buffer(buf, bufsz, bufsz + 17);

    for (i = 0; i < 32; i++) {
        err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbidv[i], NULL);
        ASSERT_EQ(0, err);

        err = mblock_write_test(mp, mbidv[i], buf, PAGE_SIZE * (i + 1));
        ASSERT_EQ(err, 0);

        err = mpool_mblock_commit(mp, mbidv[i]);
        ASSERT_EQ(0, err);
    }

    err = mpool_mcache_mmap(NULL, 32, mbidv, &map);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mcache_mmap(mp, 32, NULL, &map);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mcache_mmap(mp, 32, mbidv, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mcache_mmap(mp, 32, mbidv, &map);
    ASSERT_EQ(0, err);

    addr = mpool_mcache_getbase(NULL, 0);
    ASSERT_EQ(NULL, addr);

    addr = mpool_mcache_getbase(map, 32);
    ASSERT_EQ(NULL, addr);

    err = mpool_mcache_getpages(NULL, 1, 0, 0, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mcache_getpages(map, 1, 32, 0, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mcache_getpages(map, 1, 1, 0, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    for (i = 0; i < 32; i++) {
        off_t pagenumv[32];
        void *addrv[32];
        char *addr;
        int   j;

        addr = mpool_mcache_getbase(map, i);
        ASSERT_NE(NULL, addr);

        for (j = 0; j <= i; j++)
            pagenumv[j] = j;
        memset(addrv, 0, i * sizeof(addrv[0]));

        err = mpool_mcache_getpages(map, i + 1, i, pagenumv, addrv);
        ASSERT_EQ(0, err);

        ASSERT_EQ(addr, addrv[0]);

        for (j = 0; j <= i; j++) {
            ASSERT_NE(NULL, addrv[j]);
            if (j > 0)
                ASSERT_EQ(addrv[j - 1] + PAGE_SIZE, addrv[j]);
        }

        rc = memcmp(addr, buf, PAGE_SIZE * (i + 1));
        ASSERT_EQ(0, rc);
    }

    err = mpool_mcache_purge(map, mp);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mpool_mcache_mincore(map, mp, NULL, NULL);
    ASSERT_EQ(ENOTSUP, merr_errno(err));

    err = mpool_mcache_madvise(NULL, 0, 0, PAGE_SIZE, MADV_DONTNEED);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mcache_madvise(map, 32, 0, PAGE_SIZE, MADV_DONTNEED);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mcache_madvise(map, 0, -1, PAGE_SIZE, MADV_DONTNEED);
    ASSERT_EQ(EINVAL, merr_errno(err));

    for (i = 0; i < 32; i++) {
        err = mpool_mcache_madvise(map, i, 0, (i + 1) * PAGE_SIZE, MADV_DONTNEED);
        ASSERT_EQ(0, err);
    }

    mpool_mcache_munmap(NULL);
    mpool_mcache_munmap(map);

    for (i = 0; i < 32; i++) {
        err = mpool_mblock_delete(mp, mbidv[i]);
        ASSERT_EQ(0, err);
    }

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    setup_mclass(HSE_MCLASS_STAGING);

    err = mpool_mclass_add(HSE_MCLASS_STAGING, &tcparams);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    for (i = 0; i < 32; i++) {
        err = mpool_mblock_alloc(mp, i % 2 ? HSE_MCLASS_CAPACITY : HSE_MCLASS_STAGING, 0,
                                 &mbidv[i], NULL);
        ASSERT_EQ(0, err);

        err = mblock_write_test(mp, mbidv[i], buf, PAGE_SIZE * (i + 1));
        ASSERT_EQ(err, 0);

        err = mpool_mblock_commit(mp, mbidv[i]);
        ASSERT_EQ(0, err);
    }

    err = mpool_mcache_mmap(mp, 32, mbidv, &map);
    ASSERT_EQ(0, err);

    for (i = 0; i < 32; i++) {
        off_t pagenumv[32];
        void *addrv[32];
        char *addr;
        int   j;

        addr = mpool_mcache_getbase(map, i);
        ASSERT_NE(NULL, addr);

        for (j = 0; j <= i; j++)
            pagenumv[j] = j;
        memset(addrv, 0, i * sizeof(addrv[0]));

        err = mpool_mcache_getpages(map, i + 1, i, pagenumv, addrv);
        ASSERT_EQ(0, err);

        ASSERT_EQ(addr, addrv[0]);

        for (j = 0; j <= i; j++) {
            ASSERT_NE(NULL, addrv[j]);
            if (j > 0)
                ASSERT_EQ(addrv[j - 1] + PAGE_SIZE, addrv[j]);
        }

        rc = memcmp(addr, buf, PAGE_SIZE * (i + 1));
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < 32; i++) {
        err = mpool_mcache_madvise(map, i, 0, (i + 1) * PAGE_SIZE, MADV_DONTNEED);
        ASSERT_EQ(0, err);
    }

    mpool_mcache_munmap(map);

    for (i = 0; i < 32; i++) {
        err = mpool_mblock_delete(mp, mbidv[i]);
        ASSERT_EQ(0, err);
    }

    err = mpool_close(mp);
    ASSERT_EQ(0, err);
    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(buf);
}

MTF_DEFINE_UTEST_PREPOST(mcache_test, mcache_invalid_args, mpool_test_pre, mpool_test_post)
{
    struct mpool       *mp;
    struct mblock_fset *mbfsp;
    struct media_class *mc;
    struct mblock_file *mbfp = (struct mblock_file *)0x1234;

    char    *addr = (char *)0x1234;
    uint64_t mbid;
    merr_t   err;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mblock_alloc(mp, HSE_MCLASS_CAPACITY, 0, &mbid, NULL);
    ASSERT_EQ(0, err);

    mc = mpool_mclass_handle(mp, HSE_MCLASS_CAPACITY);
    mbfsp = mclass_fset(mc);

    err = mblock_fset_map_getbase(NULL, mbid, &addr, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_map_getbase(mbfsp, 0xffffffff, &addr, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_unmap(NULL, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_fset_unmap(mbfsp, 0xffffffff);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_map_getbase(NULL, mbid, &addr, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_map_getbase(mbfp, mbid, NULL, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mblock_unmap(NULL, mbid);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mblock_delete(mp, mbid);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);
    mpool_destroy(mtf_kvdb_home, &tdparams);
}

MTF_END_UTEST_COLLECTION(mcache_test);
