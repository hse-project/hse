/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <sys/mman.h>

#include <hse/error/merr.h>
#include <hse/mpool/mpool.h>

#include <hse/test/mtf/framework.h>

#include "cn/mbset.h"

#define ds ((struct mpool *)1)

#define mock_alen_pages 358
#define mock_wlen_pages 353

struct udata {
    uint64_t cookie;
};

#define ufn t_udata_init
#define usz sizeof(struct udata)

int mocked_mblk_mmap_errno = 0;
int mocked_mblk_munmap_errno = 0;

merr_t
mocked_mblk_mmap(struct mpool *mp, uint64_t mbid, struct kvs_mblk_desc *md)
{
    if (mocked_mblk_mmap_errno)
        return merr(mocked_mblk_mmap_errno);

    md->map_base = (void *)0x1111;
    md->mbid = mbid;
    md->alen_pages = mock_alen_pages;
    md->wlen_pages = mock_wlen_pages;
    md->mclass = 1;

    return 0;
}

merr_t
mocked_mblk_munmap(struct mpool *mp, struct kvs_mblk_desc *md)
{
    if (mocked_mblk_munmap_errno)
        return merr(mocked_mblk_munmap_errno);

    md->map_base = (void *)0x2222;
    return 0;
}

static int
init(struct mtf_test_info *mtf)
{
    return 0;
}

static int
fini(struct mtf_test_info *mtf)
{
    return 0;
}

static int
pre(struct mtf_test_info *mtf)
{
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
    MOCK_SET_FN(mblk_desc, mblk_mmap, mocked_mblk_mmap);
    MOCK_SET_FN(mblk_desc, mblk_munmap, mocked_mblk_munmap);

    return 0;
}

static int
post(struct mtf_test_info *mtf)
{
    return 0;
}

typedef merr_t
mbset_udata_init_fn(const struct kvs_mblk_desc *mblk, void *rock);

static merr_t
t_udata_init(const struct kvs_mblk_desc *mblk, void *rock)
{
    struct udata *u = rock;

    u->cookie = mblk->mbid;
    return 0;
}

struct t_callback_info {
    uint invoked;
    uint delete_error_detected;
};

static void
t_callback(void *rock, bool mblock_delete_error)
{
    struct t_callback_info *info = rock;

    info->invoked++;
    if (mblock_delete_error)
        info->delete_error_detected++;
}

#if 0
static merr_t
t_udata_update(
    struct udata   *u,
    uint           *vgroupc,
    uint64_t       *vgroupv)
{
    return 0;
}
#endif

void
idv_init(uint64_t *idv, uint idc)
{
    for (uint i = 0; i < idc; i++)
        idv[i] = 1000 + i;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(test, init, fini);

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_simple, pre, post)
{
    uint64_t idv[32];
    uint idc = NELEM(idv);
    struct mbset *mbs;
    merr_t err;

    idv_init(idv, idc);

    err = mbset_create(ds, idc, idv, usz, ufn, &mbs);
    ASSERT_EQ(err, 0);
    mbset_put_ref(mbs);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_invalid_params, pre, post)
{
    uint64_t idv[2];
    uint idc = NELEM(idv);
    struct mbset *mbs;
    merr_t err;

    idv_init(idv, idc);

    err = mbset_create(0, idc, idv, usz, ufn, &mbs);
    ASSERT_NE(err, 0);

    err = mbset_create(ds, 0, idv, usz, ufn, &mbs);
    ASSERT_NE(err, 0);

    err = mbset_create(ds, idc, 0, usz, ufn, &mbs);
    ASSERT_NE(err, 0);

    err = mbset_create(ds, idc, idv, usz, ufn, 0);
    ASSERT_NE(err, 0);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_alloc_fail, pre, post)
{
    uint64_t idv[2];
    uint idc = NELEM(idv);
    struct mbset *mbs;
    merr_t err;

    idv_init(idv, idc);

    mapi_inject_ptr(mapi_idx_malloc, 0);
    err = mbset_create(ds, idc, idv, usz, ufn, &mbs);
    ASSERT_EQ(merr_errno(err), ENOMEM);
    mapi_inject_unset(mapi_idx_malloc);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_mblk_map_fail, pre, post)
{
    uint64_t idv[2];
    uint idc = NELEM(idv);
    struct mbset *mbs;
    merr_t err;

    idv_init(idv, idc);

    mocked_mblk_mmap_errno = 1234;
    err = mbset_create(ds, idc, idv, usz, ufn, &mbs);
    ASSERT_EQ(merr_errno(err), mocked_mblk_mmap_errno);
    mocked_mblk_mmap_errno = 0;
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_mblk_unmap_errors, pre, post)
{
    uint64_t idv[2];
    uint idc = NELEM(idv);
    struct mbset *mbs;
    merr_t err;

    idv_init(idv, idc);

    err = mbset_create(ds, idc, idv, usz, ufn, &mbs);
    ASSERT_EQ(err, 0);

    mocked_mblk_munmap_errno = 1234;
    mbset_put_ref(mbs);
    mocked_mblk_munmap_errno = 0;
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_getters, pre, post)
{
    uint64_t idv[19];
    uint idc = NELEM(idv);
    struct mbset *mbs;
    merr_t err;

    idv_init(idv, idc);

    err = mbset_create(ds, idc, idv, usz, ufn, &mbs);
    ASSERT_EQ(err, 0);

    ASSERT_EQ(mbset_get_blkc(mbs), idc);
    ASSERT_EQ(mbset_get_mp(mbs), ds);
    ASSERT_EQ(mbset_get_alen(mbs), idc * mock_alen_pages * PAGE_SIZE);
    ASSERT_EQ(mbset_get_wlen(mbs), idc * mock_wlen_pages * PAGE_SIZE);

    for (uint i = 0; i < idc; i++) {
        struct udata *u;

        ASSERT_EQ(mbset_get_mbid(mbs, i), 1000 + i);

        u = mbset_get_udata(mbs, i);
        ASSERT_NE(u, NULL);
        ASSERT_EQ(u->cookie, idv[i]);
    }

    mbset_put_ref(mbs);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_callback, pre, post)
{
    merr_t err;
    struct mbset *mbs;
    uint64_t idv[4];
    uint idc = NELEM(idv);
    struct t_callback_info actual;
    struct t_callback_info expect;
    uint expect_mblock_delete_calls;

    idv_init(idv, idc);

    /* Test steps:
     * - clear put/del counts
     * - create mbset
     * - i==1,2: set del flag
     * - i==2: cause delete errors
     * - set callback
     * - destroy mbset
     * - verify put/del called as expected
     * - verify callback invoked as expected
     */
    for (uint i = 0; i < 3; i++) {

        mapi_inject(mapi_idx_mpool_mblock_delete, 0);

        err = mbset_create(ds, idc, idv, usz, ufn, &mbs);
        ASSERT_EQ(err, 0);

        switch (i) {
        case 0:
            expect.invoked = 1;
            expect.delete_error_detected = 0;
            expect_mblock_delete_calls = 0;
            break;
        case 1:
            mbset_set_delete_flag(mbs);
            expect.invoked = 1;
            expect.delete_error_detected = 0;
            expect_mblock_delete_calls = idc; /* one for each mblock */
            break;
        case 2:
            mapi_inject_set(
                mapi_idx_mpool_mblock_delete, 1, 2, 0, /* calls 1 and 2 successful */
                3, 0, -1                               /* calls 3 to forever fail */
            );
            mbset_set_delete_flag(mbs);
            expect.invoked = 1;
            expect.delete_error_detected = 1;
            expect_mblock_delete_calls = idc;
            break;

        default:
            ASSERT_TRUE(false);
            break;
        }

        /* setup for callback */
        actual.invoked = 0;
        actual.delete_error_detected = 0;

        mbset_set_callback(mbs, t_callback, &actual);

        /* drop the ref */
        mbset_put_ref(mbs);

        /* verify callback activity */
        ASSERT_EQ(expect.invoked, actual.invoked);
        ASSERT_EQ(expect.delete_error_detected, actual.delete_error_detected);
        ASSERT_EQ(expect_mblock_delete_calls, mapi_calls(mapi_idx_mpool_mblock_delete));
    }
}

MTF_END_UTEST_COLLECTION(test);
