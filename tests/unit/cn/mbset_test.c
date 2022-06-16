/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/mman.h>

#include <mpool/mpool.h>

#include <cn/mbset.h>

#define ds ((struct mpool *)1)

#define mock_alloc_cap (4 * 1024 * 1024)
#define mock_write_len (mock_alloc_cap - 128 * 1024)
#define MBLOCKS_MAX ((1UL << 30) / (32 << 20))

#define MILLION ((u64)1000000)

#define id2bnum(id) ((id)-100 * MILLION)
#define bnum2id(bnum) ((bnum) + 100 * MILLION)

#define id2map(id) ((id) + 3 * MILLION)

#define bnum2map(bnum) id2map(bnum2id(bnum))

struct udata {
    uint bnum;
    u64  id;
    int  return_code;
};

#define ufn ((mbset_udata_init_fn *)t_udata_init)
#define usz sizeof(struct udata)

/*
 * Mock mpool interfaces used by mbset.
 */
static merr_t
_mpool_mblock_props_get(struct mpool *dsp, uint64_t objid, struct mblock_props *props)
{
    memset(props, 0, sizeof(*props));

    props->mpr_objid = objid;
    props->mpr_alloc_cap = mock_alloc_cap;
    props->mpr_write_len = mock_write_len;
    return 0;
}

static merr_t
_mpool_mcache_mmap(
    struct mpool *            dsp,
    size_t                    idc,
    uint64_t *                idv,
    struct mpool_mcache_map **map)
{
    size_t i;
    u64 *  m;

    /* In this mock, an mcache map of COUNT mblocks is an array
     * of COUNT u64 values where value is a simple reversible obfuscation
     * of the mblock id.
     */
    m = mapi_safe_malloc(sizeof(*m) * idc);
    VERIFY_NE_RET(m, 0, -1);

    for (i = 0; i < idc; i++)
        m[i] = id2map(idv[i]);

    *map = (struct mpool_mcache_map *)m;
    return 0;
}

static void
_mpool_mcache_munmap(struct mpool_mcache_map *map)
{
    mapi_safe_free(map);
}

HSE_MAYBE_UNUSED
static void
mock_unset(void)
{
    MOCK_UNSET(mpool, _mpool_mblock_props_get);

    MOCK_UNSET(mpool, _mpool_mcache_mmap);
    MOCK_UNSET(mpool, _mpool_mcache_munmap);

    mapi_inject_unset(mapi_idx_mpool_mcache_madvise);
    mapi_inject_unset(mapi_idx_mpool_mblock_delete);
}

static void
mock_set(void)
{
    MOCK_SET(mpool, _mpool_mblock_props_get);

    MOCK_SET(mpool, _mpool_mcache_mmap);
    MOCK_SET(mpool, _mpool_mcache_munmap);

    mapi_inject(mapi_idx_mpool_mcache_madvise, 0);
    mapi_inject(mapi_idx_mpool_mblock_delete, 0);
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
    mock_set();
    return 0;
}

static int
post(struct mtf_test_info *mtf)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(test, init, fini);

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

static merr_t
t_udata_init(
    struct mbset *       mbs,
    uint                 bnum,
    uint *               argcp,
    u64 *                argv,
    struct mblock_props *props,
    void *               rock)
{
    struct udata *u = rock;

    u->bnum = bnum;
    u->id = props->mpr_objid;
    return u->return_code;
}

static merr_t
t_udata_update(
    struct mbset *       mbs,
    uint                 bnum,
    uint *               argcp,
    u64 *                argv,
    struct mblock_props *props,
    void *               rock)
{
    struct udata *u = rock;
    int           i;

    for (i = 0; i < *argcp; ++i) {
        if (argv[i] == u->id)
            return u->return_code;
    }

    argv[i] = u->id;
    *argcp = i + 1;

    return u->return_code;
}

static u64 *
idv_alloc(uint idc)
{
    int  i;
    u64 *idv;

    idv = mapi_safe_malloc(idc * sizeof(*idv));
    if (idv) {
        for (i = 0; i < idc; i++)
            idv[i] = bnum2id(i);
    }

    return idv;
}

static int
t_mbs_create(struct mtf_test_info *lcl_ti, uint idc, u64 **idv_out, struct mbset **mbs_out)
{
    merr_t        err;
    u64 *         idv;
    struct mbset *mbs;

    idv = idv_alloc(idc);
    ASSERT_NE_RET(idv, NULL, -1);

    err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);
    ASSERT_EQ_RET(err, 0, -1);

    *idv_out = idv;
    *mbs_out = mbs;
    return 0;
}

static int
t_mbs_verify(struct mtf_test_info *lcl_ti, uint idc, u64 *idv, struct mbset *mbs)
{
    uint i;

    ASSERT_EQ_RET(mbset_get_blkc(mbs), idc, -1);

    for (i = 0; i < idc; i++) {

        struct udata *u;
        void *        map;

        ASSERT_EQ_RET(mbset_get_mp(mbs), ds, -1);

        ASSERT_EQ_RET(mbset_get_alen(mbs), (u64)idc * mock_alloc_cap, -1);

        ASSERT_EQ_RET(mbset_get_wlen(mbs), (u64)idc * mock_write_len, -1);

        ASSERT_EQ_RET(mbset_get_mbid(mbs, i), bnum2id(i), -1);

        u = mbset_get_udata(mbs, i);
        ASSERT_NE_RET(u, NULL, -1);
        ASSERT_EQ_RET(u->bnum, i, -1);
        ASSERT_EQ_RET(u->id, idv[i], -1);

        /* Get map and map index, verify the map @ map_idx is correct.
         * See the mocked mpool_mcache_map_create (above, in this file).
         */
        map = mbset_get_map(mbs);
        ASSERT_NE_RET(map, NULL, -1);

        ASSERT_EQ_RET(((u64 *)map)[i], bnum2map(i), -1);
    }

    return 0;
}

int
t_mbs_destroy(struct mtf_test_info *lcl_ti, u64 *idv, struct mbset *mbs)
{
    mapi_safe_free(idv);
    mbset_put_ref(mbs);
    return 0;
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_simple, pre, post)
{
    u64 *         idv;
    uint          idc = 2;
    struct mbset *mbs;
    merr_t        err;

    idv = idv_alloc(idc);
    ASSERT_NE(idv, NULL);

    err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);
    ASSERT_EQ(err, 0);
    mbset_put_ref(mbs);

    mapi_safe_free(idv);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_invalid_params, pre, post)
{
    u64 *         idv;
    uint          idc = 2;
    struct mbset *mbs;
    merr_t        err;

    idv = idv_alloc(idc);
    ASSERT_NE(idv, NULL);

    err = mbset_create(0, idc, idv, usz, ufn, 0, &mbs);
    ASSERT_NE(err, 0);

    err = mbset_create(ds, 0, idv, usz, ufn, 0, &mbs);
    ASSERT_NE(err, 0);

    err = mbset_create(ds, idc, 0, usz, ufn, 0, &mbs);
    ASSERT_NE(err, 0);

    err = mbset_create(ds, idc, idv, usz, ufn, 0, 0);
    ASSERT_NE(err, 0);

    mapi_safe_free(idv);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_alloc_fail, pre, post)
{
    u64 *         idv;
    uint          idc = 2;
    struct mbset *mbs;
    merr_t        err;
    uint          i, num_allocs;

    idv = idv_alloc(idc);
    ASSERT_NE(idv, NULL);

    /* mbset_create does two allocations, and the callback does one.
     * Verify ENOMEM when first two allocs fail, verify success
     * when third alloc fails.
     */
    num_allocs = 2;
    for (i = 0; i <= num_allocs; i++) {
        mapi_inject_once_ptr(mapi_idx_malloc, i + 1, 0);
        err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);
        if (i < num_allocs) {
            ASSERT_EQ(merr_errno(err), ENOMEM);
        } else {
            ASSERT_EQ(err, 0);
            mbset_put_ref(mbs);
        }
        mapi_inject_unset(mapi_idx_malloc);
    }

    mapi_safe_free(idv);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_getters, pre, post)
{
    u64 *idv = NULL;
    uint test_cases[] = { MBLOCKS_MAX - 1,     MBLOCKS_MAX,     MBLOCKS_MAX + 1,
                          2 * MBLOCKS_MAX - 1, 2 * MBLOCKS_MAX, 2 * MBLOCKS_MAX + 1 };

    uint          tx;
    struct mbset *mbs = NULL;

    for (tx = 0; tx < NELEM(test_cases); tx++) {
        uint idc = test_cases[tx];

        t_mbs_create(lcl_ti, idc, &idv, &mbs);
        t_mbs_verify(lcl_ti, idc, idv, mbs);
        t_mbs_destroy(lcl_ti, idv, mbs);
    }
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_create_fail, pre, post)
{
    u64 *idv;
    uint test_cases[] = { MBLOCKS_MAX - 1,     MBLOCKS_MAX,     MBLOCKS_MAX + 1,
                          2 * MBLOCKS_MAX - 1, 2 * MBLOCKS_MAX, 2 * MBLOCKS_MAX + 1 };

    struct mbset *mbs;
    merr_t        err;
    uint          num_allocs;

    uint i, ax, tx;

    struct api_table {
        uint api;
        bool is_ptr;
        u64  rc;
    } api_table[] = {
        { mapi_idx_malloc, true, 0 },
        { mapi_idx_mpool_mcache_mmap, false, 1 },
        { mapi_idx_mpool_mblock_props_get, false, 1 },
    };

    /* For #mblocks in 1, 2, MAX-1, MAX, MAX+1, etc.. */
    for (tx = 0; tx < NELEM(test_cases); tx++) {

        uint idc = test_cases[tx];

        /* Allocate id vector for said number of mblocks */
        idv = idv_alloc(idc);
        ASSERT_NE(idv, NULL);

        /* For each mocked API that can fail in mbset_create */
        for (ax = 0; ax < NELEM(api_table); ax++) {

            uint api = api_table[ax].api;
            bool ptr = api_table[ax].is_ptr;
            u64  rc = api_table[ax].rc;

            /* Set 'num_allocs' to number of times this api is
             * invoked in a successful call to mbset_create.
             */
            mapi_inject_unset(api);

            err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);
            ASSERT_EQ(err, 0);
            num_allocs = mapi_calls(api);

            mbset_put_ref(mbs);

            /* Create an mbset 'num_allocs+1' times.
             * On the i-th try, force a failure on the i-th call
             * to 'api'.  mbset should fail on each one.  On last
             * iteration, mbset_create should succeed.  To get
             * maximum value from this test, run it under
             * valgrind.
             */
            for (i = 0; i <= num_allocs; i++) {
                mapi_inject_unset(api);
                if (ptr)
                    mapi_inject_once_ptr(api, i + 1, (void *)rc);
                else
                    mapi_inject_once(api, i + 1, rc);

                err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);

                if (i < num_allocs) {
                    ASSERT_NE(err, 0);
                } else {
                    ASSERT_EQ(err, 0);
                    mbset_put_ref(mbs);
                }
            }

            mapi_inject_unset(api);
        }

        mapi_safe_free(idv);
    }
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_callback, pre, post)
{
    merr_t        err;
    struct mbset *mbs;
    u64 *         idv;
    uint          idc = 4;
    uint          i;
    struct t_callback_info actual;
    struct t_callback_info expect;
    uint expect_mblock_delete_calls;

    idv = idv_alloc(idc);
    ASSERT_NE(idv, NULL);

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
    for (i = 0; i < 3; i++) {

        mapi_inject(mapi_idx_mpool_mblock_delete, 0);

        err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);
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
                mapi_inject_set(mapi_idx_mpool_mblock_delete,
                    1, 2, 0,  /* calls 1 and 2 successful */
                    3, 0, -1  /* calls 3 to forevery fail */
                    );
                mbset_set_delete_flag(mbs);
                expect.invoked = 1;
                expect.delete_error_detected = 1;
                expect_mblock_delete_calls = 3; /* two success calls to delete, one failed call */
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

    mapi_safe_free(idv);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_madvise, pre, post)
{
    u64 *         idv;
    uint          idc = 2;
    struct mbset *mbs;
    merr_t        err;

    idv = idv_alloc(idc);
    ASSERT_NE(idv, NULL);

    err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);
    ASSERT_EQ(err, 0);

    /* This madvise will fail, but we'll get coverage...
     */
    mbset_madvise(mbs, MADV_WILLNEED);

    mbset_put_ref(mbs);

    mapi_safe_free(idv);
}

MTF_DEFINE_UTEST_PREPOST(test, t_mbset_apply, pre, post)
{
    u64 *         idv;
    uint          idc = 3;
    struct mbset *mbs;
    merr_t        err;
    uint          argc = 0;
    u64           argv[idc + 1];

    idv = idv_alloc(idc);
    ASSERT_NE(idv, NULL);

    err = mbset_create(ds, idc, idv, usz, ufn, 0, &mbs);
    ASSERT_EQ(err, 0);

    mbset_apply(NULL, t_udata_update, &argc, argv);
    mbset_apply(mbs, NULL, &argc, argv);

    argv[0] = 0xdeadbeefdeadbeef;
    argv[idc] = 0xdeadbeefdeadbeef;

    mbset_apply(mbs, t_udata_update, &argc, argv);

    ASSERT_EQ(argc, idc);
    ASSERT_NE(argv[0], 0xdeadbeefdeadbeef);
    ASSERT_EQ(argv[idc], 0xdeadbeefdeadbeef);

    mbset_put_ref(mbs);

    mapi_safe_free(idv);
}

MTF_END_UTEST_COLLECTION(test);
