/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

#include <hse_util/platform.h>
#include <hse_util/slab.h>

#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/cn.h>

#include <hse/hse_limits.h>

#include "mock_kbb_vbb.h"

int
init(struct mtf_test_info *mtf)
{
    return 0;
}

int
fini(struct mtf_test_info *mtf)
{
    return 0;
}

#define TEST_DEF_UTAG 1001

static struct kvs_rparams mocked_kvs_rp;

struct kvs_rparams *
mocked_cn_get_rp(const struct cn *cn)
{
    return &mocked_kvs_rp;
}

int
pre(struct mtf_test_info *mtf)
{
    mapi_inject(mapi_idx_cn_get_cnid, TEST_DEF_UTAG);
    mapi_inject(mapi_idx_cn_get_dataset, 0);
    mapi_inject(mapi_idx_cn_get_flags, 0);

    mocked_kvs_rp = kvs_rparams_defaults();
    MOCK_SET_FN(cn, cn_get_rp, mocked_cn_get_rp);

    mock_kbb_set();
    mock_vbb_set();

    return 0;
}

int
post(struct mtf_test_info *mtf)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(test, init, fini);

#define ds ((struct mpool *)1)
#define rp ((struct kvs_rparams *)2)

#define KVSET_BUILDER_CREATE() \
    ({ kvset_builder_create(&bld, (void *)-1, 0, 1, KVSET_BUILDER_FLAGS_NONE); })

MTF_DEFINE_UTEST_PREPOST(test, t_kvset_builder_create, pre, post)
{
    u32                   api;
    merr_t                err;
    struct kvset_builder *bld = 0;

    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);
    kvset_builder_destroy(bld);

    api = mapi_idx_malloc;
    mapi_inject_ptr(api, 0);
    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(merr_errno(err), ENOMEM);
    mapi_inject_unset(api);

    api = mapi_idx_kbb_create;
    mapi_inject(api, api + 1234);
    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, api + 1234);
    mapi_inject_unset(api);

    api = mapi_idx_vbb_create;
    mapi_inject(api, api + 1234);
    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, api + 1234);
    mapi_inject_unset(api);
}

MTF_DEFINE_UTEST_PREPOST(test, t_kvset_builder_add_entry1, pre, post)
{
    merr_t                err;
    struct kvset_builder *bld = 0;
    int                   junk1 = 9;
    char                  junk2[1171];
    u64                   seq1 = 2;
    u64                   seq2 = 1;
    void *                vdata1 = &junk1;
    void *                vdata2 = &junk2;
    void *                kdata = &junk1;
    uint                  vlen1 = sizeof(junk1);
    uint                  vlen2 = sizeof(junk2);

    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);

    /*
     * Four flavors for add_val
     */
    /* zlen values: vlen or both vdata and vlen set to 0 */
    err = kvset_builder_add_val(bld, seq1, 0, 0, 0);
    ASSERT_EQ(err, 0);
    err = kvset_builder_add_val(bld, seq1, vdata1, 0, 0);
    ASSERT_EQ(err, 0);
    /* tombstone: vlen can be zero or non-zero */
    err = kvset_builder_add_val(bld, seq1, HSE_CORE_TOMB_REG, 0, 0);
    ASSERT_EQ(err, 0);
    err = kvset_builder_add_val(bld, seq1, HSE_CORE_TOMB_REG, vlen1, 0);
    ASSERT_EQ(err, 0);
    /* pfx tombstone: vlen can be zero or non-zero */
    err = kvset_builder_add_val(bld, seq1, HSE_CORE_TOMB_PFX, 0, 0);
    ASSERT_EQ(err, 0);
    err = kvset_builder_add_val(bld, seq1, HSE_CORE_TOMB_PFX, vlen1, 0);
    ASSERT_EQ(err, 0);
    /* real values */
    err = kvset_builder_add_val(bld, seq1, vdata1, vlen1, 0);
    ASSERT_EQ(err, 0);
    err = kvset_builder_add_val(bld, seq2, vdata2, vlen2, 0);
    ASSERT_EQ(err, 0);
    err = kvset_builder_add_val(bld, seq2, 0, 0, 0);
    ASSERT_EQ(err, 0);

    /*
     * Two flavors for add_nonval
     */
    err = kvset_builder_add_nonval(bld, seq2, vtype_tomb);
    ASSERT_EQ(err, 0);
    err = kvset_builder_add_nonval(bld, seq2, vtype_ptomb);
    ASSERT_EQ(err, 0);
    /* plus invalid cases */
    err = kvset_builder_add_nonval(bld, seq2, vtype_val);
    ASSERT_NE(err, 0);
    err = kvset_builder_add_nonval(bld, seq2, 1234);
    ASSERT_NE(err, 0);

    /*
     * One flavor for add_vref
     */
    err = kvset_builder_add_vref(bld, seq2, 1, 2, 3, 0);
    ASSERT_EQ(err, 0);

    /*
     * Add key: test various invalid params, then success case
     */
    struct key_obj ko;

    err = kvset_builder_add_key(bld, 0);
    ASSERT_NE(err, 0);
    key2kobj(&ko, kdata, 0);
    err = kvset_builder_add_key(bld, &ko);
    ASSERT_NE(err, 0);
    key2kobj(&ko, kdata, HSE_KVS_KLEN_MAX + 1);
    err = kvset_builder_add_key(bld, &ko);
    ASSERT_NE(err, 0);
    /* success */
    key2kobj(&ko, kdata, HSE_KVS_KLEN_MAX);
    err = kvset_builder_add_key(bld, &ko);
    ASSERT_EQ(err, 0);

    kvset_builder_destroy(bld);
}

MTF_DEFINE_UTEST_PREPOST(test, t_kvset_builder_add_val_fail1, pre, post)
{
    struct kvset_builder *bld = 0;

    u32    api;
    merr_t err;
    u64    seq = 1;

    const char *value = "foobarbazquxquuxcorgegraultgarplywaldofredplugh";

    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);

    api = mapi_idx_vbb_add_entry;
    mapi_inject(api, 1234);
    err = kvset_builder_add_val(bld, seq, value, strlen(value), 0);
    ASSERT_EQ(err, 1234);

    mapi_inject_unset(api);

    kvset_builder_destroy(bld);
}

MTF_DEFINE_UTEST_PREPOST(test, t_reserve_kmd1, pre, post)
{
    merr_t err;
    u64    seq = 0x1122334455667788ULL;
    uint   vbidx = 300;
    uint   vboff = 128 * 1000 * 1000;
    uint   vlen = 1000 * 1000;
    uint   i;

    struct kvset_builder *bld = 0;

    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);

    /* Add entries to exercise kmd growth */
    for (i = 0; i < 100; i++) {
        err = kvset_builder_add_vref(bld, seq, vbidx, vboff, vlen, 0);
        ASSERT_EQ(err, 0);
    }

    kvset_builder_destroy(bld);
}

MTF_DEFINE_UTEST_PREPOST(test, t_reserve_kmd2, pre, post)
{
    /* just like t_reserve_kmd1 but with memory allocation failures */
    u32    api;
    merr_t err;
    u64    seq = 0x1122334455667788ULL;
    uint   vbidx = 300;
    uint   vboff = 128 * 1000 * 1000;
    uint   vlen = 1000 * 1000;
    uint   i;

    struct kvset_builder *bld = 0;

    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);

    api = mapi_idx_malloc;
    mapi_inject_ptr(api, 0);

    /* Add entries to kmd, eventually we should get an ENOMEM. */
    for (i = 0; i < 100; i++) {
        err = kvset_builder_add_vref(bld, seq, vbidx, vboff, vlen, 0);
        if (err)
            break;
    }
    ASSERT_EQ(merr_errno(err), ENOMEM);

    /* Repeat with kvset_builder_add_nonval */
    for (i = 0; i < 100; i++) {
        err = kvset_builder_add_nonval(bld, seq, vtype_zval);
        if (err)
            break;
    }
    ASSERT_EQ(merr_errno(err), ENOMEM);

    /* Do it again with kvset_builder_add_val */
    for (i = 0; i < 100; i++) {
        err = kvset_builder_add_val(bld, seq, "foobar", 6, 0);
        if (err)
            break;
    }
    ASSERT_EQ(merr_errno(err), ENOMEM);

    mapi_inject_unset(api);

    kvset_builder_destroy(bld);
}

MTF_DEFINE_UTEST_PREPOST(test, t_kvset_mblocks_destroy, pre, post)
{
    struct kvset_mblocks blks = {};

    kvset_mblocks_destroy(&blks);
    kvset_mblocks_destroy(0);
}

MTF_DEFINE_UTEST_PREPOST(test, t_kvset_builder_get_mblocks, pre, post)
{
    u32                   api;
    merr_t                err;
    u32                   seq = 1;
    struct kvset_builder *bld = 0;
    struct kvset_mblocks  blks;
    struct key_obj        ko;

    /* create; get empty; destroy */
    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);

    err = kvset_builder_get_mblocks(bld, &blks);
    ASSERT_EQ(err, 0);

    kvset_builder_destroy(bld);

    /* create; get non-empty; destroy */
    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);

    err = kvset_builder_add_val(bld, seq, "foobar", 6, 0);
    ASSERT_EQ(err, 0);

    key2kobj(&ko, "foobar", 6);
    err = kvset_builder_add_key(bld, &ko);
    ASSERT_EQ(err, 0);

    err = kvset_builder_get_mblocks(bld, &blks);
    ASSERT_EQ(err, 0);

    kvset_builder_destroy(bld);

    /* create; test; destroy */
    err = KVSET_BUILDER_CREATE();
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(bld);

    api = mapi_idx_kbb_finish;
    mapi_inject(api, api + 1234);
    err = kvset_builder_get_mblocks(bld, &blks);
    ASSERT_EQ(err, api + 1234);
    mapi_inject_unset(api);

    kvset_builder_destroy(bld);
}

MTF_DEFINE_UTEST_PREPOST(test, t_kvset_build_destroy, pre, post)
{
    kvset_builder_destroy(NULL);
}

MTF_END_UTEST_COLLECTION(test);
