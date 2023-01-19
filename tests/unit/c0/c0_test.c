/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mock/api.h>
#include <mtf/framework.h>
#include <tools/key_generation.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/c0.h>
#include <hse/ikvdb/c0_kvmultiset.h>
#include <hse/ikvdb/c0sk.h>
#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/kvset_builder.h>
#include <hse/ikvdb/tuple.h>
#include <hse/test/support/random_buffer.h>
#include <hse/util/seqno.h>

#include "c0sk_mock.h"
#include "cn_mock.h"

struct c0sk *ikvdb_get_c0sk_gv_c0sk = 0;

void
_ikvdb_get_c0sk(struct ikvdb *handle, struct c0sk **out)
{
    *out = ikvdb_get_c0sk_gv_c0sk;
}

bool
_ikvdb_allows_user_writes(struct ikvdb *handle)
{
    return true;
}

static void
mock_unset()
{
    MOCK_UNSET(ikvdb, _ikvdb_get_c0sk);
    MOCK_UNSET(ikvdb, _ikvdb_allows_user_writes);
}

static void
mock_set(struct mtf_test_info *info)
{
    /* Allow repeated test_collection_setup() w/o intervening unset() */
    mock_unset();

    mapi_inject_clear();

    MOCK_SET(ikvdb, _ikvdb_get_c0sk);
    MOCK_SET(ikvdb, _ikvdb_allows_user_writes);
}

int
test_collection_setup(struct mtf_test_info *info)
{
    mock_set(info);

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    mock_unset();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(c0_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST(c0_test, basic_open_close)
{
    struct c0 *c0;
    struct cn *cn;
    struct c0sk *c0sk;
    merr_t err;

    err = create_mock_cn(&cn, false, false, 0);
    ASSERT_EQ(0, err);
    err = create_mock_c0sk(&c0sk);
    ASSERT_EQ(0, err);

    ikvdb_get_c0sk_gv_c0sk = c0sk;

    err = c0_open((void *)0x1234, cn, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0 *)0, c0);
    ASSERT_EQ(1, mapi_calls(mapi_idx_c0sk_c0_register));
    mapi_calls_clear(mapi_idx_c0sk_c0_register);

    err = c0_close(c0);
    ASSERT_EQ(0, err);

    destroy_mock_c0sk(c0sk);
    destroy_mock_cn(cn);
}

MTF_DEFINE_UTEST(c0_test, open_error_paths)
{
    struct c0 *c0 = 0;
    struct cn *cn;
    struct c0sk *c0sk;
    struct mock_c0sk *mock_c0sk;
    merr_t err;

    err = create_mock_cn(&cn, false, false, 0);
    ASSERT_EQ(0, err);
    err = create_mock_c0sk(&c0sk);
    ASSERT_EQ(0, err);
    mock_c0sk = (struct mock_c0sk *)c0sk;

    mock_c0sk->mczk_skidx = 13;

    /* allocation failure */
    ikvdb_get_c0sk_gv_c0sk = c0sk;
    mapi_inject_once_ptr(mapi_idx_malloc, 1, 0);
    err = c0_open((void *)0x1234, cn, &c0);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    ASSERT_EQ((struct c0 *)0, c0);
    ASSERT_EQ(0, mapi_calls(mapi_idx_c0sk_c0_register));

    /* get backing c0sk failure */
    ikvdb_get_c0sk_gv_c0sk = 0;
    err = c0_open((void *)0x1234, cn, &c0);
    ASSERT_EQ(EINVAL, merr_errno(err));
    ASSERT_EQ((struct c0 *)0, c0);
    ASSERT_EQ(0, mapi_calls(mapi_idx_c0sk_c0_register));

    /* c0sk register failure */
    ikvdb_get_c0sk_gv_c0sk = c0sk;
    mapi_inject_once(mapi_idx_c0sk_c0_register, 1, merr(ENOSPC));
    err = c0_open((void *)0x1234, cn, &c0);
    ASSERT_EQ(ENOSPC, merr_errno(err));
    ASSERT_EQ((struct c0 *)0, c0);
    ASSERT_EQ(1, mapi_calls(mapi_idx_c0sk_c0_register));

    destroy_mock_c0sk(c0sk);
    destroy_mock_cn(cn);
}

MTF_DEFINE_UTEST(c0_test, close_error_paths)
{
    struct c0 *c0 = 0;
    struct cn *cn;
    struct c0sk *c0sk;
    struct mock_c0sk *mock_c0sk;
    merr_t err;

    err = create_mock_cn(&cn, false, false, 0);
    ASSERT_EQ(0, err);
    err = create_mock_c0sk(&c0sk);
    ASSERT_EQ(0, err);
    mock_c0sk = (struct mock_c0sk *)c0sk;

    mock_c0sk->mczk_skidx = 13;
    ikvdb_get_c0sk_gv_c0sk = c0sk;

    /* invalid handle */
    err = c0_close(0);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* c0_sync fails */
    err = c0_open((void *)0x1234, cn, &c0);
    mapi_inject_once(mapi_idx_c0sk_sync, 1, EDOM);
    err = c0_close(c0);
    ASSERT_EQ(EDOM, merr_errno(err));
    mapi_inject_clear();

    /* c0sk_c0_deregister fails */
    err = c0_open((void *)0x1234, cn, &c0);
    mapi_inject_once(mapi_idx_c0sk_c0_deregister, 1, EDOM);
    err = c0_close(c0);
    ASSERT_EQ(EDOM, merr_errno(err));
    mapi_inject_clear();

    /* c0_sync fails, followed by a failure in c0sk_c0_deregister. The
     * first error should be the one returned.
     */
    err = c0_open((void *)0x1234, cn, &c0);
    mapi_inject_once(mapi_idx_c0sk_sync, 1, EDOM);
    mapi_inject_once(mapi_idx_c0sk_c0_deregister, 1, EAGAIN);
    err = c0_close(c0);
    ASSERT_EQ(EDOM, merr_errno(err));
    mapi_inject_clear();

    destroy_mock_c0sk(c0sk);
    destroy_mock_cn(cn);
}

MTF_DEFINE_UTEST(c0_test, basic_ops)
{
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    struct kvs_buf vbuf;
    struct c0 *c0;
    struct cn *cn;
    struct c0sk *c0sk;
    const uintptr_t seqno = 17;
    enum key_lookup_res res;
    merr_t err;

    err = create_mock_cn(&cn, false, false, 3);
    ASSERT_EQ(0, err);
    err = create_mock_c0sk(&c0sk);
    ASSERT_EQ(0, err);

    ikvdb_get_c0sk_gv_c0sk = c0sk;

    err = c0_open((void *)0x1234, cn, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0 *)0, c0);

    kvs_ktuple_init(&kt, "foo", 3);
    kvs_vtuple_init(&vt, "bar", 3);

    /* c0_put */
    err = c0_put(c0, &kt, &vt, seqno);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, mapi_calls(mapi_idx_c0sk_put));
    mapi_calls_clear(mapi_idx_c0sk_put);

    /* c0_del */
    err = c0_del(c0, &kt, seqno);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, mapi_calls(mapi_idx_c0sk_del));
    mapi_calls_clear(mapi_idx_c0sk_del);

    /* c0_get */
    err = c0_get(c0, &kt, seqno, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, mapi_calls(mapi_idx_c0sk_get));
    mapi_calls_clear(mapi_idx_c0sk_get);

    /* c0_sync */
    mapi_calls_clear(mapi_idx_c0sk_sync);
    err = c0_sync(c0);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, mapi_calls(mapi_idx_c0sk_sync));
    mapi_calls_clear(mapi_idx_c0sk_sync);

    /* c0_prefix_del */
    err = c0_prefix_del(c0, &kt, seqno);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, mapi_calls(mapi_idx_c0sk_prefix_del));
    mapi_calls_clear(mapi_idx_c0sk_prefix_del);

    err = c0_close(c0);
    ASSERT_EQ(0, err);

    destroy_mock_c0sk(c0sk);
    destroy_mock_cn(cn);
}

MTF_END_UTEST_COLLECTION(c0_test)
