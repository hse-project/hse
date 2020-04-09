/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>
#include <hse_test_support/random_buffer.h>
#include <hse_util/cursor_heap.h>
#include <hse_ikvdb/c1_kvcache.h>
#include "../../c1/c1_private.h"

static int
test_pre(struct mtf_test_info *ti)
{
    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(c1_kvcache_test)

MTF_DEFINE_UTEST_PREPOST(c1_kvcache_test, basic, test_pre, test_post)
{
    struct c1_kvbundle *kvb;
    struct c1_kvcache * kvc;
    struct c1_kvtuple * kt;
    struct c1_vtuple *  vt;
    struct c1           c1;
    merr_t              err;
    void *              obj;

    err = c1_kvcache_create(&c1);
    ASSERT_EQ(0, err);

    kvc = c1_get_kvcache(NULL);
    ASSERT_EQ(NULL, kvc);

    kvc = c1_get_kvcache(&c1);
    ASSERT_NE(NULL, kvc);

    err = c1_vtuple_alloc(&c1.c1_kvc[0], &vt);
    ASSERT_EQ(0, err);

    err = c1_kvtuple_alloc(&c1.c1_kvc[0], &kt);
    ASSERT_EQ(0, err);

    err = c1_kvbundle_alloc(&c1.c1_kvc[0], &kvb);
    ASSERT_EQ(0, err);

    obj = c1_kvcache_alloc(&c1.c1_kvc[0], 64, 128);
    ASSERT_NE(NULL, obj);

    obj = c1_kvcache_alloc(&c1.c1_kvc[0], 123, 128);
    ASSERT_EQ(NULL, obj);
}

MTF_DEFINE_UTEST_PREPOST(c1_kvcache_test, get, test_pre, test_post)
{
    struct c1_kvcache *kvc;
    struct c1          c1;
    merr_t             err;

    err = c1_kvcache_create(&c1);
    ASSERT_EQ(0, err);

    kvc = c1_get_kvcache(NULL);
    ASSERT_EQ(NULL, kvc);

    kvc = c1_get_kvcache(&c1);
    ASSERT_NE(NULL, kvc);

    kvc = c1_get_kvcache(&c1);
    ASSERT_NE(NULL, kvc);
}

MTF_END_UTEST_COLLECTION(c1_kvcache_test);
