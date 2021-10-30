/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/darray.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(darray);

static struct darray zero;

MTF_DEFINE_UTEST(darray, init_fini)
{
    struct darray da = zero;

    ASSERT_EQ(0, darray_init(&da, 0));

    darray_fini(&da);
    ASSERT_EQ(NULL, da.arr);
}

MTF_DEFINE_UTEST(darray, no_init)
{
    struct darray da = zero;

    ASSERT_EQ(0, darray_append(&da, "foo"));
    ASSERT_EQ(1, da.cur);
    ASSERT_EQ(0, strcmp(da.arr[0], "foo"));

    darray_fini(&da);
    ASSERT_EQ(NULL, da.arr);
}

MTF_DEFINE_UTEST(darray, growth)
{
    struct darray da = zero;
    char          buf[100];
    int           i;
    const int     limit = 1000;

    for (i = 0; i < limit; ++i) {
        sprintf(buf, "string %d", i);
        ASSERT_EQ(0, darray_append(&da, strdup(buf)));
    }
    ASSERT_EQ(limit, da.cur);

    for (i = 0; i < limit; ++i) {
        sprintf(buf, "string %d", i);
        ASSERT_EQ(0, strcmp(da.arr[i], buf));
        free(da.arr[i]);
    }

    darray_fini(&da);
}

MTF_DEFINE_UTEST(darray, uniq)
{
    struct darray da = zero;

    ASSERT_EQ(0, darray_append_uniq(&da, "foo"));
    ASSERT_EQ(0, darray_append_uniq(&da, "foo"));
    ASSERT_EQ(1, da.cur);
    ASSERT_EQ(0, darray_append(&da, "foo"));
    ASSERT_EQ(2, da.cur);

    darray_fini(&da);
}

/*
 * NB: test the apply funcs with the identity sum(1..N) = (N+1)*(N/2)
 *     This guarantees every element is touched exactly once,
 *     including the edges (catches off-by-one problems).
 */

static int tot;

static void
applyfunc(void *p)
{
    tot += (int)(u64)p; /* get an int from the pointer */
}

MTF_DEFINE_UTEST(darray, apply)
{
    struct darray da = zero;
    u64           i;

    tot = 0;
    for (i = 1; i <= 100; ++i)
        darray_append(&da, (void *)i);
    darray_apply(&da, applyfunc);
    ASSERT_EQ(tot, (100 + 1) * 100 / 2);

    darray_fini(&da);
}

MTF_DEFINE_UTEST(darray, apply_rev)
{
    struct darray da = zero;
    u64           i;

    tot = 0;
    for (i = 1; i <= 100; ++i)
        darray_append(&da, (void *)i);
    darray_apply_rev(&da, applyfunc);
    ASSERT_EQ(tot, (100 + 1) * 100 / 2);

    darray_fini(&da);
}

MTF_DEFINE_UTEST(darray, random_access)
{
    struct darray da = zero;
    void **       a;

    darray_init(&da, 100);
    da.arr[42] = "foo";
    da.arr[69] = "bar";

    a = darray_arr(&da);

    ASSERT_EQ(0, darray_len(&da));
    ASSERT_EQ(0, da.cur);
    ASSERT_EQ(100, da.cap);
    ASSERT_EQ(0, strcmp(a[42], "foo"));
    ASSERT_EQ(0, strcmp(a[69], "bar"));
    ASSERT_EQ(NULL, a[0]);

    darray_fini(&da);
}

MTF_DEFINE_UTEST(darray, reset)
{
    struct darray da = zero;
    u64           i;
    void **       a;

    darray_init(&da, 100);
    a = darray_arr(&da);

    for (i = 1; i < 100; ++i)
        darray_append(&da, (void *)i);

    ASSERT_EQ(99, da.cur);
    ASSERT_EQ(100, da.cap);

    darray_reset(&da);

    ASSERT_EQ(0, da.cur);
    ASSERT_EQ(100, da.cap);
    ASSERT_EQ(NULL, a[0]);
    ASSERT_EQ(NULL, a[49]);
    ASSERT_EQ(NULL, a[99]);

    darray_fini(&da);
}

MTF_DEFINE_UTEST(darray, loc)
{
    struct darray da = zero;
    void **       a;
    u64           i;

    darray_init(&da, 10);
    a = darray_arr(&da);

    for (i = 0; i < 100; ++i)
        *darray_append_loc(&da) = (void *)i;

    ASSERT_EQ(100, da.cur);
    ASSERT_GE(da.cap, 101);

    a = darray_arr(&da);
    ASSERT_EQ(a[42], (void *)42);

    darray_fini(&da);
}

#if HSE_MOCKING
MTF_DEFINE_UTEST(darray, alloc_failure)
{
    struct darray da = zero;
    int           rc;
    u64           i;

    mapi_inject(mapi_idx_malloc, 0);
    rc = darray_init(&da, 10);
    ASSERT_EQ(-ENOMEM, rc);
    mapi_inject_unset(mapi_idx_malloc);

    rc = darray_init(&da, 10);
    ASSERT_EQ(0, rc);

    mapi_inject(mapi_idx_malloc, 0);
    for (i = 0; i < 10; ++i) {
        rc = darray_append(&da, (void *)i);
        if (i < 9)
            ASSERT_EQ(0, rc);
        else
            ASSERT_EQ(-ENOMEM, rc);
    }
    mapi_inject_unset(mapi_idx_malloc);

    ASSERT_EQ(9, da.cur);
    ASSERT_GE(da.cap, 10);

    darray_fini(&da);
}
#endif /* HSE_MOCKING */

MTF_END_UTEST_COLLECTION(darray);
