/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/keycmp.h>
#include <hse_util/hse_err.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(keycmp_test);

MTF_DEFINE_UTEST(keycmp_test, basic)
{
    const unsigned char key1[] = { 0, 1, 2, 3, 4, 5 };
    const unsigned char key2[] = { 0, 1, 2, 3, 5, 4 };
    int                 rc;

    rc = keycmp(key1, sizeof(key1), key1, sizeof(key1));
    ASSERT_EQ(rc, 0);

    rc = keycmp(key1, sizeof(key1), key2, sizeof(key2));
    ASSERT_TRUE(rc < 0);

    rc = keycmp(key2, sizeof(key2), key1, sizeof(key1));
    ASSERT_TRUE(rc > 0);

    rc = keycmp(key1, sizeof(key1), key1, sizeof(key1) - 2);
    ASSERT_NE(rc, 0);

    rc = keycmp(key1, sizeof(key1) - 2, key1, sizeof(key1));
    ASSERT_NE(rc, 0);

    rc = keycmp(key1, sizeof(key1), key1, sizeof(key1) - 3);
    ASSERT_TRUE(rc > 0);

    rc = keycmp(key1, sizeof(key1) - 3, key1, sizeof(key1));
    ASSERT_TRUE(rc < 0);
}

MTF_DEFINE_UTEST(keycmp_test, prefix)
{
    const unsigned char pfx[] = { 0, 1, 2, 3 };
    const unsigned char key1[] = { 0, 1, 2, 3, 0xaa, 0xbb };
    const unsigned char key2[] = { 0, 1, 2, 0xaa, 0xbb };
    const unsigned char key3[] = { 0, 1, 2 };
    int                 rc;

    rc = keycmp_prefix(pfx, sizeof(pfx), key1, sizeof(key1));
    ASSERT_EQ(rc, 0);

    rc = keycmp_prefix(pfx, sizeof(pfx), key1, sizeof(pfx) - 1);
    ASSERT_NE(rc, 0);

    rc = keycmp_prefix(pfx, sizeof(pfx) - 1, key2, sizeof(key2));
    ASSERT_EQ(rc, 0);

    rc = keycmp_prefix(pfx, sizeof(pfx), key2, sizeof(key2));
    ASSERT_NE(rc, 0);
    ASSERT_TRUE(rc < 0);

    rc = keycmp_prefix(pfx, sizeof(pfx), key3, sizeof(key3));
    ASSERT_TRUE(rc > 0);
}

MTF_END_UTEST_COLLECTION(keycmp_test)
