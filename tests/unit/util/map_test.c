/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse/error/merr.h>
#include <hse/util/map.h>

MTF_BEGIN_UTEST_COLLECTION(map_test);

MTF_DEFINE_UTEST(map_test, pointers)
{
    bool found;
    merr_t err;
    uintptr_t val;
    const char *c;
    struct map *map;
    const char *blob1 = "hello";
    const char *blob2 = "gaurav";

    map = map_create(1024);
    ASSERT_NE(NULL, map);

    err = map_insert(map, 10, (uintptr_t)blob1);
    ASSERT_EQ(0, err);

    err = map_insert(map, 11, (uintptr_t)blob2);
    ASSERT_EQ(0, err);

    c = map_lookup_ptr(map, 10);
    ASSERT_EQ(0, strcmp(blob1, c));

    c = map_lookup_ptr(map, 42);
    ASSERT_EQ(0, c);

    found = map_lookup(map, 11, &val);
    ASSERT_TRUE(found);
    ASSERT_EQ(0, strcmp(blob2, (const char *)(val)));
    ASSERT_NE(0, val);

    found = map_remove(map, 11, NULL);
    ASSERT_TRUE(found);

    c = map_lookup_ptr(map, 11);
    ASSERT_EQ(0, c);

    map_destroy(map);
}

MTF_DEFINE_UTEST(map_test, scalars)
{
    struct map *map;
    merr_t err;
    uintptr_t val;
    bool found;

    map = map_create(1024);
    ASSERT_NE(NULL, map);

    err = map_insert(map, 11, 5);
    ASSERT_EQ(0, err);
    err = map_insert(map, 12, 6);
    ASSERT_EQ(0, err);

    found = map_lookup(map, 11, &val);
    ASSERT_TRUE(found);
    ASSERT_EQ(5, val);
    found = map_lookup(map, 12, &val);
    ASSERT_TRUE(found);
    ASSERT_EQ(6, val);

    map_destroy(map);
}

MTF_DEFINE_UTEST(map_test, refcnt)
{
    struct map *map;
    merr_t err;
    bool found;
    uintptr_t val;

    map = map_create(0);
    ASSERT_NE(NULL, map);

    err = map_insert(map, 10, 1);
    ASSERT_EQ(0, err);
    err = map_insert(map, 11, 1);
    ASSERT_EQ(0, err);
    err = map_insert(map, 12, 1);
    ASSERT_EQ(0, err);

    found = map_remove(map, 11, &val);
    ASSERT_TRUE(found);
    ASSERT_EQ(1, val);
    val += 2;
    err = map_insert(map, 11, val);
    ASSERT_EQ(0, err);

    found = map_remove(map, 12, &val);
    ASSERT_TRUE(found);
    ASSERT_NE(0, val);
    ++val;
    err = map_insert(map, 12, val);
    ASSERT_EQ(0, err);

    found = map_lookup(map, 10, &val);
    ASSERT_TRUE(found);
    ASSERT_EQ(1, val);

    found = map_lookup(map, 11, &val);
    ASSERT_TRUE(found);
    ASSERT_EQ(3, val);

    found = map_lookup(map, 12, &val);
    ASSERT_TRUE(found);
    ASSERT_EQ(2, val);

    map_destroy(map);
}

MTF_DEFINE_UTEST(map_test, iter_test)
{
    merr_t err;
    int cnt = 0;
    uintptr_t val;
    uint64_t bm = 0;
    struct map *map;
    struct map_iter iter;
    uint num_keys = sizeof(bm) * 8;

    map = map_create(0);
    ASSERT_NE(NULL, map);

    for (int i = 0; i < num_keys; i++) {
        err = map_insert(map, i, i);
        ASSERT_EQ(0, err);
    }

    map_iter_init(&iter, map);

    while (map_iter_next_val(&iter, &val)) {
        uint64_t mask = 1UL << val;

        ASSERT_EQ(0, (bm & mask));
        bm |= mask;
        ++cnt;
    }

    ASSERT_EQ(UINT64_MAX, bm);
    ASSERT_EQ(num_keys, cnt);

    map_destroy(map);
}

MTF_DEFINE_UTEST(map_test, grow_memory)
{
    int cnt = 0;
    uintptr_t *val;
    struct map *map;
    struct map_iter iter;
    int num_keys = 1000 * 1000;

    map = map_create(100);
    ASSERT_NE(NULL, map);

    for (int i = 0; i < num_keys; i++) {
        merr_t err;

        err = map_insert(map, i, i);
        ASSERT_EQ(0, err);
    }

    map_iter_init(&iter, map);

    while (map_iter_next_val(&iter, &val))
        ++cnt;

    ASSERT_EQ(num_keys, cnt);

    map_destroy(map);
}

MTF_END_UTEST_COLLECTION(map_test)
