/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>
#include <hse_util/xrand.h>

#include <hse_util/logging.h>
#include <hse_util/keylock.h>

int
test_collection_pre(struct mtf_test_info *lcl_ti)
{
    hse_openlog("keylock_test", 1);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(keylock_test, test_collection_pre);

MTF_DEFINE_UTEST(keylock_test, keylock_create_destroy)
{
    merr_t          err = 0;
    struct keylock *handle;

    err = keylock_create(65536, 0, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);
    keylock_destroy(handle);

    err = keylock_create(0, 0, &handle);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, handle);
    keylock_destroy(handle);

    err = keylock_create(65537, 0, &handle);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, handle);
    keylock_destroy(handle);

    mapi_inject_once(mapi_idx_malloc, 1, 0);

    err = keylock_create(65536, 0, &handle);
    ASSERT_EQ(0, handle);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    keylock_destroy(handle);
}

MTF_DEFINE_UTEST(keylock_test, keylock_lock_unlock)
{
    const int            table_size = 9973;
    merr_t               err = 0;
    struct keylock *     handle;
    int                  i;
    u64                  hash, num_entries = 0, index;
    u64                  entries[table_size];
    bool                 inherited;
    struct keylock_stats stats;

    srand(time(NULL));

    err = keylock_create(table_size, 0, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);

    for (i = 0; i < 10000; i++) {

        hash = (u64)rand() << 32UL | rand();

        keylock_search(handle, hash, &index);

        err = keylock_lock(handle, hash, 0, 0, &inherited);
        if (!err)
            ASSERT_FALSE(inherited);

        if (num_entries == table_size)
            ASSERT_TRUE(err);

        if (err == 0) {
            /* The insert should succeed only if it was absent. */
            ASSERT_EQ(index, table_size);

            /* Verify that the newly inserted hash is found. */
            keylock_search(handle, hash, &index);
            ASSERT_LT(index, table_size);

            ASSERT_LT(num_entries, table_size);
            entries[num_entries] = hash;
            num_entries++;
        } else {
            ASSERT_TRUE((index < table_size) || (num_entries == table_size));
        }
    }

    for (i = 0; i < num_entries; i++) {
        /* The same locker sees that the locks are already held. */
        err = keylock_lock(handle, entries[i], 0, 0, &inherited);
        ASSERT_EQ(err, 0);

        /* Verify that another locking thread sees collisions. */
        err = keylock_lock(handle, entries[i], 0, (void *)2, &inherited);
        ASSERT_EQ(ECANCELED, merr_errno(err));

        keylock_unlock(handle, entries[i], 0);
        keylock_search(handle, entries[i], &index);
        ASSERT_EQ(index, table_size);

        err = keylock_lock(handle, entries[i], 0, 0, &inherited);
        ASSERT_EQ(err, 0);
        ASSERT_FALSE(inherited);

        keylock_search(handle, entries[i], &index);
        ASSERT_LT(index, table_size);
    }

    keylock_query_stats(handle, &stats);

    for (i = 0; i < num_entries; i++)
        keylock_unlock(handle, entries[i], 0);

    keylock_destroy(handle);
}

struct keylock_cb_rock *g_rock1;
struct keylock_cb_rock *g_rock2;
u64                     g_start_seq;

bool
rock_handling(u64 start_seq, struct keylock_cb_rock *old_rock, struct keylock_cb_rock **new_rock)
{
    g_rock1 = *new_rock;
    g_rock2 = old_rock;
    g_start_seq = start_seq;

    return ((start_seq % 2) == 0);
}

MTF_DEFINE_UTEST(keylock_test, keylock_rock_handling)
{
    const int       table_size = 100;
    merr_t          err = 0;
    struct keylock *handle;
    int             i;
    u64             index;
    uintptr_t       rock;
    bool            inherited;

    err = keylock_create(table_size, rock_handling, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);

    for (i = 0; i < 10; i++) {
        keylock_search(handle, i, &index);
        ASSERT_EQ(index, table_size);

        rock = i + 1UL;
        err = keylock_lock(handle, i, i, (struct keylock_cb_rock *)rock, &inherited);
        ASSERT_EQ(0, err);

        rock = i + 2UL;
        err = keylock_lock(handle, i, i, (struct keylock_cb_rock *)rock, &inherited);
        if ((i % 2) == 0)
            ASSERT_EQ(0, err);
        else
            ASSERT_NE(0, err);

        ASSERT_EQ(i, g_start_seq);
        ASSERT_EQ(i + 2UL, (u64)g_rock1);
        ASSERT_EQ(i + 1UL, (u64)g_rock2);
    }

    keylock_destroy(handle);
}

/* This unit test tests that the default lock inheritance/transfer
 * function does not permit lock transference.
 */
MTF_DEFINE_UTEST(keylock_test, keylock_rock_default)
{
    const int       table_size = 100;
    struct keylock *handle;
    bool            inherited;
    u64             index;
    merr_t          err;
    int             i;

    err = keylock_create(table_size, NULL, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);

    for (i = 0; i < 10; i++) {
        uintptr_t rock = i;

        keylock_search(handle, i, &index);
        ASSERT_EQ(index, table_size);

        err = keylock_lock(handle, i, i, (struct keylock_cb_rock *)rock, &inherited);
        ASSERT_EQ(0, err);
        ASSERT_FALSE(inherited);

        err = keylock_lock(handle, i, i, (struct keylock_cb_rock *)(rock + 1), &inherited);
        ASSERT_NE(0, err);
        ASSERT_FALSE(inherited);
    }

    keylock_destroy(handle);
}

MTF_END_UTEST_COLLECTION(keylock_test)
