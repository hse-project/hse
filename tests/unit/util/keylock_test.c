/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/hse_err.h>
#include <hse_util/xrand.h>
#include <hse_util/logging.h>
#include <hse_util/keylock.h>

int
test_collection_pre(struct mtf_test_info *lcl_ti)
{
    hse_openlog("keylock_test", 1);
    mapi_inject_clear();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(keylock_test, test_collection_pre);

MTF_DEFINE_UTEST(keylock_test, keylock_create_destroy)
{
    merr_t          err = 0;
    struct keylock *handle;

    err = keylock_create(0, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);
    keylock_destroy(handle);

    err = keylock_create(0, &handle);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, handle);
    keylock_destroy(handle);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);

    err = keylock_create(0, &handle);
    ASSERT_EQ(0, handle);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    keylock_destroy(handle);
}

MTF_DEFINE_UTEST(keylock_test, keylock_lock_unlock)
{
    uint                 table_size = KLE_PSL_MAX;
    merr_t               err = 0;
    struct keylock *     handle;
    int                  i;
    uint                 index;
    u64                  hash, num_entries = 0;
    u64                  entries[table_size * 2];
    bool                 inherited;

    err = keylock_create(0, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);

    keylock_search(handle, 0, &table_size);

    for (i = 0; i < table_size + 100; i++) {

        hash = xrand64_tls();

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
            /* load factor should be at least .90 */
            ASSERT_TRUE((index < table_size) || (num_entries >= table_size * 90 / 100));
        }
    }

    for (i = 0; i < num_entries; i++) {
        /* The same locker sees that the locks are already held. */
        err = keylock_lock(handle, entries[i], 0, 0, &inherited);
        ASSERT_EQ(err, 0);

        /* Verify that another locking thread sees collisions. */
        err = keylock_lock(handle, entries[i], 0, 2, &inherited);
        ASSERT_EQ(ECANCELED, merr_errno(err));

        keylock_unlock(handle, entries[i], 0);
        keylock_search(handle, entries[i], &index);
        ASSERT_EQ(index, table_size);

        err = keylock_lock(handle, entries[i], 0, 0, &inherited);
        if (err) {
        } else {
            ASSERT_FALSE(inherited);

            keylock_search(handle, entries[i], &index);
            ASSERT_LT(index, table_size);
        }
    }

    for (i = 0; i < num_entries; i++)
        keylock_unlock(handle, entries[i], 0);

    keylock_destroy(handle);
}

MTF_DEFINE_UTEST(keylock_test, keylock_psl)
{
    struct keylock *handle;
    uint            table_size;
    bool            inherited;
    int             i;
    u64             hash;
    merr_t          err;

    err = keylock_create(NULL, &handle);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, handle);

    keylock_search(handle, 0, &table_size);

    /* Each hash should hash to the same bucket in the keylock table,
     * thereby triggering a whole lot of entry relocations and pushing
     * the probe sequence length to the max.
     */
    for (i = 0; i < table_size + 1; i++) {
        hash = i * table_size;

        err = keylock_lock(handle, hash, 0, 1, &inherited);
        if (err) {
            ASSERT_EQ(i, table_size);
            break;
        }

        ASSERT_EQ(0, err);
        ASSERT_FALSE(inherited);

        err = keylock_lock(handle, hash, 0, 0, &inherited);
        ASSERT_EQ(ECANCELED, merr_errno(err));
        ASSERT_FALSE(inherited);
    }

    for (i = 0; i < table_size; i++) {
        hash = i * table_size;

        keylock_unlock(handle, hash, 0);
        keylock_unlock(handle, hash, 1);
    }

    keylock_destroy(handle);
}

uint g_rock1;
uint g_rock2;
u64  g_start_seq;

bool
rock_handling(u64 start_seq, uint old_rock, uint *new_rock)
{
    g_rock1 = *new_rock;
    g_rock2 = old_rock;
    g_start_seq = start_seq;

    return ((start_seq % 2) == 0);
}

MTF_DEFINE_UTEST(keylock_test, keylock_rock_handling)
{
    uint            table_size;
    merr_t          err = 0;
    struct keylock *handle;
    int             i;
    uint            index;
    uintptr_t       rock;
    bool            inherited;

    err = keylock_create(rock_handling, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);

    keylock_search(handle, 0, &table_size);

    for (i = 0; i < 10; i++) {
        keylock_search(handle, i, &index);
        ASSERT_EQ(index, table_size);

        rock = i + 1UL;
        err = keylock_lock(handle, i, i, rock, &inherited);
        ASSERT_EQ(0, err);

        rock = i + 2UL;
        err = keylock_lock(handle, i, i, rock, &inherited);
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
    uint            table_size;
    struct keylock *handle;
    bool            inherited;
    uint            index;
    merr_t          err;
    int             i;

    err = keylock_create(NULL, &handle);
    ASSERT_TRUE(handle);
    ASSERT_FALSE(err);

    keylock_search(handle, 0, &table_size);

    for (i = 0; i < 10; i++) {
        uintptr_t rock = i;

        keylock_search(handle, i, &index);
        ASSERT_EQ(index, table_size);

        err = keylock_lock(handle, i, i, rock, &inherited);
        ASSERT_EQ(0, err);
        ASSERT_FALSE(inherited);

        err = keylock_lock(handle, i, i, (rock + 1), &inherited);
        ASSERT_NE(0, err);
        ASSERT_FALSE(inherited);
    }

    keylock_destroy(handle);
}

MTF_END_UTEST_COLLECTION(keylock_test)
