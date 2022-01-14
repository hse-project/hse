/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse_util/hse_err.h>
#include <hse_util/xrand.h>
#include <hse_util/logging.h>
#include <hse_util/keylock.h>

int
test_collection_pre(struct mtf_test_info *lcl_ti)
{
    mapi_inject_clear();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(keylock_test, test_collection_pre);

MTF_DEFINE_UTEST(keylock_test, keylock_create_destroy)
{
    struct keylock *handle = NULL;
    merr_t err = 0;

    /* [HSE_REVISIT] mapi breaks initialization of handle.
     */
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
    struct keylock *     handle = NULL;
    int                  i;
    uint                 index;
    u64                  hash, num_entries = 0;
    u64                  entries[table_size * 2];
    bool                 inherited;

    /* [HSE_REVISIT] mapi breaks initialization of handle.
     */
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
        err = keylock_lock(handle, entries[i], 2, 0, &inherited);
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

        err = keylock_lock(handle, hash, 1, 0, &inherited);
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

#define  ITERMAX (1000)
uint64_t seqnov[ITERMAX + 1];

bool
keylock_test_inheritable(uint32_t owner, uint64_t start_seq)
{
    return (start_seq > seqnov[owner]);
}

MTF_DEFINE_UTEST(keylock_test, keylock_inheritance)
{
    uint            table_size;
    merr_t          err;
    struct keylock *handle;
    uint            index, i;
    bool            inherited;
    uint64_t        hash;

    hash = xrand64_tls();

    for (i = 0; i < ITERMAX + 1; ++i)
        seqnov[i] = (xrand64_tls() % 1024) + (i * 1024);

    err = keylock_create(keylock_test_inheritable, &handle);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, handle);

    /* Get the size of the empty keylock table.
     */
    keylock_search(handle, hash, &table_size);

    for (i = 0; i < ITERMAX; ++i) {
        uint32_t owner = i;

        keylock_search(handle, hash, &index);
        if (i > 0)
            ASSERT_NE(index, table_size);

        err = keylock_lock(handle, hash, owner, seqnov[owner], &inherited);
        ASSERT_EQ(0, err);
        ASSERT_EQ(false, inherited);

        /* Should be able to re-acquire a lock I hold...
         */
        err = keylock_lock(handle, hash, owner, seqnov[owner], &inherited);
        ASSERT_EQ(0, err);
        ASSERT_EQ(false, inherited);

        /* A different owner should not be able to acquire nor inherit
         * the lock with the same seqno as the lock holder.
         */
        err = keylock_lock(handle, hash, owner + 1, seqnov[owner], &inherited);
        ASSERT_NE(0, err);

        /* New owner should be able to inherit the lock given a higher
         * seqno than the lock holder.
         */
        err = keylock_lock(handle, hash, owner + 1, seqnov[owner + 1], &inherited);
        ASSERT_EQ(0, err);
        ASSERT_EQ(true, inherited);

        /* Old owner should not be able to release nor reacquire the lock.
         */
        keylock_unlock(handle, hash, owner);

        err = keylock_lock(handle, hash, owner, seqnov[owner], &inherited);
        ASSERT_NE(0, err);

        /* Test that new owner still holds the lock...
         */
        err = keylock_lock(handle, hash, owner + 1, seqnov[owner + 1], &inherited);
        ASSERT_EQ(0, err);
        ASSERT_EQ(false, inherited);
    }

    /* Test that most recent owner still holds the lock...
     */
    err = keylock_lock(handle, hash, i, seqnov[i], &inherited);
    ASSERT_EQ(0, err);
    ASSERT_EQ(false, inherited);

    /* Test that most recent owner can unlock the lock, after which there
     * should be no more locks in the table.
     */
    keylock_unlock(handle, hash, i);
    keylock_search(handle, hash, &index);
    ASSERT_EQ(index, table_size);

    keylock_destroy(handle);
}

MTF_END_UTEST_COLLECTION(keylock_test)
