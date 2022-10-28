/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse/util/xrand.h>

#include <kvdb/kvdb_pfxlock.h>
#include <kvdb/viewset.h>

#include <hse_ikvdb/key_hash.h>

volatile u64 g_txn_horizon;

u64
_viewset_horizon(struct viewset *handle)
{
    return g_txn_horizon;
}

struct kvdb_pfxlock *kpl;

void
kvdb_pfxlock_prune(struct kvdb_pfxlock *pfx_lock);

int
mapi_pre(struct mtf_test_info *lcl_ti)
{
    merr_t err;

    g_txn_horizon = 0;
    MOCK_SET(viewset, _viewset_horizon);

    err = kvdb_pfxlock_create((void *)-1, &kpl);
    ASSERT_EQ_RET(0, err, -1);
    return 0;
}

int
mapi_post(struct mtf_test_info *lcl_ti)
{
    kvdb_pfxlock_destroy(kpl);
    kpl = NULL;
    MOCK_UNSET(viewset, _viewset_horizon);
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(kvdb_pfxlock_test)

MTF_DEFINE_UTEST_PREPOST(kvdb_pfxlock_test, basic, mapi_pre, mapi_post)
{
    const u64 hash = xrand64_tls();
    merr_t    err;
    void *    lock;

    err = kvdb_pfxlock_shared(kpl, hash, 1, &lock); /* put */
    ASSERT_EQ(0, err);
    err = kvdb_pfxlock_shared(kpl, hash, 2, &lock); /* put */
    ASSERT_EQ(0, err);

    err = kvdb_pfxlock_excl(kpl, hash, 3, &lock); /* pdel */
    ASSERT_EQ(ECANCELED, merr_errno(err));

    err = kvdb_pfxlock_shared(kpl, hash, 4, &lock); /* put */
    ASSERT_EQ(0, err);
    err = kvdb_pfxlock_shared(kpl, hash, 2, &lock); /* put */
    ASSERT_EQ(0, err);

    /* Commit at seqno 10 */
    kvdb_pfxlock_seqno_pub(kpl, 10, lock);
    err = kvdb_pfxlock_shared(kpl, hash, 2, &lock); /* put */
    ASSERT_EQ(0, err);
    err = kvdb_pfxlock_shared(kpl, hash, 11, &lock); /* put */
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_pfxlock_test, ptomb_before_put, mapi_pre, mapi_post)
{
    const u64 hash = xrand64_tls();
    merr_t    err;
    void *    lock = NULL;
    void *    lock2;

    g_txn_horizon = 0;
    err = kvdb_pfxlock_excl(kpl, hash, 3, &lock); /* pdel */
    ASSERT_EQ(0, err);

    lock2 = lock;
    err = kvdb_pfxlock_excl(kpl, hash, 3, &lock2); /* pdel, reacquire excl lock */
    ASSERT_EQ(0, err);
    ASSERT_EQ(lock2, lock);

    lock2 = NULL;
    err = kvdb_pfxlock_excl(kpl, hash, 4, &lock2);
    ASSERT_EQ(ECANCELED, merr_errno(err));

    err = kvdb_pfxlock_shared(kpl, hash, 4, &lock); /* put */
    ASSERT_EQ(ECANCELED, merr_errno(err));
    err = kvdb_pfxlock_shared(kpl, hash, 2, &lock); /* put */
    ASSERT_EQ(ECANCELED, merr_errno(err));

    /* Commit at seqno 10 */
    kvdb_pfxlock_seqno_pub(kpl, 10, lock);

    err = kvdb_pfxlock_shared(kpl, hash, 2, &lock); /* put */
    ASSERT_EQ(ECANCELED, merr_errno(err));

    err = kvdb_pfxlock_shared(kpl, hash, 11, &lock); /* put */
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_pfxlock_test, ptomb_after_put, mapi_pre, mapi_post)
{
    const u64 hash = xrand64_tls();
    merr_t    err;
    void *    lock1 = NULL;
    void *    lock2 = NULL;

    g_txn_horizon = 0;
    err = kvdb_pfxlock_shared(kpl, hash, 1, &lock1); /* put 1 */
    ASSERT_EQ(0, err);

    err = kvdb_pfxlock_shared(kpl, hash, 2, &lock2); /* put 2 */
    ASSERT_EQ(0, err);

    kvdb_pfxlock_seqno_pub(kpl, 3, lock1); /* commit put 1 */

    err = kvdb_pfxlock_excl(kpl, hash, 2, &lock2); /* pdel 2 */
    ASSERT_EQ(ECANCELED, merr_errno(err));

    err = kvdb_pfxlock_excl(kpl, hash, 4, &lock2); /* pdel 4 */
    ASSERT_EQ(0, err);

    kvdb_pfxlock_seqno_pub(kpl, 5, lock2);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_pfxlock_test, long_txn, mapi_pre, mapi_post)
{
    const u64 hash = xrand64_tls();
    merr_t    err;
    void *    lockv[32] = { NULL };

    g_txn_horizon = 0;
    err = kvdb_pfxlock_excl(kpl, hash, 100, &lockv[0]); /* pdel */
    ASSERT_EQ(0, err);

    kvdb_pfxlock_seqno_pub(kpl, 110, lockv[0]); /* Commit at seqno 110 */
    g_txn_horizon = 110;

    err = kvdb_pfxlock_shared(kpl, hash, 200, &lockv[0]); /* put by txn with view_seq = 200 */
    ASSERT_EQ(0, err);

    kvdb_pfxlock_prune(kpl); /* This should remove entries older than seqno=110 (horizon) */
    kvdb_pfxlock_prune(kpl); /* Must call twice */

    err = kvdb_pfxlock_shared(kpl, hash, 201, &lockv[1]);
    ASSERT_EQ(0, err);

    err = kvdb_pfxlock_excl(kpl, hash, 201, &lockv[2]);
    ASSERT_EQ(ECANCELED, merr_errno(err));

    g_txn_horizon = 200;
    kvdb_pfxlock_prune(kpl); /* This will clear out the entry from the rbtree */
    kvdb_pfxlock_prune(kpl); /* Must call twice */

    err = kvdb_pfxlock_excl(kpl, hash, 501, &lockv[3]);
    ASSERT_EQ(ECANCELED, merr_errno(err));

    /* Commit all entries */
    kvdb_pfxlock_seqno_pub(kpl, 502, lockv[0]);
    kvdb_pfxlock_seqno_pub(kpl, 502, lockv[1]);

    err = kvdb_pfxlock_excl(kpl, hash, 503, &lockv[3]);
    ASSERT_EQ(0, err);

    kvdb_pfxlock_seqno_pub(kpl, 504, lockv[3]);
}

MTF_END_UTEST_COLLECTION(kvdb_pfxlock_test);
