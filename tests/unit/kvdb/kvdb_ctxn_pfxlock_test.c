/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <kvdb/kvdb_ctxn_pfxlock.h>
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

    err = kvdb_pfxlock_create(&kpl, (void *)-1);
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

MTF_BEGIN_UTEST_COLLECTION(kvdb_ctxn_pfxlock_test)

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_pfxlock_test, basic, mapi_pre, mapi_post)
{
    const u64 hash = 0;
    merr_t    err;

    struct kvdb_ctxn_pfxlock *txn1, *txn2, *txn3;

    /* Begin txns */
    err = kvdb_ctxn_pfxlock_create(&txn1, kpl, 10);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_create(&txn2, kpl, 10);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_create(&txn3, kpl, 10);
    ASSERT_EQ(0, err);

    /* Put */
    err = kvdb_ctxn_pfxlock_shared(txn1, hash);
    ASSERT_EQ(0, err);

    /* Pdel: Conflict with txn1's put */
    err = kvdb_ctxn_pfxlock_excl(txn2, hash);
    ASSERT_EQ(ECANCELED, merr_errno(err));

    /* Put should work */
    err = kvdb_ctxn_pfxlock_shared(txn3, hash);
    ASSERT_EQ(0, err);

    kvdb_ctxn_pfxlock_seqno_pub(txn1, 30); /* Commit w/ seqno=30 */
    kvdb_ctxn_pfxlock_seqno_pub(txn2, 32); /* Commit w/ seqno=32 */

    kvdb_ctxn_pfxlock_destroy(txn1);
    kvdb_ctxn_pfxlock_destroy(txn2);
    kvdb_ctxn_pfxlock_destroy(txn3);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_pfxlock_test, write_conflict, mapi_pre, mapi_post)
{
    const u64 hash = 1;
    merr_t    err;

    struct kvdb_ctxn_pfxlock *txn1, *txn2;

    /* Begin txns */
    err = kvdb_ctxn_pfxlock_create(&txn1, kpl, 10);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_create(&txn2, kpl, 10);
    ASSERT_EQ(0, err);

    /* Put */
    err = kvdb_ctxn_pfxlock_shared(txn1, hash);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_excl(txn2, hash);
    ASSERT_EQ(ECANCELED, merr_errno(err));

    err = kvdb_ctxn_pfxlock_excl(txn1, hash);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_shared(txn2, hash);
    ASSERT_EQ(ECANCELED, merr_errno(err));

    err = kvdb_ctxn_pfxlock_shared(txn1, hash);
    ASSERT_EQ(0, err);

    kvdb_ctxn_pfxlock_seqno_pub(txn1, 30); /* Commit w/ seqno=30 */
    kvdb_ctxn_pfxlock_seqno_pub(txn2, 32); /* Commit w/ seqno=32 */

    kvdb_ctxn_pfxlock_destroy(txn1);
    kvdb_ctxn_pfxlock_destroy(txn2);
}
MTF_END_UTEST_COLLECTION(kvdb_ctxn_pfxlock_test);
