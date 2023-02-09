/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/ikvdb/key_hash.h>
#include <hse/util/xrand.h>

#include <hse/test/mock/api.h>
#include <hse/test/mtf/framework.h>

#include "kvdb/kvdb_ctxn_pfxlock.h"
#include "kvdb/viewset.h"

volatile uint64_t g_txn_horizon;

uint64_t
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

MTF_BEGIN_UTEST_COLLECTION(kvdb_ctxn_pfxlock_test)

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_pfxlock_test, basic, mapi_pre, mapi_post)
{
    const uint64_t hash = 0;
    merr_t err;

    struct kvdb_ctxn_pfxlock *txn1, *txn2, *txn3;

    /* Begin txns */
    err = kvdb_ctxn_pfxlock_create(kpl, 10, &txn1);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_create(kpl, 10, &txn2);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_create(kpl, 10, &txn3);
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

/* This test attempts to exhaust the emddeded entry caches of both
 * kvdb_pfxlock and kvdb_ctxn_pfxlock.
 */
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_pfxlock_test, prefix_party, mapi_pre, mapi_post)
{
    uint64_t view = (xrand64_tls() % 1024) + 100;
    const uint64_t hash = xrand64_tls();
    struct kvdb_ctxn_pfxlock *txn;
    merr_t err;
    int i, j;

    for (i = 0; i < 5; ++i) {
        err = kvdb_ctxn_pfxlock_create(kpl, ++view, &txn);
        ASSERT_EQ(0, err);

        for (j = 0; j < 50000; ++j) {
            if (xrand64_tls() < UINT64_MAX / 2)
                err = kvdb_ctxn_pfxlock_shared(txn, hash + j);
            else
                err = kvdb_ctxn_pfxlock_excl(txn, hash + j);

            ASSERT_EQ(0, err);
        }

        kvdb_ctxn_pfxlock_seqno_pub(txn, ++view);
        g_txn_horizon = view;

        kvdb_ctxn_pfxlock_destroy(txn);
    }
}

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_pfxlock_test, write_conflict, mapi_pre, mapi_post)
{
    const uint64_t hash = 1;
    merr_t err;

    struct kvdb_ctxn_pfxlock *txn1, *txn2;

    /* Begin txns */
    err = kvdb_ctxn_pfxlock_create(kpl, 10, &txn1);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_create(kpl, 10, &txn2);
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

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_pfxlock_test, excl_inheritance, mapi_pre, mapi_post)
{
    const uint64_t hash = 1;
    merr_t err;

    struct kvdb_ctxn_pfxlock *txn1, *txn2, *txn3, *txn4;

    /* Begin txn1 */
    g_txn_horizon = 10;
    err = kvdb_ctxn_pfxlock_create(kpl, 10, &txn1);
    ASSERT_EQ(0, err);

    /* Begin txn2 */
    err = kvdb_ctxn_pfxlock_create(kpl, 20, &txn2);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_excl(txn2, hash);
    ASSERT_EQ(0, err);

    kvdb_ctxn_pfxlock_seqno_pub(txn2, 30); /* Commit w/ seqno=30 */

    /* Begin txn3 */
    err = kvdb_ctxn_pfxlock_create(kpl, 40, &txn3);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_shared(txn3, hash);
    ASSERT_EQ(0, err);

    kvdb_ctxn_pfxlock_seqno_pub(txn3, 50); /* Commit w/ seqno=50 */

    /* The old txn shouldn't pass because it was created before the excl lock was unlocked */
    err = kvdb_ctxn_pfxlock_shared(txn1, hash);
    ASSERT_EQ(ECANCELED, merr_errno(err));

    err = kvdb_ctxn_pfxlock_create(kpl, 60, &txn4);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_pfxlock_excl(txn4, hash);
    ASSERT_EQ(0, err);

    kvdb_ctxn_pfxlock_destroy(txn1);
    kvdb_ctxn_pfxlock_destroy(txn2);
    kvdb_ctxn_pfxlock_destroy(txn3);
    kvdb_ctxn_pfxlock_destroy(txn4);
}

MTF_END_UTEST_COLLECTION(kvdb_ctxn_pfxlock_test);
