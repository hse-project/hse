/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse/hse.h>

#include <hse_util/hse_err.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/seqno.h>
#include <hse_util/keylock.h>

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <pthread.h>

#include <hse_test_support/key_generation.h>
#include <hse_ikvdb/tuple.h>
#include <hse_test_support/random_buffer.h>

#include "../../c0/test/cn_mock.h"

struct mock_kvdb {
    struct c0sk *ikdb_c0sk;
};

void
_ikvdb_get_c0sk(struct ikvdb *kvdb, struct c0sk **out)
{
    struct mock_kvdb *mkvdb = (struct mock_kvdb *)kvdb;

    *out = mkvdb->ikdb_c0sk;
}

int
mapi_pre(struct mtf_test_info *ti)
{
    mock_cn_set();

    return 0;
}

int
mapi_post(struct mtf_test_info *ti)
{
    mock_cn_unset();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(kvdb_cursor_test)

MTF_DEFINE_UTEST_PREPOST(kvdb_cursor_test, alloc, mapi_pre, mapi_post)
{
    struct kvdb_ctxn *handle;

    ASSERT_EQ(0, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    err = hse_kvdb_open(mock_mp, NULL, 0, &state.kvdb);

    handle = kvdb_cursor_alloc(NULL, NULL, NULL);
    ASSERT_NE(0, handle);
    ASSERT_EQ(1, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    kvdb_ctxn_free(handle);
    ASSERT_EQ(1, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(1, mapi_calls(mapi_idx_free));
}

MTF_END_UTEST_COLLECTION(kvdb_cursor_test);
