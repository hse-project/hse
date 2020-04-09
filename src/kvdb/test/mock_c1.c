/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/conditions.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/keycmp.h>
#include <hse_util/table.h>
#include <hse_ikvdb/c0skm.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_health.h>

#include "../kvdb/kvdb_log.h"
#include "../../cn/test/mock_kvset_builder.h"

#include <stdlib.h>

merr_t
_c1_alloc(struct mpool *ds, struct kvdb_cparams *cparams, u64 *oid1out, u64 *oid2out)
{
    return 0;
}

merr_t
_c1_make(struct mpool *ds, struct kvdb_cparams *cparams, u64 oid1, u64 oid2)
{
    return 0;
}

merr_t
_c1_free(struct mpool *ds, u64 oid1, u64 oid2)
{
    return 0;
}

merr_t
_c1_open(
    struct mpool *       ds,
    int                  rdonly,
    u64                  oid1,
    u64                  oid2,
    u64                  kvmsgen,
    const char *         mpname,
    struct kvdb_rparams *rparams,
    struct ikvdb *       ikvdb,
    struct c0sk *        c0sk,
    struct c1 **         out)
{
    *out = NULL;
    return 0;
}

merr_t
_c1_close(struct c1 *c1)
{
    return 0;
}

struct kvb_builder_iter;
struct c1;

merr_t
_c1_ingest(struct c1 *c1, struct kvb_builder_iter *iter, u64 size, int ingestflag)
{
    return 0;
}

merr_t
_c1_txn_begin(struct c1 *c1, u64 txnid, u64 size, int flag)
{
    return 0;
}

merr_t
_c1_txn_commit(struct c1 *c1, u64 txnid, u64 seqno, int flag)
{
    return 0;
}

merr_t
_c1_txn_abort(struct c1 *c1, u64 txnid)
{
    return 0;
}

merr_t
_c1_sync(struct c1 *c1)
{
    return 0;
}

merr_t
_c1_flush(struct c1 *c1)
{
    return 0;
}

merr_t
_c1_ingest_stripsize(struct c1 *c1)
{
    return 0;
}

void
mock_c1_set(void)
{
    MOCK_SET(c1, _c1_alloc);
    MOCK_SET(c1, _c1_make);
    MOCK_SET(c1, _c1_free);
    MOCK_SET(c1, _c1_open);
    MOCK_SET(c1, _c1_close);
    MOCK_SET(c1, _c1_ingest);
    MOCK_SET(c1, _c1_sync);
    MOCK_SET(c1, _c1_flush);
    MOCK_SET(c1, _c1_txn_begin);
    MOCK_SET(c1, _c1_txn_abort);
    MOCK_SET(c1, _c1_txn_commit);
}

void
mock_c1_unset(void)
{
    MOCK_UNSET(c1, _c1_alloc);
    MOCK_UNSET(c1, _c1_make);
    MOCK_UNSET(c1, _c1_free);
    MOCK_UNSET(c1, _c1_open);
    MOCK_UNSET(c1, _c1_close);
    MOCK_UNSET(c1, _c1_ingest);
    MOCK_UNSET(c1, _c1_sync);
    MOCK_UNSET(c1, _c1_flush);
    MOCK_UNSET(c1, _c1_txn_begin);
    MOCK_UNSET(c1, _c1_txn_abort);
    MOCK_UNSET(c1, _c1_txn_commit);
}

void
mock_c0skm_set(void)
{
    mapi_inject(mapi_idx_c0skm_sync, 0);
    mapi_inject(mapi_idx_c0skm_open, 0);
    mapi_inject(mapi_idx_c0skm_close, 0);
}

void
mock_c0skm_unset(void)
{
    mapi_inject_unset(mapi_idx_c0skm_sync);
    mapi_inject_unset(mapi_idx_c0skm_open);
    mapi_inject_unset(mapi_idx_c0skm_close);
}

merr_t
_c0skm_sync(struct c0sk *c0sk)
{
    return 0;
}

merr_t
_c0skm_open(struct c0sk *c0sk, struct kvdb_rparams *rp, struct c1 *c1_handle, const char *mpname)
{
    return 0;
}

void
_c0skm_close(struct c0sk *c0sk)
{
}

merr_t
create_mock_c0skm(struct c0sk *c0sk)
{
    MOCK_SET(c0skm, _c0skm_sync);
    MOCK_SET(c0skm, _c0skm_open);
    MOCK_SET(c0skm, _c0skm_close);

    return 0;
}
