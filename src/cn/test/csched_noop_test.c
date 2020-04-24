/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>
#include <hse_test_support/mapi_alloc_tester.h>

#include <hse_util/hse_err.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvdb_health.h>

#include "../csched_ops.h"
#include "../csched_noop.h"
#include "../cn_metrics.h"

struct kvdb_rparams *rp, rparams;
const char *         mp;
const char *         db;
struct kvdb_health   health;

int
pre_collection(struct mtf_test_info *info)
{
    return 0;
}

static void
reset_rparams(void)
{
    rparams = kvdb_rparams_defaults();
    rp = &rparams;
}

static int
pre_test(struct mtf_test_info *ti)
{
    mp = "fred_flintstone";
    db = "great_gazoo";
    reset_rparams();
    return 0;
}

void
t_job(struct sts_job *job)
{
}

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

MTF_DEFINE_UTEST_PRE(test, t_sp_noop, pre_test)
{
    struct cn_tree *   tree = (void *)1;
    struct csched_ops *ops;
    merr_t             err;

    err = sp_noop_create(rp, mp, &health, &ops);
    ASSERT_EQ(err, 0);

    ops->cs_tree_add(ops, tree);
    ops->cs_notify_ingest(ops, tree, 1234, 1234);
    ops->cs_tree_remove(ops, tree, true);

    ops->cs_destroy(0);

    ops->cs_destroy(ops);
}

MTF_END_UTEST_COLLECTION(test);
