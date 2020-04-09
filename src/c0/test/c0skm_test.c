/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/seqno.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvb_builder.h>
#include <hse_ikvdb/kvdb_health.h>

#include <hse_test_support/key_generation.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/csched.h>
#include <hse_test_support/random_buffer.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0skm.h>

#include "../../c0/c0sk_internal.h"
#include "../../c0/c0_kvmsm.h"
#include "../../c0/c0_kvmsm_internal.h"
#include "../../c0/c0_ingest_work.h"
#include "../../c0/c0skm_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <hse_ikvdb/throttle.h>

static int
test_collection_setup(struct mtf_test_info *info)
{
    return 0;
}

static int
test_collection_teardown(struct mtf_test_info *info)
{
    return 0;
}

static int
test_pre(struct mtf_test_info *info)
{
    return 0;
}

static int
test_post(struct mtf_test_info *info)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(c0skm_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST_PREPOST(c0skm_test, misc, test_pre, test_post)
{
    c0skm_sync(NULL);
    c0skm_flush(NULL);
    c0skm_get_cnid(NULL, 1);
}

MTF_END_UTEST_COLLECTION(c0skm_test)
