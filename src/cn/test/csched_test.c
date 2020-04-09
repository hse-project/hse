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
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/ikvdb.h>

#include "../csched_ops.h"
#include "../csched_noop.h"
#include "../csched_sp3.h"
#include "../cn_metrics.h"

struct kvdb_rparams *rp, rparams;
const char *         mp;

int    set_debug_rparam;
merr_t mocked_sp_create_rc;

struct throttle_sensor;

enum csched_policy policy_list[] = { csched_policy_old, csched_policy_noop, csched_policy_sp3 };

static void
mocked_sp_destroy(struct csched_ops *handle)
{
    mapi_safe_free(handle);
}

static void
mocked_sp_notify_ingest(struct csched_ops *handle, struct cn_tree *tree, size_t size, size_t dunno)
{
}

static void
mocked_sp_tree_add(struct csched_ops *handle, struct cn_tree *tree)
{
}

static void
mocked_sp_tree_remove(struct csched_ops *handle, struct cn_tree *tree, bool cancel)
{
}

static struct tbkt *
mocked_sp_tbkt_maint_get(struct csched_ops *handle)
{
    return 0;
}

static void
mocked_sp_throttle_sensor(struct csched_ops *handle, struct throttle_sensor *ts)
{
}

static void
mocked_sp_compact_request(struct csched_ops *handle, int flags)
{
}

static void
mocked_sp_compact_status(struct csched_ops *handle, struct hse_kvdb_compact_status *status)
{
}

static merr_t
mocked_sp_create2(struct kvdb_rparams *rp, const char *mp, struct csched_ops **handle)
{
    struct csched_ops *self;

    if (mocked_sp_create_rc)
        return mocked_sp_create_rc;

    assert(handle);

    self = mapi_safe_malloc(sizeof(*self));
    if (!self)
        return merr(EBUG);

    memset(self, 0, sizeof(*self));

    self->cs_destroy = mocked_sp_destroy;

    *handle = self;
    return 0;
}

static merr_t
mocked_sp_create(struct kvdb_rparams *rp, const char *mp, struct csched_ops **handle)
{
    merr_t err;

    err = mocked_sp_create2(rp, mp, handle);

    if (!err) {
        (*handle)->cs_destroy = mocked_sp_destroy;
        (*handle)->cs_notify_ingest = mocked_sp_notify_ingest;
        (*handle)->cs_tree_add = mocked_sp_tree_add;
        (*handle)->cs_tree_remove = mocked_sp_tree_remove;
        (*handle)->cs_tbkt_maint_get = mocked_sp_tbkt_maint_get;
        (*handle)->cs_throttle_sensor = mocked_sp_throttle_sensor;
        (*handle)->cs_compact_request = mocked_sp_compact_request;
        (*handle)->cs_compact_status = mocked_sp_compact_status;
    }

    return err;
}

static merr_t
mocked_sp3_create(
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         mp,
    struct csched_ops ** handle)
{
    merr_t err;

    err = mocked_sp_create(rp, mp, handle);

    return err;
}

static int
pre_collection(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *tci = info->ti_coll;
    int                        i;

    hse_log_set_verbose(true);
    hse_log_set_pri(HSE_DEBUG_VAL);

    /* To get max branch coverage, run once with
     * debug and once without.
     */
    for (i = 1; i < tci->tci_argc; i++) {
        if (!strcmp("debug", tci->tci_argv[i]))
            set_debug_rparam = 1;
    }

    return 0;
}

static void
reset_rparams(void)
{
    rparams = kvdb_rparams_defaults();
    rp = &rparams;
    if (set_debug_rparam)
        rp->csched_debug_mask = U64_MAX;
}

static int
pre_test(struct mtf_test_info *ti)
{
    mapi_inject(mapi_idx_sts_create, 0);
    mapi_inject(mapi_idx_sts_destroy, 0);
    mapi_inject(mapi_idx_sts_resume, 0);

    MOCK_SET_FN(csched_noop, sp_noop_create, mocked_sp_create);
    MOCK_SET_FN(csched_sp3, sp3_create, mocked_sp3_create);

    mp = "fred_flintstone";
    mocked_sp_create_rc = 0;
    reset_rparams();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

MTF_DEFINE_UTEST_PRE(test, t_csched_create, pre_test)
{
    struct csched *cs;
    merr_t         err;
    uint           i;

    for (i = 0; i < NELEM(policy_list); i++) {
        cs = (void *)0;
        err = csched_create(policy_list[i], NULL, rp, mp, &cs);
        ASSERT_EQ(err, 0);
        csched_destroy(cs);
    }

    /* invalid policy */
    cs = (void *)0;
    err = csched_create(12345, NULL, rp, mp, &cs);
    ASSERT_NE(err, 0);

    /* error paths */
    mocked_sp_create_rc = 1;

    for (i = 0; i < NELEM(policy_list); i++) {
        cs = (void *)0;
        err = csched_create(policy_list[i], NULL, rp, mp, &cs);
        /* mocked_sp_create_rc doesn't apply to csched_policy_old */
        if (policy_list[i] == csched_policy_old) {
            ASSERT_EQ(err, 0);
            csched_destroy(cs);
        } else {
            ASSERT_EQ(err, 1);
        }
    }
}

MTF_DEFINE_UTEST_PRE(test, t_csched_create_nomem, pre_test)
{
    struct csched *cs;
    merr_t         err;
    int            rc;

    void run(struct mtf_test_info * lcl_ti, uint i, uint j)
    {
        err = csched_create(0, NULL, rp, mp, &cs);
        if (i == j)
            ASSERT_EQ(err, 0);
        else
            ASSERT_EQ(merr_errno(err), ENOMEM);
    }

    void clean(struct mtf_test_info * lcl_ti)
    {
        /* Note: parent function local vars are preserved from
         * previous call to run().
         */
        if (!err)
            csched_destroy(cs);
    }

    rc = mapi_alloc_tester(lcl_ti, run, clean);
    ASSERT_EQ(rc, 0);
}

MTF_DEFINE_UTEST_PRE(test, t_csched_methods, pre_test)
{
    struct csched *    cs;
    enum csched_policy pol;
    merr_t             err;
    struct cn_tree *   tree = (void *)1;

    /* we can mock any policy, choose csched_policy_noop */
    pol = csched_policy_noop;
    mapi_inject_unset(mapi_idx_sp_noop_create);

    MOCK_SET_FN(csched_noop, sp_noop_create, mocked_sp_create);

    cs = (void *)0;
    err = csched_create(pol, NULL, rp, mp, &cs);
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(cs != NULL);

    int                            flags = 0;
    struct hse_kvdb_compact_status status;

    csched_tree_add(cs, tree);
    csched_throttle_sensor(cs, 0);
    csched_compact_request(cs, flags);
    csched_compact_status(cs, &status);
    csched_tbkt_maint_get(cs);
    csched_notify_ingest(cs, tree, 1234, 1234);
    csched_tree_remove(cs, tree, true);

    csched_destroy(cs);

    /* repeat with mock that has no ops */
    MOCK_SET_FN(csched_noop, sp_noop_create, mocked_sp_create2);

    cs = (void *)0;
    err = csched_create(pol, NULL, rp, mp, &cs);
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(cs != NULL);

    csched_tree_add(cs, tree);
    csched_throttle_sensor(cs, 0);
    csched_compact_request(cs, flags);
    csched_compact_status(cs, &status);
    csched_tbkt_maint_get(cs);
    csched_notify_ingest(cs, tree, 1234, 1234);
    csched_tree_remove(cs, tree, true);

    csched_destroy(cs);

    /* check w/ null ptr */
    cs = 0;
    csched_tree_add(cs, tree);
    csched_throttle_sensor(cs, 0);
    csched_tbkt_maint_get(cs);
    csched_notify_ingest(cs, tree, 1234, 1234);
    csched_tree_remove(cs, tree, true);
}

MTF_END_UTEST_COLLECTION(test);
