/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_csched

#include <hse_util/platform.h>

#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cn.h>

#include "csched_ops.h"
#include "csched_noop.h"
#include "csched_sp3.h"

struct tbkt;

merr_t
csched_create(
    enum csched_policy   policy,
    struct mpool *       ds,
    struct kvdb_rparams *rp,
    const char *         mp,
    struct kvdb_health * health,
    struct csched **     handle)
{
    merr_t             err;
    struct csched_ops *cs;

    assert(rp);
    assert(mp);
    assert(handle);

    err = merr(EINVAL);

    switch (policy) {
        case csched_policy_old:
            err = 0;
            cs = 0;
            break;
        case csched_policy_noop:
            err = sp_noop_create(rp, mp, health, &cs);
            break;
        case csched_policy_sp3:
            err = sp3_create(ds, rp, mp, health, &cs);
            break;
    }

    if (!err)
        *handle = (void *)cs;

    return err;
}

void
csched_destroy(struct csched *handle)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_destroy)
        cs->cs_destroy(cs);
}

void
csched_notify_ingest(struct csched *handle, struct cn_tree *tree, size_t alen, size_t wlen)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_notify_ingest)
        cs->cs_notify_ingest(cs, tree, alen, wlen);
}

void
csched_tree_add(struct csched *handle, struct cn_tree *tree)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_tree_add)
        cs->cs_tree_add(cs, tree);
}

void
csched_tree_remove(struct csched *handle, struct cn_tree *tree, bool cancel)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_tree_remove)
        cs->cs_tree_remove(cs, tree, cancel);
}

void
csched_throttle_sensor(struct csched *handle, struct throttle_sensor *sensor)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_throttle_sensor)
        cs->cs_throttle_sensor(cs, sensor);
}

void
csched_compact_request(struct csched *handle, int flags)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_compact_request)
        cs->cs_compact_request(cs, flags);
}

void
csched_compact_status_get(struct csched *handle, struct hse_kvdb_compact_status *status)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_compact_status_get)
        cs->cs_compact_status_get(cs, status);
}

struct tbkt *
csched_tbkt_maint_get(struct csched *handle)
{
    struct csched_ops *cs = (void *)handle;

    if (cs && cs->cs_tbkt_maint_get)
        return cs->cs_tbkt_maint_get(cs);

    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "csched_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
