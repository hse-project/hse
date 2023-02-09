/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#define MTF_MOCK_IMPL_csched

#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/csched.h>
#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/sched_sts.h>
#include <hse/util/platform.h>

#include "csched_sp3.h"

merr_t
csched_create(
    struct kvdb_rparams *rp,
    const char *kvdb_alias,
    struct kvdb_health *health,
    struct csched **handle)
{
    assert(rp && kvdb_alias && handle);

    return sp3_create(rp, kvdb_alias, health, handle);
}

void
csched_destroy(struct csched *handle)
{
    sp3_destroy(handle);
}

void
csched_notify_ingest(
    struct csched *handle,
    struct cn_tree *tree,
    size_t alen,
    size_t kwlen,
    size_t vwlen)
{
    sp3_notify_ingest(handle, tree, alen, kwlen, vwlen);
}

void
csched_tree_add(struct csched *handle, struct cn_tree *tree)
{
    sp3_tree_add(handle, tree);
}

void
csched_tree_remove(struct csched *handle, struct cn_tree *tree, bool cancel)
{
    sp3_tree_remove(handle, tree, cancel);
}

void
csched_throttle_sensor(struct csched *handle, struct throttle_sensor *sensor)
{
    sp3_throttle_sensor(handle, sensor);
}

void
csched_compact_request(struct csched *handle, unsigned int flags)
{
    sp3_compact_request(handle, flags);
}

void
csched_compact_status_get(struct csched *handle, struct hse_kvdb_compact_status *status)
{
    sp3_compact_status_get(handle, status);
}

#if HSE_MOCKING
#include "csched_ut_impl.i"
#endif /* HSE_MOCKING */
