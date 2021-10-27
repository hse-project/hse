/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_csched_noop

#include <hse_util/platform.h>
#include <hse_util/slab.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/sched_sts.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "csched_ops.h"
#include "csched_noop.h"

#include "cn_tree_compact.h"
#include "cn_tree_internal.h"
#include "kvset.h"

struct csched_noop {
    struct csched_ops ops;
};

#define h2r(_hdl) container_of(_hdl, struct csched_noop, ops)

/* Public API (via csched_ops) */
static void
noop_destroy(struct csched_ops *handle)
{
    struct csched_noop *self = h2r(handle);

    if (ev(!handle))
        return;

    free(self);
}

static void
noop_nofity_ingest(struct csched_ops *handle, struct cn_tree *tree, size_t alen, size_t wlen)
{
}

/* Public API (via csched_ops) */
static void
noop_tree_add(struct csched_ops *handle, struct cn_tree *tree)
{
}

/* Public API (via csched_ops) */
static void
noop_tree_remove(struct csched_ops *handle, struct cn_tree *tree, bool cancel)
{
}

/* Public API */
merr_t
sp_noop_create(
    struct kvdb_rparams *rp,
    const char *         mp,
    struct kvdb_health * health,
    struct csched_ops ** handle)
{
    struct csched_noop *self;

    assert(handle);

    log_info("NOOP compaction scheduler");

    self = calloc(1, sizeof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    self->ops.cs_destroy = noop_destroy;
    self->ops.cs_notify_ingest = noop_nofity_ingest;
    self->ops.cs_tree_add = noop_tree_add;
    self->ops.cs_tree_remove = noop_tree_remove;

    *handle = &self->ops;
    return 0;
}

#if HSE_MOCKING
#include "csched_noop_ut_impl.i"
#endif /* HSE_MOCKING */
