/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_cn_kvdb

#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/atomic.h>
#include <hse/error/merr.h>
#include <hse/util/event_counter.h>

#include <hse_ikvdb/cn_kvdb.h>

merr_t
cn_kvdb_create(uint cn_maint_threads, uint cn_io_threads, struct cn_kvdb **out)
{
    struct cn_kvdb *self;

    self = calloc(1, sizeof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    self->cn_maint_wq = alloc_workqueue("hse_cn_maint", 0, 3, cn_maint_threads);
    if (ev(!self->cn_maint_wq)) {
        free(self);
        return merr(ENOMEM);
    }

    self->cn_io_wq = alloc_workqueue("hse_cn_io", 0, 1, cn_io_threads);
    if (ev(!self->cn_io_wq)) {
        destroy_workqueue(self->cn_maint_wq);
        free(self);
        return merr(ENOMEM);
    }

    *out = self;

    return 0;
}

void
cn_kvdb_destroy(struct cn_kvdb *h)
{
    if (h) {
        destroy_workqueue(h->cn_maint_wq);
        destroy_workqueue(h->cn_io_wq);
        free(h);
    }
}

#if HSE_MOCKING
#include "cn_kvdb_ut_impl.i"
#endif /* HSE_MOCKING */
