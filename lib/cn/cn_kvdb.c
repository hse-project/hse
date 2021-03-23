/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_cn_kvdb

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/cn_kvdb.h>

/* handle to impl converter */
#define h2i(_H) container_of((_H), struct cn_kvdb_impl, h)

struct cn_kvdb_impl {
    struct cn_kvdb h;
};

/* MTF_MOCK */
merr_t
cn_kvdb_create(struct cn_kvdb **out)
{
    struct cn_kvdb_impl *self;

    self = calloc(1, sizeof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    atomic64_set(&self->h.cnd_kblk_cnt, 0);
    atomic64_set(&self->h.cnd_vblk_cnt, 0);
    atomic64_set(&self->h.cnd_kblk_size, 0);
    atomic64_set(&self->h.cnd_vblk_size, 0);

    *out = &self->h;

    return 0;
}

void
cn_kvdb_destroy(struct cn_kvdb *h)
{
    if (h)
        free(h2i(h));
}

#if HSE_MOCKING
#include "cn_kvdb_ut_impl.i"
#endif /* HSE_MOCKING */
