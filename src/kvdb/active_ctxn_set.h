/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_VIEWSET_H
#define HSE_KVDB_VIEWSET_H

#include <hse_util/inttypes.h>
#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>

#pragma GCC visibility push(hidden)

struct viewset;

merr_t viewset_create(struct viewset **handle, atomic64_t *kvdb_seqno_addr);

void viewset_destroy(struct viewset *handle);

merr_t viewset_insert(struct viewset *handle, u64 *viewp, void **cookiep);

void
viewset_remove(
    struct viewset *handle,
    void           *cookie,
    u32            *min_changed,
    u64            *min_view_sn);

u64 viewset_horizon(struct viewset *handle);

#pragma GCC visibility pop

#endif
