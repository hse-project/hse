/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_ACTIVE_CTXN_SET_H
#define HSE_KVDB_ACTIVE_CTXN_SET_H

#include <hse_util/inttypes.h>
#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>

#pragma GCC visibility push(hidden)

struct active_ctxn_set;

merr_t
active_ctxn_set_create(struct active_ctxn_set **handle, atomic64_t *kvdb_seqno_addr);

void
active_ctxn_set_destroy(struct active_ctxn_set *handle);

merr_t
active_ctxn_set_insert(struct active_ctxn_set *handle, u64 *viewp, void **cookiep);

void
active_ctxn_set_remove(
    struct active_ctxn_set *handle,
    void *                  cookie,
    u32 *                   min_changed,
    u64 *                   min_view_sn);

u64
active_ctxn_set_horizon(struct active_ctxn_set *handle);

#pragma GCC visibility pop

#endif
