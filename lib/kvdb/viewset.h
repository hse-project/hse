/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_VIEWSET_H
#define HSE_KVDB_VIEWSET_H

#include <hse_util/inttypes.h>
#include <hse_util/atomic.h>
#include <hse/error/merr.h>

struct viewset;

/* MTF_MOCK_DECL(viewset) */

/* MTF_MOCK */
merr_t viewset_create(struct viewset **handle, atomic_ulong *kvdb_seqno_addr, atomic_ulong *tseqnop);

/* MTF_MOCK */
void viewset_destroy(struct viewset *handle);

/* MTF_MOCK */
merr_t viewset_insert(struct viewset *handle, u64 *viewp, u64 *tseqnop, void **cookiep);

/* MTF_MOCK */
void
viewset_remove(
    struct viewset *handle,
    void           *cookie,
    u32            *min_changed,
    u64            *min_view_sn);

/* MTF_MOCK */
u64 viewset_horizon(struct viewset *handle);
u64 viewset_min_view(struct viewset *handle);

#if HSE_MOCKING
#include "viewset_ut.h"
#endif /* HSE_MOCKING */

#endif
