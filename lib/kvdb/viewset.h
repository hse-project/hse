/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KVDB_VIEWSET_H
#define HSE_KVDB_VIEWSET_H

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/util/atomic.h>

struct viewset;

/* MTF_MOCK_DECL(viewset) */

/* MTF_MOCK */
merr_t viewset_create(
    struct viewset **handle,
    atomic_ulong *kvdb_seqno_addr,
    atomic_ulong *tseqnop);

/* MTF_MOCK */
void viewset_destroy(struct viewset *handle);

/* MTF_MOCK */
merr_t viewset_insert(struct viewset *handle, uint64_t *viewp, uint64_t *tseqnop, void **cookiep);

/* MTF_MOCK */
void
viewset_remove(
    struct viewset *handle,
    void           *cookie,
    uint32_t       *min_changed,
    uint64_t       *min_view_sn);

/* MTF_MOCK */
uint64_t viewset_horizon(struct viewset *handle);
uint64_t viewset_min_view(struct viewset *handle);

#if HSE_MOCKING
#include "viewset_ut.h"
#endif /* HSE_MOCKING */

#endif
