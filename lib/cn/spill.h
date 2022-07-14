/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_SPILL_H
#define HSE_KVDB_CN_SPILL_H

#include <error/merr.h>
#include <hse_util/inttypes.h>

struct cn_compaction_work;

/* MTF_MOCK_DECL(spill) */

/**
 * cn_spill() - Build kvsets as part of a spill operation
 * @w: compaction work struct
 *
 * Notes:
 * - Each source must be ordered by key such that the first key to
 *   emerge from the iterator is the first key in the sort order.
 *
 * - The @sources must be ordered by time such that @source[i] contains
 *   newer data than @source[i+1].
 *
 * Upon successful return:
 *
 *   - All mblocks have been allocated and written but not yet committed.
 *     Caller must either abort or commit the mblocks.
 *
 *   - Caller must invoke blk_list_free() on each element of @children
 *     to free the array that holds the mblock ids:
 *
 *         blk_list_free(&children[i].kblks).
 *         blk_list_free(&children[i].vblks).
 *
 * Upon failure, no cleanup is necessary (any internally allocated
 * memory or mblocks will be cleaned up prior to return).
 */
/* MTF_MOCK */
merr_t
cn_spill(struct cn_compaction_work *w);

#if HSE_MOCKING
#include "spill_ut.h"
#endif /* HSE_MOCKING */

#endif
