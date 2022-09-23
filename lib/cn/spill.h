/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_CN_SPILL_H
#define HSE_KVDB_CN_SPILL_H

#include <hse/error/merr.h>
#include <hse_util/inttypes.h>

#include "route.h"

struct cn_compaction_work;
struct cn_tree_node;
struct kvset_meta;
struct spillctx;

struct zspill {
    struct kvset_list_entry *zsp_src_list;
};

struct subspill {
    struct list_head           ss_link;
    struct cn_compaction_work *ss_work;

    union {
        struct kvset_mblocks ss_mblks;
        struct zspill        ss_zspill;
    };

    uint64_t                   ss_kvsetid;
    uint64_t                   ss_sgen;
    struct cn_tree_node       *ss_node;
    bool                       ss_added;
    bool                       ss_is_zspill;
};

/* MTF_MOCK_DECL(spill) */

/**
 * cn_subspill() - Build kvsets as part of a spill operation
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
cn_subspill(
    struct subspill           *ss,
    struct spillctx           *sctx,
    struct cn_tree_node       *node,
    uint64_t                   node_dgen,
    const void                *ekey,
    uint                       eklen);


/* MTF_MOCK */
merr_t
cn_spill_create(struct cn_compaction_work *w, struct spillctx **sctx_out);

/* MTF_MOCK */
void
cn_spill_destroy(struct spillctx *ctx);

/* MTF_MOCK */
void
cn_subspill_get_kvset_meta(struct subspill *ss, struct kvset_meta *km);

#if HSE_MOCKING
#include "spill_ut.h"
#endif /* HSE_MOCKING */

#endif
