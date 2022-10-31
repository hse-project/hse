/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_blk_list

#include <hse/ikvdb/blk_list.h>
#include <hse/logging/logging.h>
#include <hse/error/merr.h>
#include <hse/util/event_counter.h>
#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/assert.h>

#include <hse/mpool/mpool.h>

#include "blk_list.h"

merr_t
commit_mblock(struct mpool *mp, uint64_t mbid)
{
    merr_t err;

    INVARIANT(mp);
    INVARIANT(mbid);

    err = mpool_mblock_commit(mp, mbid);
    if (err) {
        log_errx("Failed to commit mblock, blkid 0x%lx", err, mbid);
        return err;
    }

    return 0;
}

merr_t
commit_mblocks(struct mpool *mp, struct blk_list *blks)
{
    merr_t err;

    INVARIANT(mp);
    INVARIANT(blks);

    for (uint32_t i = 0; i < blks->idc; i++) {
        err = commit_mblock(mp, blks->idv[i]);
        if (err)
            return err;
    }

    return 0;
}

void
delete_mblock(struct mpool *mp, uint64_t mbid)
{
    merr_t err;

    INVARIANT(mp);

    err = mpool_mblock_delete(mp, mbid);
    if (err)
        log_errx("Failed to delete mblock 0x%lx", err, mbid);
}

void
delete_mblocks(struct mpool *mp, struct blk_list *blks)
{
    INVARIANT(mp);
    INVARIANT(blks);

    for (uint32_t i = 0; i < blks->idc; i++) {
        delete_mblock(mp, blks->idv[i]);
        blks->idv[i] = 0;
    }
}

void
blk_list_init(struct blk_list *blkl)
{
    INVARIANT(blkl);

    blkl->idv = NULL;
    blkl->n_alloc = 0;
    blkl->idc = 0;
}

merr_t
blk_list_append(struct blk_list *blks, u64 blkid)
{
    assert(blks->idc <= blks->n_alloc);

    if (blks->idc == blks->n_alloc) {

        size_t old_sz;
        size_t grow_sz;
        uint64_t *new_mbidv;

        old_sz = sizeof(blks->idv[0]) * blks->n_alloc;
        grow_sz = sizeof(blks->idv[0]) * BLK_LIST_PRE_ALLOC;
        new_mbidv = malloc(old_sz + grow_sz);
        if (ev(!new_mbidv))
            return merr(ENOMEM);

        blks->n_alloc += BLK_LIST_PRE_ALLOC;

        if (old_sz) {
            assert(blks->idv);
            memcpy(new_mbidv, blks->idv, old_sz);
            free(blks->idv);
        }

        blks->idv = new_mbidv;
    }

    blks->idv[blks->idc] = blkid;
    blks->idc++;

    return 0;
}

void
blk_list_free(struct blk_list *blks)
{
    if (!blks)
        return;

    free(blks->idv);
    blks->idv = NULL;
    blks->idc = 0;
}

#if HSE_MOCKING
#include "blk_list_ut_impl.i"
#endif
