/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_blk_list

#include <hse_ikvdb/blk_list.h>
#include <hse/logging/logging.h>
#include <hse/error/merr.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/assert.h>

#include <mpool/mpool.h>

#include "blk_list.h"

merr_t
commit_mblock(struct mpool *mp, struct kvs_block *blk)
{
    merr_t err;

    INVARIANT(blk);
    INVARIANT(blk->bk_blkid);

    err = mpool_mblock_commit(mp, blk->bk_blkid);
    if (err) {
        log_errx("Failed to commit mblock, blkid 0x%lx", err, blk->bk_blkid);
        return err;
    }

    return 0;
}

merr_t
commit_mblocks(struct mpool *mp, struct blk_list *blks)
{
    if (!mp || !blks)
        return merr(EINVAL);

    for (uint32_t i = 0; i < blks->n_blks; i++) {
        merr_t err = commit_mblock(mp, &blks->blks[i]);
        if (err)
            return err;
    }

    return 0;
}

merr_t
delete_mblock(struct mpool *mp, struct kvs_block *blk)
{
    merr_t err = mpool_mblock_delete(mp, blk->bk_blkid);
    if (err) {
        log_errx("Failed to delete mblock, blkid 0x%lx", err, blk->bk_blkid);
        return err;
    }

    blk->bk_blkid = 0;

    return 0;
}

void
delete_mblocks(struct mpool *mp, struct blk_list *blks)
{
    if (!mp || !blks)
        return;

    for (uint32_t i = 0; i < blks->n_blks; i++)
        delete_mblock(mp, &blks->blks[i]);
}

void
blk_list_init(struct blk_list *blkl)
{
    assert(blkl);

    blkl->blks = NULL;
    blkl->n_alloc = 0;
    blkl->n_blks = 0;
}

merr_t
blk_list_append(struct blk_list *blks, u64 blkid)
{
    assert(blks->n_blks <= blks->n_alloc);

    if (blks->n_blks == blks->n_alloc) {

        size_t old_sz;
        size_t grow_sz;
        struct kvs_block *new;

        old_sz = sizeof(struct kvs_block) * blks->n_alloc;
        grow_sz = sizeof(struct kvs_block) * BLK_LIST_PRE_ALLOC;
        new = malloc(old_sz + grow_sz);
        if (!new)
            return merr(ev(ENOMEM));

        blks->n_alloc += BLK_LIST_PRE_ALLOC;

        if (old_sz) {
            assert(blks->blks);
            memcpy(new, blks->blks, old_sz);
            free(blks->blks);
        }

        blks->blks = new;
    }

    blks->blks[blks->n_blks].bk_blkid = blkid;
    blks->n_blks++;

    return 0;
}

void
blk_list_free(struct blk_list *blks)
{
    if (!blks)
        return;

    free(blks->blks);
    blks->blks = NULL;
    blks->n_blks = 0;
}

#if HSE_MOCKING
#include "blk_list_ut_impl.i"
#endif
