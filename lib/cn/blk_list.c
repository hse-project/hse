/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "blk_list.h"

#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>

#include <mpool/mpool.h>

void
abort_mblocks(struct mpool *dataset, struct blk_list *blks)
{
    if (!blks)
        return;

    for (uint i = 0; i < blks->n_blks; i++)
        abort_mblock(dataset, &blks->blks[i]);
}

merr_t
commit_mblock(struct mpool *dataset, struct kvs_block *blk)
{
    merr_t err;

    assert(blk);
    assert(blk->bk_blkid);

    err = mpool_mblock_commit(dataset, blk->bk_blkid);
    if (ev(err)) {
        hse_elog(HSE_ERR "commit_mblock failed: @@e, blkid 0x%lx", err, (ulong)blk->bk_blkid);
        return err;
    }

    return 0;
}

merr_t
abort_mblock(struct mpool *dataset, struct kvs_block *blk)
{
    merr_t err;

    assert(blk);

    err = mpool_mblock_abort(dataset, blk->bk_blkid);
    if (ev(err)) {
        hse_elog(
            HSE_ERR "abort_mblock failed: @@e, blkid 0x%lx", err, (ulong)blk->bk_blkid);
    } else {
        blk->bk_blkid = 0;
    }
    return err;
}

merr_t
delete_mblock(struct mpool *dataset, struct kvs_block *blk)
{
    merr_t err = 0;

    err = mpool_mblock_delete(dataset, blk->bk_blkid);
    if (ev(err)) {
        hse_elog(
            HSE_ERR "delete_mblock failed: @@e, blkid 0x%lx", err, (ulong)blk->bk_blkid);
    } else {
        blk->bk_blkid = 0;
    }
    return err;
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
    blks->blks = 0;
    blks->n_blks = 0;
}
