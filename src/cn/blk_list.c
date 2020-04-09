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

static merr_t
get_mblock_handle(struct mpool *dataset, struct kvs_block *blk, u64 *handle)
{
    merr_t err;

    assert(!blk->bk_handle);

    err = mpool_mblock_find_get(dataset, blk->bk_blkid, &blk->bk_handle, NULL);
    if (!err) {
        *handle = blk->bk_handle;
        return 0;
    }
    hse_elog(HSE_ERR "Can't get handle for mblock %lx (@@e)", err, (ulong)blk->bk_blkid);

    blk->bk_handle = 0;
    *handle = blk->bk_handle;
    return err;
}

/**
 * The following functions, abort_mblocks(),
 * and commit_mblock() only make sense right after having called
 * mpool_mblock_alloc().  Since mpool_mblock_alloc() returns a handle,
 * the caller definitely has a handle. The function ignores the mblocks
 * which are already committed in a special case.
 */
void
abort_mblocks(struct mpool *dataset, struct blk_list *blks)
{
    u32 i;

    if (!blks)
        return;

    for (i = 0; i < blks->n_blks; i++) {
        /* skip committed mlocks that cannot be aborted */
        if (!blks->blks[i].bk_needs_commit)
            continue;

        abort_mblock(dataset, &blks->blks[i]);
    }
}

merr_t
put_mblock(struct mpool *dataset, struct kvs_block *blk)
{
    assert(blk);
    assert(dataset);

    if (blk->bk_handle) {
        mpool_mblock_put(dataset, blk->bk_handle);
        blk->bk_handle = 0;
    }
    /* HSE_REVISIT
     * We don't return errors from put.  Need to analyze whether there
     * is anything that can be done with these. */
    return 0;
}

merr_t
commit_mblock(struct mpool *dataset, struct kvs_block *blk)
{
    merr_t err;
    u64    handle = blk->bk_handle;

    assert(blk);
    assert(handle);

    err = mpool_mblock_commit(dataset, handle);
    if (ev(err)) {
        hse_elog(HSE_ERR "commit_mblock failed: @@e, blkid 0x%lx", err, (unsigned long)handle);
        return err;
    }

    /* For now, we automatically put our handle reference; there
     * might be reasons to keep them around at some point.
     */
    put_mblock(dataset, blk);

    return 0;
}

/**
 * delete_mblock() and abort_mblock() differ from the previous functions.  The
 * caller might have a handle, but the mblock might have been discovered by
 * cndb_replay(), in which case the caller might not have a handle.  So we look
 * up the handle if no valid one is found.
 */
merr_t
abort_mblock(struct mpool *dataset, struct kvs_block *blk)
{
    u64    handle = blk->bk_handle;
    merr_t err;

    assert(blk);

    if (!handle) {
        err = get_mblock_handle(dataset, blk, &handle);
        if (ev(err))
            return err;
    }

    err = mpool_mblock_abort(dataset, blk->bk_handle);
    if (ev(err)) {
        hse_elog(
            HSE_ERR "abort_mblock failed: @@e, blkid 0x%lx", err, (unsigned long)blk->bk_blkid);
    } else {
        blk->bk_blkid = 0;
        blk->bk_handle = 0;
    }
    return err;
}

merr_t
delete_mblock(struct mpool *dataset, struct kvs_block *blk)
{
    u64    handle = blk->bk_handle;
    merr_t err = 0;

    if (!handle) {
        err = get_mblock_handle(dataset, blk, &handle);
        if (ev(err))
            return err;
    }

    err = mpool_mblock_delete(dataset, handle);
    if (ev(err)) {
        hse_elog(
            HSE_ERR "delete_mblock failed: @@e, blkid 0x%lx", err, (unsigned long)blk->bk_blkid);
    } else {
        /* The mblock is deleted, so this kvs_block is no
         * longer valid.  Make sure it can't pass for a valid
         * one.  Caller should delete it forthwith...
         */
        blk->bk_blkid = 0;
        blk->bk_handle = 0;
    }
    return err;
}

merr_t
stat_mblock(struct mpool *dataset, struct kvs_block *blk, struct mblock_props *props)
{
    u64    handle = blk->bk_handle;
    merr_t err = 0;

    if (!handle) {
        err = get_mblock_handle(dataset, blk, &handle);
        if (ev(err))
            return err;
    }

    err = mpool_mblock_getprops(dataset, handle, props);
    if (ev(err)) {
        hse_elog(HSE_ERR "stat_mblock failed: @@e, blkid 0x%lx", err, (unsigned long)blk->bk_blkid);
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
blk_list_append_ext(struct blk_list *blks, u64 handle, u64 blkid, bool valid, bool needs_commit)
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

    blks->blks[blks->n_blks].bk_handle = handle;
    blks->blks[blks->n_blks].bk_blkid = blkid;
    blks->blks[blks->n_blks].bk_needs_commit = needs_commit;
    blks->blks[blks->n_blks].bk_valid = valid;
    blks->n_blks++;

    return 0;
}

merr_t
blk_list_append(struct blk_list *blks, u64 handle, u64 blkid)
{
    return blk_list_append_ext(blks, handle, blkid, true, true);
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
