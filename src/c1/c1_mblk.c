/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mpool/mpool.h>

#include <hse_ikvdb/kvset_builder.h>

#include "c1_private.h"

struct c1_mblk {
    struct list_head c1m_list;
    struct mpool *   c1m_ds;
};

struct c1_mblk_elem {
    struct list_head         c1me_list;
    u64                      c1me_mbid;
    size_t                   c1me_size;
    bool                     c1me_committed;
    struct mpool_mcache_map *c1me_map;
    merr_t                   c1me_err;
};

merr_t
c1_mblk_create(struct mpool *ds, struct c1_mblk **mblkout)
{
    struct c1_mblk *mblk;

    mblk = malloc(sizeof(*mblk));
    if (ev(!mblk))
        return merr(ENOMEM);

    INIT_LIST_HEAD(&mblk->c1m_list);
    mblk->c1m_ds = ds;

    *mblkout = mblk;

    return 0;
}

void
c1_mblk_destroy(struct c1_mblk *mblk)
{
    struct c1_mblk_elem *elm, *tmp_elm;

    list_for_each_entry_safe (elm, tmp_elm, &mblk->c1m_list, c1me_list) {
        list_del(&elm->c1me_list);

        mpool_mcache_munmap(elm->c1me_map);

        if (!elm->c1me_err)
            mpool_mblock_delete(mblk->c1m_ds, elm->c1me_mbid);

        free(elm);
    }
    free(mblk);
}

static merr_t
c1_mblk_get_blkid(struct c1_mblk *mblk, u64 blkid, struct c1_mblk_elem **elmout)
{
    struct c1_mblk_elem *elm;

    list_for_each_entry (elm, &mblk->c1m_list, c1me_list) {
        if (elm->c1me_mbid == blkid) {
            *elmout = elm;
            return 0;
        }
    }

    return merr(EINVAL);
}

static merr_t
c1_mblk_map(struct c1_mblk *mblk, u64 blkid, struct c1_mblk_elem **elmout)
{
    struct mpool_mcache_map *map;
    struct c1_mblk_elem *    elm;
    struct mblock_props      props;
    merr_t                   err;

    *elmout = NULL;

    /*
     * A crash can happen before committing mblocks. In that case
     * there can be many log entries having their values deposited
     * into the same mblock. Saving the lookup error in this cache
     * helps to avoid successive mpool_mblock_getprops. So an entry
     * for given a block id is kept in the cache irrespective of
     * whether the mblock is a valid one or not.
     */
    err = mpool_mblock_getprops(mblk->c1m_ds, blkid, &props);
    if (!ev(err)) {
        if (ev(!props.mpr_iscommitted)) {
            err = merr(ENOENT);
        }
    }

    map = NULL;

    if (!err) {
        err = mpool_mcache_mmap(mblk->c1m_ds, 1, &blkid, MPC_VMA_COLD, &map);
    }

    elm = malloc(sizeof(*elm));
    if (ev(!elm)) {
        if (!err) {
            mpool_mcache_munmap(elm->c1me_map);
        }

        return err ? err : merr(ENOMEM);
    }

    elm->c1me_mbid = blkid;
    elm->c1me_size = props.mpr_write_len;
    elm->c1me_committed = props.mpr_iscommitted;
    elm->c1me_map = map;
    elm->c1me_err = err;
    INIT_LIST_HEAD(&elm->c1me_list);

    list_add_tail(&elm->c1me_list, &mblk->c1m_list);

    *elmout = elm;

    return 0;
}

static merr_t
c1_mblk_get_val_int(struct c1_mblk_elem *elm, u64 blkoff, void **valuep, u64 vlen)
{
    if (ev(elm->c1me_err))
        return elm->c1me_err;

    blkoff += kvset_builder_vblock_hdr_len();
    if (ev((blkoff + vlen) >= elm->c1me_size))
        return merr(ERANGE);

    *valuep = mpool_mcache_getbase(elm->c1me_map, 0) + blkoff;

    return 0;
}

merr_t
c1_mblk_get_val(struct c1_mblk *mblk, u64 blkid, u64 blkoff, void **valuep, u64 vlen)
{
    struct c1_mblk_elem *elm;
    merr_t               err;

    elm = NULL;

    if (!c1_mblk_get_blkid(mblk, blkid, &elm))
        return c1_mblk_get_val_int(elm, blkoff, valuep, vlen);

    if (ev(elm && elm->c1me_err))
        return elm->c1me_err;

    err = c1_mblk_map(mblk, blkid, &elm);
    if (ev(err))
        return err;

    assert(elm);

    return c1_mblk_get_val_int(elm, blkoff, valuep, vlen);
}

void
c1_mblk_put_val(struct c1_mblk *mblk, u64 blkid, u64 blkoff, void *valuep, u64 vlen)
{
}
