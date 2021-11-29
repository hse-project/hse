/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include "mpool_internal.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

struct mpool;

merr_t
mpool_mblock_alloc(
    struct mpool        *mp,
    enum hse_mclass    mclass,
    uint64_t            *mbid,
    struct mblock_props *props)
{
    struct media_class *mc;

    merr_t err;

    if (!mp || !mbid || mclass >= HSE_MCLASS_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (ev(!mc))
        return merr(ENOENT);

    err = mblock_fset_alloc(mclass_fset(mc), 1, mbid);

    if (!err && props) {
        props->mpr_objid = *mbid;
        props->mpr_alloc_cap = mclass_mblocksz_get(mc);
        props->mpr_optimal_wrsz = MBLOCK_OPT_WRITE_SZ;
        props->mpr_mclass = mclass;
        props->mpr_write_len = 0;
    }

    return err;
}

merr_t
mpool_mblock_commit(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    enum hse_mclass   mclass;

    if (!mp)
        return merr(EINVAL);

    mclass = mcid_to_mclass(mclassid(mbid));
    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    return mblock_fset_commit(mclass_fset(mc), &mbid, 1);
}

merr_t
mpool_mblock_abort(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    enum hse_mclass   mclass;

    if (!mp)
        return merr(EINVAL);

    mclass = mcid_to_mclass(mclassid(mbid));
    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    return mblock_fset_abort(mclass_fset(mc), &mbid, 1);
}

merr_t
mpool_mblock_delete(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    enum hse_mclass   mclass;

    if (!mp)
        return merr(EINVAL);

    mclass = mcid_to_mclass(mclassid(mbid));
    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    return mblock_fset_delete(mclass_fset(mc), &mbid, 1);
}

merr_t
mpool_mblock_props_get(struct mpool *mp, uint64_t mbid, struct mblock_props *props)
{
    struct media_class *mc;
    enum hse_mclass   mclass;
    uint32_t wlen;
    merr_t   err;

    if (!mp)
        return merr(EINVAL);

    mclass = mcid_to_mclass(mclassid(mbid));
    mc = mpool_mclass_handle(mp, mclass);
    if (ev(!mc))
        return merr(ENOENT);

    err = mblock_fset_find(mclass_fset(mc), &mbid, 1, props ? &wlen : NULL);
    if (!err && props) {
        props->mpr_objid = mbid;
        props->mpr_alloc_cap = mclass_mblocksz_get(mc);
        props->mpr_optimal_wrsz = MBLOCK_OPT_WRITE_SZ;
        props->mpr_mclass = mclass;
        props->mpr_write_len = wlen;
    }

    return ev(err);
}

merr_t
mpool_mblock_write(struct mpool *mp, uint64_t mbid, const struct iovec *iov, int iovc)
{
    struct media_class *mc;
    enum hse_mclass   mclass;

    if (!mp || !iov)
        return merr(EINVAL);

    mclass = mcid_to_mclass(mclassid(mbid));
    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    return mblock_fset_write(mclass_fset(mc), mbid, iov, iovc);
}

merr_t
mpool_mblock_read(struct mpool *mp, uint64_t mbid, const struct iovec *iov, int iovc, off_t off)
{
    struct media_class *mc;
    enum hse_mclass   mclass;

    if (!mp || !iov)
        return merr(EINVAL);

    mclass = mcid_to_mclass(mclassid(mbid));
    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    return mblock_fset_read(mclass_fset(mc), mbid, iov, iovc, off);
}
