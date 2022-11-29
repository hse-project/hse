/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/util/event_counter.h>
#include <hse/logging/logging.h>

#include "mpool_internal.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

struct mpool;

merr_t
mpool_mblock_alloc(
    struct mpool        *mp,
    enum hse_mclass      mclass,
    uint32_t             flags,
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

    err = mblock_fset_alloc(mclass_fset(mc), flags, 1, mbid);

    if (!err && props) {
        props->mpr_objid = *mbid;
        props->mpr_alloc_cap = mclass_mblocksz_get(mc);
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
mpool_mblock_delete(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    enum hse_mclass   mclass;

    if (!mp)
        return merr(EINVAL);

    if (!mbid)
        return 0;

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
    merr_t err;

    if (!mp)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mcid_to_mclass(mclassid(mbid)));
    if (!mc)
        return merr(ENOENT);

    err = mblock_fset_find(mclass_fset(mc), &mbid, 1, props);
    if (err)
        return err;

    if (props)
        props->mpr_ra_pages = mclass_ra_pages(mc);

    return 0;
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

merr_t
mpool_mblock_punch(struct mpool *mp, uint64_t mbid, off_t off, size_t len)
{
    struct media_class *mc;

    if (!mp)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mcid_to_mclass(mclassid(mbid)));
    if (!mc)
        return merr(ENOENT);

    return mblock_fset_punch(mclass_fset(mc), mbid, off, len);
}

merr_t
mpool_mblock_clone(struct mpool *mp, uint64_t mbid, off_t off, size_t len, uint64_t *mbid_out)
{
    struct media_class *mc;

    if (!mp || !mbid_out)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mcid_to_mclass(mclassid(mbid)));
    if (!mc)
        return merr(ENOENT);

    return mblock_fset_clone(mclass_fset(mc), mbid, off, len, mbid_out);
}

merr_t
mpool_mblock_mmap(struct mpool *mp, uint64_t mbid, const void **addr_out)
{
    struct media_class *mc;
    uint32_t wlen;
    merr_t err;
    char *addr;

    if (!mp || !mbid || !addr_out)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mcid_to_mclass(mclassid(mbid)));
    if (!mc)
        return merr(ENOENT);

    err = mblock_fset_map_getbase(mclass_fset(mc), mbid, &addr, &wlen);
    if (err)
        return err;

    *addr_out = (const void *)addr;

    return err;
}

merr_t
mpool_mblock_munmap(struct mpool *mp, uint64_t mbid)
{
    struct media_class *mc;
    merr_t err;

    if (!mp || !mbid)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mcid_to_mclass(mclassid(mbid)));
    if (!mc)
        return merr(ENOENT);

    err = mblock_fset_unmap(mclass_fset(mc), mbid);

    return err;
}
