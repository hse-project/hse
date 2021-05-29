/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/logging.h>
#include <hse_util/page.h>

#include "mpool_internal.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

struct mpool;

/**
 * struct mpool_mcache_map - Mcache map handle
 *
 * @mp: mpool handle
 * @mbidc: count of mblocks in mbidv
 * @mbidv: vector of mblock ids
 * @addrv: mapped address for mblocks in mbidv
 * @wlenv: write lengths for mblocks in mbidv
 */
struct mpool_mcache_map {
    struct mpool *mp;
    size_t        mbidc;
    uint64_t     *mbidv;
    void        **addrv;
    uint32_t     *wlenv;
};

merr_t
mpool_mcache_mmap(struct mpool *mp, size_t mbidc, uint64_t *mbidv, struct mpool_mcache_map **mapp)
{
    struct mpool_mcache_map *map;
    struct media_class      *mc;
    size_t sz;
    merr_t err = 0;
    int    i;

    if (!mp || !mbidv || !mapp)
        return merr(EINVAL);

    *mapp = NULL;

    sz = sizeof(*map) + mbidc * (sizeof(*map->addrv) + sizeof(*map->mbidv) + sizeof(*map->wlenv));
    map = calloc(1, sz);
    if (!map)
        return merr(ENOMEM);

    map->mbidc = mbidc;
    map->addrv = (void *)(map + 1);
    map->mbidv = (void *)(map->addrv + mbidc);
    map->wlenv = (void *)(map->mbidv + mbidc);

    for (i = 0; i < mbidc; i++) {
        enum mpool_mclass mclass;
        char             *addr;
        uint32_t          wlen;

        mclass = mcid_to_mclass(mclassid(mbidv[i]));
        mc = mpool_mclass_handle(mp, mclass);
        if (!mc) {
            err = merr(ENOENT);
            goto errout;
        }

        err = mblock_fset_map_getbase(mclass_fset(mc), mbidv[i], &addr, &wlen);
        if (err)
            goto errout;

        map->addrv[i] = addr;
        map->mbidv[i] = mbidv[i];
        map->wlenv[i] = wlen;
    }
    map->mp = mp;

    *mapp = map;

    return 0;

errout:
    free(map);

    return err;
}

void
mpool_mcache_munmap(struct mpool_mcache_map *map)
{
    struct media_class *mc;
    int                 i;

    if (!map)
        return;

    for (i = 0; i < map->mbidc; i++) {
        enum mpool_mclass mclass;
        uint64_t          mbid;
        merr_t            err;

        mbid = map->mbidv[i];

        mclass = mcid_to_mclass(mclassid(mbid));
        mc = mpool_mclass_handle(map->mp, mclass);
        assert(mc);

        err = mblock_fset_unmap(mclass_fset(mc), mbid);
        if (ev(err))
            hse_log(HSE_ERR "%s: Unable to unmap mblock %lu, map %p", __func__, mbid, map);
    }

    free(map);
}

merr_t
mpool_mcache_madvise(struct mpool_mcache_map *map, uint mbidx, off_t off, size_t len, int advice)
{
    size_t   count;
    uint32_t wlen;

    if (!map || mbidx >= map->mbidc || off < 0)
        return merr(EINVAL);

    wlen = map->wlenv[mbidx];
    if (off >= wlen)
        return merr(EINVAL);

    if (len == SIZE_MAX) {
        count = map->mbidc;
        len = wlen - off;
    } else {
        if (off + len > wlen)
            return merr(EINVAL);
        count = mbidx + 1;
    }

    do {
        char *addr;
        int   rc;

        addr = map->addrv[mbidx];
        if (!addr)
            return merr(EINVAL);

        rc = madvise(addr + off, len, advice);
        if (rc)
            return merr(errno);

        if (++mbidx >= count)
            break;

        off = 0;
        len = map->wlenv[mbidx];
    } while (true);

    return 0;
}

void *
mpool_mcache_getbase(struct mpool_mcache_map *map, const uint mbidx)
{
    if (!map || mbidx >= map->mbidc)
        return NULL;

    return map->addrv[mbidx];
}

merr_t
mpool_mcache_getpages(
    struct mpool_mcache_map *map,
    const uint               pagec,
    const uint               mbidx,
    const off_t              pagenumv[],
    void                    *addrv[])
{
    char *addr;
    int   i;

    if (!map || mbidx >= map->mbidc || !addrv)
        return merr(EINVAL);

    addr = map->addrv[mbidx];
    if (!addr)
        return merr(EINVAL);

    for (i = 0; i < pagec; i++) {
        off_t off;

        off = pagenumv[i] * PAGE_SIZE;
        if (off + PAGE_SIZE > map->wlenv[mbidx])
            return merr(EINVAL);

        addrv[i] = addr + off;
    }

    return 0;
}

merr_t
mpool_mcache_purge(struct mpool_mcache_map *map, const struct mpool *mp)
{
    return merr(ENOTSUP);
}

merr_t
mpool_mcache_mincore(
    struct mpool_mcache_map *map,
    const struct mpool      *mp,
    size_t                  *rssp,
    size_t                  *vssp)
{
    return merr(ENOTSUP);
}
