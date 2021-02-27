/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include "mpool.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

struct mpool;

struct mpool_mcache_map {
    struct mpool *mp;
    size_t mbidc;
    void **addrv;
    uint64_t *mbidv;
};

merr_t
mpool_mcache_mmap(
    struct mpool             *mp,
    size_t                    mbidc,
    uint64_t                 *mbidv,
    enum mpc_vma_advice       advice, /*unused*/
    struct mpool_mcache_map **mapp)
{
    struct mpool_mcache_map *map;
    struct media_class      *mc;

    size_t sz;
    merr_t err = 0;
    int    i;

    if (!mp || !mbidv || !mapp)
        return merr(EINVAL);

    *mapp = NULL;

    sz = sizeof(*map) + mbidc * (sizeof(*map->addrv) + sizeof(*map->mbidv));
    map = calloc(1, sz);
    if (!map)
        return merr(ENOMEM);

    map->mbidc = mbidc;
    map->addrv = (void *)(map + 1);
    map->mbidv = (void *)(map->addrv + mbidc);

    for (i = 0; i < mbidc; i++) {
        enum mp_media_classp mclass;
        char                *addr;

        mclass = mcid_to_mclass(mclassid(mbidv[i]));
        mc = mpool_mclass_handle(mp, mclass);

        err = mblock_fset_map_getbase(mclass_fset(mc), mbidv[i], &addr);
        if (ev(err))
            goto errout;

        map->addrv[i] = addr;
        map->mbidv[i] = mbidv[i];
    }
    map->mp = mp;

    *mapp = map;

    return 0;

errout:
    free(map);

    return err;
}

merr_t
mpool_mcache_munmap(struct mpool_mcache_map *map)
{
    struct media_class *mc;
    int i;

    if (!map)
        return merr(EINVAL);

    for (i = 0; i < map->mbidc; i++) {
        enum mp_media_classp mclass;
        uint64_t             mbid;
        merr_t               err;

        mbid = map->mbidv[i];

        mclass = mcid_to_mclass(mclassid(mbid));
        mc = mpool_mclass_handle(map->mp, mclass);

        err = mblock_fset_unmap(mclass_fset(mc), mbid);
        if (err)
            return err;
    }

    free(map);

    return 0;
}

merr_t
mpool_mcache_madvise(struct mpool_mcache_map *map, uint mbidx, off_t off, size_t len, int advice)
{
    size_t count;

    if (!map || mbidx >= map->mbidc || off < 0 || off >= MBLOCK_SIZE_BYTES)
        return merr(EINVAL);

    if (len == SIZE_MAX) {
        count = map->mbidc;
    } else {
        if (off + len > MBLOCK_SIZE_BYTES)
            return merr(EINVAL);
        count = mbidx + 1;
    }

    do {
        char *addr;
        int   rc;

        addr = map->addrv[mbidx];
        if (!addr || addr == MAP_FAILED)
            return merr(EINVAL);

        len = MBLOCK_SIZE_BYTES - off;

        rc = madvise(addr + off, len, advice);
        if (rc)
            return merr(errno);

        off = 0;
    } while (++mbidx < count);

    return 0;
}

void *
mpool_mcache_getbase(struct mpool_mcache_map *map, const uint mbidx)
{
    if (!map || map->addrv[mbidx] == MAP_FAILED || mbidx >= map->mbidc)
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

    if (!map || mbidx >= map->mbidc)
        return merr(EINVAL);

    addr = map->addrv[mbidx];
    if (!addr || addr == MAP_FAILED)
        return merr(EINVAL);

    for (i = 0; i < pagec; i++) {
        off_t off;

        off = pagenumv[i] * PAGE_SIZE;
        if (off + PAGE_SIZE > MBLOCK_SIZE_BYTES)
            return merr(EINVAL);

        addrv[i] = addr + off;
    }

    return 0;
}
