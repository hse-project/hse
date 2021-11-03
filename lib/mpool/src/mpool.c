/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_mpool

#include <limits.h>

#include <bsd/string.h>

#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/workqueue.h>

#include <mpool/mpool.h>
#include <mpool/mpool_structs.h>

#include "mpool_internal.h"
#include "mblock_fset.h"
#include "mblock_file.h"

/**
 * struct mpool - mpool handle
 *
 * @mc:   media class handles
 * @home: kvdb home
 *
 * [HSE_REVISIT]: Remove home member when logging is reworked
 */
struct mpool {
    struct media_class *mc[MP_MED_COUNT];
    const char          home[]; /* flexible array */
};

const char *const mpool_mclass_to_string[MP_MED_COUNT] = {
    [MP_MED_CAPACITY] = MP_MED_NAME_CAPACITY,
    [MP_MED_STAGING] = MP_MED_NAME_STAGING,
};

static merr_t
mpool_to_mclass_params(
    enum mpool_mclass           mc,
    const struct mpool_cparams *cparams,
    struct mclass_params       *mcp)
{
    size_t n;

    if (cparams) {
        n = strlcpy(mcp->path, cparams->mclass[mc].path, sizeof(mcp->path));
        if (n >= sizeof(mcp->path))
            return merr(EINVAL);
    } else {
        memset(mcp->path, '\0', sizeof(mcp->path));
    }

    mcp->mblocksz = cparams->mclass[mc].mblocksz;
    mcp->filecnt = cparams->mclass[mc].filecnt;
    mcp->fmaxsz = cparams->mclass[mc].fmaxsz;

    return 0;
}

static merr_t
mclass_params_init(
    const char           *path,
    struct mclass_params *mcp)
{
    size_t n;

    if (path) {
        n = strlcpy(mcp->path, path, sizeof(mcp->path));
        if (n >= sizeof(mcp->path))
            return merr(EINVAL);
    } else {
        memset(mcp->path, '\0', sizeof(mcp->path));
    }

    mcp->mblocksz = MPOOL_MBLOCK_SIZE_DEFAULT;
    mcp->filecnt = MPOOL_MBLOCK_FILECNT_DEFAULT;
    mcp->fmaxsz = MPOOL_MBLOCK_FILESZ_DEFAULT;

    return 0;
}

static merr_t
mpool_mclass_open(
    struct mpool               *mp,
    enum mpool_mclass           mclass,
    const struct mclass_params *mcp,
    uint32_t                    flags,
    struct media_class **       mc)
{
    merr_t err;
    char * path = NULL;

    if (!mp || !mcp || !mc)
        return merr(EINVAL);

    if (mcp->path[0] == '\0') {
        if (mclass == MP_MED_CAPACITY) {
            log_err("capacity storage path not set for %s", mp->home);
            return merr(EINVAL);
        }
        return 0;
    }

    path = realpath(mcp->path, NULL);
    if (!path)
        return merr(errno);

    for (int i = mclass - 1; i >= 0; i--) {
        if (mp->mc[i] && !strcmp(path, mclass_dpath(mp->mc[i]))) {
            log_err("Duplicate storage path %s detected for mc %d and %d", path, mclass, i);
            free(path);
            return merr(EINVAL);
        }
    }

    if ((flags & O_CREAT) && mclass_files_exist(path)) {
        log_err("mclass %d path %s already initialized, should be emptied manually", mclass, path);
        free(path);
        return merr(EEXIST);
    }

    err = mclass_open(mclass, mcp, flags, mc);
    if (err) {
        log_errx("Cannot access storage path %s for mclass %d: @@e", err, path, mclass);
        free(path);
        return err;
    }

    free(path);

    return 0;
}

merr_t
mpool_mclass_add(enum mpool_mclass mclass, const struct mpool_cparams *cparams)
{
    struct media_class *mc;
    struct mclass_params mcp = {0};
    merr_t              err = 0;
    int                 flags = 0;

    if (!cparams || mclass == MP_MED_CAPACITY || cparams->mclass[mclass].path[0] == '\0')
        return merr(EINVAL);

    err = mpool_to_mclass_params(mclass, cparams, &mcp);
    if (err)
        return err;

    flags |= (O_CREAT | O_RDWR);

    err = mclass_open(mclass, &mcp, flags, &mc);
    if (!err)
        mclass_close(mc);

    return err;
}

void
mpool_mclass_destroy(enum mpool_mclass mclass, const struct mpool_dparams *dparams)
{
    const char *path;

    if (!dparams || mclass == MP_MED_CAPACITY)
        return;

    path = dparams->mclass[mclass].path;
    if (path[0] != '\0')
        mclass_destroy(path, NULL);
}

merr_t
mpool_create(const char *home, const struct mpool_cparams *cparams)
{
    struct mpool *mp;
    merr_t        err;
    int           i, flags = 0;
    size_t        sz;
    bool          rmcapdir = false;

    if (!home || !cparams)
        return merr(EINVAL);

    sz = sizeof(*mp) + strlen(home) + 1;
    mp = calloc(1, sz);
    if (!mp)
        return merr(ENOMEM);

    strcpy((char *)mp->home, home);
    flags |= (O_CREAT | O_RDWR);

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        struct mclass_params mcp = {0};

        /* If capacity path is the default, automatically create it */
        if (i == MP_MED_CAPACITY) {
            char   path[PATH_MAX];
            size_t n;

            n = snprintf(path, sizeof(path), "%s/%s", home, MPOOL_CAPACITY_MCLASS_DEFAULT_PATH);
            if (n >= sizeof(path)) {
                err = merr(ENAMETOOLONG);
                goto errout;
            }

            if (!strcmp(path, cparams->mclass[i].path)) {
                DIR *dirp = opendir(path);
                if (dirp) {
                    if (closedir(dirp)) {
                        err = merr(errno);
                        goto errout;
                    }
                } else if (errno == ENOENT) {
                    if (mkdir(path, S_IRGRP | S_IXGRP | S_IRWXU)) {
                        err = merr(errno);
                        goto errout;
                    }
                    rmcapdir = true;
                } else {
                    err = merr(errno);
                    goto errout;
                }
            }
        }

        err = mpool_to_mclass_params(i, cparams, &mcp);
        if (err)
            goto errout;

        err = mpool_mclass_open(mp, i, &mcp, flags, &mp->mc[i]);
        if (err)
            goto errout;
    }

    mpool_close(mp);

    return 0;

errout:
    while (i-- > MP_MED_BASE) {
        mclass_close(mp->mc[i]);
        mclass_destroy(cparams->mclass[i].path, NULL);

        if (i == MP_MED_CAPACITY && rmcapdir)
            remove(cparams->mclass[i].path);
    }

    free(mp);

    return err;
}

merr_t
mpool_open(
    const char                 *home,
    const struct mpool_rparams *rparams,
    uint32_t                    flags,
    struct mpool              **handle)
{
    struct mpool *mp;
    merr_t        err;
    int           i;
    size_t        sz;

    if (!home || !rparams || !handle || (flags & (O_CREAT | O_EXCL)))
        return merr(EINVAL);

    *handle = NULL;

    sz = sizeof(*mp) + strlen(home) + 1;
    mp = calloc(1, sz);
    if (!mp)
        return merr(ENOMEM);

    strcpy((char *)mp->home, home);

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        struct mclass_params mcp = {0};

        err = mclass_params_init(rparams->mclass[i].path, &mcp);
        if (err)
            goto errout;

        err = mpool_mclass_open(mp, i, &mcp, flags, &mp->mc[i]);
        if (err)
            goto errout;
    }

    *handle = mp;

    return 0;

errout:
    while (i-- > MP_MED_BASE)
        mclass_close(mp->mc[i]);

    free(mp);

    return err;
}

merr_t
mpool_close(struct mpool *mp)
{
    merr_t err = 0;
    int    i;

    if (!mp)
        return 0;

    for (i = MP_MED_COUNT - 1; i >= MP_MED_BASE; i--) {
        if (mp->mc[i]) {
            err = mclass_close(mp->mc[i]);
            ev(err);
        }
    }

    free(mp);

    return err;
}

merr_t
mpool_destroy(const char *home, const struct mpool_dparams *dparams)
{
    struct workqueue_struct *mpdwq;
    char path[PATH_MAX];
    int filecnt = 0;

    if (!home || !dparams)
        return merr(EINVAL);

    mpdwq = alloc_workqueue("mp_destroy", 0, MP_DESTROY_THREADS);
    ev(!mpdwq);

    for (int i = MP_MED_COUNT - 1; i >= MP_MED_BASE; i--) {
        const char *path = dparams->mclass[i].path;

        if (path[0] != '\0')
            filecnt += mclass_destroy(path, mpdwq);
    }

    destroy_workqueue(mpdwq);

    snprintf(path, sizeof(path), "%s/%s", home, MPOOL_CAPACITY_MCLASS_DEFAULT_PATH);
    if (!strcmp(path, dparams->mclass[MP_MED_CAPACITY].path) && !remove(path))
        filecnt++;

    return filecnt > 0 ? 0 : merr(ENOENT);
}

merr_t
mpool_mclass_props_get(struct mpool *mp, enum mpool_mclass mclass, struct mpool_mclass_props *props)
{
    struct media_class *mc;

    if (!mp || mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    mc = mp->mc[mclass];
    if (!mc)
        return merr(ENOENT);

    if (props)
        props->mc_mblocksz = mclass_mblocksz_get(mc) >> MB_SHIFT;

    return 0;
}

merr_t
mpool_mclass_stats_get(struct mpool *mp, enum mpool_mclass mclass, struct mpool_mclass_stats *stats)
{
    struct media_class *mc;

    if (!mp || mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    mc = mp->mc[mclass];
    if (!mc)
        return merr(ENOENT);

    if (stats) {
        merr_t err;

        memset(stats, 0, sizeof(*stats));
        err = mclass_stats_get(mc, stats);
        if (err)
            return err;
    }

    return 0;
}

merr_t
mpool_props_get(struct mpool *mp, struct mpool_props *props)
{
    int i;

    if (!mp || !props)
        return merr(EINVAL);

    memset(props, 0, sizeof(*props));

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        struct mpool_mclass_props mcp = {0};
        merr_t                    err;

        err = mpool_mclass_props_get(mp, i, &mcp);
        if (err) {
            if (merr_errno(err) == ENOENT)
                continue;
            return err;
        }

        props->mp_mblocksz[i] = mcp.mc_mblocksz;
    }

    return 0;
}

merr_t
mpool_stats_get(struct mpool *mp, struct mpool_stats *stats)
{
    uint64_t fsid[MP_MED_COUNT] = {};

    if (!mp || !stats)
        return merr(EINVAL);

    memset(stats, 0, sizeof(*stats));

    for (int i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        struct mpool_mclass_stats mcs = {};
        merr_t                    err;
        bool                      uniqfs = true;

        err = mpool_mclass_stats_get(mp, i, &mcs);
        if (err) {
            if (merr_errno(err) == ENOENT)
                continue;
            return err;
        }

        stats->mps_allocated += mcs.mcs_allocated;
        stats->mps_used += mcs.mcs_used;
        stats->mps_mblock_cnt += mcs.mcs_mblock_cnt;

        strlcpy(stats->mps_path[i], mcs.mcs_path, sizeof(stats->mps_path[i]));

        fsid[i] = mcs.mcs_fsid;

        for (int j = i; j >= MP_MED_BASE; j--) {
            if (j > MP_MED_BASE && fsid[j - 1] == mcs.mcs_fsid) {
                uniqfs = false;
                break;
            }
        }

        if (uniqfs) {
            stats->mps_total += mcs.mcs_total;
            stats->mps_available += mcs.mcs_available;
        }
    }

    return 0;
}

struct media_class *
mpool_mclass_handle(struct mpool *mp, enum mpool_mclass mclass)
{
    if (!mp || mclass >= MP_MED_COUNT)
        return NULL;

    return mp->mc[mclass];
}

merr_t
mpool_mclass_dirfd(struct mpool *mp, enum mpool_mclass mclass, int *dirfd)
{
    struct media_class *mc;

    if (!mp || mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    *dirfd = mclass_dirfd(mc);

    return 0;
}

merr_t
mpool_mclass_ftw(
    struct mpool         *mp,
    enum mpool_mclass     mclass,
    const char           *prefix,
    struct mpool_file_cb *cb)
{
    struct media_class *mc;

    if (!mp || mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    return mclass_ftw(mc, prefix, cb);
}

void
mpool_cparams_defaults(struct mpool_cparams *cparams)
{
    int i;

    if (!cparams)
        return;

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        cparams->mclass[i].fmaxsz = MPOOL_MBLOCK_FILESZ_DEFAULT;
        cparams->mclass[i].filecnt = MPOOL_MBLOCK_FILECNT_DEFAULT;
        cparams->mclass[i].mblocksz = MPOOL_MBLOCK_SIZE_DEFAULT;
        cparams->mclass[i].path[0] = '\0';
    }

    strlcpy(cparams->mclass[MP_MED_CAPACITY].path, MPOOL_CAPACITY_MCLASS_DEFAULT_PATH,
            sizeof(cparams->mclass[MP_MED_CAPACITY].path));
}

#if HSE_MOCKING
#include "mpool_ut_impl.i"
#endif
