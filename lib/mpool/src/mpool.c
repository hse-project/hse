/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_mpool

#include <limits.h>
#include <bsd/string.h>
#include <sys/vfs.h>

#if __linux__
#include <linux/magic.h>
#endif

#include <hse/hse.h>

#include <hse_util/assert.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/workqueue.h>
#include <hse_util/page.h>
#include <hse_util/dax.h>

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
    struct media_class *mc[HSE_MCLASS_COUNT];
    const char          home[]; /* flexible array */
};

static merr_t
mpool_to_mclass_params(
    enum hse_mclass           mc,
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
    mcp->filecnt = MPOOL_MCLASS_FILECNT_DEFAULT;
    mcp->fmaxsz = MPOOL_MCLASS_FILESZ_DEFAULT;

    return 0;
}

static merr_t
mclass_path_check(enum hse_mclass mclass, const char *path)
{
    merr_t err;
    bool isdax;

    if (path[0] == '\0')
        return 0;

    err = dax_path_is_fsdax(path, &isdax);
    if (err)
        return err;

    if (isdax != (mclass == HSE_MCLASS_PMEM)) {
        log_err("%s mclass path (%s) %s reside on a DAX filesystem",
                hse_mclass_name_get(mclass), path,
                isdax ? "must not" : "must");
        return merr(ENOTSUP);
    }

    return 0;
}

/*
 * This function currently uses a Linux-specific statfs(2) syscall.
 *
 * A portable way to implement this will be to traverse all mounted file-systems using
 * getmntent() and check whether the device ID ('st_dev' from stat(2)) of any of the
 * tmpfs file-systems matches with the device ID of 'path'.
 *
 * At this point, using statfs(2) is lightweight and this can be revisited when we
 * port HSE to other platforms.
 */
static merr_t
mclass_path_is_tmpfs(const char *path, bool *tmpfs)
{
    struct statfs sbuf;
    int rc;

    INVARIANT(path);
    INVARIANT(tmpfs);

    *tmpfs = false;

    if (path[0] == '\0')
        return 0;

    rc = statfs(path, &sbuf);
    if (rc == -1)
        return merr(errno);

    *tmpfs = (sbuf.f_type == TMPFS_MAGIC);

    return 0;
}

static merr_t
mpool_mclass_open(
    struct mpool               *mp,
    enum hse_mclass             mclass,
    const struct mclass_params *mcp,
    uint32_t                    flags,
    struct media_class **       mc)
{
    merr_t err;
    char * path = NULL;

    if (!mp || !mcp || !mc)
        return merr(EINVAL);

    if (mcp->path[0] == '\0')
        return 0;

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
mpool_mclass_add(enum hse_mclass mclass, const struct mpool_cparams *cparams)
{
    struct media_class *mc;
    struct mclass_params mcp = {0};
    merr_t              err = 0;
    int                 flags = 0;

    if (!cparams || cparams->mclass[mclass].path[0] == '\0')
        return merr(EINVAL);

    err = mpool_to_mclass_params(mclass, cparams, &mcp);
    if (err)
        return err;

    err = mclass_path_check(mclass, mcp.path);
    if (err)
        return err;

    flags |= (O_CREAT | O_RDWR);
    err = mclass_open(mclass, &mcp, flags, &mc);
    if (!err)
        mclass_close(mc);

    return err;
}

void
mpool_mclass_destroy(enum hse_mclass mclass, const struct mpool_dparams *dparams)
{
    const char *path;

    if (!dparams || mclass == HSE_MCLASS_CAPACITY)
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
    bool          rmdefault[HSE_MCLASS_COUNT] = { 0 };

    if (!home || !cparams)
        return merr(EINVAL);

    sz = sizeof(*mp) + strlen(home) + 1;
    mp = calloc(1, sz);
    if (!mp)
        return merr(ENOMEM);

    strcpy((char *)mp->home, home);
    flags |= (O_CREAT | O_RDWR);

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        struct mclass_params mcp = {0};

        /* If the capacity/pmem path is the default, automatically create it */
        if (i == HSE_MCLASS_CAPACITY || i == HSE_MCLASS_PMEM) {
            char   path[PATH_MAX];
            size_t n;

            n = snprintf(path, sizeof(path), "%s/%s", home,
                         (i == HSE_MCLASS_CAPACITY) ? MPOOL_CAPACITY_MCLASS_DEFAULT_PATH :
                         MPOOL_PMEM_MCLASS_DEFAULT_PATH);
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
                    rmdefault[i] = true;
                } else {
                    err = merr(errno);
                    goto errout;
                }
            }
        }

        err = mpool_to_mclass_params(i, cparams, &mcp);
        if (err)
            goto errout;

        err = mclass_path_check(i, mcp.path);
        if (err)
            goto errout;

        err = mpool_mclass_open(mp, i, &mcp, flags, &mp->mc[i]);
        if (err)
            goto errout;
    }

    mpool_close(mp);

    return 0;

errout:
    if (rmdefault[i])
        remove(cparams->mclass[i].path);

    while (i-- > HSE_MCLASS_BASE) {
        mclass_close(mp->mc[i]);
        mclass_destroy(cparams->mclass[i].path, NULL);

        if (rmdefault[i])
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

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        struct mclass_params mcp = {0};
        uint32_t oflags = flags;

        err = mclass_params_init(rparams->mclass[i].path, &mcp);
        if (err)
            goto errout;

        if (!rparams->mclass[i].dio_disable) {
            bool tmpfs;

            err = mclass_path_is_tmpfs(mcp.path, &tmpfs);
            if (err)
                goto errout;

            if (!tmpfs)
                oflags |= O_DIRECT;
            else
                log_info("Disabling direct I/O access as the mclass (%d) path (%s) is on a tmpfs",
                         i, mcp.path);
        }

        err = mpool_mclass_open(mp, i, &mcp, oflags, &mp->mc[i]);
        if (err)
            goto errout;
    }

    *handle = mp;

    return 0;

errout:
    while (i-- > HSE_MCLASS_BASE)
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

    for (i = HSE_MCLASS_COUNT - 1; i >= HSE_MCLASS_BASE; i--) {
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

    mpdwq = alloc_workqueue("hse_mp_destroy", 0, 1, MP_DESTROY_THREADS);
    ev(!mpdwq);

    for (int i = HSE_MCLASS_COUNT - 1; i >= HSE_MCLASS_BASE; i--) {
        const char *path = dparams->mclass[i].path;

        if (path[0] != '\0')
            filecnt += mclass_destroy(path, mpdwq);
    }

    destroy_workqueue(mpdwq);

    snprintf(path, sizeof(path), "%s/%s", home, MPOOL_CAPACITY_MCLASS_DEFAULT_PATH);
    if (!strcmp(path, dparams->mclass[HSE_MCLASS_CAPACITY].path) && !remove(path))
        filecnt++;

    snprintf(path, sizeof(path), "%s/%s", home, MPOOL_PMEM_MCLASS_DEFAULT_PATH);
    if (!strcmp(path, dparams->mclass[HSE_MCLASS_PMEM].path) && !remove(path))
        filecnt++;

    return filecnt > 0 ? 0 : merr(ENOENT);
}

merr_t
mpool_mclass_props_get(struct mpool *mp, enum hse_mclass mclass, struct mpool_mclass_props *props)
{
    struct media_class *mc;

    if (!mp || mclass >= HSE_MCLASS_COUNT || !props)
        return merr(EINVAL);

    memset(props, 0, sizeof(*props));

    mc = mp->mc[mclass];
    if (!mc)
        return merr(ENOENT);

    mclass_props_get(mc, props);

    return 0;
}

merr_t
mpool_mclass_info_get(
    struct mpool *          mp,
    const enum hse_mclass mclass,
    struct hse_mclass_info *info)
{
    struct media_class *mc;

    if (!mp || mclass >= HSE_MCLASS_COUNT || !info)
        return merr(EINVAL);

    mc = mp->mc[mclass];
    if (!mc)
        return merr(ENOENT);

    memset(info, 0, sizeof(*info));

    return mclass_info_get(mc, info);
}

merr_t
mpool_props_get(struct mpool *mp, struct mpool_props *props)
{
    int i;

    if (!mp || !props)
        return merr(EINVAL);

    memset(props, 0, sizeof(*props));

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        merr_t err;

        err = mpool_mclass_props_get(mp, i, &props->mclass[i]);
        if (err) {
            if (merr_errno(err) == ENOENT)
                continue;
            return err;
        }
    }

    return 0;
}

merr_t
mpool_info_get(struct mpool *mp, struct mpool_info *info)
{
    if (!mp || !info)
        return merr(EINVAL);

    memset(info, 0, sizeof(*info));

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        merr_t err;

        err = mpool_mclass_info_get(mp, i, &info->mclass[i]);
        if (err) {
            if (merr_errno(err) == ENOENT)
                continue;
            return err;
        }
    }

    return 0;
}

struct media_class *
mpool_mclass_handle(struct mpool *mp, enum hse_mclass mclass)
{
    if (!mp || mclass >= HSE_MCLASS_COUNT)
        return NULL;

    return mp->mc[mclass];
}

merr_t
mpool_mclass_dirfd(struct mpool *mp, enum hse_mclass mclass, int *dirfd)
{
    struct media_class *mc;

    if (!mp || mclass >= HSE_MCLASS_COUNT)
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
    enum hse_mclass     mclass,
    const char           *prefix,
    struct mpool_file_cb *cb)
{
    struct media_class *mc;

    if (!mp || mclass >= HSE_MCLASS_COUNT)
        return merr(EINVAL);

    mc = mpool_mclass_handle(mp, mclass);
    if (!mc)
        return merr(ENOENT);

    return mclass_ftw(mc, prefix, cb);
}

bool
mpool_mclass_is_configured(struct mpool *const mp, const enum hse_mclass mclass)
{
    return !!mpool_mclass_handle(mp, mclass);
}

void
mpool_cparams_defaults(struct mpool_cparams *cparams)
{
    int i;

    if (!cparams)
        return;

    for (i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        cparams->mclass[i].fmaxsz = MPOOL_MCLASS_FILESZ_DEFAULT;
        cparams->mclass[i].filecnt = MPOOL_MCLASS_FILECNT_DEFAULT;
        cparams->mclass[i].mblocksz = MPOOL_MBLOCK_SIZE_DEFAULT;
        cparams->mclass[i].path[0] = '\0';
    }

    strlcpy(cparams->mclass[HSE_MCLASS_CAPACITY].path, MPOOL_CAPACITY_MCLASS_DEFAULT_PATH,
            sizeof(cparams->mclass[HSE_MCLASS_CAPACITY].path));
}

#if HSE_MOCKING
#include "mpool_ut_impl.i"
#endif
