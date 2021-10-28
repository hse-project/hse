/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <ftw.h>

#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/logging.h>
#include <hse_util/workqueue.h>
#include <mpool/mpool_structs.h>

#include "mclass.h"
#include "mdc.h"
#include "mdc_file.h"
#include "mblock_fset.h"

#define MCLASS_FILES_MAX   (MBLOCK_FSET_FILES_MAX)

/**
 * struct media_class - mclass instance
 *
 * @dirp:     mclass directory stream
 * @mbfsp:    mblock fileset handle
 * @mblocksz: mblock size configured for this mclass
 * @mcid:     mclass ID (persisted in mblock/mdc metadata)
 * @dpath:    mclass directory path
 */
struct media_class {
    DIR *               dirp;
    struct mblock_fset *mbfsp;
    size_t              mblocksz;
    enum mclass_id      mcid;
    char *              dpath;
};

merr_t
mclass_open(
    enum mpool_mclass           mclass,
    const struct mclass_params *params,
    int                         flags,
    struct media_class **       handle)
{
    struct media_class *mc;
    DIR *               dirp;
    merr_t              err;

    if (!params || !handle || mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    dirp = opendir(params->path);
    if (!dirp) {
        err = merr(errno);
        log_errx("Opening mclass dir %s failed: @@e", err, params->path);
        return err;
    }

    mc = calloc(1, sizeof(*mc));
    if (!mc) {
        err = merr(ENOMEM);
        goto err_exit2;
    }

    mc->dirp = dirp;
    mc->mcid = mclass_to_mcid(mclass);

    mc->mblocksz = powerof2(params->mblocksz) ? params->mblocksz : MPOOL_MBLOCK_SIZE_DEFAULT;

    mc->dpath = realpath(params->path, NULL);
    if (!mc->dpath) {
        err = merr(errno);
        goto err_exit1;
    }

    err = mblock_fset_open(mc, params->filecnt, params->fmaxsz, flags, &mc->mbfsp);
    if (err) {
        log_errx("Opening data files failed, mclass %d: @@e", err, mclass);
        goto err_exit1;
    }

    *handle = mc;

    return 0;

err_exit1:
    free(mc->dpath);
    free(mc);

err_exit2:
    closedir(dirp);

    return err;
}

merr_t
mclass_close(struct media_class *mc)
{
    if (!mc)
        return merr(EINVAL);

    mblock_fset_close(mc->mbfsp);
    closedir(mc->dirp);
    free(mc->dpath);
    free(mc);

    return 0;
}

static bool
mclass_files_prefix(const char *path)
{
    const char *base = basename(path);

    return strstr(base, MBLOCK_FILE_PFX) || strstr(base, MDC_FILE_PFX) ||
        strstr(base, WAL_FILE_PFX);
}

static struct workqueue_struct *mpdwq;
static int pathc_per_thr, pathidx, filecnt;

static struct mp_destroy_work {
    struct work_struct work;
    char             **path;
    int                pathc;
    int                curpc;
} **mpdw;

static void
remove_path(struct work_struct *work)
{
    struct mp_destroy_work *mpdw;

    mpdw = container_of(work, struct mp_destroy_work, work);

    for (int i = 0; i < mpdw->pathc; i++)
        remove(mpdw->path[i]);
}

static int
mclass_removecb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (typeflag == FTW_D && ftwbuf->level > 0)
        return FTW_SKIP_SUBTREE;

    if (typeflag == FTW_D)
        return FTW_CONTINUE;

    if (mclass_files_prefix(path)) {
        struct mp_destroy_work *w;

        if (!mpdwq) {
            remove(path);
            return FTW_CONTINUE;
        }

        w = mpdw[pathidx / pathc_per_thr];

        if (ev(w->pathc == 0)) {
            remove(path);
            return FTW_CONTINUE;
        }

        strlcpy(w->path[pathidx++ % pathc_per_thr], path, PATH_MAX);
        if (++w->curpc == w->pathc) {
            INIT_WORK(&w->work, remove_path);

            if (!queue_work(mpdwq, &w->work)) {
                for (int i = 0; i < w->pathc; i++)
                    remove(w->path[i]);
            }
        }
    }

    return FTW_CONTINUE;
}

static int
mclass_filecnt_get(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (typeflag == FTW_D && ftwbuf->level > 0)
        return FTW_SKIP_SUBTREE;

    if (typeflag == FTW_D)
        return FTW_CONTINUE;

    if (mclass_files_prefix(path))
        filecnt++;

    return FTW_CONTINUE;
}

static void
mclass_destroy_setup(uint8_t filecnt, struct workqueue_struct *wq)
{
    size_t worksz, sz;
    int    pathc, workc, fcnt;

    workc = MP_DESTROY_THREADS;
    pathc = filecnt / workc;
    if (filecnt % workc)
        pathc++;

    worksz = sizeof(*mpdw) + pathc * (sizeof((*mpdw)->path) + PATH_MAX);
    sz = workc * (sizeof(mpdw) + worksz);
    mpdw = calloc(1, sz);
    if (ev(!mpdw))
        return;

    pathidx = 0;
    mpdwq = wq;
    pathc_per_thr = pathc;
    fcnt = 0;

    for (int i = 0; i < workc; i++) {
        struct mp_destroy_work *w;
        char                   *p;

        w = (struct mp_destroy_work *)((char *)(mpdw + workc) + (i * worksz));
        mpdw[i] = w;

        w->path = (char **)(w + 1);
        p = (char *)(w->path + pathc);

        for (int j = 0; j < pathc; j++)
            w->path[j] = p + j * PATH_MAX;

        w->pathc = pathc;
        if (fcnt + pathc > filecnt) {
            w->pathc = filecnt - fcnt;
            break;
        }
        fcnt += pathc;
    }
}

static void
mclass_destroy_teardown(void)
{
    flush_workqueue(mpdwq);
    mpdwq = NULL;
    free(mpdw);
    mpdw = NULL;
}

bool
mclass_files_exist(const char *path)
{
    filecnt = 0;

    nftw(path, mclass_filecnt_get, MCLASS_FILES_MAX, FTW_PHYS | FTW_ACTIONRETVAL);

    return filecnt > 0;
}

int
mclass_destroy(const char *path, struct workqueue_struct *wq)
{
    if (access(path, F_OK) == -1)
        return 0;

    if (!mclass_files_exist(path))
        return 0;

    if (wq)
        mclass_destroy_setup(filecnt, wq);

    nftw(path, mclass_removecb, MCLASS_FILES_MAX, FTW_PHYS | FTW_ACTIONRETVAL);

    if (wq)
        mclass_destroy_teardown();

    return filecnt;
}

int
mclass_id(struct media_class *mc)
{
    return mc ? mc->mcid : MCID_INVALID;
}

int
mclass_dirfd(struct media_class *mc)
{
    return mc ? dirfd(mc->dirp) : -1;
}

const char *
mclass_dpath(struct media_class *mc)
{
    return mc ? mc->dpath : NULL;
}

struct mblock_fset *
mclass_fset(struct media_class *mc)
{
    return mc ? mc->mbfsp : NULL;
}

size_t
mclass_mblocksz_get(struct media_class *mc)
{
    return mc ? mc->mblocksz : 0;
}

void
mclass_mblocksz_set(struct media_class *mc, size_t mblocksz)
{
    if (ev(!mc))
        return;

    mc->mblocksz = mblocksz;
}

enum mclass_id
mclass_to_mcid(enum mpool_mclass mclass)
{
    switch (mclass) {
        case MP_MED_CAPACITY:
            return MCID_CAPACITY;

        case MP_MED_STAGING:
            return MCID_STAGING;

        default:
            break;
    }

    return MCID_INVALID;
}

enum mpool_mclass
mcid_to_mclass(enum mclass_id mcid)
{
    switch (mcid) {
        case MCID_CAPACITY:
            return MP_MED_CAPACITY;

        case MCID_STAGING:
            return MP_MED_STAGING;

        default:
            break;
    }

    return MP_MED_INVALID;
}

merr_t
mclass_stats_get(struct media_class *mc, struct mpool_mclass_stats *stats)
{
    merr_t err;

    assert(mc);
    assert(stats);

    err = mblock_fset_stats_get(mc->mbfsp, stats);
    if (err)
        return err;

    strlcpy(stats->mcs_path, mclass_dpath(mc), sizeof(stats->mcs_path));

    return 0;
}

merr_t
mclass_ftw(struct media_class *mc, const char *prefix, struct mpool_file_cb *cb)
{
    assert(mc);

    int
    mclass_file_cb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
    {
        if (typeflag == FTW_D && ftwbuf->level > 0)
            return FTW_SKIP_SUBTREE;

        if (typeflag == FTW_D)
            return FTW_CONTINUE;

        if (!prefix || strstr(basename(path), prefix))
            cb->cbfunc(cb->cbarg, path);

        return FTW_CONTINUE;
    }

    nftw(mc->dpath, mclass_file_cb, MCLASS_FILES_MAX, FTW_PHYS | FTW_ACTIONRETVAL);

    return 0;
}
