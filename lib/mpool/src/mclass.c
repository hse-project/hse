/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <ftw.h>

#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/logging.h>

#include "mclass.h"
#include "mblock_fset.h"

/**
 * struct media_class - mclass instance
 *
 * @dirp:     mclass directory stream
 * @mbfsp:    mblock fileset handle
 * @mblocksz: mblock size configured for this mclass
 * @mcid:     mclass ID (persisted in mblock/mdc metadata)
 * @lockfd:   fd of the lock file
 * @dpath:    mclass directory path
 */
struct media_class {
    DIR                *dirp;
    struct mblock_fset *mbfsp;
    size_t              mblocksz;
    enum mclass_id      mcid;
    int                 lockfd;
    char               *dpath;
};

static merr_t
mclass_lockfile_acq(int dirfd, int *lockfd)
{
    int    fd, rc;
    merr_t err;

    fd = openat(dirfd, ".lockfile", O_CREAT | O_EXCL | O_SYNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        if (errno != EEXIST)
            return merr(errno);

        /*
         * Try to reopen file O_RDWR and acquire exclusive lock.
         * If the lock acquisition succeeds, then it's likely
         * that the prior instance crashed.
         */
        fd = openat(dirfd, ".lockfile", O_RDWR);
        if (fd < 0)
            return merr(errno);
    }

    rc = flock(fd, LOCK_EX | LOCK_NB);
    if (rc) {
        err = (errno == EWOULDBLOCK) ? merr(EBUSY) : merr(errno);
        close(fd);
        return err;
    }

    *lockfd = fd;

    return 0;
}

static void
mclass_lockfile_rel(int dirfd, int lockfd)
{
    if (lockfd != -1) {
        flock(lockfd, LOCK_UN);
        close(lockfd);
    }
    unlinkat(dirfd, ".lockfile", 0);
}

merr_t
mclass_open(
    struct mpool         *mp,
    enum mpool_mclass     mclass,
    struct mclass_params *params,
    int                   flags,
    struct media_class  **handle)
{
    struct media_class *mc;
    DIR   *dirp;
    int    lockfd = -1;
    merr_t err;

    if (!mp || !params || !handle || mclass >= MP_MED_COUNT)
        return merr(EINVAL);

    dirp = opendir(params->path);
    if (!dirp) {
        err = merr(errno);
        hse_elog(HSE_ERR "%s: Opening mclass dir %s failed: @@e", err, __func__, params->path);
        return err;
    }

    if (mclass == MP_MED_CAPACITY) {
        err = mclass_lockfile_acq(dirfd(dirp), &lockfd);
        if (err) {
            closedir(dirp);
            return err;
        }
    }

    mc = calloc(1, sizeof(*mc));
    if (!mc) {
        err = merr(ENOMEM);
        goto err_exit2;
    }

    mc->dirp = dirp;
    mc->mcid = mclass_to_mcid(mclass);
    mc->lockfd = lockfd;

    mc->mblocksz = powerof2(params->mblocksz) ? params->mblocksz : MBLOCK_SIZE_BYTES;

    mc->dpath = realpath(params->path, NULL);
    if (!mc->dpath) {
        err = merr(errno);
        goto err_exit2;
    }

    err = mblock_fset_open(mc, params->filecnt, params->fszmax, flags, &mc->mbfsp);
    if (err) {
        hse_elog(HSE_ERR "%s: Opening data files failed, mclass %d: @@e", err, __func__, mclass);
        goto err_exit1;
    }

    *handle = mc;

    return 0;

err_exit1:
    free(mc->dpath);
    free(mc);

err_exit2:
    if (mclass == MP_MED_CAPACITY)
        mclass_lockfile_rel(dirfd(dirp), lockfd);
    closedir(dirp);

    return err;
}

merr_t
mclass_close(struct media_class *mc)
{
    if (!mc)
        return merr(EINVAL);

    mblock_fset_close(mc->mbfsp);

    if (mcid_to_mclass(mc->mcid) == MP_MED_CAPACITY)
        mclass_lockfile_rel(dirfd(mc->dirp), mc->lockfd);

    closedir(mc->dirp);

    free(mc->dpath);
    free(mc);

    return 0;
}

void
mclass_destroy(struct media_class *mc, struct workqueue_struct *wq)
{
    if (!mc)
        return;

    mblock_fset_remove(mc->mbfsp, wq);

    if (mcid_to_mclass(mc->mcid) == MP_MED_CAPACITY)
        mclass_lockfile_rel(dirfd(mc->dirp), mc->lockfd);

    closedir(mc->dirp);

    free(mc->dpath);
    free(mc);
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

    if (!mc || !stats)
        return merr(EINVAL);

    err = mblock_fset_stats_get(mc->mbfsp, stats);
    if (err)
        return err;

    strlcpy(stats->mcs_path, mclass_dpath(mc), sizeof(stats->mcs_path));

    return 0;
}
