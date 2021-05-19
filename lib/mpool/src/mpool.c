/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_mpool

#include <stdlib.h>
#include <fcntl.h>

#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/string.h>
#include <hse_util/workqueue.h>

#include <hse/hse.h>
#include <mpool/mpool.h>

#include "mpool_internal.h"
#include "mblock_fset.h"
#include "mblock_file.h"
#include "mdc.h"

#define UUID_STRLEN 36

/**
 * struct mpool - mpool handle
 *
 * @mc:   media class handles
 * @name: mpool/kvdb name
 */
struct mpool {
    struct media_class *mc[MP_MED_COUNT];

    char name[64];
};

/*
 * TODO: The below param parsing logic will go away with config updates.
 */
enum param_key_index {
    PARAM_PATH     = 0,
    PARAM_ENV_PATH = 1,
    PARAM_OBJSZ    = 2,
    PARAM_FCNT     = 3,
    PARAM_FSIZE    = 4,
    PARAM_MAX      = 5,
};

static const char *param_key[PARAM_MAX][MP_MED_COUNT] =
{
    { "kvdb.storage_path", "kvdb.staging_path" },
    { "HSE_STORAGE_PATH", "HSE_STAGING_PATH" },
    { "kvdb.storage_objsz", "kvdb.staging_objsz" },
    { "kvdb.storage_filecnt", "kvdb.staging_filecnt" },
    { "kvdb.storage_filesz", "kvdb.staging_filesz" },
};

static merr_t
mclass_params_init(enum mpool_mclass mclass, struct mclass_params *mcp)
{
    char *path;

    path = getenv(param_key[PARAM_ENV_PATH][mclass]);
    if (path) {
        size_t n;

        n = strlcpy(mcp->path, path, sizeof(mcp->path));
        if (n >= sizeof(mcp->path))
            return merr(EINVAL);
    }

    mcp->mblocksz = MBLOCK_SIZE_BYTES;
    mcp->filecnt = MBLOCK_FSET_FILES_DEFAULT;
    mcp->fszmax = MBLOCK_FILE_SIZE_MAX;

    return 0;
}

static merr_t
hse_to_mclass_params(
    const struct hse_params *params,
    enum mpool_mclass        mclass,
    struct mclass_params    *mcp)
{
    char buf[PATH_MAX];

    if (!params)
        return 0;

    if (hse_params_get(params, param_key[PARAM_PATH][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0') {
        size_t n;

        n = strlcpy(mcp->path, buf, sizeof(mcp->path));
        if (n >= sizeof(mcp->path))
            return merr(EINVAL);
    }

    if (hse_params_get(params, param_key[PARAM_OBJSZ][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0') {
        mcp->mblocksz = atoi(buf);
        mcp->mblocksz <<= 20;
    }

    if (hse_params_get(params, param_key[PARAM_FCNT][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0')
        mcp->filecnt = atoi(buf);

    if (hse_params_get(params, param_key[PARAM_FSIZE][mclass], buf, sizeof(buf), NULL) &&
        buf[0] != '\0') {
        mcp->fszmax = atoi(buf);
        mcp->fszmax <<= 30;
    }

    return 0;
}

merr_t
mpool_open(const char *name, const struct hse_params *params, uint32_t flags, struct mpool **handle)
{
    struct mpool *mp;
    merr_t        err;
    int           i;

    if (!name || !handle)
        return merr(EINVAL);

    *handle = NULL;

    mp = calloc(1, sizeof(*mp));
    if (!mp)
        return merr(ENOMEM);

    if (flags & O_CREAT)
        flags |= O_RDWR;

    for (i = MP_MED_BASE; i < MP_MED_COUNT; i++) {
        struct mclass_params mcp = {};

        err = mclass_params_init(i, &mcp);
        if (err)
            goto errout;

        err = hse_to_mclass_params(params, i, &mcp);
        if (err)
            goto errout;

        if (mcp.path[0] != '\0') {
            int flags2 = 0;

            for (int j = i - 1; j >= 0; j--) {
                if (mp->mc[j] && !strcmp(mcp.path, mclass_dpath(mp->mc[j]))) {
                    err = merr(EINVAL);
                    hse_log(
                        HSE_ERR "%s: Duplicate storage path detected for mc %d and %d",
                        __func__,
                        i,
                        j);
                    goto errout;
                }
            }

            do {
                err = mclass_open(mp, i, &mcp, flags | flags2, &mp->mc[i]);
                if (err) {
                    if (i != MP_MED_CAPACITY && merr_errno(err) == ENOENT && !(flags & O_CREAT) &&
                        !(flags2 & O_CREAT)) {
                        /* Don't initialize new mclass for O_RDONLY open */
                        if ((flags & O_ACCMODE) == O_RDONLY) {
                            err = 0;
                            break;
                        }

                        flags2 = (O_CREAT | O_RDWR);
                        continue;
                    }

                    if (err) {
                        hse_elog(
                            HSE_ERR "%s: Cannot access storage path for mclass %d: @@e",
                            err,
                            __func__,
                            i);
                        goto errout;
                    }
                }
                break;
            } while (true);
        } else if (i == MP_MED_CAPACITY) {
            err = merr(EINVAL);
            hse_log(HSE_ERR "%s: storage path not set for %s", __func__, name);
            goto errout;
        }
    }

    strlcpy(mp->name, name, sizeof(mp->name));

    err = mpool_mdc_root_init(mp);
    if (err)
        goto errout;

    *handle = mp;

    return 0;

errout:
    while (i-- > MP_MED_BASE) {
        if (flags & O_CREAT)
            mclass_destroy(mp->mc[i], NULL);
        else
            mclass_close(mp->mc[i]);
    }

    free(mp);

    return err;
}

merr_t
mpool_close(struct mpool *mp)
{
    merr_t err = 0;
    int    i;

    if (!mp)
        return merr(EINVAL);

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
mpool_destroy(struct mpool *mp)
{
    struct workqueue_struct *mpdwq;
    merr_t                   err;
    int                      i;

    if (!mp)
        return merr(EINVAL);

    err = mpool_mdc_root_destroy(mp);
    if (err)
        return err;

    mpdwq = alloc_workqueue("mp_destroy", 0, MP_DESTROY_THREADS);
    ev(!mpdwq);

    for (i = MP_MED_COUNT - 1; i >= MP_MED_BASE; i--) {
        if (mp->mc[i])
            mclass_destroy(mp->mc[i], mpdwq);
    }

    destroy_workqueue(mpdwq);
    free(mp);

    return 0;
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
        props->mc_mblocksz = mclass_mblocksz_get(mc) >> 20;

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
        struct mpool_mclass_props mcp = {};
        merr_t                    err;

        err = mpool_mclass_props_get(mp, i, &mcp);
        if (err) {
            if (merr_errno(err) == ENOENT)
                continue;
            return err;
        }

        props->mp_mblocksz[i] = mcp.mc_mblocksz;
    }

    props->mp_vma_size_max = 30;

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

#if HSE_MOCKING
#include "mpool_ut_impl.i"
#endif
