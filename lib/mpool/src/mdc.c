/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <dirent.h>

#define MTF_MOCK_IMPL_mpool

#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>

#include <mpool/mpool.h>

#include "mpool_internal.h"
#include "mclass.h"
#include "mdc.h"
#include "mdc_file.h"

/**
 * struct mpool_mdc - MDC handle
 *
 * lock: lock serializing MDC ops
 * mfp1: mdc file pointer 1
 * mfp2: mdc file pointer 2
 * mfpa: active mdc file handle (either mfp1 or mfp2)
 */
struct mpool_mdc {
    struct mutex     lock;
    struct mdc_file *mfp1;
    struct mdc_file *mfp2;
    struct mdc_file *mfpa;
};

merr_t
mpool_mdc_alloc(
    struct mpool     *mp,
    uint32_t          magic,
    size_t            capacity,
    enum hse_mclass   mclass,
    uint64_t         *logid1,
    uint64_t         *logid2)
{
    enum mclass_id mcid;
    uint64_t id[2];
    merr_t   err;
    int      dirfd, flags, mode, i, rc;

    if (!mp || mclass >= HSE_MCLASS_COUNT || capacity < MDC_LOGHDR_LEN || !logid1 || !logid2)
        return merr(EINVAL);

    err = mpool_mclass_dirfd(mp, mclass, &dirfd);
    if (err)
        return err;

    mcid = mclass_to_mcid(mclass);

    flags = O_RDWR | O_CREAT | O_EXCL;
    mode = S_IRUSR | S_IWUSR;

    for (i = 0; i < 2; i++) {
        char name[MDC_NAME_LENGTH_MAX];

        id[i] = logid_make(i, mcid, magic);
        mdc_filename_gen(name, sizeof(name), id[i]);

        err = mdc_file_create(dirfd, name, flags, mode, mclass, capacity);
        if (err) {
            if (i != 0) {
                mdc_filename_gen(name, sizeof(name), id[0]);
                mdc_file_destroy(dirfd, name);
            }

            return err;
        }
    }

    rc = fsync(dirfd);
    if (rc == -1) {
        err = merr(errno);
        mpool_mdc_delete(mp, id[0], id[1]);
        return err;
    }

    *logid1 = id[0];
    *logid2 = id[1];

    return 0;
}

merr_t
mpool_mdc_commit(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    merr_t   err;
    int      dirfd, mcid, i;
    uint64_t id[] = { logid1, logid2 };

    if (!mp || !logids_valid(logid1, logid2))
        return merr(EINVAL);

    mcid = logid_mcid(logid1);
    err = mpool_mclass_dirfd(mp, mcid_to_mclass(mcid), &dirfd);
    if (err)
        return err;

    for (i = 0; i < 2; i++) {
        char name[MDC_NAME_LENGTH_MAX];

        mdc_filename_gen(name, sizeof(name), id[i]);

        err = mdc_file_commit(dirfd, name);
        if (err) {
            while (i >= 0) {
                mdc_filename_gen(name, sizeof(name), id[i--]);
                mdc_file_destroy(dirfd, name);
            }

            return err;
        }
    }

    return 0;
}

merr_t
mpool_mdc_delete(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    merr_t              err, rval = 0;
    int                 dirfd, mcid;
    uint64_t            id[] = { logid1, logid2 };

    if (!mp || !logids_valid(logid1, logid2))
        return merr(EINVAL);

    mcid = logid_mcid(logid1);
    err = mpool_mclass_dirfd(mp, mcid_to_mclass(mcid), &dirfd);
    if (err)
        return err;

    for (int i = 0; i < 2; i++) {
        char name[MDC_NAME_LENGTH_MAX];

        mdc_filename_gen(name, sizeof(name), id[i]);
        err = mdc_file_destroy(dirfd, name);
        if (err)
            rval = err;
    }

    return rval;
}

merr_t
mpool_mdc_abort(struct mpool *mp, uint64_t logid1, uint64_t logid2)
{
    return mpool_mdc_delete(mp, logid1, logid2);
}

merr_t
mpool_mdc_open(
    struct mpool       *mp,
    uint64_t           logid1,
    uint64_t           logid2,
    bool               rdonly,
    struct mpool_mdc **handle)
{
    struct mdc_file  *mfp[2] = {};
    struct mpool_mdc *mdc;
    enum mclass_id    mcid;
    merr_t   err, err1, err2;
    int      dirfd;
    uint64_t gen1, gen2;
    bool     gclose;
    char     name[2][MDC_NAME_LENGTH_MAX];

    if (!mp || !handle || !logids_valid(logid1, logid2))
        return merr(EINVAL);

    mcid = logid_mcid(logid1);
    err = mpool_mclass_dirfd(mp, mcid_to_mclass(mcid), &dirfd);
    if (err)
        return err;

    mdc = calloc(1, sizeof(*mdc));
    if (!mdc)
        return merr(ENOMEM);

    gclose = mclass_gclose_get(mpool_mclass_handle(mp, mcid_to_mclass(mcid)));

    mdc_filename_gen(name[0], sizeof(name[0]), logid1);
    err1 = mdc_file_open(mdc, dirfd, name[0], logid1, rdonly, gclose, &gen1, &mfp[0]);

    mdc_filename_gen(name[1], sizeof(name[1]), logid2);
    err2 = mdc_file_open(mdc, dirfd, name[1], logid2, rdonly, gclose, &gen2, &mfp[1]);

    err = err1 ? err1 : err2;

    /* Handle incomplete log header from a crash during mdc file erase */
    if ((merr_errno(err1) == ENOMSG && !err2) || (!err1 && merr_errno(err2) == ENOMSG)) {
        err = 0;
        if (!err1)
            gen2 = gen1 + 1;
        else
            gen1 = gen2 + 1;
    }

    if (err || (!err && gen1 && gen1 == gen2)) {
        err = err ?: merr(EINVAL);
        log_err("MDC (%lu:%lu) corrupt: bad pair err (%d, %d) gen (%lu, %lu)",
                logid1, logid2, merr_errno(err1), merr_errno(err2), gen1, gen2);
    } else {
        /* active log is valid log with smallest gen */
        if (gen2 < gen1) {
            mdc->mfpa = mfp[1];

            /**
             * Unconditionally erase the passive log.
             * This handles the following crash scenarios:
             * 1. Crash after mdc_cstart but before mdc_cend()
             * 2. Crash after gen update and during passive log erase
             * 3. Crash after passive log erase
             */
            if (!rdonly) {
                err = mdc_file_erase(mfp[0], gen2 + 1);
                if (err)
                    log_errx("mdc file1 logid %lu erase failed, gen (%lu, %lu): @@e",
                             err, logid1, gen1, gen2);
            }
        } else {
            mdc->mfpa = mfp[0];

            if (!rdonly) {
                err = mdc_file_erase(mfp[1], gen1 + 1);
                if (err)
                    log_errx("mdc file2 logid %lu erase failed, gen (%lu, %lu): @@e",
                             err, logid2, gen1, gen2);
            }
        }
    }

    if (!err) {
        mdc->mfp1 = mfp[0];
        mdc->mfp2 = mfp[1];
        mutex_init(&mdc->lock);

        *handle = mdc;
    } else {
        mdc_file_close(mfp[0]);
        mdc_file_close(mfp[1]);
    }

    if (err)
        free(mdc);

    return err;
}

merr_t
mpool_mdc_close(struct mpool_mdc *mdc)
{
    merr_t err, rval = 0;

    if (!mdc)
        return merr(EINVAL);

    mutex_lock(&mdc->lock);

    err = mdc_file_close(mdc->mfp1);
    if (err)
        rval = err;

    err = mdc_file_close(mdc->mfp2);
    if (err)
        rval = err;

    mutex_unlock(&mdc->lock);

    free(mdc);

    return rval;
}

merr_t
mpool_mdc_cstart(struct mpool_mdc *mdc)
{
    struct mdc_file *tgth;
    merr_t           err;

    if (!mdc)
        return merr(EINVAL);

    mutex_lock(&mdc->lock);

    if (mdc->mfpa == mdc->mfp1)
        tgth = mdc->mfp2;
    else
        tgth = mdc->mfp1;

    err = mdc_file_sync(tgth);
    if (!err)
        mdc->mfpa = tgth;

    mutex_unlock(&mdc->lock);

    if (err)
        mpool_mdc_close(mdc);

    return err;
}

merr_t
mpool_mdc_cend(struct mpool_mdc *mdc)
{
    struct mdc_file *srch, *tgth;
    merr_t           err;
    uint64_t         gentgt = 0;

    if (!mdc)
        return merr(EINVAL);

    mutex_lock(&mdc->lock);

    if (mdc->mfpa == mdc->mfp1) {
        tgth = mdc->mfp1;
        srch = mdc->mfp2;
    } else {
        tgth = mdc->mfp2;
        srch = mdc->mfp1;
    }

    err = mdc_file_sync(tgth);
    if (!err) {
        err = mdc_file_gen(tgth, &gentgt);
        if (!err)
            err = mdc_file_erase(srch, gentgt + 1);
    }

    mutex_unlock(&mdc->lock);

    if (err)
        mpool_mdc_close(mdc);

    return err;
}

merr_t
mpool_mdc_sync(struct mpool_mdc *mdc)
{
    merr_t err;

    assert(mdc);

    mutex_lock(&mdc->lock);
    err = mdc_file_sync(mdc->mfpa);
    mutex_unlock(&mdc->lock);

    return err;
}

merr_t
mpool_mdc_rewind(struct mpool_mdc *mdc)
{
    merr_t err;

    if (!mdc)
        return merr(EINVAL);

    mutex_lock(&mdc->lock);
    err = mdc_file_rewind(mdc->mfpa);
    mutex_unlock(&mdc->lock);

    return err;
}

merr_t
mpool_mdc_read(struct mpool_mdc *mdc, void *data, size_t len, size_t *rdlen)
{
    merr_t err;
    bool   verify = false;

    if (!mdc || !data)
        return merr(EINVAL);

    mutex_lock(&mdc->lock);
    err = mdc_file_read(mdc->mfpa, data, len, verify, rdlen);
    mutex_unlock(&mdc->lock);
    if (err && (merr_errno(err) != EOVERFLOW))
        log_errx("mdc %p read failed, mdc file %p len %lu: @@e",
                 err, mdc, mdc->mfpa, len);

    return err;
}

merr_t
mpool_mdc_append(struct mpool_mdc *mdc, void *data, size_t len, bool sync)
{
    merr_t err;

    if (!mdc || !data)
        return merr(EINVAL);

    mutex_lock(&mdc->lock);
    err = mdc_file_append(mdc->mfpa, data, len, sync);
    mutex_unlock(&mdc->lock);
    if (err)
        log_errx("mdc %p append failed, mdc file %p, len %lu sync %d: @@e",
                 err, mdc, mdc->mfpa, len, sync);

    return err;
}

merr_t
mpool_mdc_usage(struct mpool_mdc *mdc, uint64_t *size, uint64_t *allocated, uint64_t *used)
{
    merr_t   err;

    if (!mdc || !size || !allocated || !used)
        return merr(EINVAL);

    mutex_lock(&mdc->lock);

    if (mdc->mfpa == mdc->mfp1)
        err = mdc_file_stats(mdc->mfp1, size, allocated, used);
    else
        err = mdc_file_stats(mdc->mfp2, size, allocated, used);

    mutex_unlock(&mdc->lock);

    return err;
}
