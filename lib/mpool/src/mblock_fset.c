/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <ftw.h>

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>
#include <hse_util/page.h>
#include <hse_util/string.h>
#include <hse_util/workqueue.h>

#include "omf.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

#define MBLOCK_FSET_HDRLEN (4096)

/**
 * struct mblock_fset - mblock fileset instance
 *
 * @mc:        media class handle
 *
 * @fidx:      next file index to use for allocation
 * @fszmax:    max mblock data file size
 * @filev:     vector of mblock file handles
 * @fcnt:      mblock file count
 *
 * @maddr:     mapped addr of the mblock metadata file
 * @metasz:    size of the per-class mblock metadata file
 * @metafd:    fd of the mblock fileset meta file
 * @mlock:     whether the mlock the mapped meta file
 * @meta_name: mblock fileset meta file name
 */
struct mblock_fset {
    struct media_class *mc;

    atomic64_t           fidx;
    size_t               fszmax;
    struct mblock_file **filev;
    int                  fcnt;

    char  *maddr;
    size_t metasz;
    int    metafd;
    bool   mlock;
    char   mname[32];
};

static void
mblock_metahdr_init(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
    mh->vers = MBLOCK_METAHDR_VERSION;
    mh->magic = MBLOCK_METAHDR_MAGIC;
    mh->fszmax_gb = mbfsp->fszmax >> 30;
    mh->mblksz_mb = mclass_mblocksz_get(mbfsp->mc) >> 20;
    mh->mcid = mclass_id(mbfsp->mc);
    mh->fcnt = mbfsp->fcnt;
    mh->blkbits = MBID_BLOCK_BITS;
    mh->mcbits = MBID_MCID_BITS;
}

static bool
mblock_metahdr_validate(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
    return (mh->vers == MBLOCK_METAHDR_VERSION) && (mh->magic == MBLOCK_METAHDR_MAGIC) &&
           (mh->mcid == mclass_id(mbfsp->mc)) && (mh->blkbits == MBID_BLOCK_BITS) &&
           (mh->mcbits == MBID_MCID_BITS);
}

static void
mblock_fset_meta_get(struct mblock_fset *mbfsp, int fidx, char **maddr)
{
    off_t off;

    off = MBLOCK_FSET_HDRLEN +
        (fidx * mblock_file_meta_len(mbfsp->fszmax, mclass_mblocksz_get(mbfsp->mc)));

    *maddr = mbfsp->maddr + off;
}

static merr_t
mblock_fset_meta_mmap(struct mblock_fset *mbfsp, int fd, size_t sz, int flags, bool mlock)
{
    int   prot, mode;
    char *addr;

    mode = (flags & O_ACCMODE);
    prot = (mode == O_RDWR ? (PROT_READ | PROT_WRITE) : 0);
    prot |= (mode == O_RDONLY ? PROT_READ : 0);
    prot |= (mode == O_WRONLY ? PROT_WRITE : 0);

    addr = mmap(NULL, sz, prot, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
        return merr(errno);

    mbfsp->maddr = addr;
    mbfsp->mlock = false;

    if (mlock) {
        int rc;

        rc = mlock2(addr, sz, MLOCK_ONFAULT);
        if (!rc)
            mbfsp->mlock = true;
        else
            ev(1);
    }

    return 0;
}

static void
mblock_fset_meta_unmap(struct mblock_fset *mbfsp, size_t sz)
{
    char *addr = mbfsp->maddr;

    if (addr) {
        if (mbfsp->mlock) {
            munlock(addr, sz);
            mbfsp->mlock = false;
        }
        munmap(addr, sz);
    }

    mbfsp->maddr = NULL;
}

static merr_t
mblock_fset_meta_format(struct mblock_fset *mbfsp, int flags)
{
    struct mblock_metahdr mh = {};

    char  *addr;
    int    rc, len = MBLOCK_FSET_HDRLEN;
    merr_t err = 0;
    bool   unmap = false;

    addr = mbfsp->maddr;
    if (!addr) {
        err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, len, flags, false);
        if (err)
            return err;

        addr = mbfsp->maddr;
        unmap = true;
    }

    mblock_metahdr_init(mbfsp, &mh);
    omf_mblock_metahdr_pack_htole(&mh, addr);

    rc = msync(addr, len, MS_SYNC);
    if (rc < 0)
        err = merr(errno);

    rc = fsync(mbfsp->metafd);
    if (rc < 0)
        err = merr(errno);

    if (unmap)
        mblock_fset_meta_unmap(mbfsp, len);

    return err;
}

static merr_t
mblock_fset_meta_load(struct mblock_fset *mbfsp, int flags)
{
    struct mblock_metahdr mh = {};

    bool   valid, unmap = false;
    char  *addr;
    merr_t err = 0;
    int    len = MBLOCK_FSET_HDRLEN;

    addr = mbfsp->maddr;
    if (!addr) {
        err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, len, flags, false);
        if (err)
            return err;

        addr = mbfsp->maddr;
        unmap = true;
    }

    /* Validate meta header */
    omf_mblock_metahdr_unpack_letoh(addr, &mh);
    valid = mblock_metahdr_validate(mbfsp, &mh);
    if (!valid)
        err = merr(EBADMSG);

    if (!err) {
        mbfsp->fcnt = mh.fcnt;
        mbfsp->fszmax = (uint64_t)mh.fszmax_gb << 30;
        mclass_mblocksz_set(mbfsp->mc, (size_t)mh.mblksz_mb << 20);
    }

    if (unmap)
        mblock_fset_meta_unmap(mbfsp, len);

    return err;
}

static void
mblock_fset_meta_close(struct mblock_fset *mbfsp)
{
    if (mbfsp->maddr) {
        msync(mbfsp->maddr, mbfsp->metasz, MS_SYNC);
        mblock_fset_meta_unmap(mbfsp, mbfsp->metasz);
    }

    if (mbfsp->metafd != -1) {
        fsync(mbfsp->metafd);
        close(mbfsp->metafd);
        mbfsp->metafd = -1;
    }
}

static void
mblock_fset_meta_remove(int dirfd, const char *name)
{
    unlinkat(dirfd, name, 0);
}

static void
mblock_fset_free(struct mblock_fset *mbfsp)
{
    free(mbfsp->filev);
    free(mbfsp);
}

/* Init metadata file that persists mblocks in the data files */
static merr_t
mblock_fset_meta_open(struct mblock_fset *mbfsp, int flags)
{
    int    fd, dirfd, rc;
    merr_t err;
    bool   create = false;

    mbfsp->metafd = -1;

    flags &= (O_RDWR | O_RDONLY | O_WRONLY | O_CREAT);
    if (flags & O_CREAT) {
        flags |= O_EXCL;
        create = true;
    }

    snprintf(mbfsp->mname, sizeof(mbfsp->mname), "%s-%d", "mblock-meta", mclass_id(mbfsp->mc));
    dirfd = mclass_dirfd(mbfsp->mc);

    rc = faccessat(dirfd, mbfsp->mname, F_OK, 0);
    if (rc < 0 && errno == ENOENT && !create)
        return merr(ENOENT);
    if (rc == 0 && create)
        return merr(EEXIST);

    fd = openat(dirfd, mbfsp->mname, flags, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return merr(errno);
    mbfsp->metafd = fd;

    /* Preallocate metadata file. */
    if (create) {
        size_t sz;

        assert(mbfsp->fcnt != 0);
        sz = MBLOCK_FSET_HDRLEN +
            (mbfsp->fcnt * mblock_file_meta_len(mbfsp->fszmax, mclass_mblocksz_get(mbfsp->mc)));

        rc = fallocate(fd, 0, 0, sz);
        if (rc < 0) {
            if (errno != EOPNOTSUPP) {
                err = merr(errno);
                goto errout;
            }

            rc = ftruncate(fd, sz);
            if (rc < 0) {
                err = merr(errno);
                goto errout;
            }
        }
    }

    if (create)
        err = mblock_fset_meta_format(mbfsp, flags);
    else
        err = mblock_fset_meta_load(mbfsp, flags);
    if (err)
        goto errout;

    return 0;

errout:
    mblock_fset_meta_close(mbfsp);
    if (create)
        mblock_fset_meta_remove(dirfd, mbfsp->mname);

    return err;
}

merr_t
mblock_fset_open(
    struct media_class  *mc,
    uint8_t              fcnt,
    size_t               fszmax,
    int                  flags,
    struct mblock_fset **handle)
{
    struct mblock_fset        *mbfsp;
    struct mblock_file_params  fparams;

    size_t sz, mblocksz;
    merr_t err;
    int    i;

    if (!mc || !handle)
        return merr(EINVAL);

    mbfsp = calloc(1, sizeof(*mbfsp));
    if (!mbfsp)
        return merr(ENOMEM);

    mbfsp->mc = mc;
    mbfsp->fcnt = fcnt ?: MBLOCK_FSET_FILES_DEFAULT;
    mbfsp->fszmax = fszmax ? : MBLOCK_FILE_SIZE_MAX;

    err = mblock_fset_meta_open(mbfsp, flags);
    if (err) {
        mblock_fset_free(mbfsp);
        return err;
    }

    mblocksz = mclass_mblocksz_get(mbfsp->mc);
    if ((mbfsp->fszmax < mblocksz) ||
        ((1ULL << MBID_BLOCK_BITS) * mblocksz < mbfsp->fszmax)) {
        err = merr(EINVAL);
        hse_log(HSE_ERR "%s: Invalid mblock parameters filesz %lu mblocksz %lu",
                __func__, mbfsp->fszmax, mblocksz);
        goto errout;
    }

    mbfsp->metasz = MBLOCK_FSET_HDRLEN +
        (mbfsp->fcnt * mblock_file_meta_len(mbfsp->fszmax, mblocksz));

    err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, mbfsp->metasz, flags, true);
    if (err)
        goto errout;

    sz = mbfsp->fcnt * sizeof(*mbfsp->filev);
    mbfsp->filev = calloc(1, sz);
    if (!mbfsp->filev) {
        err = merr(ENOMEM);
        goto errout;
    }

    fparams.mblocksz = mblocksz;
    fparams.fszmax = mbfsp->fszmax;

    for (i = 0; i < mbfsp->fcnt; i++) {
        char *addr;

        mblock_fset_meta_get(mbfsp, i, &addr);

        fparams.fileid = i + 1;
        err = mblock_file_open(mbfsp, mc, &fparams, flags, addr, &mbfsp->filev[i]);
        if (err)
            goto errout;
    }

    atomic64_set(&mbfsp->fidx, 0);

    *handle = mbfsp;

    return 0;

errout:
    if (flags & O_CREAT)
        mblock_fset_remove(mbfsp, NULL); /* Remove data and meta files */
    else
        mblock_fset_close(mbfsp);

    return err;
}

static merr_t
mblock_fset_meta_usage(struct mblock_fset *mbfsp, uint64_t *allocated)
{
    struct stat sbuf = {};
    int rc;

    if (!mbfsp || !allocated)
        return merr(EINVAL);

    rc = fstat(mbfsp->metafd, &sbuf);
    if (rc < 0)
        return merr(errno);

    *allocated = 512 * sbuf.st_blocks;

    return 0;
}

void
mblock_fset_close(struct mblock_fset *mbfsp)
{
    if (!mbfsp)
        return;

    if (mbfsp->filev) {
        int i = mbfsp->fcnt;

        while (i-- > 0) {
            mblock_file_close(mbfsp->filev[i]);
            mbfsp->filev[i] = NULL;
        }
    }

    mblock_fset_meta_close(mbfsp);

    free(mbfsp->filev);
    free(mbfsp);
}


static struct workqueue_struct *mpdwq;
static int pathc_per_thr, idx;

static struct mp_destroy_work {
    struct work_struct   work;
    char               **path;
    int                  pathc;
    int                  curpc;
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
mblock_fset_removecb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (typeflag == FTW_D && ftwbuf->level > 0)
        return FTW_SKIP_SUBTREE;

    if (strstr(path, MBLOCK_DATA_FILE_PFX)) {
        struct mp_destroy_work *w;

        if (!mpdwq) {
            remove(path);
            return FTW_CONTINUE;
        }

        w = mpdw[idx / pathc_per_thr];

        if (ev(w->pathc == 0)) {
            remove(path);
            return FTW_CONTINUE;
        }

        strlcpy(w->path[idx++ % pathc_per_thr], path, PATH_MAX);
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

static void
mbfs_destroy_setup(uint8_t filecnt, struct workqueue_struct *wq)
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

    idx = 0;
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
mbfs_destroy_teardown(void)
{
    flush_workqueue(mpdwq);
    mpdwq = NULL;
    free(mpdw);
    mpdw = NULL;
}

void
mblock_fset_remove(struct mblock_fset *mbfsp, struct workqueue_struct *wq)
{
    const char *dpath;
    char        name[32];
    int         dirfd;
    uint8_t     filecnt = mbfsp->fcnt;

    dirfd = mclass_dirfd(mbfsp->mc);
    dpath = mclass_dpath(mbfsp->mc);
    strlcpy(name, mbfsp->mname, sizeof(name));

    mblock_fset_close(mbfsp);

    if (wq)
        mbfs_destroy_setup(filecnt, wq);

    nftw(dpath, mblock_fset_removecb, MBLOCK_FSET_FILES_MAX, FTW_PHYS | FTW_ACTIONRETVAL);

    mblock_fset_meta_remove(dirfd, name);

    if (wq)
        mbfs_destroy_teardown();
}

merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, int mbidc, uint64_t *mbidv)
{
    struct mblock_file *mbfp;

    merr_t err;
    int    fidx;
    int    retries;

    if (!mbfsp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    retries = mbfsp->fcnt - 1;

    do {
        fidx = atomic64_fetch_add(1, &mbfsp->fidx) % mbfsp->fcnt;

        mbfp = mbfsp->filev[fidx];
        assert(mbfp);

        err = mblock_file_alloc(mbfp, mbidc, mbidv);
        if (merr_errno(err) != ENOSPC)
            break;
    } while (retries--);

    return err;
}

merr_t
mblock_fset_commit(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;
    merr_t err;
    int    rc;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    err = mblock_file_commit(mbfp, mbidv, mbidc);
    if (err)
        return err;

    rc = fsync(mbfsp->metafd);
    if (rc < 0)
        return merr(errno);

    return 0;
}

merr_t
mblock_fset_abort(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_abort(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_delete(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;
    merr_t err;
    int    rc;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    err = mblock_file_delete(mbfp, mbidv, mbidc);
    if (err)
        return err;

    rc = fsync(mbfsp->metafd);
    if (rc < 0)
        return merr(errno);

    return 0;
}

merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc, uint32_t *wlen)
{
    struct mblock_file *mbfp;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_find(mbfp, mbidv, mbidc, wlen);
}

merr_t
mblock_fset_write(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_write(mbfp, mbid, iov, iovc);
}

merr_t
mblock_fset_read(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_read(mbfp, mbid, iov, iovc, off);
}

merr_t
mblock_fset_map_getbase(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    char              **addr_out,
    uint32_t           *wlen)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_map_getbase(mbfp, mbid, addr_out, wlen);
}

merr_t
mblock_fset_unmap(
    struct mblock_fset *mbfsp,
    uint64_t            mbid)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_unmap(mbfp, mbid);
}

merr_t
mblock_fset_stats_get(struct mblock_fset *mbfsp, struct mpool_mclass_stats *stats)
{
    struct statvfs sbuf = {};
    uint64_t       allocated = 0;
    int            i, rc;
    merr_t         err;

    if (!mbfsp || !stats)
        return merr(EINVAL);

    for (i = 0; i < mbfsp->fcnt; i++) {
        struct mblock_file_stats fst = {};

        err = mblock_file_stats_get(mbfsp->filev[i], &fst);
        if (err)
            return err;

        stats->mcs_allocated += fst.allocated;
        stats->mcs_used += fst.used;
        stats->mcs_mblock_cnt += fst.mbcnt;
    }

    err = mblock_fset_meta_usage(mbfsp, &allocated);
    if (err)
        return err;
    stats->mcs_allocated += allocated;
    stats->mcs_used += allocated;

    rc = fstatvfs(mbfsp->metafd, &sbuf);
    if (rc < 0)
        return merr(errno);

    stats->mcs_total = sbuf.f_blocks * sbuf.f_frsize;
    stats->mcs_available = sbuf.f_bavail * sbuf.f_bsize;
    stats->mcs_fsid = sbuf.f_fsid;

    return 0;
}
