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
#include <fcntl.h>
#include <ftw.h>

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>
#include <hse_util/page.h>
#include <hse_util/string.h>

#include "omf.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

#define MBLOCK_FSET_HDRLEN (4096)

/**
 * struct mblock_fset - mblock fileset instance
 *
 * @mc:        media class handle
 * @filev:     vector of mblock file handles
 * @fcnt:      mblock file count
 * @metafd:    fd of the fileset meta file
 * @meta_name: fileset meta file name
 */
struct mblock_fset {
    struct media_class *mc;

    atomic64_t           fidx;
    struct mblock_file **filev;
    int                  fcnt;

    char  *maddr;
    size_t metasz;
    int    metafd;
    char   mname[32];
};

static void
mblock_metahdr_init(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
    mh->vers = MBLOCK_METAHDR_VERSION;
    mh->magic = MBLOCK_METAHDR_MAGIC;
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

    off = MBLOCK_FSET_HDRLEN + (fidx * mblock_file_meta_len());
    *maddr = mbfsp->maddr + off;
}

static merr_t
mblock_fset_meta_mmap(struct mblock_fset *mbfsp, int fd, size_t sz)
{
    int   prot;
    char *addr;

    prot = PROT_READ | PROT_WRITE;
    addr = mmap(NULL, sz, prot, MAP_SHARED, fd, 0);
    if (ev(addr == MAP_FAILED))
        return merr(errno);

    mbfsp->maddr = addr;

    return 0;
}

static void
mblock_fset_meta_unmap(struct mblock_fset *mbfsp, size_t sz)
{
    if (mbfsp->maddr)
        munmap(mbfsp->maddr, sz);
    mbfsp->maddr = NULL;
}

static merr_t
mblock_fset_meta_format(struct mblock_fset *mbfsp)
{
    struct mblock_metahdr mh = {};

    char  *addr;
    int    rc, len = MBLOCK_FSET_HDRLEN;
    merr_t err = 0;
    bool   unmap = false;

    addr = mbfsp->maddr;
    if (!addr) {
        err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, len);
        if (ev(err))
            return err;

        addr = mbfsp->maddr;
        unmap = true;
    }

    mblock_metahdr_init(mbfsp, &mh);
    omf_mblock_metahdr_pack_htole(&mh, addr);

    rc = msync(addr, len, MS_SYNC);
    if (ev(rc < 0))
        err = merr(errno);

    if (unmap)
        mblock_fset_meta_unmap(mbfsp, len);

    return err;
}

static merr_t
mblock_fset_meta_load(struct mblock_fset *mbfsp)
{
    struct mblock_metahdr mh = {};

    bool   valid, unmap = false;
    char  *addr;
    merr_t err = 0;
    int    len = MBLOCK_FSET_HDRLEN;

    addr = mbfsp->maddr;
    if (!addr) {
        err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, len);
        if (ev(err))
            return err;

        addr = mbfsp->maddr;
        unmap = true;
    }

    /* Validate meta header */
    omf_mblock_metahdr_unpack_letoh(&mh, addr);
    valid = mblock_metahdr_validate(mbfsp, &mh);
    if (!valid)
        err = merr(EBADMSG);

    if (!err && mh.fcnt != 0)
        mbfsp->fcnt = mh.fcnt;

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

    flags &= O_RDWR | O_CREAT;
    if (flags & O_CREAT) {
        flags |= O_EXCL;
        create = true;
    }
    flags |= O_RDWR;

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
        sz = MBLOCK_FSET_HDRLEN + (mbfsp->fcnt * mblock_file_meta_len());

        rc = fallocate(fd, 0, 0, sz);
        if (ev(rc < 0)) {
            err = merr(rc);
            goto errout;
        }
    }

    if (create)
        err = mblock_fset_meta_format(mbfsp);
    else
        err = mblock_fset_meta_load(mbfsp);
    if (ev(err))
        goto errout;

    return 0;

errout:
    mblock_fset_meta_close(mbfsp);
    if (create)
        mblock_fset_meta_remove(dirfd, mbfsp->mname);

    return err;
}

merr_t
mblock_fset_open(struct media_class *mc, uint8_t fcnt, int flags, struct mblock_fset **handle)
{
    struct mblock_fset *mbfsp;

    size_t sz;
    merr_t err;
    int    i;

    if (ev(!mc || !handle))
        return merr(EINVAL);

    mbfsp = calloc(1, sizeof(*mbfsp));
    if (ev(!mbfsp))
        return merr(ENOMEM);

    mbfsp->mc = mc;
    mbfsp->fcnt = fcnt ?: MBLOCK_FSET_FILES_DEFAULT;

    err = mblock_fset_meta_open(mbfsp, flags);
    if (ev(err)) {
        mblock_fset_free(mbfsp);
        return err;
    }

    mbfsp->metasz = MBLOCK_FSET_HDRLEN + (mbfsp->fcnt * mblock_file_meta_len());

    err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, mbfsp->metasz);
    if (ev(err))
        goto errout;

    sz = mbfsp->fcnt * sizeof(*mbfsp->filev);
    mbfsp->filev = calloc(1, sz);
    if (ev(!mbfsp->filev)) {
        err = merr(ENOMEM);
        goto errout;
    }

    for (i = 0; i < mbfsp->fcnt; i++) {
        char *addr;

        mblock_fset_meta_get(mbfsp, i, &addr);

        err = mblock_file_open(mbfsp, mc, i + 1, flags, addr, &mbfsp->filev[i]);
        if (ev(err))
            goto errout;
    }

    atomic64_set(&mbfsp->fidx, 0);

    *handle = mbfsp;

    return 0;

errout:
    if (flags & O_CREAT)
        mblock_fset_remove(mbfsp); /* Remove data and meta files */
    else
        mblock_fset_close(mbfsp);

    return err;
}

void
mblock_fset_close(struct mblock_fset *mbfsp)
{
    if (ev(!mbfsp))
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

static int
mblock_fset_removecb(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if (strstr(path, MBLOCK_DATA_FILE_PFX))
        return remove(path);

    return 0;
}

void
mblock_fset_remove(struct mblock_fset *mbfsp)
{
    const char *dpath;
    char        name[32];
    int         dirfd;

    dirfd = mclass_dirfd(mbfsp->mc);
    dpath = mclass_dpath(mbfsp->mc);
    strlcpy(name, mbfsp->mname, sizeof(name));

    mblock_fset_close(mbfsp);

    nftw(dpath, mblock_fset_removecb, MBLOCK_FSET_FILES_MAX, FTW_DEPTH | FTW_PHYS);

    mblock_fset_meta_remove(dirfd, name);
}

merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, int mbidc, uint64_t *mbidv)
{
    struct mblock_file *mbfp;

    merr_t err;
    int    fidx;
    int    retries;

    if (ev(!mbfsp || !mbidv))
        return merr(EINVAL);

    if (ev(mbidc > 1))
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

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_commit(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_abort(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_abort(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_delete(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_delete(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt))
        return merr(EINVAL);

    if (ev(mbidc > 1))
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_find(mbfp, mbidv, mbidc);
}

merr_t
mblock_fset_write(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    const struct iovec *iov,
    int                 iovc,
    off_t               off)
{
    struct mblock_file *mbfp;

    if (ev(!mbfsp) || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_write(mbfp, mbid, iov, iovc, off);
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

    if (ev(!mbfsp || file_id(mbid) > mbfsp->fcnt))
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_read(mbfp, mbid, iov, iovc, off);
}

merr_t
mblock_fset_map_getbase(
    struct mblock_fset *mbfsp,
    uint64_t            mbid,
    char              **addr_out)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_map_getbase(mbfp, mbid, addr_out);
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
