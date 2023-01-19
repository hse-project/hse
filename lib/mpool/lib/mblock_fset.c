/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <sys/mman.h>
#include <sys/statvfs.h>

#include <hse/logging/logging.h>
#include <hse/util/assert.h>
#include <hse/util/event_counter.h>
#include <hse/util/minmax.h>
#include <hse/util/page.h>
#include <hse/util/slab.h>
#include <hse/util/storage.h>

#include "io.h"
#include "mblock_file.h"
#include "mblock_fset.h"
#include "mclass.h"
#include "omf.h"

/* clang-format off */

#define MBLOCK_FSET_HDR_LEN        (4096)
#define MBLOCK_FSET_NAME_LEN       (32)
#define MBLOCK_FSET_RMCACHE_CNT    (4)

/* clang-format on */

/**
 * struct mblock_fset - mblock fileset instance
 *
 * @mc:        media class handle
 *
 * @fidx:      next file index to use for allocation
 * @filev:     vector of mblock file handles
 *
 * @ug_maddr:   upgrade target mapped addr
 * @ug_mname:   upgrade target meta file name
 * @ug_metafd:  upgrade target meta file fd
 * @ug_metalen: upgrade target meta file length
 * @ug_mlock:   upgrade target meta mlock
 *
 * @maddr:   mapped addr of the mblock metadata file
 * @metalen: mblock metadata file length
 * @metafd:  fd of the mblock fileset meta file
 * @mlock:   whether the mlock the mapped meta file
 * @mname:   mblock fileset meta file name
 */
struct mblock_fset {
    struct media_class *mc;
    struct kmem_cache *rmcache[MBLOCK_FSET_RMCACHE_CNT];

    atomic_ulong fidx;
    struct mblock_file **filev;
    struct mblock_metahdr mhdr;
    struct io_ops io;

    char *ug_maddr;
    char *ug_mname;
    int ug_metafd;
    size_t ug_metalen;
    bool ug_mlock;

    char *maddr;
    size_t metalen;
    int metafd;
    bool mlock;
    bool rdonly;
    char mname[MBLOCK_FSET_NAME_LEN];
};

static void
mblock_metahdr_init(struct mblock_fset *mbfsp)
{
    struct mblock_metahdr *mh = &mbfsp->mhdr;

    mh->vers = MBLOCK_METAHDR_VERSION;
    mh->magic = MBLOCK_METAHDR_MAGIC;
    mh->mcid = mclass_id(mbfsp->mc);
    mh->blkbits = MBID_BLOCK_BITS;
    mh->mcbits = MBID_MCID_BITS;
    mh->gclose = false;
}

static merr_t
mblock_metahdr_validate(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
    if (mh->vers > MBLOCK_METAHDR_VERSION)
        return merr(EPROTO);

    if ((mh->mcid != mclass_id(mbfsp->mc)) || (mh->blkbits != MBID_BLOCK_BITS) ||
        (mh->mcbits != MBID_MCID_BITS))
        return merr(EBADMSG);

    return 0;
}

static off_t
mblock_fset_metaoff_get(struct mblock_fset *mbfsp, int fidx, uint32_t version)
{
    size_t metalen = mblock_file_meta_len(mbfsp->mhdr.fszmax, mbfsp->mhdr.mblksz, version);

    return MBLOCK_FSET_HDR_LEN + (fidx * metalen);
}

static merr_t
mblock_fset_meta_mmap(
    struct mblock_fset *mbfsp,
    int metafd,
    size_t metalen,
    int flags,
    char **addrout)
{
    int prot, mode;

    *addrout = NULL;

    mode = (flags & O_ACCMODE);
    prot = (mode == O_RDWR ? (PROT_READ | PROT_WRITE) : 0);
    prot |= (mode == O_RDONLY ? PROT_READ : 0);
    prot |= (mode == O_WRONLY ? PROT_WRITE : 0);

    return mbfsp->io.mmap((void **)addrout, metalen, prot, MAP_SHARED, metafd, 0);
}

static void
mblock_fset_meta_unmap(struct mblock_fset *mbfsp, char *addr, size_t len)
{
    mbfsp->io.munmap(addr, len);
}

static bool
mblock_fset_meta_mlock(const char *addr, size_t len)
{
    if (mlock2(addr, len, MLOCK_ONFAULT) == 0)
        return true;

    ev_info(1);

    return false;
}

static void
mblock_fset_meta_munlock(const char *addr, size_t len)
{
    munlock(addr, len);
}

static merr_t
mblock_fset_meta_format(struct mblock_fset *mbfsp, char *addr, int metafd)
{
    size_t len = MBLOCK_FSET_HDR_LEN;
    merr_t err = 0;

    INVARIANT(mbfsp && addr);

    omf_mblock_metahdr_pack(&mbfsp->mhdr, addr);

    err = mbfsp->io.msync(addr, len, MS_SYNC);
    if (!err) {
        int rc = fdatasync(metafd);
        if (rc == -1)
            err = merr(errno);
    }

    return err;
}

static merr_t
mblock_fset_meta_load(struct mblock_fset *mbfsp, int flags)
{
    struct mblock_metahdr *mh;
    char *addr;
    merr_t err = 0;
    size_t len = MBLOCK_FSET_HDR_LEN;

    err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, len, flags, &addr);
    if (err)
        return err;

    mh = &mbfsp->mhdr;
    err = omf_mblock_metahdr_unpack(addr, mh);
    if (!err) {
        err = mblock_metahdr_validate(mbfsp, mh);
        if (!err) {
            size_t metalen;

            mclass_mblocksz_set(mbfsp->mc, mh->mblksz);
            if (mh->gclose)
                mclass_gclose_set(mbfsp->mc);

            assert(mh->fcnt != 0);
            metalen = mblock_file_meta_len(mh->fszmax, mh->mblksz, mh->vers);
            mbfsp->metalen = MBLOCK_FSET_HDR_LEN + (mh->fcnt * metalen);
        }
    }

    mblock_fset_meta_unmap(mbfsp, addr, len);

    return err;
}

static void
mblock_fset_meta_close(struct mblock_fset *mbfsp)
{
    if (mbfsp->maddr) {
        if (!mbfsp->rdonly) {
            omf_mblock_metahdr_gclose_set(mbfsp->maddr, true);
            mbfsp->io.msync(mbfsp->maddr, mbfsp->metalen, MS_SYNC);
        }
        if (mbfsp->mlock) {
            mblock_fset_meta_munlock(mbfsp->maddr, mbfsp->metalen);
            mbfsp->mlock = false;
        }
        mblock_fset_meta_unmap(mbfsp, mbfsp->maddr, mbfsp->metalen);
        mbfsp->maddr = NULL;
    }

    if (mbfsp->metafd != -1) {
        fsync(mbfsp->metafd);
        close(mbfsp->metafd);
        mbfsp->metafd = -1;
    }
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
    int fd, dirfd, rc;
    merr_t err;
    bool create = false;

    mbfsp->metafd = -1;

    flags &= (O_RDWR | O_RDONLY | O_WRONLY | O_CREAT);
    if (flags & O_CREAT)
        create = true;

    snprintf(
        mbfsp->mname, sizeof(mbfsp->mname), "%s-%s-%d", MBLOCK_FILE_PFX, "meta",
        mclass_id(mbfsp->mc));
    dirfd = mclass_dirfd(mbfsp->mc);

    rc = faccessat(dirfd, mbfsp->mname, F_OK, 0);
    if (rc == -1 && errno == ENOENT && !create)
        return merr(ENOENT);
    if (rc == 0 && create)
        return merr(EEXIST);

    fd = openat(dirfd, mbfsp->mname, flags, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return merr(errno);
    mbfsp->metafd = fd;

    /* Preallocate metadata file. */
    if (create) {
        size_t metalen;

        assert(mbfsp->mhdr.fcnt != 0);
        metalen =
            mblock_file_meta_len(mbfsp->mhdr.fszmax, mbfsp->mhdr.mblksz, MBLOCK_METAHDR_VERSION);
        mbfsp->metalen = MBLOCK_FSET_HDR_LEN + (mbfsp->mhdr.fcnt * metalen);

        rc = posix_fallocate(fd, 0, mbfsp->metalen);
        if (ev(rc)) {
            rc = ftruncate(fd, mbfsp->metalen);
            if (rc == -1) {
                err = merr(errno);
                goto errout;
            }
        }

        mbfsp->mhdr.vers = MBLOCK_METAHDR_VERSION;
    } else {
        err = mblock_fset_meta_load(mbfsp, flags);
        if (err)
            goto errout;
    }

    return 0;

errout:
    mblock_fset_meta_close(mbfsp);

    return err;
}

static void
mblock_fset_upgrade_cleanup(struct mblock_fset *mbfsp)
{
    INVARIANT(mbfsp);

    if (mbfsp->ug_maddr) {
        if (mbfsp->ug_mlock) {
            mblock_fset_meta_munlock(mbfsp->ug_maddr, mbfsp->ug_metalen);
            mbfsp->ug_mlock = false;
        }
        mblock_fset_meta_unmap(mbfsp, mbfsp->ug_maddr, mbfsp->ug_metalen);
        mbfsp->ug_maddr = NULL;
    }

    if (mbfsp->ug_metafd > 0) {
        close(mbfsp->ug_metafd);
        unlinkat(mclass_dirfd(mbfsp->mc), mbfsp->ug_mname, 0);
        mbfsp->ug_metafd = -1;
    }

    free(mbfsp->ug_mname);
}

static merr_t
mblock_fset_upgrade_prepare(struct mblock_fset *mbfsp, bool create)
{
    merr_t err;
    size_t sz, metalen;
    int dirfd, fd, rc;

    INVARIANT(mbfsp);

    if (mbfsp->mhdr.vers > MBLOCK_METAHDR_VERSION)
        return merr(EPROTO);

    if (mbfsp->mhdr.vers == MBLOCK_METAHDR_VERSION || create || mbfsp->rdonly)
        return 0; /* Nothing to do */

    sz = strlen(mbfsp->mname) + 2; /* +1 for . and +1 for \0 */
    mbfsp->ug_mname = malloc(sz);
    if (!mbfsp->ug_mname)
        return merr(ENOMEM);

    snprintf(mbfsp->ug_mname, sz, "%s%s", ".", mbfsp->mname);

    dirfd = mclass_dirfd(mbfsp->mc);
    fd = openat(dirfd, mbfsp->ug_mname, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        err = merr(errno);
        free(mbfsp->ug_mname);
        return err;
    }
    mbfsp->ug_metafd = fd;

    metalen = mblock_file_meta_len(mbfsp->mhdr.fszmax, mbfsp->mhdr.mblksz, MBLOCK_METAHDR_VERSION);
    mbfsp->ug_metalen = MBLOCK_FSET_HDR_LEN + (mbfsp->mhdr.fcnt * metalen);

    rc = posix_fallocate(fd, 0, mbfsp->ug_metalen);
    if (ev(rc)) {
        rc = ftruncate(fd, mbfsp->ug_metalen);
        if (rc == -1) {
            err = merr(errno);
            goto errout;
        }
    }

    err = mblock_fset_meta_mmap(mbfsp, fd, mbfsp->ug_metalen, O_RDWR, &mbfsp->ug_maddr);
    if (err)
        goto errout;

    mbfsp->ug_mlock = mblock_fset_meta_mlock(mbfsp->ug_maddr, mbfsp->ug_metalen);

    return 0;

errout:
    mblock_fset_upgrade_cleanup(mbfsp);

    return err;
}

static merr_t
mblock_fset_upgrade_commit(struct mblock_fset *mbfsp)
{
    merr_t err = 0;
    int rc, dirfd;

    INVARIANT(mbfsp);

    if (mbfsp->mhdr.vers == MBLOCK_METAHDR_VERSION || !mbfsp->ug_maddr || mbfsp->rdonly)
        return 0; /* Nothing to do */

    err = mbfsp->io.msync(mbfsp->ug_maddr, mbfsp->ug_metalen, MS_SYNC);
    if (err)
        goto errout;

    mbfsp->mhdr.vers = MBLOCK_METAHDR_VERSION;
    err = mblock_fset_meta_format(mbfsp, mbfsp->ug_maddr, mbfsp->ug_metafd);
    if (err)
        goto errout;

    rc = fsync(mbfsp->ug_metafd);
    if (rc == -1) {
        err = merr(errno);
        goto errout;
    }

    mblock_fset_meta_close(mbfsp);

    dirfd = mclass_dirfd(mbfsp->mc);
    rc = renameat(dirfd, mbfsp->ug_mname, dirfd, mbfsp->mname);
    if (rc == -1) {
        err = merr(errno);
        goto errout;
    }

    mbfsp->maddr = mbfsp->ug_maddr;
    mbfsp->metalen = mbfsp->ug_metalen;
    mbfsp->metafd = mbfsp->ug_metafd;
    mbfsp->mlock = mbfsp->ug_mlock;

    free(mbfsp->ug_mname);
    mbfsp->ug_mname = mbfsp->ug_maddr = NULL;
    mbfsp->ug_metafd = -1;
    mbfsp->ug_mlock = false;

    return 0;

errout:
    mblock_fset_upgrade_cleanup(mbfsp);

    return err;
}

merr_t
mblock_fset_open(
    struct media_class *mc,
    uint8_t fcnt,
    size_t fszmax,
    int flags,
    struct mblock_fset **handle)
{
    struct mblock_fset *mbfsp;
    struct mblock_file_params fparams = { 0 };
    size_t sz;
    merr_t err;
    bool create;
    int i;

    if (!mc || !handle)
        return merr(EINVAL);

    mbfsp = calloc(1, sizeof(*mbfsp));
    if (!mbfsp)
        return merr(ENOMEM);

    mbfsp->mc = mc;
    mbfsp->mhdr.fcnt = fcnt ? fcnt : MPOOL_MCLASS_FILECNT_DEFAULT;
    mbfsp->mhdr.fszmax = fszmax ? fszmax : MPOOL_MCLASS_FILESZ_DEFAULT;
    mbfsp->mhdr.mblksz = mclass_mblocksz_get(mc);

    mclass_io_ops_set(mcid_to_mclass(mclass_id(mc)), &mbfsp->io);

    flags &= (O_RDWR | O_RDONLY | O_WRONLY | O_CREAT | O_DIRECT);
    create = (flags & O_CREAT);
    if (create)
        flags |= O_EXCL;

    mbfsp->rdonly = ((flags & O_ACCMODE) == O_RDONLY);

    err = mblock_fset_meta_open(mbfsp, flags);
    if (err) {
        mblock_fset_free(mbfsp);
        return err;
    }

    if ((mbfsp->mhdr.fszmax < mbfsp->mhdr.mblksz) ||
        ((1ULL << MBID_BLOCK_BITS) * mbfsp->mhdr.mblksz < mbfsp->mhdr.fszmax))
    {
        err = merr(EINVAL);
        log_err(
            "Invalid mblock parameters filesz %lu mblocksz %lu", mbfsp->mhdr.fszmax,
            mbfsp->mhdr.mblksz);
        goto errout;
    }

    sz = mbfsp->mhdr.fcnt * sizeof(*mbfsp->filev);
    mbfsp->filev = calloc(1, sz);
    if (!mbfsp->filev) {
        err = merr(ENOMEM);
        goto errout;
    }

    fparams.mblocksz = mbfsp->mhdr.mblksz;
    fparams.fszmax = mbfsp->mhdr.fszmax;

    for (i = 0; i < MBLOCK_FSET_RMCACHE_CNT; i++) {
        char name[32];

        snprintf(name, sizeof(name), "%s-%d-%d", "mpool-rgnmap", mclass_id(mc), i);
        mbfsp->rmcache[i] = kmem_cache_create(
            name, sizeof(struct mblock_rgn), alignof(struct mblock_rgn), SLAB_PACKED, NULL);
        if (!mbfsp->rmcache[i])
            goto errout;
    }

    err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, mbfsp->metalen, flags, &mbfsp->maddr);
    if (err)
        goto errout;

    mbfsp->mlock = mblock_fset_meta_mlock(mbfsp->maddr, mbfsp->metalen);

    err = mblock_fset_upgrade_prepare(mbfsp, create);
    if (err)
        goto errout;

    for (i = 0; i < mbfsp->mhdr.fcnt; i++) {
        off_t off;

        fparams.fileid = i + 1;
        fparams.rmcache = mbfsp->rmcache[i % MBLOCK_FSET_RMCACHE_CNT];
        fparams.gclose = mbfsp->mhdr.gclose;

        off = mblock_fset_metaoff_get(mbfsp, i, mbfsp->mhdr.vers);
        fparams.meta_addr = mbfsp->maddr + off;

        if (mbfsp->ug_maddr) {
            off = mblock_fset_metaoff_get(mbfsp, i, MBLOCK_METAHDR_VERSION);
            fparams.meta_ugaddr = mbfsp->ug_maddr + off;
        }

        fparams.metaio = &mbfsp->io;

        err = mblock_file_open(mbfsp, mc, &fparams, flags, mbfsp->mhdr.vers, &mbfsp->filev[i]);
        if (err)
            goto errout;
    }

    err = mblock_fset_upgrade_commit(mbfsp);
    if (err)
        goto errout;

    atomic_set(&mbfsp->fidx, 0);

    /*
     * Write the mblock metadata header at the end of fset create. This is to
     * detect partial fset create during reopen.
     */
    if (create) {
        int dirfd, rc;

        mblock_metahdr_init(mbfsp);
        err = mblock_fset_meta_format(mbfsp, mbfsp->maddr, mbfsp->metafd);
        if (err)
            goto errout;

        dirfd = mclass_dirfd(mc);
        rc = fsync(dirfd);
        if (rc == -1) {
            err = merr(errno);
            goto errout;
        }
    } else if (!mbfsp->rdonly) {
        omf_mblock_metahdr_gclose_set(mbfsp->maddr, false);
        mbfsp->io.msync(mbfsp->maddr, MBLOCK_FSET_HDR_LEN, MS_SYNC);
    }

    *handle = mbfsp;

    return 0;

errout:
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
    if (rc == -1)
        return merr(errno);

    *allocated = 512 * sbuf.st_blocks;

    return 0;
}

void
mblock_fset_close(struct mblock_fset *mbfsp)
{
    int i;

    if (!mbfsp)
        return;

    if (mbfsp->filev) {
        int i = mbfsp->mhdr.fcnt;

        while (i-- > 0) {
            mblock_file_close(mbfsp->filev[i]);
            mbfsp->filev[i] = NULL;
        }
    }

    mblock_fset_meta_close(mbfsp);

    for (i = 0; i < MBLOCK_FSET_RMCACHE_CNT; i++)
        kmem_cache_destroy(mbfsp->rmcache[i]);

    free(mbfsp->filev);
    free(mbfsp);
}

merr_t
mblock_fset_alloc(struct mblock_fset *mbfsp, uint32_t flags, int mbidc, uint64_t *mbidv)
{
    struct mblock_file *mbfp;
    merr_t err;
    int fidx;
    int retries;

    if (!mbfsp || !mbidv)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    retries = mbfsp->mhdr.fcnt - 1;

    do {
        fidx = atomic_fetch_add(&mbfsp->fidx, 1) % mbfsp->mhdr.fcnt;

        mbfp = mbfsp->filev[fidx];
        assert(mbfp);

        err = mblock_file_alloc(mbfp, flags, mbidc, mbidv);
        if (merr_errno(err) != ENOSPC)
            break;
    } while (retries-- > 0);

    return err;
}

merr_t
mblock_fset_commit(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;
    merr_t err;
    int rc;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    err = mblock_file_commit(mbfp, mbidv, mbidc);
    if (err)
        return err;

    rc = fdatasync(mbfsp->metafd);
    if (rc == -1)
        return merr(errno);

    return 0;
}

merr_t
mblock_fset_delete(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;
    merr_t err;
    int rc;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    err = mblock_file_delete(mbfp, mbidv, mbidc);
    if (err)
        return err;

    rc = fdatasync(mbfsp->metafd);
    if (rc == -1)
        return merr(errno);

    return 0;
}

merr_t
mblock_fset_punch(struct mblock_fset *mbfsp, uint64_t mbid, off_t off, size_t len)
{
    if (!mbfsp || file_id(mbid) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    return mblock_punch(mbfsp->filev[file_index(mbid)], mbid, off, len);
}

merr_t
mblock_fset_find(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc, struct mblock_props *props)
{
    struct mblock_file *mbfp;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    return mblock_file_find(mbfp, mbidv, mbidc, props);
}

merr_t
mblock_fset_write(struct mblock_fset *mbfsp, uint64_t mbid, const struct iovec *iov, int iovc)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_write(mbfp, mbid, iov, iovc);
}

merr_t
mblock_fset_read(
    struct mblock_fset *mbfsp,
    uint64_t mbid,
    const struct iovec *iov,
    int iovc,
    off_t off)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_read(mbfp, mbid, iov, iovc, off);
}

merr_t
mblock_fset_map_getbase(struct mblock_fset *mbfsp, uint64_t mbid, char **addr_out, uint32_t *wlen)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_map_getbase(mbfp, mbid, addr_out, wlen);
}

merr_t
mblock_fset_unmap(struct mblock_fset *mbfsp, uint64_t mbid)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->mhdr.fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_unmap(mbfp, mbid);
}

merr_t
mblock_fset_info_get(struct mblock_fset *mbfsp, struct hse_mclass_info *info)
{
    uint64_t allocated = 0;
    int i;
    merr_t err;

    INVARIANT(mbfsp);
    INVARIANT(info);

    for (i = 0; i < mbfsp->mhdr.fcnt; i++) {
        struct mblock_file_info fst = {};

        err = mblock_file_info_get(mbfsp->filev[i], &fst);
        if (err)
            return err;

        info->mi_allocated_bytes += fst.allocated;
        info->mi_used_bytes += fst.used;
    }

    err = mblock_fset_meta_usage(mbfsp, &allocated);
    if (err)
        return err;
    info->mi_allocated_bytes += allocated;
    info->mi_used_bytes += allocated;

    return 0;
}

size_t
mblock_fset_fmaxsz_get(const struct mblock_fset * const mbfsp)
{
    return mbfsp ? mbfsp->mhdr.fszmax : 0;
}

uint8_t
mblock_fset_filecnt_get(const struct mblock_fset * const mbfsp)
{
    return mbfsp ? mbfsp->mhdr.fcnt : 0;
}

merr_t
mblock_fset_clone(
    struct mblock_fset *mbfsp,
    uint64_t src_mbid,
    off_t off,
    size_t len,
    uint64_t *mbid_out)
{
    struct mblock_file *src_mbfp, *tgt_mbfp;
    struct mblock_file_mbinfo src_mbinfo, tgt_mbinfo;
    off_t src_off = off, tgt_off = off;
    uint64_t tgt_mbid;
    size_t wlen;
    merr_t err;

    INVARIANT(mbfsp && mbid_out);

    if (!PAGE_ALIGNED(off) || !PAGE_ALIGNED(len))
        return merr(EINVAL);

    src_mbfp = mbfsp->filev[file_index(src_mbid)];
    err = mblock_info_get(src_mbfp, src_mbid, &src_mbinfo);
    if (err)
        return err;

    wlen = src_mbinfo.wlen;

    if (off < 0 || off >= wlen || off + len > wlen)
        return merr(EINVAL);

    if (len == 0) {
        len = wlen - off;
        assert(PAGE_ALIGNED(len));
    }

    err = mblock_fset_alloc(mbfsp, MPOOL_MBLOCK_PUNCH_HOLE, 1, &tgt_mbid);
    if (err)
        return err;

    tgt_mbfp = mbfsp->filev[file_index(tgt_mbid)];
    err = mblock_info_get(tgt_mbfp, tgt_mbid, &tgt_mbinfo);
    if (err)
        goto errout;
    assert(tgt_mbinfo.wlen == 0);

    src_off += src_mbinfo.off;
    tgt_off += tgt_mbinfo.off;

    err = mbfsp->io.clone(src_mbinfo.fd, src_off, tgt_mbinfo.fd, tgt_off, len, 0);
    if (err)
        goto errout;

    mblock_wlen_set(tgt_mbfp, tgt_mbid, off + len, false, off > 0);

    *mbid_out = tgt_mbid;

    return 0;

errout:
    mblock_fset_delete(mbfsp, &tgt_mbid, 1);

    return err;
}
