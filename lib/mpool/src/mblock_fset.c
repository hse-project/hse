/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <sys/statvfs.h>

#include <hse_util/event_counter.h>
#include <hse_util/logging.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_ikvdb/omf_version.h>

#include "omf.h"
#include "mclass.h"
#include "mblock_fset.h"
#include "mblock_file.h"

/* clang-format off */

#define MBLOCK_FSET_HDR_LEN        (4096)
#define MBLOCK_FSET_NAME_LEN       (32)
#define GB_SHIFT                   (30)
#define MBLOCK_FSET_RMCACHE_CNT    (4)

/* clang-format on */

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
    struct media_class  *mc;
    struct kmem_cache   *rmcache[MBLOCK_FSET_RMCACHE_CNT];

    atomic64_t           fidx;
    size_t               fszmax;
    struct mblock_file **filev;
    int                  fcnt;

    char  *maddr;
    size_t metasz;
    int    metafd;
    bool   mlock;
    char   mname[MBLOCK_FSET_NAME_LEN];
};

static void
mblock_metahdr_init(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
    mh->vers = MBLOCK_METAHDR_VERSION;
    mh->magic = MBLOCK_METAHDR_MAGIC;
    mh->fszmax_gb = mbfsp->fszmax >> GB_SHIFT;
    mh->mblksz_sec = mclass_mblocksz_get(mbfsp->mc) >> SECTOR_SHIFT;
    mh->mcid = mclass_id(mbfsp->mc);
    mh->fcnt = mbfsp->fcnt;
    mh->blkbits = MBID_BLOCK_BITS;
    mh->mcbits = MBID_MCID_BITS;
}

static merr_t
mblock_metahdr_validate(struct mblock_fset *mbfsp, struct mblock_metahdr *mh)
{
	if (mh->magic != MBLOCK_METAHDR_MAGIC) {
		bool big = (HSE_OMF_BYTE_ORDER == __ORDER_BIG_ENDIAN__);

		if (mh->magic != bswap_32(MBLOCK_METAHDR_MAGIC))
			return merr(EBADMSG);

		log_err("MDC format is %s endian, but libhse is configured to use %s endian,"
                        "try reconfiguring with -Domf-byte-order=%s",
                        big ? "little" : "big",
                        big ? "big" : "little",
                        big ? "little" : "big");

		return merr(EPROTO);
	}

    if (mh->vers != MBLOCK_METAHDR_VERSION)
        return merr(EPROTO);

    if ((mh->mcid != mclass_id(mbfsp->mc)) ||
        (mh->blkbits != MBID_BLOCK_BITS) || (mh->mcbits != MBID_MCID_BITS))
        return merr(EBADMSG);

    return 0;
}

static void
mblock_fset_meta_get(struct mblock_fset *mbfsp, int fidx, char **maddr)
{
    off_t off;

    off = MBLOCK_FSET_HDR_LEN +
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
    int    rc, len = MBLOCK_FSET_HDR_LEN;
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
    if (rc == -1)
        err = merr(errno);

    rc = fsync(mbfsp->metafd);
    if (rc == -1)
        err = merr(errno);

    if (unmap)
        mblock_fset_meta_unmap(mbfsp, len);

    return err;
}

static merr_t
mblock_fset_meta_load(struct mblock_fset *mbfsp, int flags)
{
    struct mblock_metahdr mh = {};
    bool   unmap = false;
    char  *addr;
    merr_t err = 0;
    int    len = MBLOCK_FSET_HDR_LEN;

    addr = mbfsp->maddr;
    if (!addr) {
        err = mblock_fset_meta_mmap(mbfsp, mbfsp->metafd, len, flags, false);
        if (err)
            return err;

        addr = mbfsp->maddr;
        unmap = true;
    }

    omf_mblock_metahdr_unpack_letoh(addr, &mh);

    err = mblock_metahdr_validate(mbfsp, &mh);
    if (!err) {
        mbfsp->fcnt = mh.fcnt;
        mbfsp->fszmax = (uint64_t)mh.fszmax_gb << GB_SHIFT;
        mclass_mblocksz_set(mbfsp->mc, (size_t)mh.mblksz_sec << SECTOR_SHIFT);
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

    if (flags & O_CREAT)
        create = true;

    snprintf(mbfsp->mname, sizeof(mbfsp->mname), "%s-%s-%d", MBLOCK_FILE_PFX, "meta",
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
        size_t sz;

        assert(mbfsp->fcnt != 0);
        sz = MBLOCK_FSET_HDR_LEN +
             (mbfsp->fcnt * mblock_file_meta_len(mbfsp->fszmax, mclass_mblocksz_get(mbfsp->mc)));

        rc = posix_fallocate(fd, 0, sz);
        if (ev(rc)) {
            rc = ftruncate(fd, sz);
            if (rc == -1) {
                err = merr(errno);
                goto errout;
            }
        }
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

merr_t
mblock_fset_open(
    struct media_class  *mc,
    uint8_t              fcnt,
    size_t               fszmax,
    int                  flags,
    struct mblock_fset **handle)
{
    struct mblock_fset       *mbfsp;
    struct mblock_file_params fparams;
    size_t sz, mblocksz;
    merr_t err;
    int    i;

    if (!mc || !handle)
        return merr(EINVAL);

    mbfsp = calloc(1, sizeof(*mbfsp));
    if (!mbfsp)
        return merr(ENOMEM);

    mbfsp->mc = mc;
    mbfsp->fcnt = fcnt ?: MPOOL_MBLOCK_FILECNT_DEFAULT;
    mbfsp->fszmax = fszmax ?: MPOOL_MBLOCK_FILESZ_DEFAULT;

    flags &= (O_RDWR | O_RDONLY | O_WRONLY | O_CREAT);
    if (flags & O_CREAT)
        flags |= O_EXCL;

    err = mblock_fset_meta_open(mbfsp, flags);
    if (err) {
        mblock_fset_free(mbfsp);
        return err;
    }

    mblocksz = mclass_mblocksz_get(mbfsp->mc);
    if ((mbfsp->fszmax < mblocksz) || ((1ULL << MBID_BLOCK_BITS) * mblocksz < mbfsp->fszmax)) {
        err = merr(EINVAL);
        log_err("Invalid mblock parameters filesz %lu mblocksz %lu",
                mbfsp->fszmax, mblocksz);
        goto errout;
    }

    mbfsp->metasz =
        MBLOCK_FSET_HDR_LEN + (mbfsp->fcnt * mblock_file_meta_len(mbfsp->fszmax, mblocksz));

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

    for (i = 0; i < MBLOCK_FSET_RMCACHE_CNT; i++) {
        char name[32];

        snprintf(name, sizeof(name), "%s-%d-%d", "mpool-rgnmap", mclass_id(mbfsp->mc), i);
        mbfsp->rmcache[i] = kmem_cache_create(name, sizeof(struct mblock_rgn),
                                              alignof(struct mblock_rgn), SLAB_PACKED, NULL);
        if (!mbfsp->rmcache[i])
            goto errout;
    }

    for (i = 0; i < mbfsp->fcnt; i++) {
        char *addr;

        mblock_fset_meta_get(mbfsp, i, &addr);

        fparams.fileid = i + 1;
        err = mblock_file_open(mbfsp, mc, &fparams, flags, addr,
                               mbfsp->rmcache[i % MBLOCK_FSET_RMCACHE_CNT], &mbfsp->filev[i]);
        if (err)
            goto errout;
    }

    atomic64_set(&mbfsp->fidx, 0);

    /*
     * Write the mblock metadata header at the end of fset create. This is to
     * detect partial fset create during reopen.
     */
    if (flags & O_CREAT) {
        err = mblock_fset_meta_format(mbfsp, flags);
        if (err)
            goto errout;
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
    int         rc;

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
        int i = mbfsp->fcnt;

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
    } while (retries-- > 0);

    return err;
}

merr_t
mblock_fset_commit(struct mblock_fset *mbfsp, uint64_t *mbidv, int mbidc)
{
    struct mblock_file *mbfp;
    merr_t              err;
    int                 rc;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    err = mblock_file_commit(mbfp, mbidv, mbidc);
    if (err)
        return err;

    rc = fsync(mbfsp->metafd);
    if (rc == -1)
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
    merr_t              err;
    int                 rc;

    if (!mbfsp || !mbidv || file_id(*mbidv) > mbfsp->fcnt)
        return merr(EINVAL);

    if (mbidc > 1)
        return merr(ENOTSUP);

    mbfp = mbfsp->filev[file_index(*mbidv)];

    err = mblock_file_delete(mbfp, mbidv, mbidc);
    if (err)
        return err;

    rc = fsync(mbfsp->metafd);
    if (rc == -1)
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
mblock_fset_write(struct mblock_fset *mbfsp, uint64_t mbid, const struct iovec *iov, int iovc)
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
mblock_fset_map_getbase(struct mblock_fset *mbfsp, uint64_t mbid, char **addr_out, uint32_t *wlen)
{
    struct mblock_file *mbfp;

    if (!mbfsp || file_id(mbid) > mbfsp->fcnt)
        return merr(EINVAL);

    mbfp = mbfsp->filev[file_index(mbid)];

    return mblock_file_map_getbase(mbfp, mbid, addr_out, wlen);
}

merr_t
mblock_fset_unmap(struct mblock_fset *mbfsp, uint64_t mbid)
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
    if (rc == -1)
        return merr(errno);

    stats->mcs_total = sbuf.f_blocks * sbuf.f_frsize;
    stats->mcs_available = sbuf.f_bavail * sbuf.f_bsize;
    stats->mcs_fsid = sbuf.f_fsid;

    return 0;
}
