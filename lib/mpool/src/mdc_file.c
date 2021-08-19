/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c/crc32c.h>
#include <hse_util/string.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>

#include "mdc.h"
#include "mdc_file.h"
#include "omf.h"
#include "io.h"

/**
 * struct mdc_file - MDC file handle
 *
 * @mdc: MDC handle
 * @lh:  MDC log header
 *
 * @logid: log/file identifier
 * @fd:    file descriptor
 *
 * @raoff: tracks readahead window for issuing DONTNEED
 * @woff:  next offset to append to
 * @roff:  next offset to read from
 * @size:  current size of this MDC file
 * @maxsz: max. size to which this MDC file can extend
 *
 * io:     IO ops
 * addr:   mapped addr for this MDC file
 * name:   name for this MDC file
 */
struct mdc_file {
    struct mpool_mdc *mdc;
    struct mdc_loghdr lh;

    uint64_t logid;
    int      fd;

    off_t  raoff;
    off_t  woff;
    off_t  roff;
    size_t size;
    size_t maxsz;

    struct io_ops io;
    char         *addr;
    char          name[MDC_NAME_LENGTH_MAX];
};

static void
loghdr_init(struct mdc_loghdr *lh, uint64_t gen)
{
    lh->vers = MDC_LOGHDR_VERSION;
    lh->magic = MDC_LOGHDR_MAGIC;
    lh->gen = gen;
    lh->rsvd = 0;
    lh->crc = 0;
}

static merr_t
loghdr_update_byfd(int fd, struct mdc_loghdr *lh, uint64_t gen)
{
    struct mdc_loghdr_omf lhomf;
    merr_t err;
    size_t len;
    int    cc, rc;

    loghdr_init(lh, gen);

    err = omf_mdc_loghdr_pack_htole(lh, (char *)&lhomf);
    if (err)
        return err;

    len = omf_mdc_loghdr_len();
    cc = pwrite(fd, &lhomf, len, 0);
    if (cc != len)
        return merr(errno);

    rc = fsync(fd);
    if (rc == -1)
        return merr(errno);

    return 0;
}

static merr_t
loghdr_update(struct mdc_file *mfp, struct mdc_loghdr *lh, uint64_t gen)
{
    merr_t err;
    size_t len;
    int    rc;

    loghdr_init(lh, gen);

    err = omf_mdc_loghdr_pack_htole(lh, (char *)mfp->addr);
    if (err)
        return err;

    len = omf_mdc_loghdr_len();
    rc = msync(mfp->addr, len, MS_SYNC);
    if (rc == -1)
        return merr(errno);

    return 0;
}

static merr_t
loghdr_validate(struct mdc_file *mfp, uint64_t *gen)
{
    struct mdc_loghdr *lh;
    merr_t             err;

    lh = &mfp->lh;

    err = omf_mdc_loghdr_unpack_letoh((const char *)mfp->addr, lh);
    if (err)
        return err;

    if (lh->magic != MDC_LOGHDR_MAGIC)
        return merr(EBADMSG);

    if (gen)
        *gen = lh->gen;

    return 0;
}

static uint32_t
logrec_crc_get(const uint8_t *data1, size_t len1, const uint8_t *data2, size_t len2)
{
    uint32_t crc;

    crc = crc32c(0, data1, len1);

    return crc32c(crc, data2, len2);
}

static merr_t
logrec_validate(struct mdc_file *mfp, char *addr, size_t *recsz)
{
    struct mdc_rechdr      rh;
    struct mdc_rechdr_omf *rhomf;
    uint32_t               crc;
    uint8_t                hdrlen;

    *recsz = 0;

    omf_mdc_rechdr_unpack_letoh((const char *)addr, &rh);
    if (rh.size == 0 && rh.crc == 0)
        return merr(ENOMSG); /* end-of-log */

    if (addr + rh.size - mfp->addr > mfp->size || rh.rsvd != 0)
        return merr(EBADMSG); /* corruption */

    rhomf = (struct mdc_rechdr_omf *)addr;
    addr += omf_mdc_rechdr_len();

    hdrlen = sizeof(rhomf->rh_size);
    crc = logrec_crc_get((const uint8_t *)&rhomf->rh_size, hdrlen, (const uint8_t *)addr, rh.size);
    if (crc != rh.crc)
        return merr(ENOMSG); /* Likely crashed while writing record, mark end-of-log */

    *recsz = rh.size;

    return 0;
}

merr_t
mdc_file_create(int dirfd, const char *name, int flags, int mode, size_t capacity)
{
    int    fd, rc;
    merr_t err = 0;

    fd = openat(dirfd, name, flags, mode);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    rc = ftruncate(fd, capacity);
    if (rc == -1) {
        err = merr(errno);
        mdc_file_destroy(dirfd, name);
    }

    close(fd);

    return err;
}

merr_t
mdc_file_destroy(int dirfd, const char *name)
{
    int  rc;

    rc = unlinkat(dirfd, name, 0);
    if (rc == -1)
        return merr(errno);

    return 0;
}

/* At commit, the log header of both MDC files are initialized. */
merr_t
mdc_file_commit(int dirfd, const char *name)
{
    struct mdc_loghdr lh;
    merr_t            err = 0;
    int               fd;

    fd = openat(dirfd, name, O_RDWR);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    err = loghdr_update_byfd(fd, &lh, 0);
    close(fd);

    return err;
}

static merr_t
mdc_file_mmap(struct mdc_file *mfp, size_t newsize)
{
    void *addr;

    if (!mfp)
        return merr(EINVAL);

    do {
        int prot = PROT_READ | PROT_WRITE;

        addr = mmap(mfp->addr, newsize, prot, MAP_SHARED, mfp->fd, 0);
        if (addr == MAP_FAILED)
            return merr(errno);

        if (!mfp->addr || mfp->addr == addr)
            break;

        munmap(mfp->addr, mfp->size);
    } while (0);

    mfp->addr = addr;
    mfp->size = newsize;

    return 0;
}

static merr_t
mdc_file_unmap(struct mdc_file *mfp)
{
    int rc;

    if (mfp->addr) {
        rc = munmap(mfp->addr, mfp->size);
        if (rc == -1)
            return merr(errno);
        mfp->addr = NULL;
    }

    return 0;
}

static merr_t
mdc_file_validate(struct mdc_file *mfp, uint64_t *gen)
{
    char  *addr;
    merr_t err;
    int    rc;
    int    rhlen;

    if (!mfp)
        return merr(EINVAL);

    addr = mfp->addr;

    /* The MDC file will now be read sequentially. Pass this hint to VMM via madvise. */
    rc = madvise(addr, mfp->size, MADV_SEQUENTIAL);
    ev(rc == -1);

    /* Step 1: validate log header */
    err = loghdr_validate(mfp, gen);
    if (err)
        goto errout;

    if (mfp->size > MDC_LOGHDR_LEN) {
        addr += MDC_LOGHDR_LEN; /* move past the log header */
        rhlen = omf_mdc_rechdr_len();

        /* Step 2: validate log records */
        do {
            size_t recsz;

            err = logrec_validate(mfp, addr, &recsz);
            if (err) {
                if (merr_errno(err) == ENOMSG) { /* End of log */
                    err = 0;
                    mfp->woff = addr - mfp->addr;
                    break;
                }
                goto errout;
            }

            addr += (rhlen + recsz);
        } while (true);
    }

errout:
    madvise(mfp->addr, mfp->size, MADV_DONTNEED);

    return err;
}

merr_t
mdc_file_size(int fd, size_t *size)
{
    struct stat s;
    int         rc;

    rc = fstat(fd, &s);
    if (rc == -1)
        return merr(errno);

    *size = s.st_size;

    return 0;
}

merr_t
mdc_file_open(
    struct mpool_mdc *mdc,
    int               dirfd,
    const char       *name,
    uint64_t          logid,
    uint64_t         *gen,
    struct mdc_file **handle)
{
    struct mdc_file *mfp;
    int    fd;
    merr_t err;

    if (!mdc)
        return merr(EINVAL);

    fd = openat(dirfd, name, O_RDWR);
    if (fd < 0) {
        err = merr(errno);
        return err;
    }

    mfp = calloc(1, sizeof(*mfp));
    if (!mfp) {
        err = merr(ENOMEM);
        goto err_exit2;
    }

    err = mdc_file_size(fd, &mfp->size);
    if (err)
        goto err_exit1;

    /* Automatic extension upto MDC_EXTEND_FACTOR x the original capacity */
    mfp->maxsz = MDC_EXTEND_FACTOR * mfp->size;

    mfp->mdc = mdc;
    mfp->logid = logid;
    mfp->fd = fd;
    mfp->io = io_sync_ops;
    strlcpy(mfp->name, name, sizeof(mfp->name));
    mfp->roff = MDC_LOGHDR_LEN;
    mfp->raoff = MDC_RA_BYTES;

    err = mdc_file_mmap(mfp, mfp->size);
    if (err)
        goto err_exit1;

    err = mdc_file_validate(mfp, gen);
    if (err) {
        mdc_file_unmap(mfp);
        goto err_exit1;
    }

    *handle = mfp;

    return 0;

err_exit1:
    free(mfp);

err_exit2:
    close(fd);

    return err;
}

merr_t
mdc_file_close(struct mdc_file *mfp)
{
    if (!mfp)
        return merr(EINVAL);

    mdc_file_sync(mfp);
    mdc_file_unmap(mfp);
    close(mfp->fd);
    free(mfp);

    return 0;
}

merr_t
mdc_file_erase(struct mdc_file *mfp, uint64_t newgen)
{
    merr_t err;
    int    rc;

    if (!mfp)
        return merr(EINVAL);

    err = loghdr_update(mfp, &mfp->lh, newgen);
    if (err)
        return err;

    if (mfp->size > MDC_LOGHDR_LEN) {
        rc = msync(mfp->addr + MDC_LOGHDR_LEN, mfp->size - MDC_LOGHDR_LEN, MS_INVALIDATE);
        if (rc == -1)
            return merr(errno);

        rc = fallocate(
            mfp->fd,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            MDC_LOGHDR_LEN,
            mfp->size - MDC_LOGHDR_LEN);
        if (rc == -1) {
            if (errno != EOPNOTSUPP)
                return merr(errno);

            rc = ftruncate(mfp->fd, MDC_LOGHDR_LEN);
            if (rc == -1)
                return merr(errno);

            rc = ftruncate(mfp->fd, mfp->size);
            if (rc == -1)
                return merr(errno);
        }
    }

    rc = fsync(mfp->fd);
    if (rc == -1)
        return merr(errno);

    mfp->woff = MDC_LOGHDR_LEN;
    mfp->roff = MDC_LOGHDR_LEN;
    mfp->raoff = MDC_RA_BYTES;

    return 0;
}

merr_t
mdc_file_gen(struct mdc_file *mfp, uint64_t *gen)
{
    if (!mfp || !gen)
        return merr(EINVAL);

    *gen = mfp->lh.gen;

    return 0;
}

merr_t
mdc_file_exists(int dirfd, const char *name1, const char *name2, bool *exist)
{
    int    rc;
    merr_t err;

    *exist = false;

    rc = faccessat(dirfd, name1, F_OK, 0);
    if (rc == -1) {
        err = merr(errno);
        if (merr_errno(err) == ENOENT)
            return 0;
        return err;
    }

    rc = faccessat(dirfd, name2, F_OK, 0);
    if (rc == -1) {
        err = merr(errno);
        if (merr_errno(err) == ENOENT)
            return 0;
        return err;
    }

    *exist = true;
    return 0;
}

merr_t
mdc_file_sync(struct mdc_file *mfp)
{
    int rc;

    if (!mfp)
        return merr(EINVAL);

    rc = msync(mfp->addr, mfp->woff, MS_SYNC);
    if (rc == -1)
        return merr(errno);

    rc = fsync(mfp->fd);
    if (rc == -1)
        return merr(errno);

    return 0;
}

merr_t
mdc_file_rewind(struct mdc_file *mfp)
{
    if (!mfp)
        return merr(EINVAL);

    mfp->roff = MDC_LOGHDR_LEN;
    mfp->raoff = MDC_RA_BYTES;

    return 0;
}

merr_t
mdc_file_stats(struct mdc_file *mfp, uint64_t *allocated, uint64_t *used)
{
    if (!mfp)
        return merr(EINVAL);

    if (allocated) {
        struct stat sbuf = {};
        int         rc;

        rc = fstat(mfp->fd, &sbuf);
        if (rc == -1)
            return merr(errno);

        *allocated = 512 * sbuf.st_blocks;
    }

    if (used)
        *used = mfp->woff;

    return 0;
}

merr_t
mdc_file_read(struct mdc_file *mfp, void *data, size_t len, bool verify, size_t *rdlen)
{
    struct mdc_rechdr rh;
    char             *addr;
    int               rhlen, rc;

    if (!mfp || !data)
        return merr(EINVAL);

    if (mfp->roff == MDC_LOGHDR_LEN) { /* First read */
        rc = madvise(mfp->addr, mfp->woff, MADV_SEQUENTIAL);
        ev(rc);
    }

    addr = mfp->addr + mfp->roff;

    /* DONTNEED pages from the previous ra window. */
    if (mfp->roff > mfp->raoff) {
        rc = madvise(addr - MDC_RA_BYTES, MDC_RA_BYTES, MADV_DONTNEED);
        ev(rc);

        mfp->raoff <<= 1;
    }

    omf_mdc_rechdr_unpack_letoh((const char *)addr, &rh);
    if (mfp->roff == mfp->woff) {
        if (rdlen)
            *rdlen = 0;
        return 0; /* Reached end of log */
    }

    if (rdlen)
        *rdlen = rh.size;

    if (ev(rh.size > len))
        return merr(EOVERFLOW);

    rhlen = omf_mdc_rechdr_len();
    memcpy(data, addr + rhlen, rh.size);

    if (verify) {
        struct mdc_rechdr_omf *rhomf;
        uint32_t               crc;
        uint8_t                hdrlen;

        rhomf = (struct mdc_rechdr_omf *)addr;

        hdrlen = sizeof(rhomf->rh_size);
        crc = logrec_crc_get(
            (const uint8_t *)&rhomf->rh_size,
            hdrlen,
            (const uint8_t *)data,
            rh.size);
        if (crc != rh.crc)
            return merr(EBADMSG);
    }

    mfp->roff += (rhlen + rh.size);

    return 0;
}

static merr_t
mdc_file_extend(struct mdc_file *mfp, size_t minsz)
{
    merr_t err;
    int    rc;
    size_t sz;

    sz = 2 * mfp->size;
    if (sz < minsz)
        sz = 2 * minsz;

    if (sz > mfp->maxsz)
        return 0; /* Do nothing */

    err = mdc_file_sync(mfp);
    if (err)
        return err;

    rc = ftruncate(mfp->fd, sz);
    if (rc == -1)
        return merr(errno);

    err = mdc_file_mmap(mfp, sz);
    if (err)
        return merr(errno);

    return 0;
}

static merr_t
mdc_file_append_sys(struct mdc_file *mfp, void *data, size_t len)
{
    struct mdc_rechdr_omf rhomf = {};
    struct iovec          iov[2];
    merr_t   err;
    uint32_t crc;
    uint8_t hdrlen;

    omf_set_rh_rsvd(&rhomf, 0);
    omf_set_rh_size(&rhomf, len);

    hdrlen = sizeof(rhomf.rh_size);
    crc = logrec_crc_get((const uint8_t *)&rhomf.rh_size, hdrlen, data, len);
    omf_set_rh_crc(&rhomf, crc);

    iov[0].iov_base = &rhomf;
    iov[0].iov_len = omf_mdc_rechdr_len();

    iov[1].iov_base = data;
    iov[1].iov_len = len;

    err = mfp->io.write(mfp->fd, mfp->woff, (const struct iovec *)&iov, 2, 0, NULL);
    if (err)
        return err;

    return 0;
}

static merr_t
mdc_file_append_mem(struct mdc_file *mfp, void *data, size_t len)
{
    struct mdc_rechdr_omf *rhomf;
    char    *addr;
    uint32_t crc;
    uint8_t hdrlen;

    addr = mfp->addr + mfp->woff;

    rhomf = (struct mdc_rechdr_omf *)addr;
    omf_set_rh_rsvd(rhomf, 0);
    omf_set_rh_size(rhomf, len);

    hdrlen = sizeof(rhomf->rh_size);
    crc = logrec_crc_get((const uint8_t *)&rhomf->rh_size, hdrlen, data, len);
    omf_set_rh_crc(rhomf, crc);

    memcpy(addr + omf_mdc_rechdr_len(), data, len);

    return 0;
}

merr_t
mdc_file_append(struct mdc_file *mfp, void *data, size_t len, bool sync)
{
    merr_t err;
    size_t tlen;

    if (!mfp || !data)
        return merr(EINVAL);

    tlen = omf_mdc_rechdr_len() + len;

    /* Extend file if the usage exceeds 75% of current size. */
    if (mfp->woff + tlen > ((3 * mfp->size) / 4)) {
        err = mdc_file_extend(mfp, mfp->size + tlen);
        if (err)
            return err;
    }

    if ((mfp->woff + tlen) > mfp->size)
        return merr(EFBIG);

    if (len >= PAGE_SIZE)
        err = mdc_file_append_sys(mfp, data, len);
    else
        err = mdc_file_append_mem(mfp, data, len);

    if (err)
        return err;

    mfp->woff += tlen;

    if (sync) {
        err = mdc_file_sync(mfp);
        if (err)
            return err;
    }

    return 0;
}
