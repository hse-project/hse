/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <crc32c/crc32c.h>
#include <hse_util/string.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>

#include "mdc.h"
#include "mdc_file.h"
#include "omf.h"
#include "io.h"

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

    struct io_ops  io;
    char          *addr;
    char           name[32];
};

static void
loghdr_init(struct mdc_loghdr *lh, uint64_t gen)
{
    lh->vers = MDC_LOGHDR_VERSION;
    lh->magic = MDC_LOGHDR_MAGIC;
    lh->rsvd = 0;
    lh->gen = gen;
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
    if (ev(err))
        return err;

    len = omf_mdc_loghdr_len();
    cc = pwrite(fd, &lhomf, len, 0);
    if (ev(cc != len))
        return merr(errno);

    rc = fsync(fd);
    if (ev(rc < 0))
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
    if (ev(err))
        return err;

    len = omf_mdc_loghdr_len();
    rc = msync(mfp->addr, len, MS_SYNC);
    if (ev(rc < 0))
        return merr(errno);

    return 0;
}

static merr_t
loghdr_validate(struct mdc_file *mfp, uint64_t *gen)
{
    struct mdc_loghdr *lh;
    merr_t             err;

    lh = &mfp->lh;

    err = omf_mdc_loghdr_unpack_letoh(lh, (const char *)mfp->addr);
    if (ev(err))
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
logrec_validate(char *addr, size_t *recsz)
{
    struct mdc_rechdr      rh;
    struct mdc_rechdr_omf *rhomf;
    uint32_t               crc;

    *recsz = 0;

    omf_mdc_rechdr_unpack_letoh(&rh, (const char *)addr);
    if (rh.size == 0 && rh.crc == 0)
        return merr(ENOMSG);

    rhomf = (struct mdc_rechdr_omf *)addr;
    addr += omf_mdc_rechdr_len();

    crc = logrec_crc_get(
        (const uint8_t *)&rhomf->rh_size, sizeof(rhomf->rh_size), (const uint8_t *)addr, rh.size);
    if (ev(crc != rh.crc))
        return merr(EBADMSG);

    *recsz = rh.size;

    return 0;
}

merr_t
mdc_file_create(int dirfd, uint64_t logid, int flags, int mode, size_t capacity)
{
    int    fd, rc;
    merr_t err = 0;
    char   name[32];

    mdc_filename_gen(name, sizeof(name), logid);

    fd = openat(dirfd, name, flags, mode);
    if (ev(fd < 0)) {
        err = merr(errno);
        return err;
    }

    rc = ftruncate(fd, capacity);
    if (ev(rc < 0)) {
        err = merr(errno);
        mdc_file_destroy(dirfd, logid);
        hse_elog(HSE_ERR "%s: Pre-allocating mdc file 1 failed, name %s: @@e", err, __func__, name);
    }

    close(fd);

    return err;
}

merr_t
mdc_file_destroy(int dirfd, uint64_t logid)
{
    char name[32];
    int  rc;

    mdc_filename_gen(name, sizeof(name), logid);

    rc = unlinkat(dirfd, name, 0);
    if (ev(rc < 0))
        return merr(errno);

    return 0;
}

/* At commit, the log header of both MDC files are initialized. */
merr_t
mdc_file_commit(int dirfd, uint64_t logid)
{
    struct mdc_loghdr lh;
    char              name[32];
    merr_t            err = 0;
    int               fd;

    mdc_filename_gen(name, sizeof(name), logid);

    fd = openat(dirfd, name, O_RDWR);
    if (fd < 0) {
        err = merr(errno);
        hse_elog(HSE_ERR "%s: Commit mdc file failed, name %s: @@e", err, __func__, name);
        return err;
    }

    err = loghdr_update_byfd(fd, &lh, 0);

    close(fd);

    return err;
}

static merr_t
mdc_file_mmap(struct mdc_file *mfp)
{
    int flags, prot;

    if (ev(!mfp))
        return merr(EINVAL);

    flags = MAP_SHARED;
    prot = PROT_READ | PROT_WRITE;

    mfp->addr = mmap(NULL, mfp->size, prot, flags, mfp->fd, 0);
    if (ev(mfp->addr == MAP_FAILED))
        return merr(errno);

    return 0;
}

static merr_t
mdc_file_unmap(struct mdc_file *mfp)
{
    int rc;

    rc = munmap(mfp->addr, mfp->size);
    if (ev(rc < 0))
        return merr(errno);

    return 0;
}

static merr_t
mdc_file_validate(struct mdc_file *mfp, uint64_t *gen)
{
    char  *addr;
    merr_t err;
    int    rc;
    int    rhlen;

    if (ev(!mfp))
        return merr(EINVAL);

    addr = mfp->addr;

    /* The MDC file will now be read sequentially. Pass this hint to VMM via madvise. */
    rc = madvise(addr, mfp->size, MADV_SEQUENTIAL);
    if (rc < 0)
        hse_log(HSE_WARNING "%s: madvise mdc file %s %p failed", __func__, mfp->name, addr);

    /* Step 1: validate log header */
    err = loghdr_validate(mfp, gen);
    if (ev(err))
        goto errout;

    if (mfp->size > MDC_LOGHDR_LEN) {
        addr += MDC_LOGHDR_LEN; /* move past the log header */
        rhlen = omf_mdc_rechdr_len();

        /* Step 2: validate log records */
        do {
            size_t recsz;

            err = logrec_validate(addr, &recsz);
            if (err) {
                if (merr_errno(err) == ENOMSG) { /* End of log */
                    err = 0;
                    mfp->woff = addr - mfp->addr;
                    break;
                }
                ev(1);
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
    if (ev(rc < 0))
        return merr(errno);

    *size = s.st_size;

    return 0;
}

merr_t
mdc_file_open(struct mpool_mdc *mdc, uint64_t logid, uint64_t *gen, struct mdc_file **handle)
{
    struct mdc_file *mfp;

    int    fd, dirfd;
    merr_t err;
    char   name[32];

    if (ev(!mdc))
        return merr(EINVAL);

    mdc_filename_gen(name, sizeof(name), logid);
    dirfd = mclass_dirfd(mdc_mclass_get(mdc));

    fd = openat(dirfd, name, O_RDWR);
    if (ev(fd < 0)) {
        err = merr(errno);
        return err;
    }

    mfp = calloc(1, sizeof(*mfp));
    if (ev(!mfp)) {
        err = merr(ENOMEM);
        goto err_exit2;
    }

    err = mdc_file_size(fd, &mfp->size);
    if (ev(err))
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

    err = mdc_file_mmap(mfp);
    if (ev(err))
        goto err_exit1;

    err = mdc_file_validate(mfp, gen);
    if (ev(err)) {
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
    if (ev(!mfp))
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

    if (ev(!mfp))
        return merr(EINVAL);

    err = loghdr_update(mfp, &mfp->lh, newgen);
    if (ev(err))
        return err;

    if (mfp->size > MDC_LOGHDR_LEN) {
        rc = msync(mfp->addr + MDC_LOGHDR_LEN, mfp->size - MDC_LOGHDR_LEN, MS_INVALIDATE);
        if (ev(rc < 0))
            return merr(errno);

        rc = fallocate(
            mfp->fd,
            FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            MDC_LOGHDR_LEN,
            mfp->size - MDC_LOGHDR_LEN);
        if (ev(rc < 0))
            return merr(errno);
    }

    rc = fsync(mfp->fd);
    if (ev(rc < 0))
        return merr(errno);

    mfp->woff = MDC_LOGHDR_LEN;
    mfp->roff = MDC_LOGHDR_LEN;
    mfp->raoff = MDC_RA_BYTES;

    return 0;
}

merr_t
mdc_file_gen(struct mdc_file *mfp, uint64_t *gen)
{
    if (ev(!mfp || !gen))
        return merr(EINVAL);

    *gen = mfp->lh.gen;

    return 0;
}

merr_t
mdc_file_exists(int dirfd, uint64_t logid1, uint64_t logid2, bool *exist)
{
    char   name[32];
    int    fd;
    merr_t err;

    *exist = false;

    mdc_filename_gen(name, sizeof(name), logid1);
    fd = openat(dirfd, name, O_RDONLY);
    if (fd < 0) {
        err = merr(errno);
        if (merr_errno(err) == ENOENT)
            return 0;
        return err;
    }
    close(fd);

    mdc_filename_gen(name, sizeof(name), logid2);
    fd = openat(dirfd, name, O_RDONLY);
    if (fd < 0) {
        err = merr(errno);
        if (merr_errno(err) == ENOENT)
            return 0;
        return err;
    }
    close(fd);

    *exist = true;

    return 0;
}

merr_t
mdc_file_sync(struct mdc_file *mfp)
{
    int rc;

    if (ev(!mfp))
        return merr(EINVAL);

    rc = msync(mfp->addr, mfp->woff, MS_SYNC);
    if (ev(rc < 0))
        return merr(errno);

    rc = fsync(mfp->fd);
    if (ev(rc < 0))
        return merr(errno);

    return 0;
}

merr_t
mdc_file_rewind(struct mdc_file *mfp)
{
    if (ev(!mfp))
        return merr(EINVAL);

    mfp->roff = MDC_LOGHDR_LEN;
    mfp->raoff = MDC_RA_BYTES;

    return 0;
}

merr_t
mdc_file_usage(struct mdc_file *mfp, size_t *usage)
{
    if (ev(!mfp || !usage))
        return merr(EINVAL);

    *usage = mfp->woff;

    return 0;
}

merr_t
mdc_file_read(struct mdc_file *mfp, void *data, size_t len, size_t *rdlen, bool verify)
{
    struct mdc_rechdr rh;
    char             *addr;
    int               rhlen, rc;

    if (ev(!mfp || !data))
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

    omf_mdc_rechdr_unpack_letoh(&rh, (const char *)addr);
    if (rh.size == 0 && rh.crc == 0) { /* Reached end of log */
        if (rdlen)
            *rdlen = 0;
        return 0;
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

        rhomf = (struct mdc_rechdr_omf *)addr;

        crc = logrec_crc_get(
            (const uint8_t *)&rhomf->rh_size,
            sizeof(rhomf->rh_size),
            (const uint8_t *)data,
            rh.size);
        if (ev(crc != rh.crc))
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
    if (ev(err))
        return err;

    err = mdc_file_unmap(mfp);
    if (ev(err))
        return err;

    mfp->size = sz;

    rc = ftruncate(mfp->fd, mfp->size);
    if (ev(rc < 0))
        return merr(errno);

    err = mdc_file_mmap(mfp);
    if (ev(err))
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

    omf_set_rh_size(&rhomf, len);

    crc = logrec_crc_get((const uint8_t *)&rhomf.rh_size, sizeof(rhomf.rh_size), data, len);
    omf_set_rh_crc(&rhomf, crc);

    iov[0].iov_base = &rhomf;
    iov[0].iov_len = omf_mdc_rechdr_len();

    iov[1].iov_base = data;
    iov[1].iov_len = len;

    err = mfp->io.write(mfp->fd, mfp->woff, (const struct iovec *)&iov, 2, 0);
    if (ev(err))
        return err;

    return 0;
}

static merr_t
mdc_file_append_mem(struct mdc_file *mfp, void *data, size_t len)
{
    struct mdc_rechdr_omf *rhomf;

    char    *addr;
    uint32_t crc;

    addr = mfp->addr + mfp->woff;

    rhomf = (struct mdc_rechdr_omf *)addr;
    omf_set_rh_size(rhomf, len);

    crc = logrec_crc_get((const uint8_t *)&rhomf->rh_size, sizeof(rhomf->rh_size), data, len);
    omf_set_rh_crc(rhomf, crc);

    memcpy(addr + omf_mdc_rechdr_len(), data, len);

    return 0;
}

merr_t
mdc_file_append(struct mdc_file *mfp, void *data, size_t len, bool sync)
{
    merr_t err;
    size_t tlen;

    if (ev(!mfp || !data))
        return merr(EINVAL);

    tlen = omf_mdc_rechdr_len() + len;

    /* Extend file if the usage exceeds 75% of current size. */
    if (mfp->woff + tlen > ((3 * mfp->size) / 4)) {
        err = mdc_file_extend(mfp, mfp->size + tlen);
        if (ev(err))
            return err;
    }

    if (ev((mfp->woff + tlen) > mfp->size))
        return merr(EFBIG);

    if (len >= PAGE_SIZE)
        err = mdc_file_append_sys(mfp, data, len);
    else
        err = mdc_file_append_mem(mfp, data, len);

    if (ev(err))
        return err;

    mfp->woff += tlen;

    if (sync) {
        err = mdc_file_sync(mfp);
        if (ev(err))
            return err;
    }

    return 0;
}
