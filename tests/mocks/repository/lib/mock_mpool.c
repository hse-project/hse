/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/util/inttypes.h>
#include <hse/logging/logging.h>
#include <hse/util/event_counter.h>
#include <hse/util/page.h>
#include <hse/util/slab.h>
#include <hse/util/minmax.h>
#include <hse/util/compiler.h>

#include <hse/ikvdb/limits.h>

#include <bsd/string.h>

#include <mocks/mock_mpool.h>

struct mocked_mblock {
    void * mb_base;
    size_t mb_alloc_cap;
    size_t mb_write_len;
};

struct mocked_map {
    u64 *mbidv;
    int  mbidc;
    bool mapped;
};

struct mocked_mdc {
    int  len, cap;
    int  cur, wcur;
    char array[0];
    size_t (*getlen)(void *, size_t);
};

struct mocked_mblock mocked_mblocks[MPM_MAX_MBLOCKS];
struct mocked_map    mocked_maps[MPM_MAX_MAPS];

/* Can only mock a single MDC */
u64 mocked_mdc_id;

#define id2index(id)    ((id)-MPM_MBLOCK_ID_BASE)
#define index2id(index) ((index) + MPM_MBLOCK_ID_BASE)

static merr_t
get_mblock(u64 id, struct mocked_mblock **mb)
{
    u64 i = id2index(id);

    if (i >= MPM_MAX_MBLOCKS)
        return merr(EBUG);

    if (!mocked_mblocks[i].mb_base)
        return merr(EBUG);

    *mb = &mocked_mblocks[i];

    return 0;
}

static merr_t
_mpool_mblock_alloc(
    struct mpool *       mp,
    enum hse_mclass      mclass,
    uint32_t             flags,
    uint64_t *           handle,
    struct mblock_props *props)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;
    u64                   blkid;

    err = mpm_mblock_alloc(KBLOCK_MAX_SIZE, &blkid);
    if (err)
        return err;

    err = get_mblock(blkid, &mb);
    if (err)
        return err;

    *handle = blkid & 0x0fffffffffffffff; /* make sure not negative */
    if (props) {
        memset(props, 0, sizeof(*props));
        props->mpr_objid = blkid;
        props->mpr_alloc_cap = mb->mb_alloc_cap;
        props->mpr_write_len = 0;
    }

    return 0;
}

merr_t
_mpool_mblock_props_get(struct mpool *mp, uint64_t objid, struct mblock_props *props)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;
    int                   i;

    /* Find a slot in the array that isn't in use yet */
    for (i = 0; i < MPM_MAX_MBLOCKS; i++) {
        if (!mocked_mblocks[i].mb_base) {
            mb = mocked_mblocks + i;
            break;
        }
    }

    if (!mb)
        return merr(EBUG);

    err = get_mblock(objid, &mb);
    if (err)
        return err;

    if (props) {
        memset(props, 0, sizeof(*props));
        props->mpr_objid = objid;
    }

    return 0;
}

static merr_t
_mpool_mblock_commit(struct mpool *mp, uint64_t id)
{
    return 0;
}

static merr_t
_mpool_mblock_delete(struct mpool *mp, uint64_t id)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;

    err = get_mblock(id, &mb);
    if (err)
        return err;

    if (!mb->mb_base)
        return merr(EBUG);

    free(mb->mb_base);
    mb->mb_base = 0;
    mb->mb_alloc_cap = 0;
    mb->mb_write_len = 0;

    return 0;
}

merr_t
_mpool_props_get(struct mpool *mp, struct mpool_props *props)
{
    assert(HSE_MCLASS_BASE == HSE_MCLASS_CAPACITY);

    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (i == HSE_MCLASS_BASE) {
            strlcpy(
                props->mclass[i].mc_path,
                MPOOL_CAPACITY_MCLASS_DEFAULT_PATH,
                sizeof(props->mclass[i].mc_path));
        }

        props->mclass[i].mc_mblocksz = MPOOL_MBLOCK_SIZE_DEFAULT;
        props->mclass[i].mc_filecnt = MPOOL_MCLASS_FILECNT_DEFAULT;
        props->mclass[i].mc_fmaxsz = MPOOL_MCLASS_FILESZ_DEFAULT;
    }

    return 0;
}

merr_t
_mpool_mclass_props_get(
    struct mpool *             mp,
    enum hse_mclass            mclass,
    struct mpool_mclass_props *props)
{
    if (mclass >= HSE_MCLASS_COUNT || !props)
        return merr(EINVAL);

    memset(props, 0, sizeof(*props));

    if (mclass == HSE_MCLASS_BASE) {
        strlcpy(
            props->mc_path,
            MPOOL_CAPACITY_MCLASS_DEFAULT_PATH,
            sizeof(props->mc_path));

        props->mc_mblocksz = MPOOL_MBLOCK_SIZE_DEFAULT;
        props->mc_filecnt = MPOOL_MCLASS_FILECNT_DEFAULT;
        props->mc_fmaxsz = MPOOL_MCLASS_FILESZ_DEFAULT;
    }

    return mclass == HSE_MCLASS_BASE ? 0 : merr(ENOENT);
}

bool
_mpool_mclass_is_configured(struct mpool *const mp, const enum hse_mclass mclass)
{
    if (mclass >= HSE_MCLASS_COUNT)
        return merr(EINVAL);

    return mclass == HSE_MCLASS_BASE;
}

/*
 * Internal function to support _mpool_mblock_read and mpool_mblock_write_data.
 * For writes, it is assumed the offset parameter is 0.
 */
static merr_t
mblock_rw(u64 id, const struct iovec *iov, int niov, size_t off, bool read)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;
    size_t                total_len = 0;
    void *                src;
    void *                dst;
    int                   i;

    err = get_mblock(id, &mb);
    if (err)
        return err;

    if (!read && off != 0)
        return merr(EBUG);

    /*
     * Enforce mpool_mblock_read/write IO restrictions.
     */

    /* block offset must be a multiple of page size */
    if (!IS_ALIGNED(off, PAGE_SIZE))
        return merr(EINVAL);

    for (i = 0; i < niov; i++) {
        /* Each iovec address must be page aligned */
        if (!IS_ALIGNED((uintptr_t)iov[i].iov_base, PAGE_SIZE))
            return merr(EINVAL);
        /* Each iovec length must be page aligned */
        if (!IS_ALIGNED(iov[i].iov_len, PAGE_SIZE))
            return merr(EINVAL);
        total_len += iov[i].iov_len;
    }

    if (read) {
        if (off + total_len > mb->mb_write_len)
            return merr(EBUG);
    } else {
        if (off + total_len > mb->mb_alloc_cap)
            return merr(EBUG);
    }

    for (i = 0; i < niov; i++) {
        if (read) {
            src = mb->mb_base + off;
            dst = iov[i].iov_base;
        } else {
            src = iov[i].iov_base;
            dst = mb->mb_base + off;
        }
        memcpy(dst, src, iov[i].iov_len);
        off += iov[i].iov_len;
    }

    if (!read)
        mb->mb_write_len = total_len;

    return 0;
}

static merr_t
_mpool_mblock_read(struct mpool *mp, uint64_t id, const struct iovec *iovec, int niov, off_t off)
{
    return mblock_rw(id, iovec, niov, off, true);
}

static merr_t
_mpool_mblock_write(struct mpool *mp, uint64_t id, const struct iovec *iovec, int niov)
{
    return mblock_rw(id, iovec, niov, 0, false);
}

/*
 * MDC mocking concept:
 * The backing mocked_mblock holds the original data from file.
 * The internal array holds data written by the unit test.
 * Reads come from the mocked_mblock, writes go to mdc->array.
 *
 * Read must be blocked, then a buffer of len bytes is returned on each read.
 * The complication is the .dat files are not encapsulated as in an MDC,
 * and the MDC guarantees complete records.
 *
 * At close, if there is data in the internal array,
 * it should be compared to the mocked_mblock --
 * any difference is reported as an error.
 *
 * This latter test should be done in each testcase,
 * where it has context and can annotate why there
 * are any differences.
 */

struct mpm_mdc_rechdr_default {
    u32 type;
    u32 len;
};

static size_t
mpm_getlen_default(void *buf, size_t len)
{
    struct mpm_mdc_rechdr_default *p = buf;

    assert(len >= sizeof(struct mpm_mdc_rechdr_default));
    return p->len + sizeof(struct mpm_mdc_rechdr_default);
}

static merr_t
_mpool_mdc_open(struct mpool *mp, uint64_t oid1, uint64_t oid2, bool rdonly, struct mpool_mdc **mdc)
{
    struct mocked_mblock *mb = 0;
    struct mocked_mdc *   m;
    int                   cap;

    if (!mocked_mdc_id)
        return 0;

    if (get_mblock(mocked_mdc_id, &mb))
        return 0;

    cap = mb->mb_write_len;
    cap += cap / 2;
    m = mapi_safe_malloc(sizeof(*m) + cap);
    if (!m)
        return merr(ev(ENOMEM));
    bzero(m, sizeof(*m) + cap);
    m->len = mb->mb_write_len;
    m->cap = cap;
    m->cur = 0;
    m->wcur = 0;
    m->getlen = mpm_getlen_default;

    *mdc = (struct mpool_mdc *)m;
    return 0;
}

merr_t
mpm_mdc_set_getlen(struct mpool_mdc *mdc, size_t (*getlen)(void *, size_t))
{
    struct mocked_mdc *m;

    m = (void *)mdc;
    m->getlen = getlen;

    return 0;
}

merr_t
_mpool_mdc_close(struct mpool_mdc *mdc)
{
    free(mdc);
    return 0;
}

merr_t
_mpool_mdc_cstart(struct mpool_mdc *mdc)
{
    struct mocked_mdc *m = (void *)mdc;

    /* switches to the "other" mdc, presently empty */
    m->wcur = 0;
    return 0;
}

merr_t
_mpool_mdc_cend(struct mpool_mdc *mdc)
{
    return 0;
}

merr_t
_mpool_mdc_append(struct mpool_mdc *mdc, void *data, size_t len, bool sync)
{
    struct mocked_mdc *m = (void *)mdc;
    int                end = m->wcur + len;

    if (end > m->cap)
        return merr(ev(EFBIG));
    memcpy(m->array + m->wcur, data, len);
    m->wcur = end;
    return 0;
}

merr_t
_mpool_mdc_rewind(struct mpool_mdc *mdc)
{
    struct mocked_mdc *m = (void *)mdc;

    m->cur = 0;
    return 0;
}

merr_t
_mpool_mdc_read(struct mpool_mdc *mdc, void *data, size_t max, size_t *dlen)
{
    struct mocked_mdc *   m = (void *)mdc;
    struct mocked_mblock *mb = 0;
    size_t                len = 0;

    if (!mocked_mdc_id)
        return merr(EBUG);

    if (get_mblock(mocked_mdc_id, &mb))
        return merr(EBUG);

    /* read one record, do not read past end of mocked_mdc */

    if (!m->getlen)
        return merr(ev(EUNATCH));

    if (m->cur >= m->len) {
        *dlen = 0;
        return 0;
    }

    len = m->getlen(mb->mb_base + m->cur, m->len - m->cur);
    memcpy(data, mb->mb_base + m->cur, len);
    m->cur += len;
    *dlen = len;

    return 0;
}

/*----------------------------------------------------------------
 * Mock Back Doors
 */

merr_t
mpm_mblock_alloc(size_t capacity, u64 *id_out)
{
    struct mocked_mblock *mb = 0;
    void *                mem;
    int                   i;

    /* Find a slot in the array that isn't in use yet */
    for (i = 0; i < MPM_MAX_MBLOCKS; i++) {
        if (!mocked_mblocks[i].mb_base) {
            mb = mocked_mblocks + i;
            break;
        }
    }

    if (!mb)
        return merr(EBUG);

    capacity = ALIGN(capacity, PAGE_SIZE);
    mem = mapi_safe_malloc(capacity);
    if (!mem)
        return merr(EBUG);

    memset(mem, 0xff, capacity);

    mb->mb_write_len = 0;
    mb->mb_alloc_cap = capacity;
    mb->mb_base = mem;
    *id_out = index2id(i);
    return 0;
}

merr_t
mpm_mblock_write(u64 id, const void *data, u64 off, u32 len)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;

    err = get_mblock(id, &mb);
    if (err)
        return err;

    if (off + len > mb->mb_alloc_cap)
        return merr(EBUG);

    mb->mb_write_len = max(mb->mb_write_len, off + len);

    memcpy(mb->mb_base + off, data, len);

    return 0;
}

merr_t
mpm_mblock_read(u64 id, void *data, u64 off, u32 len)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;

    err = get_mblock(id, &mb);
    if (err)
        return err;

    if (off + len > mb->mb_alloc_cap)
        return merr(EBUG);

    memcpy(data, mb->mb_base + off, len);

    return 0;
}

static merr_t
mpm_read_fd(void *buf, size_t bufsz, size_t *bytes_read, int fd)
{
    size_t  off = 0;
    ssize_t rc, request, chunk = 1024 * 1024;
    char    tmp;

    while (off < bufsz) {
        request = bufsz - off < chunk ? bufsz - off : chunk;
        rc = read(fd, buf + off, request);
        if (rc == 0)
            break;
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0)
            return merr(errno);
        off += rc;
    }

    if (off != bufsz) {
        rc = read(fd, &tmp, 1);
        if (rc != 0)
            return merr(ENOSPC);
    }

    *bytes_read = off;
    return 0;
}

static merr_t
mpm_read_pipe(void *buf, size_t bufsz, size_t *bytes_read, char *fmt, ...)
{
    va_list ap;
    FILE *  fp;
    char    cmd[BUFSIZ];
    int     rc;
    merr_t  err;

    va_start(ap, fmt);
    rc = vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    if (rc >= sizeof(cmd))
        return merr(EINVAL);

    fp = popen(cmd, "r");
    if (!fp)
        return merr(errno);

    err = mpm_read_fd(buf, bufsz, bytes_read, fileno(fp));
    pclose(fp);

    return err;
}

static merr_t
mpm_read_file(void *buf, size_t bufsz, size_t *bytes_read, const char *file)
{
    FILE * fp;
    int    len;
    merr_t err;

    len = strlen(file);
    if (len > 3 && strcmp(file + len - 3, ".gz") == 0)
        return mpm_read_pipe(buf, bufsz, bytes_read, "zcat %s", file);

    if (len > 3 && strcmp(file + len - 3, ".xz") == 0)
        return mpm_read_pipe(buf, bufsz, bytes_read, "xzcat %s", file);

    fp = fopen(file, "r");
    if (!fp)
        return merr(errno);

    err = mpm_read_fd(buf, bufsz, bytes_read, fileno(fp));
    fclose(fp);

    return err;
}

merr_t
mpm_mblock_load_file(u64 id, const char *filename)
{
    struct mocked_mblock *mb = 0;
    merr_t                err;
    size_t                bytes_read;

    err = get_mblock(id, &mb);
    if (err)
        return err;

    err = mpm_read_file(mb->mb_base, mb->mb_alloc_cap, &bytes_read, filename);
    if (err)
        return err;

    mb->mb_write_len = bytes_read;

    return err;
}

merr_t
mpm_mblock_alloc_file(u64 *id_out, const char *filename)
{
    u64    id;
    merr_t err;

    err = mpm_mblock_alloc(VBLOCK_MAX_SIZE, &id);
    if (err)
        return err;

    err = mpm_mblock_load_file(id, filename);
    if (err)
        return err;

    *id_out = id;
    return 0;
}

merr_t
mpm_mdc_load_file(const char *filename, char **data, int *len)
{
    struct mocked_mblock *mb = 0;
    merr_t                err;

    err = mpm_mblock_alloc_file(&mocked_mdc_id, filename);
    if (err)
        return err;

    err = get_mblock(mocked_mdc_id, &mb);
    if (err)
        return err;

    if (data) {
        *data = mb->mb_base;
        *len = (int)mb->mb_write_len;
    }

    return 0;
}

merr_t
mpm_mblock_get_base(u64 id, void **data, size_t *wlen)
{
    struct mocked_mblock *mb = 0;
    merr_t                err;

    err = get_mblock(id, &mb);
    if (err)
        return err;

    *data = mb->mb_base;
    *wlen = mb->mb_write_len;
    return 0;
}

merr_t
mpm_mdc_get_written(struct mpool_mdc *mdc, char **data, int *len)
{
    struct mocked_mdc *m = (void *)mdc;

    *data = m->array;
    *len = m->wcur;

    return 0;
}

/*----------------------------------------------------------------
 * Install/Remove mpool mock
 */

void
mock_mpool_set(void)
{
    /* Allow repeated init() w/o intervening unset() */
    mock_mpool_unset();

    MOCK_SET(mpool, _mpool_mblock_alloc);
    MOCK_SET(mpool, _mpool_mblock_commit);
    MOCK_SET(mpool, _mpool_mblock_delete);
    MOCK_SET(mpool, _mpool_mblock_props_get);
    MOCK_SET(mpool, _mpool_mblock_read);
    MOCK_SET(mpool, _mpool_mblock_write);

    MOCK_SET(mpool, _mpool_mdc_append);
    MOCK_SET(mpool, _mpool_mdc_cend);
    MOCK_SET(mpool, _mpool_mdc_close);
    MOCK_SET(mpool, _mpool_mdc_cstart);
    MOCK_SET(mpool, _mpool_mdc_open);
    MOCK_SET(mpool, _mpool_mdc_read);
    MOCK_SET(mpool, _mpool_mdc_rewind);

    MOCK_SET(mpool, _mpool_props_get);

    MOCK_SET(mpool, _mpool_mclass_props_get);
    MOCK_SET(mpool, _mpool_mclass_is_configured);
}

void
mock_mpool_unset(void)
{
    int i;

    MOCK_UNSET(mpool, _mpool_mblock_alloc);
    MOCK_UNSET(mpool, _mpool_mblock_commit);
    MOCK_UNSET(mpool, _mpool_mblock_delete);
    MOCK_UNSET(mpool, _mpool_mblock_props_get);
    MOCK_UNSET(mpool, _mpool_mblock_read);
    MOCK_UNSET(mpool, _mpool_mblock_write);

    MOCK_UNSET(mpool, _mpool_mdc_append);
    MOCK_UNSET(mpool, _mpool_mdc_cend);
    MOCK_UNSET(mpool, _mpool_mdc_close);
    MOCK_UNSET(mpool, _mpool_mdc_cstart);
    MOCK_UNSET(mpool, _mpool_mdc_open);
    MOCK_UNSET(mpool, _mpool_mdc_read);
    MOCK_UNSET(mpool, _mpool_mdc_rewind);

    MOCK_UNSET(mpool, _mpool_props_get);

    MOCK_UNSET(mpool, _mpool_mclass_props_get);
    MOCK_UNSET(mpool, _mpool_mclass_is_configured);

    for (i = 0; i < MPM_MAX_MBLOCKS; ++i)
        mapi_safe_free(mocked_mblocks[i].mb_base);

    for (i = 0; i < MPM_MAX_MAPS; ++i)
        mapi_safe_free(mocked_maps[i].mbidv);

    memset(&mocked_mblocks, 0, sizeof(mocked_mblocks));
    memset(&mocked_maps, 0, sizeof(mocked_maps));
}
