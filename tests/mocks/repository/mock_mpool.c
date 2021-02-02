/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include "framework_external.h"

#include <hse_ut/conditions.h>

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>

#include <hse_ikvdb/limits.h>

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

#define id2index(id) ((id)-MPM_MBLOCK_ID_BASE)
#define index2id(index) ((index) + MPM_MBLOCK_ID_BASE)

static merr_t
get_mocked_map(struct mpool_mcache_map *map, struct mocked_map **mocked)
{
    size_t addr = (size_t)map;
    size_t base = (size_t)&mocked_maps[0];

    VERIFY_TRUE_RET(base <= addr, merr(EBUG));
    VERIFY_TRUE_RET(addr < base + sizeof(mocked_maps), merr(EBUG));
    VERIFY_TRUE_RET(0 == ((addr - base) % sizeof(mocked_maps[0])), merr(EBUG));

    *mocked = (struct mocked_map *)addr;
    return 0;
}

static merr_t
get_mblock(u64 id, struct mocked_mblock **mb)
{
    u64 i = id2index(id);

    VERIFY_LT_RET(i, MPM_MAX_MBLOCKS, merr(EBUG));
    VERIFY_TRUE_RET(mocked_mblocks[i].mb_base, merr(EBUG));

    *mb = &mocked_mblocks[i];
    return 0;
}

static merr_t
_mpool_mblock_alloc(
    struct mpool *       mp,
    enum mp_media_classp mclassp,
    bool                 spare,
    uint64_t *           handle,
    struct mblock_props *props)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;
    u64                   blkid;

    err = mpm_mblock_alloc(KBLOCK_MAX_SIZE, &blkid);
    VERIFY_TRUE_RET(err == 0, err);

    err = get_mblock(blkid, &mb);
    VERIFY_TRUE_RET(err == 0, err);

    *handle = blkid & 0x0fffffffffffffff; /* make sure not negative */
    if (props) {
        memset(props, 0, sizeof(*props));
        props->mpr_objid = blkid;
        props->mpr_alloc_cap = mb->mb_alloc_cap;
        props->mpr_write_len = 0;
        props->mpr_optimal_wrsz = 4096 * 3;
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
    VERIFY_TRUE_RET(mb, merr(EBUG));

    err = get_mblock(objid, &mb);
    VERIFY_TRUE_RET(err == 0, err);
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
_mpool_mblock_abort(struct mpool *mp, uint64_t id)
{
    return 0;
}

static merr_t
_mpool_mblock_delete(struct mpool *mp, uint64_t id)
{
    merr_t                err;
    struct mocked_mblock *mb = 0;

    err = get_mblock(id, &mb);
    VERIFY_EQ_RET(err, 0, err);

    VERIFY_TRUE_RET(mb->mb_base, merr(EBUG));

    free(mb->mb_base);
    mb->mb_base = 0;
    mb->mb_alloc_cap = 0;
    mb->mb_write_len = 0;

    return 0;
}

merr_t
_mpool_params_get(struct mpool *mp, struct mpool_params *params)
{
    params->mp_vma_size_max = 30;
    params->mp_mblocksz[MP_MED_CAPACITY] = 32 << 20;

    return 0;
}

merr_t
_mpool_mclass_get(struct mpool *mp, enum mp_media_classp mclass, struct mpool_mclass_props *props)
{
    if (mclass >= MP_MED_NUMBER)
        return merr(EINVAL);

    if (mclass == MP_MED_STAGING)
        return merr(ENOENT);

    return 0;
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
    VERIFY_EQ_RET(err, 0, err);

    if (!read)
        VERIFY_TRUE_RET(off == 0, merr(EBUG));

    /*
     * Enforce mpool_mblock_read/write IO restrictions.
     */

    /* block offset must be a multiple of page size */
    if (!IS_ALIGNED(off, PAGE_SIZE))
        return merr(EINVAL);

    for (i = 0; i < niov; i++) {
        /* Each iovec address must be page aligned */
        if (!IS_ALIGNED((unsigned long)iov[i].iov_base, PAGE_SIZE))
            return merr(EINVAL);
        /* Each iovec length must be page aligned */
        if (!IS_ALIGNED(iov[i].iov_len, PAGE_SIZE))
            return merr(EINVAL);
        total_len += iov[i].iov_len;
    }

    if (read)
        VERIFY_TRUE_RET(off + total_len <= mb->mb_write_len, merr(EBUG));
    else
        VERIFY_TRUE_RET(off + total_len <= mb->mb_alloc_cap, merr(EBUG));

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

    return 0;
}

static merr_t
_mpool_mcache_mmap(
    struct mpool *            mp,
    size_t                    mbidc,
    uint64_t *                mbidv,
    enum mpc_vma_advice       advice,
    struct mpool_mcache_map **handle)
{
    struct mocked_map *map = 0;
    int                i;

    VERIFY_TRUE_RET(handle, merr(EBUG));
    VERIFY_GT_RET(mbidc, 0, merr(EBUG));
    VERIFY_TRUE_RET(mbidv, merr(EBUG));

    for (i = 0; i < MPM_MAX_MAPS; i++) {
        if (!mocked_maps[i].mapped) {
            map = &mocked_maps[i];
            break;
        }
    }
    VERIFY_TRUE_RET(map, merr(EBUG));

    map->mbidv = mapi_safe_malloc(mbidc * sizeof(*mbidv));
    VERIFY_TRUE_RET(map->mbidv, merr(EBUG));

    for (i = 0; i < mbidc; i++)
        map->mbidv[i] = mbidv[i];

    map->mapped = 1;
    map->mbidc = mbidc;

    *handle = (struct mpool_mcache_map *)map;

    return 0;
}

static merr_t
_mpool_mcache_munmap(struct mpool_mcache_map *handle)
{
    merr_t             err;
    struct mocked_map *map = NULL;

    err = get_mocked_map(handle, &map);
    VERIFY_EQ_RET(err, 0, err);

    free(map->mbidv);
    map->mbidv = 0;
    map->mbidc = 0;
    map->mapped = 0;

    return 0;
}

static void *
_mpool_mcache_getbase(struct mpool_mcache_map *handle, u_int idx)
{
    merr_t                err;
    struct mocked_map *   map = NULL;
    struct mocked_mblock *mb  = 0;

    err = get_mocked_map(handle, &map);
    VERIFY_EQ_RET(err, 0, NULL);
    VERIFY_LT_RET(idx, map->mbidc, NULL);

    err = get_mblock(map->mbidv[idx], &mb);
    VERIFY_EQ_RET(err, 0, NULL);

    return mb->mb_base;
}

static merr_t
_mpool_mcache_madvise(
    struct mpool_mcache_map *map,
    uint                     mbidx,
    off_t                    offset,
    size_t                   length,
    int                      advice)
{
    return 0;
}

static merr_t
_mpool_mcache_getpages(
    struct mpool_mcache_map *handle,
    u_int                    pagec,
    u_int                    idx,
    const off_t              offsets[],
    void *                   pagev[])
{
    struct mocked_map *map = NULL;
    merr_t             err;
    u_int              i;

    err = get_mocked_map(handle, &map);
    VERIFY_EQ_RET(err, 0, err);

    VERIFY_LT_RET(idx, map->mbidc, merr(EBUG));

    for (i = 0; i < pagec; i++) {
        struct iovec iov;

        iov.iov_len = PAGE_SIZE;
        iov.iov_base = hse_page_alloc();
        VERIFY_TRUE_RET(iov.iov_base, merr(EBUG));

        err = mblock_rw(map->mbidv[idx], &iov, 1, offsets[i] * PAGE_SIZE, true);
        VERIFY_EQ_RET(err, 0, err);

        pagev[i] = iov.iov_base;
    }
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
_mpool_mdc_open(
    struct mpool *     mp,
    uint64_t           oid1,
    uint64_t           oid2,
    struct mpool_mdc **mdc)
{
    struct mocked_mblock *mb = 0;
    struct mocked_mdc *   m;
    int                   cap;

    VERIFY_NE_RET(0, mocked_mdc_id, 0);
    VERIFY_EQ_RET(0, get_mblock(mocked_mdc_id, &mb), 0);

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

    VERIFY_NE_RET(0, mocked_mdc_id, 0);
    VERIFY_EQ_RET(0, get_mblock(mocked_mdc_id, &mb), 0);

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

    VERIFY_TRUE_RET(mb, merr(EBUG));

    capacity = ALIGN(capacity, PAGE_SIZE);
    mem = mapi_safe_malloc(capacity);
    VERIFY_TRUE_RET(mem, merr(EBUG));

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
    VERIFY_EQ_RET(err, 0, err);

    VERIFY_TRUE_RET(off + len <= mb->mb_alloc_cap, merr(EBUG));
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
    VERIFY_EQ_RET(err, 0, err);

    VERIFY_TRUE_RET(off + len <= mb->mb_write_len, merr(EBUG));
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
        VERIFY_TRUE_RET(rc > 0, merr(errno));
        off += rc;
    }

    if (off != bufsz) {
        rc = read(fd, &tmp, 1);
        VERIFY_TRUE_RET(rc == 0, merr(ENOSPC));
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
    VERIFY_TRUE_RET(fp != 0, merr(errno));

    err = mpm_read_fd(buf, bufsz, bytes_read, fileno(fp));
    pclose(fp);
    VERIFY_EQ_RET(err, 0, err);
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
    VERIFY_TRUE_RET(fp != 0, merr(errno));

    err = mpm_read_fd(buf, bufsz, bytes_read, fileno(fp));
    fclose(fp);
    VERIFY_EQ_RET(err, 0, err);
    return 0;
}

merr_t
mpm_mblock_load_file(u64 id, const char *filename)
{
    struct mocked_mblock *mb = 0;
    merr_t                err;
    size_t                bytes_read;

    err = get_mblock(id, &mb);
    VERIFY_EQ_RET(err, 0, err);

    err = mpm_read_file(mb->mb_base, mb->mb_alloc_cap, &bytes_read, filename);
    VERIFY_EQ_RET(err, 0, err);

    mb->mb_write_len = bytes_read;
    return 0;
}

merr_t
mpm_mblock_alloc_file(u64 *id_out, const char *filename)
{
    u64    id;
    merr_t err;

    err = mpm_mblock_alloc(VBLOCK_MAX_SIZE, &id);
    VERIFY_TRUE_RET(err == 0, err);

    err = mpm_mblock_load_file(id, filename);
    VERIFY_TRUE_RET(err == 0, err);

    *id_out = id;
    return 0;
}

merr_t
mpm_mdc_load_file(const char *filename, char **data, int *len)
{
    struct mocked_mblock *mb = 0;
    merr_t                err;

    err = mpm_mblock_alloc_file(&mocked_mdc_id, filename);
    VERIFY_TRUE_RET(err == 0, err);

    err = get_mblock(mocked_mdc_id, &mb);
    VERIFY_EQ_RET(err, 0, err);

    if (data) {
        *data = mb->mb_base;
        *len = (int)mb->mb_write_len;
    }

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
    MOCK_SET(mpool, _mpool_mblock_props_get);
    MOCK_SET(mpool, _mpool_mblock_abort);
    MOCK_SET(mpool, _mpool_mblock_commit);
    MOCK_SET(mpool, _mpool_mblock_delete);
    MOCK_SET(mpool, _mpool_mblock_read);
    MOCK_SET(mpool, _mpool_mblock_write);

    MOCK_SET(mpool, _mpool_mcache_mmap);
    MOCK_SET(mpool, _mpool_mcache_munmap);
    MOCK_SET(mpool, _mpool_mcache_madvise);
    MOCK_SET(mpool, _mpool_mcache_getbase);
    MOCK_SET(mpool, _mpool_mcache_getpages);

    MOCK_SET(mpool, _mpool_mdc_open);
    MOCK_SET(mpool, _mpool_mdc_close);
    MOCK_SET(mpool, _mpool_mdc_cstart);
    MOCK_SET(mpool, _mpool_mdc_cend);
    MOCK_SET(mpool, _mpool_mdc_append);
    MOCK_SET(mpool, _mpool_mdc_rewind);
    MOCK_SET(mpool, _mpool_mdc_read);
    MOCK_SET(mpool, _mpool_params_get);
    MOCK_SET(mpool, _mpool_mclass_get);

    mapi_inject(mapi_idx_mpool_mdc_rootid_get, 0);
}

void
mock_mpool_unset(void)
{
    int i;

    MOCK_UNSET(mpool, _mpool_mblock_alloc);
    MOCK_UNSET(mpool, _mpool_mblock_abort);
    MOCK_UNSET(mpool, _mpool_mblock_commit);
    MOCK_UNSET(mpool, _mpool_mblock_delete);
    MOCK_UNSET(mpool, _mpool_mblock_read);
    MOCK_UNSET(mpool, _mpool_mblock_write);
    MOCK_UNSET(mpool, _mpool_params_get);
    MOCK_UNSET(mpool, _mpool_mclass_get);

    MOCK_UNSET(mpool, _mpool_mcache_mmap);
    MOCK_UNSET(mpool, _mpool_mcache_munmap);
    MOCK_UNSET(mpool, _mpool_mcache_madvise);
    MOCK_UNSET(mpool, _mpool_mcache_getbase);
    MOCK_UNSET(mpool, _mpool_mcache_getpages);

    MOCK_UNSET(mpool, _mpool_mdc_open);
    MOCK_UNSET(mpool, _mpool_mdc_close);
    MOCK_UNSET(mpool, _mpool_mdc_cstart);
    MOCK_UNSET(mpool, _mpool_mdc_cend);
    MOCK_UNSET(mpool, _mpool_mdc_append);
    MOCK_UNSET(mpool, _mpool_mdc_rewind);
    MOCK_UNSET(mpool, _mpool_mdc_read);

    mapi_inject_unset(mapi_idx_mpool_mdc_rootid_get);

    for (i = 0; i < MPM_MAX_MBLOCKS; ++i)
        mapi_safe_free(mocked_mblocks[i].mb_base);

    for (i = 0; i < MPM_MAX_MAPS; ++i)
        mapi_safe_free(mocked_maps[i].mbidv);

    memset(&mocked_mblocks, 0, sizeof(mocked_mblocks));
    memset(&mocked_maps, 0, sizeof(mocked_maps));
}
