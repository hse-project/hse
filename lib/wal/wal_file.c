/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/mutex.h>
#include <hse_util/list.h>
#include <hse_util/page.h>
#include <hse_util/logging.h>
#include <hse_util/string.h>

#include "wal.h"
#include "wal_file.h"
#include "wal_omf.h"

#define WAL_FILE_HDR_LEN   (PAGE_SIZE)
#define WAL_FILE_HDR_OFF   (0)


struct wal_fileset {
    struct mutex lock HSE_ALIGNED(SMP_CACHE_BYTES);
    struct list_head active;
    struct list_head complete;

    atomic64_t activec;
    atomic64_t compc;
    atomic64_t reclaimc;

    struct mpool *mp HSE_ALIGNED(SMP_CACHE_BYTES);
    enum mpool_mclass mclass;
    size_t capacity;
    u32    magic;
    u32    version;

};

struct wal_file {
    struct list_head link;

    struct wal_minmax_info info;
    off_t roff;
    off_t woff;
    off_t soff;
    atomic64_t ref;

    struct mpool_file *mpf HSE_ALIGNED(SMP_CACHE_BYTES);
    struct wal_fileset *wfset;
    uint64_t gen;
    int      fileid;
    char     name[64];

};


static merr_t
wal_file_format(struct wal_file *wfile, off_t soff, bool closing)
{
    char buf[WAL_FILE_HDR_LEN] HSE_ALIGNED(PAGE_SIZE) = {0};
    struct wal_fileset *wfset = wfile->wfset;

    wal_filehdr_pack(wfset->magic, wfset->version, &wfile->info, soff, closing, buf);

    return mpool_file_write(wfile->mpf, WAL_FILE_HDR_OFF, buf, sizeof(buf), NULL);
}

void
wal_file_minmax_init(struct wal_minmax_info *info)
{
    info->min_seqno = info->min_gen = info->min_txid = U64_MAX;
    info->max_seqno = info->max_gen = info->max_txid = 0;
}

void
wal_file_minmax_update(struct wal_file *wfile, struct wal_minmax_info *info)
{
    struct wal_minmax_info *winfo;

    winfo = &wfile->info;
    winfo->min_seqno = min_t(u64, winfo->min_seqno, info->min_seqno);
    winfo->max_seqno = max_t(u64, winfo->max_seqno, info->max_seqno);
    winfo->min_gen = min_t(u64, winfo->min_gen, info->min_gen);
    winfo->max_gen = max_t(u64, winfo->max_gen, info->max_gen);
    winfo->min_txid = min_t(u64, winfo->min_txid, info->min_txid);
    winfo->max_txid = max_t(u64, winfo->max_txid, info->max_txid);
}

merr_t
wal_fileset_reclaim(struct wal_fileset *wfset, u64 seqno, u64 gen, u64 txhorizon, bool closing)
{
    struct wal_file *cur, *next;
    struct list_head reclaim;

    INIT_LIST_HEAD(&reclaim);

    mutex_lock(&wfset->lock);
    list_for_each_entry_safe(cur, next, &wfset->complete, link) {
        struct wal_minmax_info *info = &cur->info;

        if (info->max_gen > gen) {
            if (closing) {
                /* TODO: Seems like this cannot happen during graceful close.
                 * If it does happen, do not destroy the file.
                 */
                list_del_init(&cur->link);
                wal_file_put(cur);
                continue;
            }
            break;
        }

        if (info->max_seqno <= seqno && info->max_txid < txhorizon) {
            assert(info->max_gen <= gen);
            list_del_init(&cur->link);
            list_add_tail(&cur->link, &reclaim);
        }
    }
    mutex_unlock(&wfset->lock);

    list_for_each_entry_safe(cur, next, &reclaim, link) {
        u64 gen = cur->gen;
        int fileid = cur->fileid;

#ifndef NDEBUG
        struct wal_minmax_info *info = &cur->info;

        hse_log(HSE_NOTICE
                "Reclaiming gen %lu [%lu, %lu] seqno %lu [%lu, %lu] txid %lu [%lu, %lu]",
                gen, info->min_gen, info->max_gen,
                seqno, info->min_seqno, info->max_seqno,
                txhorizon, info->min_txid, info->max_txid);
#endif

        list_del(&cur->link);
        assert(atomic64_read(&cur->ref) == 1);
        wal_file_put(cur);
        wal_file_destroy(wfset, gen, fileid);
        atomic64_inc(&wfset->reclaimc);
    }

    return 0;
}

void
wal_file_cb(void *wfset, const char *path)
{
    /* Until replay is implemented, remove leftover WAL files from crash  */
    hse_log(HSE_NOTICE "Removing WAL file %s, recovery not implemented", path);
    remove(path);
}

merr_t
wal_fileset_replay(struct wal_fileset *wfset)
{
    struct mpool_file_cb cb;

    cb.cbarg = (void *)wfset;
    cb.cbfunc = wal_file_cb;

    return mpool_mclass_ftw(wfset->mp, wfset->mclass, WAL_FILE_PFX, &cb);
}

struct wal_fileset *
wal_fileset_open(struct mpool *mp, enum mpool_mclass mclass, size_t capacity, u32 magic, u32 vers)
{
    struct wal_fileset *wfset;

    wfset = calloc(1, sizeof(*wfset));
    if (!wfset)
        return NULL;

    mutex_init(&wfset->lock);
    INIT_LIST_HEAD(&wfset->active);
    INIT_LIST_HEAD(&wfset->complete);
    atomic64_set(&wfset->activec, 0);
    atomic64_set(&wfset->compc, 0);
    atomic64_set(&wfset->reclaimc, 0);

    wfset->mp = mp;
    wfset->mclass = mclass;
    wfset->capacity = capacity;
    wfset->magic = magic;
    wfset->version = vers;

    if (wal_fileset_replay(wfset)) {
        free(wfset);
        return NULL;
    }

    return wfset;
}

void
wal_fileset_close(struct wal_fileset *wfset, u64 ingestseq, u64 ingestgen, u64 txhorizon)
{
    if (!wfset)
        return;

    list_splice_tail(&wfset->active, &wfset->complete);
    INIT_LIST_HEAD(&wfset->active);
    wal_fileset_reclaim(wfset, ingestseq, ingestgen, txhorizon, true);

    mutex_destroy(&wfset->lock);
    free(wfset);
}

merr_t
wal_file_open(
    struct wal_fileset *wfset,
    uint64_t            gen,
    int                 fileid,
    struct wal_file   **handle)
{
    struct wal_file   *wfile, *cur = NULL, *next;
    struct mpool_file *mpf;
    merr_t err;
    char name[64];
    bool sparse = false;

    if (!wfset)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", WAL_FILE_PFX, gen, fileid);

    err = mpool_file_open(wfset->mp, wfset->mclass, name, O_RDWR | O_DIRECT,
                          wfset->capacity, sparse, &mpf);
    if (err)
        return err;

    wfile = aligned_alloc(alignof(*wfile), sizeof(*wfile));
    if (!wfile) {
        mpool_file_close(mpf);
        return merr(ENOMEM);
    }

    wfile->mpf = mpf;
    wfile->wfset = wfset;
    wfile->gen = gen;
    wfile->fileid = fileid;
    strlcpy(wfile->name, name, sizeof(wfile->name));

    wal_file_minmax_init(&wfile->info);
    wfile->roff = 0;
    wfile->woff = 0;
    wfile->soff = 0;
    atomic64_set(&wfile->ref, 1);

    INIT_LIST_HEAD(&wfile->link);

    mutex_lock(&wfset->lock);
    list_for_each_entry_safe(cur, next, &wfset->active, link) {
        if (cur->gen <= wfile->gen) {
            list_add_tail(&wfile->link, &cur->link);
            break;
        }
    }
    if (!cur)
        list_add(&wfile->link, &wfset->active);
    mutex_unlock(&wfset->lock);

    atomic64_inc(&wfset->activec);

    *handle = wfile;

    return 0;
}

merr_t
wal_file_close(struct wal_file *wfile)
{
    merr_t err;

    if (!wfile)
        return merr(EINVAL);

    err = mpool_file_close(wfile->mpf);
    if (err)
        return err;

    free(wfile);

    return 0;
}

merr_t
wal_file_complete(struct wal_fileset *wfset, struct wal_file *wfile)
{
    struct wal_file *cur = NULL, *next;
    merr_t err;

    err = wal_file_format(wfile, wfile->soff, true);
    if (err)
        return err;

    mutex_lock(&wfset->lock);
    list_del_init(&wfile->link);
    list_for_each_entry_safe(cur, next, &wfset->complete, link) {
        if (cur->gen >= wfile->gen) {
            list_add_tail(&wfile->link, &cur->link);
            break;
        }
    }
    if (!cur)
        list_add_tail(&wfile->link, &wfset->complete);
    mutex_unlock(&wfset->lock);
    atomic64_inc(&wfset->compc);

    return 0;
}

void
wal_file_get(struct wal_file *wfile)
{
    if (!wfile)
        return;

    atomic64_inc(&wfile->ref);
}

void
wal_file_put(struct wal_file *wfile)
{
    if (wfile && atomic64_dec_return(&wfile->ref) == 0)
        wal_file_close(wfile);
}

merr_t
wal_file_destroy(struct wal_fileset *wfset, uint64_t gen, int fileid)
{
    char name[PATH_MAX];

    if (!wfset)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", WAL_FILE_PFX, gen, fileid);

    return mpool_file_destroy(wfset->mp, wfset->mclass, name);
}

merr_t
wal_file_read(struct wal_file *wfile, char *buf, size_t len)
{
    merr_t err;
    off_t off;
    size_t len_copy = len;

    if (!wfile)
        return merr(EINVAL);

    off = wfile->roff;
    while (len > 0) {
        size_t cc;

        err = mpool_file_read(wfile->mpf, off, buf, len, &cc);
        if (err)
            return err;

        buf += cc;
        off += cc;
        len -= cc;
    }

    wfile->roff += len_copy;

    return 0;
}

merr_t
wal_file_write(struct wal_file *wfile, const char *buf, size_t len)
{
    merr_t err;
    const char *abuf;
    off_t off, aoff;
    size_t alen, roundsz;
    bool adjust_woff = false;

    if (!wfile)
        return merr(EINVAL);

    /* rounddown the buf and file offset to 4K alignment */
    abuf = (const char *)((uintptr_t)buf & PAGE_MASK);
    off = wfile->woff;
    aoff = (off & PAGE_MASK);

    roundsz = buf - abuf;
    if (roundsz != (off - aoff)) { /* Must be the first write if buf and off alignment mismatch */
        assert(off == WAL_FILE_HDR_OFF);
        if (off != WAL_FILE_HDR_OFF)
            return merr(EBUG);

        adjust_woff = true;
    }

    /* Pack file header with the start offset for the first record */
    if (off == WAL_FILE_HDR_OFF) {
        err = wal_file_format(wfile, roundsz, false);
        if (err)
            return err;

        wfile->soff = roundsz;
        aoff += WAL_FILE_HDR_LEN;
        wfile->woff += WAL_FILE_HDR_LEN;
    }

    /* roundup the len to 4K alignment */
    alen = len + roundsz;
    alen = ALIGN(alen, PAGE_SIZE);

    assert(PAGE_ALIGNED(abuf) && PAGE_ALIGNED(aoff) && PAGE_ALIGNED(alen));

    while (alen > 0) {
        size_t cc;

        err = mpool_file_write(wfile->mpf, aoff, abuf, alen, &cc);
        if (err)
            return err;

        assert(PAGE_ALIGNED(cc));
        abuf += cc;
        aoff += cc;
        alen -= cc;
    }

    err = mpool_file_sync(wfile->mpf);
    if (err)
        return err;

    /* Bring the buffer addr and file offset to the same alignment if it mismatched */
    if (adjust_woff)
        wfile->woff += roundsz;

    wfile->woff += len;

    return 0;
}
