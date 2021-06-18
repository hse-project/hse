/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/mutex.h>
#include <hse_util/list.h>
#include <hse_util/page.h>
#include <hse_util/logging.h>

#include "wal.h"
#include "wal_file.h"
#include "wal_omf.h"


struct wal_fileset {
    struct list_head active;
    struct list_head complete;

    atomic64_t activec;
    atomic64_t compc;
    atomic64_t reclaimc;

    struct mpool *mp;
    enum mpool_mclass mclass;
    size_t capacity;
    u32    magic;
    u32    version;

    struct mutex lock HSE_ALIGNED(SMP_CACHE_BYTES);
};

struct wal_file {
    struct list_head   link;

    struct mpool_file *mpf;
    uint64_t gen;
    int      fileid;
    char     name[64];

    struct wal_minmax_info info HSE_ALIGNED(SMP_CACHE_BYTES);
    off_t    roff;
    off_t    woff;

    atomic64_t ref HSE_ALIGNED(SMP_CACHE_BYTES);
};

/* Forward decls */
static merr_t
wal_file_pwrite(struct wal_file *wfile, const char *buf, size_t len, off_t off);

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
        struct wal_minmax_info *info = &cur->info;

#ifndef NDEBUG
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

struct wal_fileset *
wal_fileset_open(struct mpool *mp, enum mpool_mclass mclass, size_t capacity, u32 magic, u32 vers)
{
    struct wal_fileset *wfset;

    wfset = calloc(1, sizeof(*wfset));
    if (!wfset)
        return NULL;

    INIT_LIST_HEAD(&wfset->active);
    INIT_LIST_HEAD(&wfset->complete);
    atomic64_set(&wfset->activec, 0);
    atomic64_set(&wfset->compc, 0);
    atomic64_set(&wfset->reclaimc, 0);

    mutex_init(&wfset->lock);

    wfset->mp = mp;
    wfset->mclass = mclass;
    wfset->capacity = capacity;
    wfset->magic = magic;
    wfset->version = vers;

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

static merr_t
wal_file_format(struct wal_file *wfile, u32 magic, u32 version)
{
    char buf[PAGE_SIZE] = {};

    wal_filehdr_pack(magic, version, false, &wfile->info, buf);

    return wal_file_write(wfile, (const char *)buf, sizeof(buf));
}

merr_t
wal_file_open(
    struct wal_fileset *wfset,
    uint64_t            gen,
    int                 fileid,
    struct wal_file   **handle)
{
    struct wal_file   *wfile, *cur, *next;
    struct mpool_file *mpf;
    merr_t err;
    char name[PATH_MAX];
    bool sparse = true, added = false;

    if (!wfset)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", "wal", gen, fileid);

    err = mpool_file_open(wfset->mp, wfset->mclass, name, O_RDWR, wfset->capacity, sparse, &mpf);
    if (err)
        return err;

    wfile = calloc(1, sizeof(*wfile));
    if (!wfile) {
        mpool_file_close(mpf);
        return merr(ENOMEM);
    }

    wfile->mpf = mpf;
    wfile->gen = gen;
    wfile->fileid = fileid;
    wfile->roff = 0;
    wfile->woff = 0;

    atomic64_set(&wfile->ref, 1);

    mutex_lock(&wfset->lock);
    list_for_each_entry_safe(cur, next, &wfset->active, link) {
        if (cur->gen <= wfile->gen) {
            list_add_tail(&wfile->link, &cur->link);
            added = true;
            break;
        }
    }
    if (!added)
        list_add(&wfile->link, &wfset->active);
    mutex_unlock(&wfset->lock);

    atomic64_inc(&wfset->activec);

    wal_file_minmax_init(&wfile->info);
    wal_file_format(wfile, wfset->magic, wfset->version);

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
    struct wal_filehdr_omf fhomf;
    struct wal_file *cur, *next;
    bool added = false;
    merr_t err;

    wal_filehdr_pack(wfset->magic, wfset->version, true, &wfile->info, &fhomf);
    err = wal_file_pwrite(wfile, (const char *)&fhomf, sizeof(fhomf), 0);
    if (err)
        return err;

    mutex_lock(&wfset->lock);
    list_del_init(&wfile->link);
    list_for_each_entry_safe(cur, next, &wfset->complete, link) {
        if (cur->gen >= wfile->gen) {
            list_add_tail(&wfile->link, &cur->link);
            added = true;
            break;
        }
    }
    if (!added)
        list_add_tail(&wfile->link, &wfset->complete);
    mutex_unlock(&wfset->lock);
    atomic64_inc(&wfset->compc);

    return 0;
}

void
wal_file_get(struct wal_file *wfile)
{
    atomic64_inc(&wfile->ref);
}

void
wal_file_put(struct wal_file *wfile)
{
    if (atomic64_dec_return(&wfile->ref) == 0)
        wal_file_close(wfile);
}

merr_t
wal_file_destroy(struct wal_fileset *wfset, uint64_t gen, int fileid)
{
    char name[PATH_MAX];

    if (!wfset)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", "wal", gen, fileid);

    return mpool_file_destroy(wfset->mp, wfset->mclass, name);
}

merr_t
wal_file_read(struct wal_file *wfile, char *buf, size_t len)
{
    merr_t err;
    size_t rdlen;

    if (!wfile)
        return merr(EINVAL);

    err = mpool_file_read(wfile->mpf, wfile->roff, buf, len, &rdlen);
    if (err)
        return err;

    wfile->roff += rdlen;

    return 0;
}

static merr_t
wal_file_write_impl(struct wal_file *wfile, const char *buf, size_t len, off_t off)
{
    merr_t err;

    if (!wfile)
        return merr(EINVAL);

    err = mpool_file_write(wfile->mpf, off, buf, len);
    if (err)
        return err;

    err = mpool_file_sync(wfile->mpf);
    if (err)
        return err;

    return 0;
}

merr_t
wal_file_write(struct wal_file *wfile, const char *buf, size_t len)
{
    merr_t err;

    err = wal_file_write_impl(wfile, buf, len, wfile->woff);
    if (err)
        return err;

    wfile->woff += len;

    return 0;
}

static merr_t
wal_file_pwrite(struct wal_file *wfile, const char *buf, size_t len, off_t off)
{
    return wal_file_write_impl(wfile, buf, len, off);
}

