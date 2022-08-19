/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <bsd/string.h>

#include <hse_util/platform.h>
#include <hse_util/mutex.h>
#include <hse_util/list.h>
#include <hse_util/page.h>
#include <logging/logging.h>

#include <hse_ikvdb/cndb.h>

#include "wal.h"
#include "wal_file.h"
#include "wal_omf.h"
#include "wal_replay.h"

#define WAL_FILE_HDR_LEN       (PAGE_SIZE)
#define WAL_FILE_HDR_OFF       (0)
#define WAL_FILE_NAME_LEN_MAX  (64)


struct wal_fileset {
    struct mutex lock HSE_ACP_ALIGNED;
    struct list_head active;
    struct list_head complete;
    struct list_head replay;

    struct mpool *mp HSE_L1D_ALIGNED;
    enum hse_mclass mclass;
    size_t   capacity;
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    merr_t   err;
    void    *repbuf;
};

struct wal_file {
    struct list_head link HSE_ACP_ALIGNED;

    struct wal_minmax_info info;
    off_t roff;
    off_t woff;
    off_t soff;
    atomic_long ref;

    struct mpool_file *mpf HSE_L1D_ALIGNED;
    struct wal_fileset *wfset;
    uint64_t gen;
    char    *addr;
    int      fileid;
    bool     close;
    char     name[WAL_FILE_NAME_LEN_MAX];

};


static merr_t
wal_file_format(struct wal_file *wfile, off_t soff, off_t eoff, bool closing)
{
    char buf[WAL_FILE_HDR_LEN] HSE_ALIGNED(PAGE_SIZE) = {0};
    struct wal_fileset *wfset = wfile->wfset;

    wal_filehdr_pack(wfset->magic, wfset->version, &wfile->info, soff, eoff, closing, buf);

    return mpool_file_write(wfile->mpf, WAL_FILE_HDR_OFF, buf, sizeof(buf), NULL);
}

void
wal_file_minmax_init(struct wal_minmax_info *info)
{
    info->min_seqno = info->min_gen = info->min_txid = UINT64_MAX;
    info->max_seqno = info->max_gen = info->max_txid = 0;
}

void
wal_file_minmax_update(struct wal_file *wfile, struct wal_minmax_info *info)
{
    struct wal_minmax_info *winfo;

    winfo = &wfile->info;
    winfo->min_seqno = min_t(uint64_t, winfo->min_seqno, info->min_seqno);
    winfo->max_seqno = max_t(uint64_t, winfo->max_seqno, info->max_seqno);
    winfo->min_gen = min_t(uint64_t, winfo->min_gen, info->min_gen);
    winfo->max_gen = max_t(uint64_t, winfo->max_gen, info->max_gen);
    winfo->min_txid = min_t(uint64_t, winfo->min_txid, info->min_txid);
    winfo->max_txid = max_t(uint64_t, winfo->max_txid, info->max_txid);
}

merr_t
wal_fileset_reclaim(
    struct wal_fileset *wfset,
    uint64_t            seqno,
    uint64_t            gen,
    uint64_t            txhorizon,
    bool                closing)
{
    struct wal_file *cur, *next;
    struct list_head reclaim;

    INIT_LIST_HEAD(&reclaim);

    mutex_lock(&wfset->lock);
    list_for_each_entry_safe(cur, next, &wfset->complete, link) {
        struct wal_minmax_info *info = &cur->info;
        bool seqno_valid, txid_valid, seqno_reclaim, txid_reclaim = false;

        /*
         * If info->min/max seqno is invalid, then this file has 0 non-tx and tx-commit records
         * if info->min/max txid is invalid, then this file has 0 tx records
         * If both info->seqno and info->txid are invalid, there this file has no valid records
         */
        seqno_valid = (info->min_seqno != UINT64_MAX && info->max_seqno != 0);
        seqno_reclaim = seqno_valid ? info->max_seqno <= seqno : true;

        if (seqno_reclaim) {
            txid_valid = (info->min_txid != UINT64_MAX && info->max_txid != 0);
            txid_reclaim = txid_valid ? info->max_txid < txhorizon : true;
        }

        if (seqno_reclaim && txid_reclaim) {
            list_del_init(&cur->link);
            list_add_tail(&cur->link, &reclaim);
        } else if (closing) {
            list_del_init(&cur->link);
            wal_file_put(cur);
        }
    }
    mutex_unlock(&wfset->lock);

    list_for_each_entry_safe(cur, next, &reclaim, link) {
        uint64_t gen = cur->gen;
        int fileid = cur->fileid;

#ifndef NDEBUG
        struct wal_minmax_info *info = &cur->info;

        log_debug("Reclaiming gen %lu [%lu, %lu] seqno %lu [%lu, %lu] txid %lu [%lu, %lu]",
                  gen, info->min_gen, info->max_gen,
                  seqno, info->min_seqno, info->max_seqno,
                  txhorizon, info->min_txid, info->max_txid);
#endif

        list_del(&cur->link);
        assert(atomic_read(&cur->ref) == 1);
        wal_file_put(cur);
        wal_file_destroy(wfset, gen, fileid);
    }

    return 0;
}

void
wal_fileset_mclass_set(struct wal_fileset *wfset, enum hse_mclass mclass)
{
    wfset->mclass = mclass;
}

void
wal_fileset_version_set(struct wal_fileset *wfset, uint32_t version)
{
    wfset->version = version;
}

void
wal_fileset_flags_set(struct wal_fileset *wfset, uint32_t flags)
{
    wfset->flags = flags;
}

struct wal_fileset *
wal_fileset_open(
    struct mpool     *mp,
    enum hse_mclass   mclass,
    size_t            capacity,
    uint32_t          magic,
    uint32_t          vers)
{
    struct wal_fileset *wfset;

    wfset = aligned_alloc(__alignof__(*wfset), sizeof(*wfset));
    if (!wfset)
        return NULL;

    memset(wfset, 0, sizeof(*wfset));
    mutex_init(&wfset->lock);
    INIT_LIST_HEAD(&wfset->active);
    INIT_LIST_HEAD(&wfset->complete);
    INIT_LIST_HEAD(&wfset->replay);

    wfset->mp = mp;
    wfset->mclass = mclass;
    wfset->capacity = capacity;
    wfset->magic = magic;
    wfset->version = vers;
    wfset->flags = 0;
    wfset->repbuf = NULL;

    return wfset;
}

void
wal_fileset_close(
    struct wal_fileset *wfset,
    uint64_t            ingestseq,
    uint64_t            ingestgen,
    uint64_t            txhorizon)
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
    bool                replay,
    struct wal_file   **handle)
{
    struct wal_file   *wfile, *cur = NULL, *next;
    struct mpool_file *mpf;
    merr_t err;
    char name[WAL_FILE_NAME_LEN_MAX];
    bool sparse = false;
    int flags;

    if (!wfset)
        return merr(EINVAL);

    snprintf(name, sizeof(name), "%s-%lu-%d", WAL_FILE_PFX, gen, fileid);

    flags = replay ? O_RDONLY : wfset->flags | O_RDWR | O_SYNC;

    err = mpool_file_open(wfset->mp, wfset->mclass, name, flags, wfset->capacity, sparse, &mpf);
    if (err)
        return err;

    wfile = aligned_alloc(__alignof__(*wfile), sizeof(*wfile));
    if (!wfile) {
        mpool_file_close(mpf);
        return merr(ENOMEM);
    }

    memset(wfile, 0, sizeof(*wfile));
    wfile->mpf = mpf;
    wfile->wfset = wfset;
    wfile->gen = gen;
    wfile->fileid = fileid;
    strlcpy(wfile->name, name, sizeof(wfile->name));

    wal_file_minmax_init(&wfile->info);
    wfile->roff = 0;
    wfile->woff = 0;
    wfile->soff = 0;
    wfile->close = false;
    atomic_set(&wfile->ref, 1);

    INIT_LIST_HEAD(&wfile->link);

    mutex_lock(&wfset->lock);
    list_for_each_entry_safe(cur, next, &wfset->active, link) {
        if (cur->gen <= wfile->gen) {
            list_add_tail(&wfile->link, &cur->link);
            break;
        }
    }
    if (!cur)
        list_add_tail(&wfile->link, &wfset->active);
    mutex_unlock(&wfset->lock);

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

static merr_t
wal_file_mmap(struct wal_file *wfile, int advice)
{
    return mpool_file_mmap(wfile->mpf, true, advice, &wfile->addr);
}

static size_t
wal_file_size(struct wal_file *wfile)
{
    return mpool_file_size(wfile->mpf);
}

merr_t
wal_file_complete(struct wal_fileset *wfset, struct wal_file *wfile)
{
    struct wal_file *cur = NULL, *next;
    merr_t err;

    err = mpool_file_sync(wfile->mpf);
    if (err)
        return err;

    err = wal_file_format(wfile, wfile->soff, wfile->woff, true);
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

    return 0;
}

merr_t
wal_file_get(struct wal_file *wfile)
{
    if (!wfile) {
        assert(wfile);
        return merr(EBUG);
    }

    atomic_inc(&wfile->ref);

    return 0;
}

void
wal_file_put(struct wal_file *wfile)
{
    assert(wfile);

    if (wfile && atomic_dec_return(&wfile->ref) == 0)
        wal_file_close(wfile);
}

merr_t
wal_file_destroy(struct wal_fileset *wfset, uint64_t gen, int fileid)
{
    char name[WAL_FILE_NAME_LEN_MAX];

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
wal_file_write(struct wal_file *wfile, char *buf, size_t len, bool bufwrap)
{
    merr_t err;
    char *abuf;
    off_t off, aoff;
    size_t alen, roundsz;
    bool adjust_woff = false;

    if (!wfile)
        return merr(EINVAL);

    /* rounddown the buf and file offset to 4K alignment */
    abuf = (char *)((uintptr_t)buf & PAGE_MASK);
    off = wfile->woff;
    aoff = (off & PAGE_MASK);

    roundsz = buf - abuf;
    if (roundsz != (off - aoff)) { /* Must be the first write if buf and off alignment mismatch */
        assert(off == WAL_FILE_HDR_OFF);
        if (off != WAL_FILE_HDR_OFF)
            return merr(EBUG);

        adjust_woff = true;
    } else if (ev(bufwrap && roundsz > 0)) {
        char rdbuf[PAGE_SIZE] HSE_ALIGNED(PAGE_SIZE);
        size_t cc;

        assert(roundsz < PAGE_SIZE);
        err = mpool_file_read(wfile->mpf, aoff, rdbuf, PAGE_SIZE, &cc);
        if (err)
            return err;

        assert(cc >= roundsz);
        memcpy((void *)abuf, rdbuf, roundsz);
    }

    /* Pack file header with the start offset for the first record */
    if (off == WAL_FILE_HDR_OFF) {
        err = wal_file_format(wfile, roundsz, 0, false);
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

        err = mpool_file_write(wfile->mpf, aoff, (const char *)abuf, alen, &cc);
        if (err)
            return err;

        assert(PAGE_ALIGNED(cc));
        abuf += cc;
        aoff += cc;
        alen -= cc;
    }

    /* Bring the buffer addr and file offset to the same alignment if it mismatched */
    if (adjust_woff)
        wfile->woff += roundsz;

    wfile->woff += len;

    return 0;
}


/*
 * WAL fileset replay interfaces
 */

static void
wal_file_cb(void *wfset, const char *path)
{
    struct wal_file *wfile HSE_MAYBE_UNUSED;
    uint64_t gen;
    int fileid;
    merr_t err = 0;
    char *name, *tok, *end = NULL, *pathdup;
    const char *delim = "-";

    pathdup = strdup(path);
    if (!pathdup) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    name = basename(pathdup);
    tok = strsep(&name, delim);
    if (strcmp(tok, WAL_FILE_PFX) != 0) {
        err = merr(EINVAL);
        goto err_exit;
    }

    /* Parse gen */
    tok = strsep(&name, delim);
    errno = 0;
    gen = strtoull(tok, &end, 10);
    if (errno || *end || gen == 0) {
        err = merr(EINVAL);
        goto err_exit;
    }

    /* Parse fileid */
    tok = strsep(&name, delim);
    errno = 0;
    fileid = strtol(tok, &end, 10);
    if (errno || *end || fileid < 0 || fileid >= WAL_BUF_MAX) {
        err = merr(EINVAL);
        goto err_exit;
    }

    err = wal_file_open(wfset, gen, fileid, true, &wfile);

err_exit:
    free(pathdup);

    if (err)
        ((struct wal_fileset *)wfset)->err = err;
}

merr_t
wal_fileset_replay(
    struct wal_fileset          *wfset,
    struct wal_replay_info      *rinfo,
    uint32_t                    *rgcnt_out,
    struct wal_replay_gen_info **rginfo_out)
{
    struct mpool_file_cb cb;
    struct wal_file *cur, *next;
    struct wal_replay_gen_info *rginfo;
    merr_t err;
    size_t sz;
    uint32_t fcnt, i;
    uint64_t maxgen;

    cb.cbarg = (void *)wfset;
    cb.cbfunc = wal_file_cb;

    err = mpool_mclass_ftw(wfset->mp, wfset->mclass, WAL_FILE_PFX, &cb);
    if (err || wfset->err) {
        if (!err)
            err = wfset->err;
        goto exit;
    }

    cur = list_first_entry_or_null(&wfset->active, typeof(*cur), link);
    if (!cur) {
        *rgcnt_out = 0;
        return 0; /* Nothing to replay */
    }

    maxgen = cur->gen;

    /*
     * Move candidate wal files from the active to replay list.
     * No need to acquire the list lock as there are no other threads concurrently
     * working on this list.
     */
    fcnt = 0;
    list_for_each_entry_reverse_safe(cur, next, &wfset->active, link) {
        bool discard = false;

        err = wal_file_mmap(cur, MADV_SEQUENTIAL);
        if (err) {
            if (merr_errno(err) == EINVAL && wal_file_size(cur) == 0) {
                /* Possible that the crash happened just after file creation */
                log_info("WAL replay: Discarding empty wal file: gen %lu fileid %u",
                         cur->gen, cur->fileid);
                discard = true;
                goto discard;
            }
            goto exit;
        }

        err = wal_filehdr_unpack(cur->addr, wfset->magic, wfset->version, &cur->close,
                                 &cur->soff, &cur->woff, &cur->info);
        if (err) {
            if (cur->gen == maxgen && merr_errno(err) == ENODATA) {
                /* Can safely delete this empty file */
                log_info("WAL replay: Discarding empty wal file, gen %lu fileid %u",
                         cur->gen, cur->fileid);
                discard = true;
                goto discard;
            }

            /* Fail replay for now. If the corrupted header gen is the same as the maxgen,
             * then all the files belonging to this corrupted gen can be destroyed.
             * TODO: Address this when adding force replay support.
             */
            log_errx("WAL replay: Need force replay support to recover data, "
                     "gen %lu fileid %u maxgen %lu",
                     err, cur->gen, cur->fileid, maxgen);
            goto exit;
        }

        /* Can trust minmax info only if the close flag is set */
        if (!cur->close) {
            list_del_init(&cur->link);
            list_add_tail(&cur->link, &wfset->replay);
            fcnt++;
        } else {
            struct wal_minmax_info *info = &cur->info;
            bool seqno_discard, txid_discard;

            seqno_discard = (info->max_seqno != 0 && info->max_seqno <= rinfo->seqno);
            txid_discard = (seqno_discard && rinfo->txhorizon != CNDB_INVAL_HORIZON &&
                            info->max_txid < rinfo->txhorizon);

            if (seqno_discard && txid_discard) {
                log_info("WAL replay: Skipping wal file, gen %lu fileid %u, "
                         "cndb seqno %lu txhorizon %lu gen %lu",
                         cur->gen, cur->fileid, rinfo->seqno, rinfo->txhorizon, rinfo->gen);
                discard = true;
                goto discard;
            } else {
                list_del_init(&cur->link);
                list_add_tail(&cur->link, &wfset->replay);
                fcnt++;
            }
        }

discard:
        if (discard) {
            uint64_t gen = cur->gen;
            int fileid = cur->fileid;

            err = 0;
            list_del_init(&cur->link);
            wal_file_close(cur);
            wal_file_destroy(wfset, gen, fileid);
        }
    }

    sz = fcnt * sizeof(*rginfo);
    rginfo = aligned_alloc(__alignof__(*rginfo), sz);
    if (!rginfo) {
        err = merr(ENOMEM);
        goto exit;
    }
    memset(rginfo, 0, sz);

    wfset->repbuf = rginfo;

    i = 0;
    list_for_each_entry_safe(cur, next, &wfset->replay, link) {
        rginfo[i].info_valid = cur->close;
        rginfo[i].info = cur->info;
        rginfo[i].gen = cur->gen;
        rginfo[i].fileid = cur->fileid;
        rginfo[i].soff = WAL_FILE_HDR_LEN + cur->soff;
        rginfo[i].eoff = cur->woff;
        rginfo[i].buf = cur->addr + rginfo[i].soff;
        rginfo[i].size = wal_file_size(cur);
        spin_lock_init(&rginfo[i].txm_lock);
        rginfo[i].txm_root = RB_ROOT;
        rginfo[i].txcid_root = RB_ROOT;
        i++;
    }
    assert(i == fcnt);

    *rgcnt_out = fcnt;
    *rginfo_out = rginfo;

exit:
    if (err)
        wal_fileset_replay_free(wfset, !!err);

    return err;
}

void
wal_fileset_replay_free(struct wal_fileset *wfset, bool failed)
{
    struct wal_file *cur, *next;
    merr_t err;

    if (!wfset)
        return;

    /* The active list would be non-empty for a failed wal_fileset_replay() */
    list_for_each_entry_safe(cur, next, &wfset->active, link) {
        list_del_init(&cur->link);
        err = wal_file_close(cur);
        ev(err);
    }

    list_for_each_entry_safe(cur, next, &wfset->replay, link) {
        uint64_t gen = cur->gen;
        uint32_t fileid = cur->fileid;

        list_del_init(&cur->link);
        err = wal_file_close(cur);
        ev(err);

        /* Do not destroy the wal files on replay failure */
        if (!failed)
            wal_file_destroy(wfset, gen, fileid);
    }

    free(wfset->repbuf);
    wfset->repbuf = NULL;
}
