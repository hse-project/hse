/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <sys/sysinfo.h>

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/vlb.h>
#include <hse_util/logging.h>
#include <hse_util/slab.h>
#include <hse_util/list.h>
#include <hse_util/condvar.h>
#include <hse_util/mutex.h>

#include "wal.h"
#include "wal_omf.h"
#include "wal_buffer.h"
#include "wal_file.h"


/* Until we have some synchronization in place we need to make bufsz
 * large enough to accomodate several outstanding c0kvms buffers.
 */
#define WAL_BUFSZ_MAX       (16ul << 30)
#define WAL_NODE_MAX        (4)
#define WAL_BPN_MAX         (2)

#define WAL_BUFALLOCSZ_MAX \
    (ALIGN(WAL_BUFSZ_MAX + wal_rec_len() + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX, 2ul << 20))


struct wal_io_work {
    struct list_head  iow_list;
    struct wal_io    *iow_io;

    const char *iow_buf;
    u64  iow_len;
    u64  iow_dgen;
    uint iow_index;
} HSE_ALIGNED(SMP_CACHE_BYTES);


struct wal_io {
    struct list_head io_active;
    struct mutex     io_lock;
    struct cv        io_cv;
    bool             io_stop;

    struct wal_file   *io_file HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t        *io_doff;
    atomic64_t        *io_dgen;
    atomic64_t         io_err;

    u64                io_pending;
    u64                io_completed;

    uint               io_index;
    struct mpool      *io_mp;
    struct kmem_cache *io_cache;
    struct work_struct io_work;
};


struct wal_buffer {
    atomic64_t wb_offset HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    atomic64_t wb_doff HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t wb_foff;
    atomic64_t wb_dgen;
    atomic_t   wb_flushing;
    uint       wb_index;

    struct work_struct  wb_fwork HSE_ALIGNED(SMP_CACHE_BYTES);
    struct wal_bufset  *wb_bs;
    struct wal_io       wb_io;

    char *wb_buf HSE_ALIGNED(SMP_CACHE_BYTES);
};


struct wal_bufset {
    struct mpool *wbs_mp;

    struct workqueue_struct *wbs_flushwq;
    struct workqueue_struct *wbs_iowq;

    struct kmem_cache *wbs_iowcache;

    atomic64_t wbs_err;

    uint wbs_bufc;
    struct wal_buffer *wbs_bufv;
};

/* Forward decls */
static void
wal_buffer_flush_worker(struct work_struct *work);

/*
 * WAL IO routines.
 */

merr_t
wal_io_submit(struct wal_io_work *iow)
{
    struct wal_io *io;
    struct wal_file *file;
    size_t buflen;
    merr_t err = 0;
    u64 dgen, cdgen;

    io = iow->iow_io;
    buflen = iow->iow_len;

    cdgen = atomic64_read(io->io_dgen);
    dgen = iow->iow_dgen;
    if (dgen > cdgen) {
        atomic64_set(io->io_dgen, dgen);
        if (io->io_file) {
            wal_file_close(io->io_file);
            io->io_file = NULL;
        }
    } else {
        assert(dgen == cdgen);
        wal_file_get(io->io_file);
    }

    file = io->io_file;
    if (!file) {
        merr_t err;

        err = wal_file_open(io->io_mp, MP_MED_CAPACITY, dgen, iow->iow_index, 2ul << 30, &file);
        if (err)
            return err;
    }

    err = wal_file_write(file, iow->iow_buf, buflen);
    if (!err)
        atomic64_add(buflen, io->io_doff);

    if (io->io_file)
        wal_file_put(file);
    else
        io->io_file = file;

    return err;
}

static void
wal_io_worker(struct work_struct *work)
{
    struct wal_io *io;

    io = container_of(work, struct wal_io, io_work);

    while (true) {
        struct wal_io_work *iow, *next;
        struct list_head active;

        INIT_LIST_HEAD(&active);

        mutex_lock(&io->io_lock);

        while (list_empty(&io->io_active)) {
            if (io->io_stop) {
                mutex_unlock(&io->io_lock);
                return;
            }
            cv_wait(&io->io_cv, &io->io_lock);
        }

        list_splice(&io->io_active, &active);
        INIT_LIST_HEAD(&io->io_active);
        mutex_unlock(&io->io_lock);

        list_for_each_entry_safe(iow, next, &active, iow_list) {
            merr_t err;

            assert(iow->iow_index == io->io_index);

            err = wal_io_submit(iow);
            if (err)
                atomic64_set(&io->io_err, err);

            list_del(&iow->iow_list);
            kmem_cache_free(io->io_cache, iow);
            io->io_completed++;
        }
    }
}

static merr_t
wal_io_enqueue(struct wal_io *io, const char *buf, u64 len, u64 dgen)
{
    struct wal_io_work *iow;

    iow = kmem_cache_alloc(io->io_cache);
    if (!iow)
        return merr(ENOMEM);

    iow->iow_io = io;
    iow->iow_buf = buf;
    iow->iow_len = len;
    iow->iow_dgen = dgen;
    iow->iow_index = io->io_index;

    INIT_LIST_HEAD(&iow->iow_list);

    mutex_lock(&io->io_lock);
    list_add_tail(&iow->iow_list, &io->io_active);
    io->io_pending++;
    cv_signal(&io->io_cv);
    mutex_unlock(&io->io_lock);

    hse_log(HSE_ERR "IO stats, pending %lu completed %lu", io->io_pending, io->io_completed);

    return 0;
}

void
wal_io_init(struct wal_buffer *wb)
{
    struct wal_io *io;
    struct wal_bufset *wbs;

    io = &wb->wb_io;
    INIT_LIST_HEAD(&io->io_active);
    mutex_init(&io->io_lock);
    cv_init(&io->io_cv, "wal_wcv");
    io->io_stop = false;

    atomic64_set(&io->io_err, 0);
    io->io_doff = &wb->wb_doff;
    io->io_dgen = &wb->wb_dgen;
    io->io_index = wb->wb_index;

    wbs = wb->wb_bs;
    io->io_mp = wbs->wbs_mp;
    io->io_cache = wbs->wbs_iowcache;

    INIT_WORK(&io->io_work, wal_io_worker);
    queue_work(wbs->wbs_iowq, &io->io_work);
}

/*
 * WAL bufset routines
 */

static uint
wal_bufset_bufcnt(void)
{
    return WAL_NODE_MAX * WAL_BPN_MAX;
}

struct wal_bufset *
wal_bufset_open(struct wal *wal)
{
    struct wal_bufset *wbs;
    uint i, j, bufc;
    size_t sz;
    uint threads;

    bufc = wal_bufset_bufcnt();
    sz = sizeof(*wbs) + bufc * sizeof(*wbs->wbs_bufv);
    wbs = calloc(1, sz);
    if (!wbs)
        return NULL;

    wbs->wbs_bufv = (void *)(wbs + 1);
    wbs->wbs_bufc = bufc;
    wbs->wbs_mp = wal_mpool_get(wal);
    atomic64_set(&wbs->wbs_err, 0);

    threads = wbs->wbs_bufc;
    wbs->wbs_flushwq = alloc_workqueue("wal_flush_wq", 0, threads);
    if (!wbs->wbs_flushwq)
        goto errout;

    wbs->wbs_iowq = alloc_workqueue("wal_io_wq", 0, threads);
    if (!wbs->wbs_iowq)
        goto errout;

    wbs->wbs_iowcache = kmem_cache_create("wal-iowork", sizeof(struct wal_io_work),
                                          alignof(struct wal_io_work), 0, NULL);
    if (!wbs->wbs_iowcache)
        goto errout;

    for (i = 0; i < get_nprocs_conf(); ++i) {
        struct wal_buffer *wb;
        uint index = (hse_cpu2node(i) % WAL_NODE_MAX) * WAL_BPN_MAX;

        wb = wbs->wbs_bufv + index;
        if (wb->wb_buf)
            continue;

        for (j = 0; j < WAL_BPN_MAX; ++j, ++wb) {
            atomic64_set(&wb->wb_offset, 0);
            atomic64_set(&wb->wb_doff, 0);
            atomic64_set(&wb->wb_foff, 0);
            atomic64_set(&wb->wb_dgen, 0);
            atomic_set(&wb->wb_flushing, 0);

            wb->wb_index = index + j;
            wb->wb_bs = wbs;
            INIT_WORK(&wb->wb_fwork, wal_buffer_flush_worker);

            wal_io_init(wb);

            wb->wb_buf = vlb_alloc(WAL_BUFALLOCSZ_MAX);
            if (!wb->wb_buf)
                goto errout;
        }
    }

    return wbs;

errout:
    wal_bufset_close(wbs);

    return NULL;
}

void
wal_bufset_close(struct wal_bufset *wbs)
{
    uint i;

    for (i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;
        struct wal_io *io;

        io = &wb->wb_io;
        mutex_lock(&io->io_lock);
        io->io_stop = true;
        cv_signal(&io->io_cv);
        mutex_unlock(&io->io_lock);

        vlb_free(wb->wb_buf, WAL_BUFALLOCSZ_MAX);
    }

    destroy_workqueue(wbs->wbs_iowq);

    for (i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;
        struct wal_io *io;

        io = &wb->wb_io;
        mutex_destroy(&io->io_lock);
        cv_destroy(&io->io_cv);
    }

    kmem_cache_destroy(wbs->wbs_iowcache);
    destroy_workqueue(wbs->wbs_flushwq);
    free(wbs);
}

void *
wal_bufset_alloc(struct wal_bufset *wbs, size_t len)
{
    struct wal_buffer *wb;
    uint cpuid, nodeid, coreid;
    u64 offset;

    hse_getcpu(&cpuid, &nodeid, &coreid);

    wb = wbs->wbs_bufv;
    wb += (nodeid % WAL_NODE_MAX) * WAL_BPN_MAX;
    wb += (coreid % WAL_BPN_MAX);

    offset = atomic64_fetch_add(len, &wb->wb_offset);
    offset %= WAL_BUFSZ_MAX;

    return wb->wb_buf + offset;
}

merr_t
wal_bufset_flush(struct wal_bufset *wbs)
{
    struct workqueue_struct *wq;
    uint i;

    if (!wbs)
        return merr(EINVAL);

    wq = wbs->wbs_flushwq;

    for (i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        if (wb->wb_buf && atomic_cmpxchg(&wb->wb_flushing, 0, 1) == 0)
            queue_work(wq, &wb->wb_fwork);
    }
    flush_workqueue(wq);

    return 0;
}

/*
 * WAL buffer routines
 */

/*
 * Flush worker routine - for a specific buffer
 *
 * Waits for a sequential range of buffer to be completely filled
 * by the client threads without any gap or holes.
 *
 * Queues an IO work to the log writer thread.
 *
 */
static void
wal_buffer_flush_worker(struct work_struct *work)
{
    struct wal_buffer *wb;
    struct wal_rechdr_omf *rhdr;
    u64 coff, foff, prev_foff, cdgen, max_cnt = 0, start_foff;
    u32 flags;
    bool skip_rec = false;
    merr_t err;

    wb = container_of(work, struct wal_buffer, wb_fwork);

    coff = atomic64_read(&wb->wb_offset);
    foff = atomic64_read(&wb->wb_foff);

    if (coff == foff)
        goto out;

    cdgen = 0;
    prev_foff = foff;
    start_foff = foff;

    while (foff < coff) {
        u64 start, cnt = 0;
        bool txrec;

        rhdr = (struct wal_rechdr_omf *)(wb->wb_buf + foff % WAL_BUFSZ_MAX);

        start = jclock_ns;
        while (le32_to_cpu(atomic_read((atomic_t *)&rhdr->rh_cksum)) == 0) {
            cpu_relax();
            if (ev(cnt++ % 1024 == 0)) {
                if (ev(NSEC_TO_MSEC(jclock_ns - start) > 10)) {
                    flags = omf_rh_flags(rhdr);
                    flags |= WAL_FLAGS_ERROR;
                    skip_rec = true;
                    break; /* skip this record */
                }
            }
        }

        /* Set the BOR flag in the first record */
        if (prev_foff == foff) {
            flags = omf_rh_flags(rhdr);
            flags |= WAL_FLAGS_BORG;
            omf_set_rh_flags(rhdr, flags);
        }

        txrec = wal_rectype_txn(omf_rh_type(rhdr));
        if (!txrec && !skip_rec) { /* Valid records with dgen */
            u64 rdgen = omf_rh_dgen(rhdr);

            /* Mark flush boundary on encountering the first dgen change */
            if (cdgen > 0 && rdgen > cdgen)
                break;

            cdgen = rdgen;
        }

        prev_foff = foff;
        foff += (wal_rechdr_len() + omf_rh_len(rhdr));
        max_cnt = max_t(u64, cnt, max_cnt); /* For debugging */
    }
    assert(foff <= coff);

    rhdr = (struct wal_rechdr_omf *)(wb->wb_buf + prev_foff % WAL_BUFSZ_MAX);

    /* Set the EOR flag in the last record */
    flags = omf_rh_flags(rhdr);
    flags |= WAL_FLAGS_EORG;
    omf_set_rh_flags(rhdr, flags);

    /* Set flush offset to the next record */
    foff = prev_foff + (wal_rechdr_len() + omf_rh_len(rhdr));
    atomic64_set(&wb->wb_foff, foff);

    err = wal_io_enqueue(&wb->wb_io, wb->wb_buf + start_foff, foff - start_foff, cdgen);
    if (err)
        atomic64_set(&wb->wb_bs->wbs_err, err);

out:
    atomic_set(&wb->wb_flushing, 0);
}


