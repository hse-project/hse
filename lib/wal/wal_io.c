/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <sys/sysinfo.h>

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/logging.h>
#include <hse_util/slab.h>
#include <hse_util/list.h>
#include <hse_util/condvar.h>
#include <hse_util/mutex.h>

#include "wal.h"
#include "wal_file.h"

static struct kmem_cache       *iowcache;
static struct workqueue_struct *iowq;

struct wal_io_work {
    struct list_head  iow_list;
    struct wal_io    *iow_io;
    struct wal_minmax_info iow_info;

    const char *iow_buf;
    u64         iow_len;
    u64         iow_gen;
    uint        iow_index;
    bool        iow_bufwrap;
    bool        iow_gendone;
} HSE_ALIGNED(SMP_CACHE_BYTES);


struct wal_io {
    struct list_head io_active HSE_ALIGNED(SMP_CACHE_BYTES);
    struct mutex     io_lock;
    struct cv        io_cv;
    bool             io_stop;

    atomic64_t          io_pend HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t          io_comp;
    atomic64_t          io_gen;
    atomic64_t         *io_doff;
    atomic_t            io_stopped;

    struct wal_fileset *io_wfset;
    struct wal_file    *io_wfile;
    struct wal_iocb    *io_cb;
    atomic64_t          io_err;
    uint                io_index;
    struct work_struct  io_work;
};


static merr_t
wal_io_submit(struct wal_io_work *iow)
{
    struct wal_io *io;
    struct wal_file *wfile;
    size_t buflen;
    merr_t err = 0;
    u64 gen, cgen;

    io = iow->iow_io;
    buflen = iow->iow_len;

    cgen = atomic64_read(&io->io_gen);
    gen = iow->iow_gen;
    if (gen > cgen) {
        atomic64_set(&io->io_gen, gen);
        if (io->io_wfile) {
            err = wal_file_complete(io->io_wfset, io->io_wfile);
            if (err)
                return err;
            io->io_wfile = NULL;
        }
    } else {
        ev(gen < cgen);
        assert(io->io_wfile);
        wal_file_get(io->io_wfile);
    }

    wfile = io->io_wfile;
    if (!wfile) {
        merr_t err;

        err = wal_file_open(io->io_wfset, gen, iow->iow_index, false, &wfile);
        if (err)
            return err;
    }

    err = wal_file_write(wfile, iow->iow_buf, buflen, iow->iow_bufwrap);
    if (!err) {
        wal_file_minmax_update(wfile, &iow->iow_info);
        atomic64_add(buflen, io->io_doff);
        io->io_cb->iocb(io->io_cb->cbarg, err);
    }

    if (io->io_wfile) {
        wal_file_put(wfile);
        if (iow->iow_gendone && gen == cgen) {
            err = wal_file_complete(io->io_wfset, wfile);
            if (err)
                return err;
            io->io_wfile = NULL;
        }
    } else {
        io->io_wfile = wfile;
    }

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
                atomic_set(&io->io_stopped, 1);
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
            if (err) {
                atomic64_set(&io->io_err, err);
                io->io_cb->iocb(io->io_cb->cbarg, err); /* Notify sync waiters */
            }

            list_del(&iow->iow_list);
            kmem_cache_free(iowcache, iow);
            atomic64_inc(&io->io_comp);
        }
    }
}

merr_t
wal_io_enqueue(
    struct wal_io          *io,
    const char             *buf,
    u64                     len,
    u64                     gen,
    struct wal_minmax_info *info,
    bool                    bufwrap,
    bool                    gendone)
{
    struct wal_io_work *iow;
    merr_t err;

    if ((err = atomic64_read(&io->io_err)))
        return err;

    iow = kmem_cache_alloc(iowcache);
    if (!iow)
        return merr(ENOMEM);

    iow->iow_io = io;
    iow->iow_buf = buf;
    iow->iow_len = len;
    iow->iow_gen = gen;
    iow->iow_index = io->io_index;
    iow->iow_info = *info;
    iow->iow_bufwrap = bufwrap;
    iow->iow_gendone = gendone;

    INIT_LIST_HEAD(&iow->iow_list);

    mutex_lock(&io->io_lock);
    list_add_tail(&iow->iow_list, &io->io_active);
    atomic64_inc(&io->io_pend);
    cv_signal(&io->io_cv);
    mutex_unlock(&io->io_lock);

#ifndef NDEBUG
    if (atomic64_read(&io->io_pend) % 1536 == 0)
        hse_log(HSE_DEBUG "IO stats: pend %lu comp %lu",
                atomic64_read(&io->io_pend), atomic64_read(&io->io_comp));
#endif

    return 0;
}

struct wal_io *
wal_io_create(
    struct wal_fileset *wfset,
    uint                index,
    atomic64_t         *doff,
    struct wal_iocb    *iocb)
{
    struct wal_io *io;
    size_t sz;

    sz = sizeof(*io);
    io = aligned_alloc(alignof(*io), sz);
    if (!io)
        return NULL;
    memset(io, 0, sz);

    INIT_LIST_HEAD(&io->io_active);
    mutex_init(&io->io_lock);
    cv_init(&io->io_cv, "wal_wcv");
    io->io_stop = false;

    atomic64_set(&io->io_err, 0);
    atomic64_set(&io->io_gen, 0);
    atomic_set(&io->io_stopped, 0);

    io->io_doff = doff;
    io->io_index = index;
    io->io_wfset = wfset;
    io->io_cb = iocb;

    INIT_WORK(&io->io_work, wal_io_worker);
    queue_work(iowq, &io->io_work);

    return io;
}

void
wal_io_destroy(struct wal_io *io)
{
    mutex_lock(&io->io_lock);
    io->io_stop = true;
    cv_signal(&io->io_cv);
    mutex_unlock(&io->io_lock);

    while (atomic_read(&io->io_stopped) == 0)
        cpu_relax();

    mutex_destroy(&io->io_lock);
    cv_destroy(&io->io_cv);

    free(io);
}

merr_t
wal_io_init(u32 threads)
{
    iowcache = kmem_cache_create("wal-iowork", sizeof(struct wal_io_work),
                                 alignof(struct wal_io_work), 0, NULL);
    if (!iowcache)
        return merr(ENOMEM);

    iowq = alloc_workqueue("wal_io_wq", 0, threads);
    if (!iowq)
        return merr(ENOMEM);

    return 0;
}

void
wal_io_fini()
{
    destroy_workqueue(iowq);
    kmem_cache_destroy(iowcache);
}
