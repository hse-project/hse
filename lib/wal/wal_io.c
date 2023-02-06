/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <sys/sysinfo.h>

#include <hse/logging/logging.h>

#include <hse/util/condvar.h>
#include <hse/util/event_counter.h>
#include <hse/util/list.h>
#include <hse/util/mutex.h>
#include <hse/util/platform.h>
#include <hse/util/page.h>
#include <hse/util/slab.h>

#include "wal.h"
#include "wal_file.h"

static struct kmem_cache       *iowcache HSE_READ_MOSTLY;
static struct workqueue_struct *iowq HSE_READ_MOSTLY;

struct wal_io_work {
    struct list_head  iow_list;
    struct wal_io    *iow_io;
    struct wal_minmax_info iow_info;

    char       *iow_buf;
    uint64_t    iow_len;
    uint64_t    iow_gen;
    uint32_t    iow_index;
    bool        iow_bufwrap;
} HSE_L1D_ALIGNED;


struct wal_io {
    struct mutex     io_lock HSE_ACP_ALIGNED;
    struct list_head io_active;
    bool             io_stop;
    struct cv        io_cv;

    atomic_long         io_pend HSE_L1D_ALIGNED;
    atomic_long         io_comp;
    atomic_ulong        io_gen;
    atomic_ulong       *io_doff;
    atomic_int          io_stopped;

    struct wal_fileset *io_wfset;
    struct wal_file    *io_wfile;
    struct wal_iocb    *io_cb;
    atomic_long         io_err;
    uint32_t            io_index;
    struct work_struct  io_work;
};


static merr_t
wal_io_submit(struct wal_io_work *iow)
{
    struct wal_io *io;
    size_t buflen;
    merr_t err = 0;
    uint64_t gen, cgen;

    io = iow->iow_io;
    buflen = iow->iow_len;

    cgen = atomic_read(&io->io_gen);
    gen = iow->iow_gen;
    if (gen > cgen) {
        atomic_set(&io->io_gen, gen);
        if (io->io_wfile) {
            err = wal_file_complete(io->io_wfset, io->io_wfile);
            if (err)
                return err;
            io->io_wfile = NULL;
        }
    } else {
        ev(gen < cgen);
        err = wal_file_get(io->io_wfile);
        if (err)
            return err;
    }

    if (!io->io_wfile) {
        merr_t err;

        err = wal_file_open(io->io_wfset, gen, iow->iow_index, false, &io->io_wfile);
        if (err)
            return err;

        wal_file_get(io->io_wfile);
    }

    assert(io->io_wfile);

    err = wal_file_write(io->io_wfile, iow->iow_buf, buflen, iow->iow_bufwrap);
    if (err) {
        wal_file_put(io->io_wfile);
        return err;
    }

    wal_file_minmax_update(io->io_wfile, &iow->iow_info);
    atomic_add(io->io_doff, buflen);
    io->io_cb->iocb(io->io_cb->cbarg, 0);

    wal_file_put(io->io_wfile);

    return 0;
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
        end_stats_work();

        while (list_empty(&io->io_active)) {
            if (io->io_stop) {
                mutex_unlock(&io->io_lock);
                atomic_set(&io->io_stopped, 1);
                return;
            }

            cv_timedwait(&io->io_cv, &io->io_lock, -1, "walioslp");
        }

        begin_stats_work();
        list_splice(&io->io_active, &active);
        INIT_LIST_HEAD(&io->io_active);
        mutex_unlock(&io->io_lock);

        list_for_each_entry_safe(iow, next, &active, iow_list) {
            if (atomic_read(&io->io_err) == 0) {
                merr_t err;

                assert(iow->iow_index == io->io_index);

                err = wal_io_submit(iow);
                if (err) {
                    atomic_set(&io->io_err, err);
                    io->io_cb->iocb(io->io_cb->cbarg, err); /* Notify sync waiters */
                }

                atomic_inc(&io->io_comp);
            }

            list_del(&iow->iow_list);
            kmem_cache_free(iowcache, iow);
        }
    }
}

merr_t
wal_io_enqueue(
    struct wal_io          *io,
    char                   *buf,
    uint64_t                len,
    uint64_t                gen,
    struct wal_minmax_info *info,
    bool                    bufwrap)
{
    struct wal_io_work *iow;
    merr_t err;

    if ((err = atomic_read(&io->io_err)))
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

    INIT_LIST_HEAD(&iow->iow_list);

    mutex_lock(&io->io_lock);
    list_add_tail(&iow->iow_list, &io->io_active);
    atomic_inc(&io->io_pend);
    cv_signal(&io->io_cv);
    mutex_unlock(&io->io_lock);

#ifndef NDEBUG
    if (atomic_read(&io->io_pend) % 1536 == 0)
        log_debug("IO stats: pend %lu comp %lu",
                  atomic_read(&io->io_pend), atomic_read(&io->io_comp));
#endif

    return 0;
}

struct wal_io *
wal_io_create(
    struct wal_fileset *wfset,
    uint32_t            index,
    atomic_ulong       *doff,
    struct wal_iocb    *iocb)
{
    struct wal_io *io;
    size_t sz;

    sz = sizeof(*io);
    io = aligned_alloc(__alignof__(*io), sz);
    if (!io)
        return NULL;

    memset(io, 0, sz);
    INIT_LIST_HEAD(&io->io_active);
    mutex_init(&io->io_lock);
    cv_init(&io->io_cv);
    io->io_stop = false;

    atomic_set(&io->io_err, 0);
    atomic_set(&io->io_gen, 0);
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
    if (!io)
        return;

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
wal_io_init(uint32_t threads)
{
    iowcache = kmem_cache_create("wal-iowork", sizeof(struct wal_io_work),
                                 alignof(struct wal_io_work), 0, NULL);
    if (!iowcache)
        return merr(ENOMEM);

    iowq = alloc_workqueue("hse_wal_io", 0, threads, threads);
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
