/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <sys/sysinfo.h>

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/vlb.h>
#include <hse_util/logging.h>

#include "wal.h"
#include "wal_omf.h"
#include "wal_buffer.h"


/* Until we have some synchronization in place we need to make bufsz
 * large enough to accomodate several outstanding c0kvms buffers.
 */
#define WAL_BUFSZ_MAX       (16ul << 30)
#define WAL_NODE_MAX        (4)
#define WAL_BPN_MAX         (2)

#define WAL_BUFALLOCSZ_MAX \
    (ALIGN(WAL_BUFSZ_MAX + wal_rec_len() + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX, 2ul << 20))


struct wal_buffer {
    atomic64_t w_offset HSE_ALIGNED(SMP_CACHE_BYTES * 2);

    atomic64_t w_doff HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t w_foff;
    atomic_t   w_flushing;

    struct work_struct w_fwork HSE_ALIGNED(SMP_CACHE_BYTES);

    char *w_buf HSE_ALIGNED(SMP_CACHE_BYTES);
};

/* Forward decls */
static void
wal_flush_worker(struct work_struct *work);

uint
wal_active_buf_cnt(void)
{
    return WAL_NODE_MAX * WAL_BPN_MAX;
}

struct wal_buffer *
wal_buffer_create(struct wal *wal)
{
    struct wal_buffer *wbuf;
    uint i, j;
    size_t sz;

    sz = WAL_NODE_MAX * WAL_BPN_MAX * sizeof(*wbuf);
    wbuf = calloc(1, sz);
    if (!wbuf)
        return NULL;

    for (i = 0; i < get_nprocs_conf(); ++i) {
        struct wal_buffer *wb;

        wb = wbuf + (hse_cpu2node(i) % WAL_NODE_MAX) * WAL_BPN_MAX;
        if (wb->w_buf)
            continue;

        for (j = 0; j < WAL_BPN_MAX; ++j, ++wb) {
            atomic64_set(&wb->w_offset, 0);
            atomic64_set(&wb->w_doff, 0);
            atomic64_set(&wb->w_foff, 0);
            atomic_set(&wbuf->w_flushing, 0);

            INIT_WORK(&wb->w_fwork, wal_flush_worker);

            wb->w_buf = vlb_alloc(WAL_BUFALLOCSZ_MAX);
            if (!wb->w_buf) {
                while (i-- > 0)
                    vlb_free(wbuf[i].w_buf, WAL_BUFALLOCSZ_MAX);
                free(wbuf);
                return NULL;
            }
        }
    }

    return wbuf;
}

void
wal_buffer_destroy(struct wal_buffer *wbuf)
{
    uint i;

    for (i = 0; i < WAL_NODE_MAX * WAL_BPN_MAX; ++i) {
        struct wal_buffer *wb = wbuf + i;

        vlb_free(wb->w_buf, WAL_BUFALLOCSZ_MAX);
    }

    free(wbuf);
}

void *
wal_buffer_alloc(struct wal_buffer *wbuf, size_t len)
{
    struct wal_buffer *wb;
    uint cpuid, nodeid, coreid;
    u64 offset;

    hse_getcpu(&cpuid, &nodeid, &coreid);

    wb = wbuf;
    wb += (nodeid % WAL_NODE_MAX) * WAL_BPN_MAX;
    wb += (coreid % WAL_BPN_MAX);

    offset = atomic64_fetch_add(len, &wb->w_offset);
    offset %= WAL_BUFSZ_MAX;

    return wb->w_buf + offset;
}

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
wal_flush_worker(struct work_struct *work)
{
    struct wal_buffer *wb;
    struct wal_rechdr_omf *rhdr;
    u64 coff, foff, prev_foff, cdgen, max_cnt = 0;
    u32 flags;
    u64 doff HSE_MAYBE_UNUSED;
    u64 start_foff HSE_MAYBE_UNUSED;
    bool skip_rec = false;

    wb = container_of(work, struct wal_buffer, w_fwork);

    coff = atomic64_read(&wb->w_offset);
    foff = atomic64_read(&wb->w_foff);

    if (coff == foff) {
        atomic_set(&wb->w_flushing, 0);
        return; /* No work to do */
    }

    cdgen = 0;
    prev_foff = foff;
    start_foff = foff;

    while (foff < coff) {
        u64 start, cnt = 0;
        bool txrec;

        rhdr = (struct wal_rechdr_omf *)(wb->w_buf + foff % WAL_BUFSZ_MAX);

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
        max_cnt = max_t(u64, cnt, max_cnt); /* Debugging */
    }
    assert(foff <= coff);

    rhdr = (struct wal_rechdr_omf *)(wb->w_buf + prev_foff % WAL_BUFSZ_MAX);

    /* Set the EOR flag in the last record */
    flags = omf_rh_flags(rhdr);
    flags |= WAL_FLAGS_EORG;
    omf_set_rh_flags(rhdr, flags);

    /* Set flush offset to the next record */
    foff = prev_foff + (wal_rechdr_len() + omf_rh_len(rhdr));
    atomic64_set(&wb->w_foff, foff);

    doff = atomic64_read(&wb->w_doff);

    /* Enqueue [start_foff, foff) for IO */
    //hse_log(HSE_ERR "%p: Enqueue [%lu, %lu) : [%lu] [%lu]", wb, start_foff, foff, doff, max_cnt);

    atomic_set(&wb->w_flushing, 0);

    /* Simulate IO completion */
    atomic64_set(&wb->w_doff, foff);
}

merr_t
wal_buffer_flush(struct wal_buffer *wbuf, struct workqueue_struct *wq)
{
    uint i;

    for (i = 0; i < WAL_NODE_MAX * WAL_BPN_MAX; ++i) {
        struct wal_buffer *wb = wbuf + i;

        if (wb->w_buf && atomic_cmpxchg(&wb->w_flushing, 0, 1) == 0)
            queue_work(wq, &wb->w_fwork);
    }
    flush_workqueue(wq);

    return 0;
}
