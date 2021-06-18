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

#include "wal.h"
#include "wal_omf.h"
#include "wal_buffer.h"
#include "wal_file.h"
#include "wal_io.h"


/* Until we have some synchronization in place we need to make bufsz
 * large enough to accomodate several outstanding c0kvms buffers.
 */
#define WAL_BUFSZ_MAX       (16ul << 30)
#define WAL_NODE_MAX        (4)
#define WAL_BPN_MAX         (2)

#define WAL_BUFALLOCSZ_MAX \
    (ALIGN(WAL_BUFSZ_MAX + wal_rec_len() + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX, 2ul << 20))


struct wal_buffer {
    atomic64_t wb_doff;
    atomic64_t wb_foff;
    atomic64_t wb_flushreq;
    atomic_t   wb_flushing;

    struct work_struct  wb_fwork HSE_ALIGNED(SMP_CACHE_BYTES);
    struct wal_bufset  *wb_bs;
    struct wal_io      *wb_io;
    uint                wb_index;

    atomic64_t wb_offset HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    char *wb_buf HSE_ALIGNED(SMP_CACHE_BYTES);
} HSE_ALIGNED(SMP_CACHE_BYTES);


struct wal_bufset {
    struct workqueue_struct *wbs_flushwq;

    atomic64_t *wbs_ingestgen;
    atomic64_t  wbs_err;

    uint wbs_bufc;
    struct wal_buffer *wbs_bufv;
};

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
    struct wal_minmax_info info = {};
    const char *buf;
    u64 coff, foff, prev_foff, cgen, start_foff;
    u32 flags, rhlen;
    merr_t err;

    wb = container_of(work, struct wal_buffer, wb_fwork);

    coff = atomic64_read(&wb->wb_offset);
    rhlen = wal_rechdr_len();

restart:
    foff = atomic64_read(&wb->wb_foff);
    info.min_seqno = info.min_gen = info.min_txid = U64_MAX;

    if (coff == foff) {
        atomic_set(&wb->wb_flushing, 0);
        return;
    }

    cgen = 0;
    prev_foff = foff;
    start_foff = foff;

    while (foff < coff) {
        bool txmeta, txcom, nontx;
        u32 rtype;
        u64 seqno;

        buf = wb->wb_buf + (foff % WAL_BUFSZ_MAX);
        rhdr = (void *)buf;

        while (le64_to_cpu(atomic64_read((atomic64_t *)&rhdr->rh_off)) != foff)
            cpu_relax();

        /* Set the BOR flag in the first record */
        if (prev_foff == foff) {
            flags = omf_rh_flags(rhdr);
            flags |= WAL_FLAGS_BORG;
            omf_set_rh_flags(rhdr, flags);
        }

        rtype = omf_rh_type(rhdr);
        txmeta = wal_rectype_txnmeta(rtype);
        if (!txmeta) {
            u64 rgen = omf_rh_gen(rhdr);

            /* Mark flush boundary on encountering a gen increase */
            if (cgen > 0 && rgen > cgen)
                break;

            if (rgen > cgen)
                cgen = rgen;

            info.min_gen = min_t(u64, info.min_gen, rgen);
            info.max_gen = max_t(u64, info.max_gen, rgen);
        }

        /* Determine min/max seqno from non-tx op and tx-commit record */
        nontx = wal_rectype_nontx(rtype);
        txcom = wal_rectype_txcommit(rtype);
        if (nontx || txcom) {
            struct wal_rec_omf *r = (void *)buf;
            struct wal_txnrec_omf *tr = (void *)buf;

            seqno = nontx ? omf_r_seqno(r) : omf_tr_seqno(tr);
            info.min_seqno = min_t(u64, info.min_seqno, seqno);
            info.max_seqno = max_t(u64, info.max_seqno, seqno);
        }

        /* Determine min/max txid from txmeta */
        if (txmeta) {
            struct wal_txnrec_omf *tr = (void *)buf;
            u64 txid = omf_tr_txid(tr);

            info.min_txid = min_t(u64, info.min_txid, txid);
            info.max_txid = max_t(u64, info.max_txid, txid);
        }

        prev_foff = foff;
        foff += (rhlen + omf_rh_len(rhdr));
    }
    assert(foff <= coff);

    rhdr = (void *)(wb->wb_buf + prev_foff % WAL_BUFSZ_MAX);

    /* Set the EOR flag in the last record */
    flags = omf_rh_flags(rhdr);
    flags |= WAL_FLAGS_EORG;
    omf_set_rh_flags(rhdr, flags);

    /* Set flush offset to the next record */
    foff = prev_foff + (rhlen + omf_rh_len(rhdr));
    atomic64_set(&wb->wb_foff, foff);

    buf = wb->wb_buf + (start_foff % WAL_BUFSZ_MAX);
    err = wal_io_enqueue(wb->wb_io, buf, foff - start_foff, cgen, &info);
    if (err)
        atomic64_set(&wb->wb_bs->wbs_err, err);

    if (foff < coff)
        goto restart;

    assert(foff == coff);

#ifndef NDEBUG
    if (atomic64_inc_return(&wb->wb_flushreq) % 1536 == 0)
        hse_log(HSE_NOTICE "Flush stats: coff %lu foff %lu doff %lu igen %lu",
                atomic64_read(&wb->wb_offset), foff, atomic64_read(&wb->wb_doff),
                atomic64_read(wb->wb_bs->wbs_ingestgen));
#endif

    atomic_set(&wb->wb_flushing, 0);
}

/*
 * WAL bufset routines
 */

struct wal_bufset *
wal_bufset_open(struct wal_fileset *wfset, atomic64_t *ingestgen)
{
    struct wal_bufset *wbs;
    uint i, j;
    size_t sz;
    uint threads;
    merr_t err;

    wbs = calloc(1, sizeof(*wbs));
    if (!wbs)
        return NULL;

    sz = sizeof(*wbs->wbs_bufv) * WAL_NODE_MAX * WAL_BPN_MAX;
    wbs->wbs_bufv = aligned_alloc(alignof(*wbs->wbs_bufv), sz);
    if (!wbs->wbs_bufv) {
        free(wbs);
        return NULL;
    }
    memset(wbs->wbs_bufv, 0, sz);

    atomic64_set(&wbs->wbs_err, 0);
    wbs->wbs_ingestgen = ingestgen;

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
            atomic64_set(&wb->wb_flushreq, 0);
            atomic_set(&wb->wb_flushing, 0);

            wb->wb_index = index + j;
            wb->wb_bs = wbs;
            INIT_WORK(&wb->wb_fwork, wal_buffer_flush_worker);

            wb->wb_buf = vlb_alloc(WAL_BUFALLOCSZ_MAX);
            if (!wb->wb_buf)
                goto errout;
            wbs->wbs_bufc++;
        }
    }

    threads = wbs->wbs_bufc;
    wbs->wbs_flushwq = alloc_workqueue("wal_flush_wq", 0, threads);
    if (!wbs->wbs_flushwq)
        goto errout;

    err = wal_io_init(threads);
    if (err)
        goto errout;

    for (i = 0; i < threads; i++) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        wb->wb_io = wal_io_create(wfset, i, &wb->wb_doff);
        if (!wb->wb_io)
            goto errout;
    }

    return wbs;

errout:
    wal_bufset_close(wbs);

    return NULL;
}

void
wal_bufset_close(struct wal_bufset *wbs)
{
    int i;

    destroy_workqueue(wbs->wbs_flushwq);

    for (i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        wal_io_destroy(wb->wb_io);

        vlb_free(wb->wb_buf, WAL_BUFALLOCSZ_MAX);
    }
    wal_io_fini();

    free(wbs->wbs_bufv);
    free(wbs);
}

void *
wal_bufset_alloc(struct wal_bufset *wbs, size_t len, u64 *offout)
{
    struct wal_buffer *wb;
    uint cpuid, nodeid, coreid;
    u64 offset, doff;

    hse_getcpu(&cpuid, &nodeid, &coreid);

    wb = wbs->wbs_bufv;
    wb += (nodeid % WAL_NODE_MAX) * WAL_BPN_MAX;
    wb += (coreid % WAL_BPN_MAX);

    offset = atomic64_fetch_add(len, &wb->wb_offset);
    doff = atomic64_read(&wb->wb_doff);
    assert(offset >= doff);
    if (offset > doff && offset - doff >= WAL_BUFSZ_MAX) {
        assert(0); /* TODO: needs to be handled to avoid corruption */
        return NULL;
    }

    *offout = offset;
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
