/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/vlb.h>
#include <hse_util/logging.h>
#include <hse_util/xrand.h>
#include <hse_util/slab.h>
#include <hse_util/storage.h>

#include "wal.h"
#include "wal_omf.h"
#include "wal_buffer.h"
#include "wal_file.h"
#include "wal_io.h"

/* clang-format off */

struct wal_buffer {
    atomic64_t wb_offset_head HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    atomic64_t wb_offset_tail;

    atomic64_t wb_doff HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t wb_foff;
    char      *wb_buf;
    atomic64_t wb_curgen;
    atomic_t   wb_flushing;
    atomic_t   wb_wrap;
    atomic64_t wb_flushb;
    atomic64_t wb_flushc;

    struct work_struct  wb_fwork HSE_ALIGNED(SMP_CACHE_BYTES);
    struct wal_bufset  *wb_bs;
    struct wal_io      *wb_io;
    uint32_t            wb_index;

    /* TODO: Need to ensure there can never be more c0kvms
     * inflight than we can track...
     */
    atomic64_t wb_genlenv[32] HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t wb_genoffv[32];
};

struct wal_bufset {
    struct workqueue_struct *wbs_flushwq;

    size_t      wbs_buf_sz;
    size_t      wbs_buf_allocsz;

    atomic64_t *wbs_ingestgen;
    atomic64_t  wbs_err;

    uint32_t          wbs_bufc;
    struct wal_buffer wbs_bufv[];
};

/* clang-format on */

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
    char *buf;
    uint64_t coff, foff, prev_foff, cgen, rgen, start_foff, flushb = 0, buflen;
    uint32_t flags, rhlen;
    size_t bufsz, bufasz;
    merr_t err;
    bool wrap;

    wb = container_of(work, struct wal_buffer, wb_fwork);

    coff = atomic64_read(&wb->wb_offset_head);
    rhlen = wal_rechdr_len();
    bufsz = wb->wb_bs->wbs_buf_sz;
    bufasz = wb->wb_bs->wbs_buf_allocsz;

restart:
    foff = atomic64_read(&wb->wb_foff);
    info.min_seqno = info.min_gen = info.min_txid = UINT64_MAX;
    info.max_seqno = info.max_gen = info.max_txid = 0;
    wrap = false;

    if (coff == foff) {
        atomic_set(&wb->wb_flushing, 0);
        return;
    }

    cgen = 0;
    prev_foff = foff;
    start_foff = foff;

    while (foff < coff) {
        bool skiprec = false;
        uint64_t recoff;

        buf = wb->wb_buf + (foff % bufsz);
        rhdr = (void *)buf;

        while ((recoff = le64_to_cpu(atomic64_read((atomic64_t *)&rhdr->rh_off))) != foff) {
            if (recoff >= WAL_ROFF_RECOV_ERR) {
                if (recoff == WAL_ROFF_RECOV_ERR) {
                    skiprec = true;
                } else {
                    err = ENODATA;
                    goto exit;
                }
                break;
            }
            cpu_relax();
        }

        /* Set the BOR flag in the first record */
        if (prev_foff == foff) {
            flags = omf_rh_flags(rhdr);
            flags |= WAL_FLAGS_BORG;
            omf_set_rh_flags(rhdr, flags);
        }

        rgen = omf_rh_gen(rhdr);
        assert(rgen);
        cgen = cgen ? : rgen;

        /* Mark flush boundary on encountering a gen increase */
        if (rgen > cgen)
            break;

        /* Do not allow the IO payload to exceed 32 MiB */
        if ((foff - start_foff) >= (32u << MB_SHIFT))
            break;

        info.min_gen = min_t(uint64_t, info.min_gen, rgen);
        info.max_gen = max_t(uint64_t, info.max_gen, rgen);

        if (!skiprec) {
            /* Determine min/max seqno from non-tx op and tx-commit record */
            wal_update_minmax_seqno(buf, &info);

            /* Determine min/max txid from tx op and tx-meta record */
            wal_update_minmax_txid(buf, &info);
        }

        prev_foff = foff;
        foff += (rhlen + omf_rh_len(rhdr));

        if ((foff % bufsz) < (prev_foff % bufsz)) {
            wrap = true;
            break;
        }
    }
    assert(foff <= coff);

    rhdr = (void *)(wb->wb_buf + prev_foff % bufsz);

    /* Set the EOR flag in the last record */
    flags = omf_rh_flags(rhdr);
    flags |= WAL_FLAGS_EORG;
    omf_set_rh_flags(rhdr, flags);

    /* Set flush offset to the next record */
    foff = prev_foff + (rhlen + omf_rh_len(rhdr));
    atomic64_set(&wb->wb_foff, foff);
    assert(foff > start_foff);

    buf = wb->wb_buf + (start_foff % bufsz);
    buflen = foff - start_foff; /* foff is exclusive */

    if (buf + buflen - wb->wb_buf > bufasz) {
        assert(buf + buflen - wb->wb_buf <= bufasz);
        err = merr(EBUG);
        goto exit;
    }

    err = wal_io_enqueue(wb->wb_io, buf, buflen, cgen, &info, !!atomic_read(&wb->wb_wrap));
    if (err)
        goto exit;

    flushb += (foff - start_foff);

    atomic_set(&wb->wb_wrap, wrap ? 1 : 0);

    if (foff < coff)
        goto restart;

    assert(foff == coff);

#ifndef NDEBUG
    if (atomic64_inc_return(&wb->wb_flushc) % 1536 == 0)
        hse_log(HSE_DEBUG "Flush stats: coff %lu,%lu foff %lu doff %lu igen %lu",
                atomic64_read(&wb->wb_offset_head), atomic64_read(&wb->wb_offset_tail),
                foff, atomic64_read(&wb->wb_doff), atomic64_read(wb->wb_bs->wbs_ingestgen));
#endif

exit:
    if (err)
        atomic64_set(&wb->wb_bs->wbs_err, err);
    atomic64_set(&wb->wb_flushb, flushb);
    atomic_set(&wb->wb_flushing, 0);
}

/*
 * WAL bufset routines
 */

struct wal_bufset *
wal_bufset_open(
    struct wal_fileset *wfset,
    size_t              bufsz,
    atomic64_t         *ingestgen,
    struct wal_iocb    *iocb)
{
    struct wal_bufset *wbs;
    uint32_t i, j, k;
    size_t sz;
    uint32_t threads;
    merr_t err;

    sz = sizeof(*wbs) + sizeof(*wbs->wbs_bufv) * WAL_NODE_MAX * WAL_BPN_MAX;

    wbs = aligned_alloc(alignof(*wbs), roundup(sz, alignof(*wbs)));
    if (!wbs)
        return NULL;

    memset(wbs, 0, sz);
    atomic64_set(&wbs->wbs_err, 0);
    wbs->wbs_ingestgen = ingestgen;

    wbs->wbs_buf_sz = bufsz;
    wbs->wbs_buf_allocsz = ALIGN(bufsz + wal_reclen() + HSE_KVS_KEY_LEN_MAX +
                                 HSE_KVS_VALUE_LEN_MAX, 2ul << MB_SHIFT);

    for (i = 0; i < get_nprocs_conf(); ++i) {
        struct wal_buffer *wb;
        uint32_t index = (hse_cpu2node(i) % WAL_NODE_MAX) * WAL_BPN_MAX;

        wb = wbs->wbs_bufv + index;
        if (wb->wb_buf)
            continue;

        for (j = 0; j < WAL_BPN_MAX; ++j, ++wb) {
            atomic64_set(&wb->wb_offset_head, PAGE_SIZE);
            atomic64_set(&wb->wb_offset_tail, PAGE_SIZE);
            atomic64_set(&wb->wb_doff, PAGE_SIZE);
            atomic64_set(&wb->wb_foff, PAGE_SIZE);
            atomic64_set(&wb->wb_curgen, 0);
            atomic64_set(&wb->wb_flushc, 0);
            atomic_set(&wb->wb_flushing, 0);
            atomic_set(&wb->wb_wrap, 0);

            for (k = 0; k < NELEM(wb->wb_genlenv); ++k) {
                atomic64_set(&wb->wb_genlenv[k], 0);
                atomic64_set(&wb->wb_genoffv[k], 0);
            }

            wb->wb_index = index + j;
            wb->wb_bs = wbs;
            INIT_WORK(&wb->wb_fwork, wal_buffer_flush_worker);

            wb->wb_buf = vlb_alloc(wbs->wbs_buf_allocsz);
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

        wb->wb_io = wal_io_create(wfset, i, &wb->wb_doff, iocb);
        if (!wb->wb_io)
            goto errout;
    }

    return wbs;

errout:
    wal_bufset_close(wbs);

    return NULL;
}

#ifndef NDEBUG
void
wal_bufset_stats_dump(struct wal_bufset *wbs)
{
    for (int i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        hse_log(HSE_DEBUG "WAL closing - Offsets (%d - %lu, %lu : %lu : %lu)",
                i, atomic64_read(&wb->wb_offset_head), atomic64_read(&wb->wb_offset_tail),
                atomic64_read(&wb->wb_foff), atomic64_read(&wb->wb_doff));
    }
}
#endif

void
wal_bufset_close(struct wal_bufset *wbs)
{
    if (!wbs)
        return;

    destroy_workqueue(wbs->wbs_flushwq);

    for (int i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        wal_io_destroy(wb->wb_io);

        vlb_free(wb->wb_buf, wbs->wbs_buf_allocsz);
    }

    wal_io_fini();
#ifndef NDEBUG
    wal_bufset_stats_dump(wbs);
#endif
    free(wbs);
}

void *
wal_bufset_alloc(
    struct wal_bufset *wbs,
    size_t             len,
    uint64_t          *offout,
    uint32_t          *wbidx,
    int64_t           *cookie)
{
    const size_t hwm = wbs->wbs_buf_sz - (8u << MB_SHIFT);
    struct wal_buffer *wb;
    uint64_t offset, doff;
    int slot;

    slot = *cookie;
    if (HSE_LIKELY(slot == -1)) {
        uint32_t cpuid, nodeid, coreid;

        hse_getcpu(&cpuid, &nodeid, &coreid);
        slot = (nodeid % WAL_NODE_MAX) * WAL_BPN_MAX + (coreid % WAL_BPN_MAX);
        *cookie = slot;
    }

    wb = wbs->wbs_bufv + slot;

    offset = atomic64_fetch_add(len, &wb->wb_offset_head);

    while (1) {
        uint64_t tail = atomic64_read(&wb->wb_offset_tail);

        if (tail >= offset || offset - tail < hwm) {
            doff = atomic64_read(&wb->wb_doff);
            if (offset < doff)
                return NULL;

            if (offset - doff < hwm)
                break;
        }

        /* An excessive number of txn put+abort calls can fill up our buffer
         * without an associated ingest to clean it up.
         */
        if (atomic64_read(wbs->wbs_ingestgen) + 1 >= atomic64_read(&wb->wb_curgen)) {
            /* HSE_REVISIT: Force a c0kvms ingest... */
            ev(1);
        }

        /* At this point we're within 8M of overflowing the wal buffer which
         * we cannot allow.  This should only happen if the ingest pipeline
         * configuration or throttle sensors are out of whack...
         */
        usleep((xrand64_tls() % 256) + 128);
    }

    *offout = offset;
    *wbidx = slot;

    return wb->wb_buf + (offset % wbs->wbs_buf_sz);
}

void
wal_bufset_finish(struct wal_bufset *wbs, uint32_t wbidx, size_t len, uint64_t gen, uint64_t endoff)
{
    struct wal_buffer *wb = wbs->wbs_bufv + wbidx;
    uint32_t slot;

    slot = gen % NELEM(wb->wb_genoffv);

    /*
     * Record the maximum buffer offset for each gen in wb_genoffv[].
     * The ingest thread calls wal_cond_sync() on the ingesting gen (before starting ingest)
     * and waits for the offset recorded in wb_genoffv to become durable.
     */
    if (gen > atomic64_read(&wb->wb_curgen) || (gen + 1 == atomic64_read(&wb->wb_curgen))) {
        uint64_t off = atomic64_read(&wb->wb_genoffv[slot]);

        while (endoff > off && !atomic64_cas(&wb->wb_genoffv[slot], off, endoff))
            off = atomic64_read(&wb->wb_genoffv[slot]);
    }

    while (gen > atomic64_read(&wb->wb_curgen) &&
           !atomic64_cas(&wb->wb_curgen, atomic64_read(&wb->wb_curgen), gen))
        ; /* do nothing */

    assert(sizeof(wb->wb_genlenv) == sizeof(wb->wb_genoffv));
    atomic64_add(len, &wb->wb_genlenv[slot]);
}

void
wal_bufset_reclaim(struct wal_bufset *wbs, uint64_t gen)
{
    struct wal_buffer *wb;
    uint64_t n;
    int i;

    gen %= NELEM(wb->wb_genlenv);

    for (i = 0; i < wbs->wbs_bufc; ++i) {
        wb = wbs->wbs_bufv + i;
        if (!wb)
            continue;

        n = atomic64_read(&wb->wb_genlenv[gen]);
        atomic64_sub(n, &wb->wb_genlenv[gen]);
        atomic64_add(n, &wb->wb_offset_tail);
    }
}

merr_t
wal_bufset_flush(struct wal_bufset *wbs, uint64_t *flushb, uint64_t *bufszp, uint64_t *buflenp)
{
    struct workqueue_struct *wq;
    merr_t err;
    uint32_t i;

    if (!wbs)
        return merr(EINVAL);

    wq = wbs->wbs_flushwq;

    for (i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        if (wb->wb_buf && atomic_cmpxchg(&wb->wb_flushing, 0, 1) == 0) {
            atomic64_set(&wb->wb_flushb, 0);
            queue_work(wq, &wb->wb_fwork);
        }
    }
    flush_workqueue(wq);

    if ((err = atomic64_read(&wbs->wbs_err)))
        return err;

    *bufszp = wbs->wbs_buf_sz;
    *buflenp = 0;
    *flushb = 0;

    for (i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;
        uint64_t head, tail;

        *flushb += atomic64_read(&wb->wb_flushb);

        tail = atomic64_read_acq(&wb->wb_offset_tail);
        head = atomic64_read(&wb->wb_offset_head);
        if (head - tail > *buflenp)
            *buflenp = head - tail;
    }

    return 0;
}

int
wal_bufset_curoff(struct wal_bufset *wbs, int offc, uint64_t *offv)
{
    assert(offc >= wbs->wbs_bufc);

    if (offc < wbs->wbs_bufc)
        return -1;

    for (int i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        offv[i] = atomic64_read(&wb->wb_offset_head);
    }

    return wbs->wbs_bufc;
}

int
wal_bufset_genoff(struct wal_bufset *wbs, uint64_t gen, int offc, uint64_t *offv)
{
    assert(offc >= wbs->wbs_bufc);

    if (offc < wbs->wbs_bufc)
        return -1;

    for (int i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        gen %= NELEM(wb->wb_genlenv);

        offv[i] = atomic64_read(&wb->wb_genoffv[gen]);
    }

    return wbs->wbs_bufc;
}

int
wal_bufset_durcnt(struct wal_bufset *wbs, int offc, uint64_t *offv)
{
    int reached = 0;

    assert(offc >= wbs->wbs_bufc);
    if (offc < wbs->wbs_bufc)
        return -1;

    for (int i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        if (atomic64_read(&wb->wb_doff) >= offv[i])
            reached++;
    }

    return reached;
}
