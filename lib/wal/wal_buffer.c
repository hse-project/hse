/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

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

/* clang-format off */

/* Until we have some synchronization in place we need to make bufsz
 * large enough to accomodate several outstanding c0kvms buffers.
 */
#define WAL_BUFSZ_MAX       (8ul << 30)

#define WAL_BUFALLOCSZ_MAX \
    (ALIGN(WAL_BUFSZ_MAX + wal_rec_len() + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX, 2ul << 20))


struct wal_buffer {
    atomic64_t wb_offset_head HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    atomic64_t wb_offset_tail;

    atomic64_t wb_doff HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t wb_foff;
    char      *wb_buf;
    atomic64_t wb_curgen;
    atomic_t   wb_flushing;
    atomic64_t wb_flushb;
    atomic64_t wb_flushc;

    struct work_struct  wb_fwork HSE_ALIGNED(SMP_CACHE_BYTES);
    struct wal_bufset  *wb_bs;
    struct wal_io      *wb_io;
    uint                wb_index;

    /* TODO: Need to ensure there can never be more c0kvms
     * inflight than we can track...
     */
    atomic64_t wb_genlenv[32] HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic64_t wb_genoffv[32];
};

struct wal_bufset {
    struct workqueue_struct *wbs_flushwq;

    atomic64_t *wbs_ingestgen;
    atomic64_t  wbs_err;

    uint              wbs_bufc;
    struct wal_buffer wbs_bufv[];
};

/* clang-format on */

static HSE_ALWAYS_INLINE void
wal_buffer_minmax_seqno(const char *buf, uint rtype, struct wal_minmax_info *info)
{
    bool nontx, txcom;

    nontx = wal_rectype_nontx(rtype);
    txcom = wal_rectype_txcommit(rtype);
    if (nontx || txcom) {
        struct wal_rec_omf *r = (void *)buf;
        struct wal_txnrec_omf *tr = (void *)buf;
        u64 seqno = nontx ? omf_r_seqno(r) : omf_tr_seqno(tr);

        info->min_seqno = min_t(u64, info->min_seqno, seqno);
        info->max_seqno = max_t(u64, info->max_seqno, seqno);
    }
}

static HSE_ALWAYS_INLINE void
wal_buffer_minmax_txid(const char *buf, uint rtype, struct wal_minmax_info *info)
{
    bool txmeta;

    txmeta = wal_rectype_txnmeta(rtype);
    if (txmeta) {
        struct wal_txnrec_omf *tr = (void *)buf;
        u64 txid = omf_tr_txid(tr);

        info->min_txid = min_t(u64, info->min_txid, txid);
        info->max_txid = max_t(u64, info->max_txid, txid);
    }
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
wal_buffer_flush_worker(struct work_struct *work)
{
    struct wal_buffer *wb;
    struct wal_rechdr_omf *rhdr;
    struct wal_minmax_info info = {};
    const char *buf;
    u64 coff, foff, prev_foff, cgen, rgen, start_foff, flushb = 0, buflen;
    u32 flags, rhlen;
    merr_t err;

    wb = container_of(work, struct wal_buffer, wb_fwork);

    coff = atomic64_read(&wb->wb_offset_head);
    rhlen = wal_rechdr_len();

restart:
    foff = atomic64_read(&wb->wb_foff);
    info.min_seqno = info.min_gen = info.min_txid = U64_MAX;
    info.max_seqno = info.max_gen = info.max_txid = 0;

    if (coff == foff) {
        atomic_set(&wb->wb_flushing, 0);
        return;
    }

    cgen = 0;
    prev_foff = foff;
    start_foff = foff;

    while (foff < coff) {
        bool skiprec = false;
        u32 rtype;
        u64 recoff;

        buf = wb->wb_buf + (foff % WAL_BUFSZ_MAX);
        rhdr = (void *)buf;

        while ((recoff = le64_to_cpu(atomic64_read((atomic64_t *)&rhdr->rh_off))) != foff) {
            if (recoff >= U64_MAX - 1) {
                if (recoff == U64_MAX - 1) {
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

        if (skiprec) { /* go to next record */
            prev_foff = foff;
            foff += (rhlen + omf_rh_len(rhdr));
            continue;
        }

        /* Mark flush boundary on encountering a gen increase */
        rgen = omf_rh_gen(rhdr);
        if (cgen > 0 && rgen > cgen)
            break;

        /* Do not allow the IO payload to exceed 32 MiB */
        if (cgen > 0 && (foff - start_foff) >= (32 << 20))
            break;

        if (rgen > cgen)
            cgen = rgen;

        info.min_gen = min_t(u64, info.min_gen, rgen);
        info.max_gen = max_t(u64, info.max_gen, rgen);

        /* Determine min/max seqno from non-tx op and tx-commit record */
        rtype = omf_rh_type(rhdr);
        wal_buffer_minmax_seqno(buf, rtype, &info);

        /* Determine min/max txid from tx meta record */
        wal_buffer_minmax_txid(buf, rtype, &info);

        prev_foff = foff;
        foff += (rhlen + omf_rh_len(rhdr));

        if ((foff % WAL_BUFSZ_MAX) < (prev_foff % WAL_BUFSZ_MAX))
            break;
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
    assert(foff > start_foff);
    buflen = foff - start_foff; /* foff is exclusive */
    assert(buf + buflen - wb->wb_buf <= WAL_BUFALLOCSZ_MAX);
    if (buf + buflen - wb->wb_buf > WAL_BUFALLOCSZ_MAX) {
        err = merr(EBUG);
        goto exit;
    }

    err = wal_io_enqueue(wb->wb_io, buf, buflen, cgen, &info);
    if (err)
        goto exit;
    flushb += (foff - start_foff);

    if (foff < coff)
        goto restart;

    assert(foff == coff);

#ifndef NDEBUG
    if (atomic64_inc_return(&wb->wb_flushc) % 1536 == 0)
        hse_log(HSE_NOTICE "Flush stats: coff %lu,%lu foff %lu doff %lu igen %lu",
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
wal_bufset_open(struct wal_fileset *wfset, atomic64_t *ingestgen, struct wal_iocb *iocb)
{
    struct wal_bufset *wbs;
    uint i, j, k;
    size_t sz;
    uint threads;
    merr_t err;

    sz = sizeof(*wbs) + sizeof(*wbs->wbs_bufv) * WAL_NODE_MAX * WAL_BPN_MAX;

    wbs = aligned_alloc(alignof(*wbs), sz);
    if (!wbs)
        return NULL;

    memset(wbs, 0, sz);
    atomic64_set(&wbs->wbs_err, 0);
    wbs->wbs_ingestgen = ingestgen;

    for (i = 0; i < get_nprocs_conf(); ++i) {
        struct wal_buffer *wb;
        uint index = (hse_cpu2node(i) % WAL_NODE_MAX) * WAL_BPN_MAX;

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

            for (k = 0; k < NELEM(wb->wb_genlenv); ++k) {
                atomic64_set(&wb->wb_genlenv[k], 0);
                atomic64_set(&wb->wb_genoffv[k], 0);
            }

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

        hse_log(HSE_NOTICE "WAL closing - Offsets (%d - %lu, %lu : %lu : %lu)",
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

        vlb_free(wb->wb_buf, WAL_BUFALLOCSZ_MAX);
    }

    wal_io_fini();
#ifndef NDEBUG
    wal_bufset_stats_dump(wbs);
#endif
    free(wbs);
}

void *
wal_bufset_alloc(struct wal_bufset *wbs, size_t len, u64 *offout, uint *wbidx)
{
    const size_t hwm = WAL_BUFSZ_MAX * 93 / 100;
    struct wal_buffer *wb;
    uint cpuid, nodeid, coreid;
    u64 offset, doff;

    hse_getcpu(&cpuid, &nodeid, &coreid);

    wb = wbs->wbs_bufv;
    wb += (nodeid % WAL_NODE_MAX) * WAL_BPN_MAX;
    wb += (coreid % WAL_BPN_MAX);

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

        /* HSE_REVISIT: Add a throttle sensor to each bufset to mitigate
         * having to stall hard here when we hit the HWM.
         */
        usleep(131);
        ev(1);
    }

    *offout = offset;
    *wbidx = wb - wbs->wbs_bufv;

    return wb->wb_buf + (offset % WAL_BUFSZ_MAX);
}

void
wal_bufset_finish(struct wal_bufset *wbs, uint wbidx, size_t len, uint64_t gen, u64 endoff)
{
    struct wal_buffer *wb = wbs->wbs_bufv + wbidx;
    uint slot;

    slot = gen % NELEM(wb->wb_genoffv);

    /*
     * Record the maximum buffer offset for each gen in wb_genoffv[].
     * The ingest thread calls wal_cond_sync() on the ingesting gen (before starting ingest)
     * and waits for the offset recorded in wb_genoffv to become durable.
     */
    if (gen > atomic64_read(&wb->wb_curgen) || (gen + 1 == atomic64_read(&wb->wb_curgen))) {
        u64 off = atomic64_read(&wb->wb_genoffv[slot]);

        while (endoff > off && atomic64_cas(&wb->wb_genoffv[slot], off, endoff) != off)
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
wal_bufset_flush(struct wal_bufset *wbs, u64 *flushb)
{
    struct workqueue_struct *wq;
    uint i;
    merr_t err;

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

    *flushb = 0;
    for (i = 0; i < wbs->wbs_bufc; ++i) {
        struct wal_buffer *wb = wbs->wbs_bufv + i;

        *flushb += atomic64_read(&wb->wb_flushb);
    }

    return 0;
}

int
wal_bufset_curoff(struct wal_bufset *wbs, int offc, u64 *offv)
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
wal_bufset_genoff(struct wal_bufset *wbs, u64 gen, int offc, u64 *offv)
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
wal_bufset_durcnt(struct wal_bufset *wbs, int offc, u64 *offv)
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
