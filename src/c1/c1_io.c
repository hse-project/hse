/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/throttle.h>
#include <hse_ikvdb/kvb_builder.h>

#include "c1_private.h"
#include "c1_io_internal.h"
#include "c1_omf_internal.h"

/* c1q_txn and c1q_iter can never be set at the same time. c1q_txn is set
 * only by the c1_io_txn_* APIs.
 */
struct c1_io_queue {
    struct list_head         c1q_list;
    struct c1_tree          *c1q_tree;
    struct kvb_builder_iter *c1q_iter;
    struct c1_ttxn          *c1q_txn;
    u64                      c1q_txnid;
    u64                      c1q_mutation;
    u64                      c1q_stime;
    int                      c1q_idx;
    int                      c1q_sync;
    struct c1_ttxn           c1q_txnbuf;

    __aligned(SMP_CACHE_BYTES)
    struct mutex             c1q_mtx;
    struct cv                c1q_cv;
};

struct c1_io_worker {
    struct mutex        c1w_mtx;
    struct list_head    c1w_list;
    bool                c1w_stop;
    struct cv           c1w_cv;

    struct work_struct  c1w_work;
    struct c1_io       *c1w_io;
    int                 c1w_idx;
} __aligned(SMP_CACHE_BYTES);

struct c1_io {
    u32                         c1io_kvbmetasz;
    u32                         c1io_kmetasz;
    u32                         c1io_vmetasz;
    int                         c1io_threads;
    struct c1_kvset_builder    *c1io_bldr;
    merr_t                      c1io_err;

    struct perfc_set            c1io_pcset;
    struct c1_io_worker        *c1io_slave;
    u64                         c1io_dtimens;

    struct workqueue_struct    *c1io_wq;

    __aligned(SMP_CACHE_BYTES)
    struct mutex                c1io_space_mtx;
    struct list_head            c1io_qfree;

    __aligned(SMP_CACHE_BYTES)
    atomic_t                    c1io_pending_reqs;

    __aligned(SMP_CACHE_BYTES)
    struct c1_io_queue          c1io_ioqv[47];
};


static void
c1_io_worker(struct work_struct *work)
{
    struct kvb_builder_iter    *iter;
    struct c1_io_worker        *slave;
    struct c1_io_queue         *q;
    struct c1_io               *io;
    u64 start;
    int tidx;

    slave = container_of(work, struct c1_io_worker, c1w_work);

    io = slave->c1w_io;
    tidx = slave->c1w_idx;

    assert(tidx < io->c1io_threads);

    hse_log(HSE_DEBUG "c1 io worker %d starting", tidx);

    start = 0;
    q = NULL;

    while (1) {
        merr_t  err;

        if (q) {
            mutex_lock(&io->c1io_space_mtx);
            list_add(&q->c1q_list, &io->c1io_qfree);
            mutex_unlock(&io->c1io_space_mtx);
            q = NULL;
        }

        mutex_lock(&slave->c1w_mtx);
        while (list_empty(&slave->c1w_list)) {
            if (slave->c1w_stop) {
                mutex_unlock(&slave->c1w_mtx);

                hse_log(HSE_DEBUG "c1 io worker %d stopped", tidx);
                return;
            }

            cv_wait(&slave->c1w_cv, &slave->c1w_mtx);
        }

        q = list_first_entry(&slave->c1w_list, struct c1_io_queue, c1q_list);

        list_del(&q->c1q_list);
        err = ev(io->c1io_err);
        mutex_unlock(&slave->c1w_mtx);

        assert(tidx == q->c1q_idx);
        assert(atomic_read(&io->c1io_pending_reqs) > 0);

        if (PERFC_ISON(&io->c1io_pcset)) {
            perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOPRO);
            perfc_rec_lat(&io->c1io_pcset, PERFC_LT_C1_IOQUE, q->c1q_stime);
            start = perfc_lat_start(&io->c1io_pcset);
        }

        if (q->c1q_txn) {
            err = c1_tree_issue_txn(
                q->c1q_tree, q->c1q_idx, q->c1q_mutation, q->c1q_txn, q->c1q_sync);
            if (err) {
                hse_elog(HSE_ERR "%s: c1 log failed : @@e", err, __func__);
                io->c1io_err = err;
                perfc_inc(&io->c1io_pcset, PERFC_BA_C1_IOERR);
            }

            c1_io_rec_perf(io, q, start, err);

            atomic_dec(&io->c1io_pending_reqs);
            continue;
        }

        iter = q->c1q_iter;
        if (c1_sync_or_flush_command(iter)) {
            mutex_lock(&q->c1q_mtx);
            cv_signal(&q->c1q_cv);
            mutex_unlock(&q->c1q_mtx);

            /* q came from caller's stack (e.g., c1_issue_sync())
             * and must not be touched after dropping the mutex.
             */
            atomic_dec(&io->c1io_pending_reqs);
            q = NULL;
            continue;
        }

        if (!err) {
            c1_io_iter_kvbtxn(io, q, tidx);
            c1_io_rec_perf(io, q, start, err);
        } else {
            c1_io_rec_perf(io, q, start, err);
            iter->put(iter);
        }

        atomic_dec(&io->c1io_pending_reqs);
    }
}

static void
c1_io_shutdown_threads(struct c1_io *io)
{
    struct c1_io_worker *slave;
    int i;

    for (i = 0; i < io->c1io_threads; ++i) {
        slave = &io->c1io_slave[i];

        mutex_lock(&slave->c1w_mtx);
        slave->c1w_stop = true;
        cv_signal(&slave->c1w_cv);
        mutex_unlock(&slave->c1w_mtx);
    }

    destroy_workqueue(io->c1io_wq);

    for (i = 0; i < io->c1io_threads; ++i) {
        slave = &io->c1io_slave[i];

        mutex_destroy(&slave->c1w_mtx);
        cv_destroy(&slave->c1w_cv);
    }
}

static void
c1_io_queue_free(struct c1_io *io, struct c1_io_queue *q)
{
    if (q < io->c1io_ioqv || q >= io->c1io_ioqv + NELEM(io->c1io_ioqv))
        free(q);
}

static void
c1_io_destroy_impl(struct c1_io *io)
{
    struct c1_io_queue *q;

    if (!io)
        return;

    c1_io_shutdown_threads(io);

    c1_kvset_builder_destroy(io->c1io_bldr);

    c1_perfc_io_free(&io->c1io_pcset);

    while (!list_empty(&io->c1io_qfree)) {
        q = list_first_entry(&io->c1io_qfree, typeof(*q), c1q_list);
        list_del(&q->c1q_list);
        c1_io_queue_free(io, q);
    }

    mutex_destroy(&io->c1io_space_mtx);

    free_aligned(io->c1io_slave);
    free_aligned(io);
}

void
c1_io_destroy(struct c1 *c1)
{
    c1_io_destroy_impl(c1->c1_io);
}

merr_t
c1_io_create(struct c1 *c1, u64 dtime, const char *mpname, int threads)
{
    struct c1_io       *io;
    merr_t              err;
    size_t              sz;
    int                 i;

    c1->c1_io = NULL;

    io = alloc_aligned(sizeof(*io), PAGE_SIZE, 0);
    if (ev(!io))
        return merr(ENOMEM);

    hse_log(HSE_ERR "%s: %zu %p %zu",
            __func__, sizeof(*io), io, offsetof(struct c1_io, c1io_ioqv));
    memset(io, 0, sizeof(*io));
    INIT_LIST_HEAD(&io->c1io_qfree);
    mutex_init(&io->c1io_space_mtx);

    io->c1io_dtimens = dtime * 1000UL * 1000;
    atomic_set(&io->c1io_pending_reqs, 0);

    /* Prime the io queue cache with preallocated items...
     */
    for (i = 0; i < NELEM(io->c1io_ioqv); ++i) {
        struct c1_io_queue *q = io->c1io_ioqv + i;

        list_add_tail(&q->c1q_list, &io->c1io_qfree);
    }

    sz = threads * sizeof(*io->c1io_slave);

    io->c1io_slave = alloc_aligned(sz, __alignof(*io->c1io_slave), 0);
    if (ev(!io->c1io_slave)) {
        err = merr(ENOMEM);
        goto errout;
    }

    err = c1_kvset_builder_create(c1_c0sk_get(c1), &io->c1io_bldr);
    if (ev(err))
        goto errout;

    c1_perfc_io_alloc(&io->c1io_pcset, mpname);

    err = c1_record_type2len(C1_TYPE_KVT, C1_VERSION, &io->c1io_kmetasz);
    if (ev(err))
        goto errout;

    err = c1_record_type2len(C1_TYPE_VT, C1_VERSION, &io->c1io_vmetasz);
    if (ev(err))
        goto errout;

    err = c1_record_type2len(C1_TYPE_KVB, C1_VERSION, &io->c1io_kvbmetasz);
    if (ev(err))
        goto errout;

    io->c1io_wq = alloc_workqueue("%s", 0, threads, "c1wq");
    if (ev(!io->c1io_wq)) {
        err = merr(ENOMEM);
        goto errout;
    }

    io->c1io_threads = threads;
    c1->c1_io = io;

    for (i = 0; i < threads; ++i) {
        struct c1_io_worker *slave = &io->c1io_slave[i];

        memset(slave, 0, sizeof(*slave));
        mutex_init(&slave->c1w_mtx);
        INIT_LIST_HEAD(&slave->c1w_list);
        cv_init(&slave->c1w_cv, "c1wcv");

        INIT_WORK(&slave->c1w_work, c1_io_worker);
        slave->c1w_idx = i;
        slave->c1w_io = io;

        queue_work(io->c1io_wq, &slave->c1w_work);
    }

  errout:
    if (err)
        c1_io_destroy_impl(io);

    return err;
}

static merr_t
c1_io_next_tree(struct c1 *c1, struct c1_tree *cur)
{
    struct c1_complete cmp;

    merr_t err;

    (void)c1_tree_get_complete(cur, &cmp);

    err = c1_mark_tree_complete(c1, cur);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: Cannot mark tree full : @@e", err, __func__);
        return err;
    }

    hse_log(
        HSE_DEBUG "c1 current tree %p ver %ld-%ld kvseqno %ld exhausted, "
                  "allocating new",
        cur,
        (unsigned long)cur->c1t_seqno,
        (unsigned long)cur->c1t_gen,
        (unsigned long)cmp.c1c_kvseqno);

    err = c1_next_tree(c1);

    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 cannot allocate new tree : @@e", err, __func__);
        return err;
    }

    return 0;
}

merr_t
c1_io_get_tree_txn(
    struct c1 *         c1,
    struct c1_iterinfo *ci,
    struct c1_tree **   out,
    int *               idx,
    u64 *               mutation)
{
    struct c1_tree *tree;
    struct c1_io *  io;

    merr_t err = 0;
    u64    txsz;
    u32    recsz, kvbc;
    bool   spare, retry;

    io = c1->c1_io;

    err = c1_record_type2len(C1_TYPE_TXN, C1_VERSION, &recsz);
    if (ev(err))
        return err;
    recsz *= 2; /* begin + abort/commit */

    /* Add the kvtuple, vtuple and kvb meta sz */
    assert(c1_ingest_stripsize(c1) != 0);
    txsz = ci->ci_total.ck_kvsz;
    kvbc = (txsz / c1_ingest_stripsize(c1)) + 1;
    txsz +=
        (io->c1io_kmetasz * ci->ci_total.ck_kcnt + io->c1io_vmetasz * ci->ci_total.ck_vcnt +
         io->c1io_kvbmetasz * kvbc);

    spare = retry = false;
    while (1) {
        tree = c1_current_tree(c1);
        assert(tree != NULL);

        /* Try reserving space from the current c1 tree for
         * both data and tx records.
         */
        err = c1_tree_reserve_space_txn(tree, txsz + recsz);
        if (err && (ev(merr_errno(err) != ENOMEM) || retry)) {
            hse_elog(
                HSE_ERR "Unable to reserve mutation set size %lu in a c1 tree: @@e",
                err,
                txsz + recsz);
            return err;
        }

        if (!err) {
            /* Reserve recsz first */
            err = c1_tree_reserve_space(tree, recsz, idx, mutation, spare);
            if (err && (ev(merr_errno(err) != ENOMEM) || retry))
                return err;

            if (!err) {
                /* Try reserving space for the mutation set by iter */
                err = c1_tree_reserve_space_iter(
                    tree,
                    io->c1io_kmetasz,
                    io->c1io_vmetasz,
                    io->c1io_kvbmetasz,
                    c1_ingest_stripsize(c1),
                    ci);
                if (ev(err) && retry) {
                    hse_elog(
                        HSE_ERR "Unable to reserve mutation set size %lu by iter: @@e", err, txsz);
                    return err;
                }

                if (!err)
                    break;
            }
        }

        assert(!retry);

        /* If either c1 tree or mlog reservation fails, retry once with a new tree. */
        err = c1_io_next_tree(c1, tree);
        if (ev(err))
            return err;

        retry = true;
    }

    *out = tree;

    return 0;
}

merr_t
c1_io_get_tree(struct c1 *c1, struct c1_kvinfo *cki, struct c1_tree **out, int *idx, u64 *mutation)
{
    struct c1_tree *tree;
    struct c1_io *  io;
    u32             kvbc;
    u64             kvsz;

    merr_t err;

    io = c1->c1_io;

    tree = c1_current_tree(c1);
    assert(tree != NULL);

    /* Add the kvtuple, vtuple and kvb meta sz */
    assert(c1_ingest_stripsize(c1) != 0);
    kvsz = cki->ck_kvsz;
    kvbc = (kvsz / c1_ingest_stripsize(c1)) + 1;
    kvsz +=
        (io->c1io_kmetasz * cki->ck_kcnt + io->c1io_vmetasz * cki->ck_vcnt +
         io->c1io_kvbmetasz * kvbc);

    /* Reserve space from mlog. */
    err = c1_tree_reserve_space(tree, kvsz, idx, mutation, false);
    if (ev(err)) {
        /* Use from the spare tree capacity to finish logging this mutation set. */
        err = c1_tree_reserve_space(tree, kvsz, idx, mutation, true);
        if (ev(err)) {
            hse_elog(HSE_ERR "Reservation from spare failed, kvsz %lu :@@e", err, kvsz);
            return err;
        }
    }

    *out = tree;

    return 0;
}

static inline bool
c1_io_pending_reqs(struct c1_io *io)
{
    return atomic_read(&io->c1io_pending_reqs);
}

void
c1_io_iter_kvbtxn(struct c1_io *io, struct c1_io_queue *q, u8 tidx)
{
    struct c1_kvbundle *     kvb;
    struct kvb_builder_iter *iter;
    merr_t                   err;

    iter = q->c1q_iter;

    while (1) {
        err = iter->get_next(iter, &kvb);
        if (ev(err) || !kvb) {
            if (!kvb && iter->kvbi_bldrelm) {

                err = c1_kvset_builder_flush_elem(iter->kvbi_bldrelm, tidx);
                if (ev(err))
                    io->c1io_err = err;
            }

            iter->put(iter);
            io->c1io_err = err;
            break;
        }

        if (iter->kvbi_bldrelm)
            assert(c1_kvset_builder_elem_valid(iter->kvbi_bldrelm, iter->kvbi_ingestid));

        err = c1_tree_issue_kvb(
            q->c1q_tree,
            iter->kvbi_bldrelm,
            iter->kvbi_ingestid,
            iter->kvbi_vsize,
            q->c1q_idx,
            q->c1q_txnid,
            q->c1q_mutation,
            kvb,
            q->c1q_sync,
            tidx);
        if (ev(err)) {
            iter->put(iter);
            io->c1io_err = err;

            perfc_inc(&io->c1io_pcset, PERFC_BA_C1_IOERR);
            break;
        }
    }
}

bool
c1_sync_or_flush_command(struct kvb_builder_iter *iter)
{
    return iter == NULL;
}

merr_t
c1_issue_sync(struct c1 *c1, int sync, bool skip_flush)
{
    struct c1_io_queue      q = { .c1q_sync = sync };
    struct c1_io_worker    *worker;
    struct c1_io           *io;
    merr_t                  err;

    io = c1->c1_io;

    if (sync != C1_INGEST_SYNC)
        return io->c1io_err;

    if (!c1_io_pending_reqs(io)) {
        if (!skip_flush)
            goto log_flush;

        return io->c1io_err;
    }

    INIT_LIST_HEAD(&q.c1q_list);

    mutex_init(&q.c1q_mtx);
    cv_init(&q.c1q_cv, "c1synccv");

    mutex_lock(&q.c1q_mtx);

    worker = &io->c1io_slave[q.c1q_idx];

    mutex_lock(&worker->c1w_mtx);
    list_add_tail(&q.c1q_list, &worker->c1w_list);
    atomic_inc(&io->c1io_pending_reqs);
    cv_signal(&worker->c1w_cv);
    mutex_unlock(&worker->c1w_mtx);

    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);

    cv_wait(&q.c1q_cv, &q.c1q_mtx);
    mutex_unlock(&q.c1q_mtx);

    cv_destroy(&q.c1q_cv);
    mutex_destroy(&q.c1q_mtx);

    if (ev(io->c1io_err))
        return io->c1io_err;

    if (skip_flush)
        return 0;

log_flush:
    mutex_lock(&io->c1io_space_mtx);

    err = c1_tree_flush(c1_current_tree(c1));
    if (!ev(err)) {
        err = c1_kvset_builder_flush(io->c1io_bldr);
        if (merr_errno(err) == ENOENT)
            err = 0;
    }
    mutex_unlock(&io->c1io_space_mtx);

    return err;
}

merr_t
c1_issue_iter(
    struct c1 *              c1,
    struct kvb_builder_iter *iter,
    u64                      txnid,
    struct c1_kvinfo *       cki,
    int                      sync)
{
    struct c1_kvset_builder_elem   *bldr;
    struct c1_io_worker            *worker;
    struct c1_io_queue             *q;
    struct c1_io                   *io;
    merr_t                          err;

    if (c1_sync_or_flush_command(iter))
        return c1_issue_sync(c1, sync, false);

    io = c1->c1_io;
    assert(io);
    assert(io->c1io_bldr);
    assert(!iter->kvbi_bldrelm);

    bldr = NULL;
    if (likely(c1_vbldr(c1))) {
        err = c1_kvset_builder_elem_create(io->c1io_bldr, iter->kvbi_ingestid, &bldr);
        assert(!err);
        if (ev(err))
            return err;
    }

    iter->kvbi_bldrelm = bldr;

    mutex_lock(&io->c1io_space_mtx);
    q = list_first_entry_or_null(&io->c1io_qfree, typeof(*q), c1q_list);
    if (ev(!q)) {
        mutex_unlock(&io->c1io_space_mtx);

        q = calloc(1, sizeof(*q));
        if (ev(!q))
            return merr(ENOMEM);

        mutex_lock(&io->c1io_space_mtx);
        list_add(&q->c1q_list, &io->c1io_qfree);
    }

    list_del(&q->c1q_list);

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = sync;
    q->c1q_iter = iter;
    q->c1q_txnid = txnid;
    q->c1q_txn = NULL;
    q->c1q_idx = 0;

    err = c1_io_get_tree(c1, cki, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (ev(err)) {
        mutex_unlock(&io->c1io_space_mtx);

        if (bldr)
            c1_kvset_builder_elem_put(io->c1io_bldr, bldr);

        iter->kvbi_bldrelm = NULL;
        c1_io_queue_free(io, q);
        return err;
    }
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(io->c1io_err)) {
        if (bldr)
            c1_kvset_builder_elem_put(io->c1io_bldr, bldr);

        iter->kvbi_bldrelm = NULL;
        c1_io_queue_free(io, q);
        return io->c1io_err;
    }

    q->c1q_stime = perfc_lat_start(&io->c1io_pcset);
    worker = &io->c1io_slave[q->c1q_idx];

    mutex_lock(&worker->c1w_mtx);
    list_add_tail(&q->c1q_list, &worker->c1w_list);
    atomic_inc(&io->c1io_pending_reqs);
    cv_signal(&worker->c1w_cv);
    mutex_unlock(&worker->c1w_mtx);

    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);

    return 0;
}

merr_t
c1_io_txn_begin(struct c1 *c1, u64 txnid, struct c1_iterinfo *ci, int sync)
{
    struct c1_io_worker    *worker;
    struct c1_io_queue     *q;
    struct c1_ttxn         *txn;
    struct c1_io           *io;
    merr_t                  err;

    io = c1->c1_io;

    mutex_lock(&io->c1io_space_mtx);
    q = list_first_entry_or_null(&io->c1io_qfree, typeof(*q), c1q_list);
    if (ev(!q)) {
        mutex_unlock(&io->c1io_space_mtx);

        q = calloc(1, sizeof(*q));
        if (ev(!q))
            return merr(ENOMEM);

        mutex_lock(&io->c1io_space_mtx);
        list_add(&q->c1q_list, &io->c1io_qfree);
    }

    list_del(&q->c1q_list);

    txn = &q->c1q_txnbuf;
    txn->c1t_kvseqno = C1_INVALID_SEQNO;
    txn->c1t_txnid = txnid;
    txn->c1t_cmd = C1_TYPE_TXN_BEGIN;
    txn->c1t_flag = sync;

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = sync;
    q->c1q_txn = txn;
    q->c1q_iter = NULL;
    q->c1q_idx = 0;

    err = c1_io_get_tree_txn(c1, ci, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (ev(err)) {
        mutex_unlock(&io->c1io_space_mtx);

        c1_io_queue_free(io, q);
        return err;
    }

    txn->c1t_segno = q->c1q_tree->c1t_seqno;
    txn->c1t_gen = q->c1q_tree->c1t_gen;
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(io->c1io_err)) {
        c1_io_queue_free(io, q);
        return io->c1io_err;
    }

    q->c1q_stime = perfc_lat_start(&io->c1io_pcset);
    worker = &io->c1io_slave[q->c1q_idx];

    mutex_lock(&worker->c1w_mtx);
    list_add_tail(&q->c1q_list, &worker->c1w_list);
    atomic_inc(&io->c1io_pending_reqs);
    cv_signal(&worker->c1w_cv);
    mutex_unlock(&worker->c1w_mtx);

    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);
    perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_TXBEG);

    return 0;
}

merr_t
c1_io_txn_commit(struct c1 *c1, u64 txnid, u64 seqno, int sync)
{
    struct c1_kvinfo        cki = {};
    struct c1_io_worker    *worker;
    struct c1_io_queue     *q;
    struct c1_ttxn         *txn;
    struct c1_tree         *tree;
    struct c1_io           *io;
    merr_t                  err;
    u32                     size;

    err = c1_record_type2len(C1_TYPE_TXN, C1_VERSION, &size);
    if (ev(err))
        return err;
    size *= 2;

    io = c1->c1_io;

    mutex_lock(&io->c1io_space_mtx);
    q = list_first_entry_or_null(&io->c1io_qfree, typeof(*q), c1q_list);
    if (ev(!q)) {
        mutex_unlock(&io->c1io_space_mtx);

        q = calloc(1, sizeof(*q));
        if (ev(!q))
            return merr(ENOMEM);

        mutex_lock(&io->c1io_space_mtx);
        list_add(&q->c1q_list, &io->c1io_qfree);
    }

    list_del(&q->c1q_list);

    txn = &q->c1q_txnbuf;
    txn->c1t_kvseqno = seqno;
    txn->c1t_txnid = txnid;
    txn->c1t_cmd = C1_TYPE_TXN_COMMIT;
    txn->c1t_flag = sync;

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = sync;
    q->c1q_txn = txn;
    q->c1q_iter = NULL;
    q->c1q_idx = 0;

    cki.ck_kvsz = size;

    err = c1_io_get_tree(c1, &cki, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (ev(err)) {
        mutex_unlock(&io->c1io_space_mtx);

        c1_io_queue_free(io, q);
        return err;
    }
    tree = q->c1q_tree;

    txn->c1t_segno = q->c1q_tree->c1t_seqno;
    txn->c1t_gen = q->c1q_tree->c1t_gen;
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(io->c1io_err)) {
        c1_io_queue_free(io, q);
        return io->c1io_err;
    }

    q->c1q_stime = perfc_lat_start(&io->c1io_pcset);
    worker = &io->c1io_slave[q->c1q_idx];

    mutex_lock(&worker->c1w_mtx);
    list_add_tail(&q->c1q_list, &worker->c1w_list);
    atomic_inc(&io->c1io_pending_reqs);
    cv_signal(&worker->c1w_cv);
    mutex_unlock(&worker->c1w_mtx);

    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);
    perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_TXCOM);

    err = c1_issue_sync(c1, sync, true);
    if (ev(err))
        return err;

    /* Now that the current mutation set is committed, refresh the current tree's space usage */
    c1_tree_refresh_space(tree);

    return 0;
}

BullseyeCoverageSaveOff
merr_t
c1_io_txn_abort(struct c1 *c1, u64 txnid)
{
    struct c1_kvinfo        cki = {};
    struct c1_io_worker    *worker;
    struct c1_io_queue     *q;
    struct c1_ttxn         *txn;
    struct c1_io           *io;
    merr_t                  err;
    u32                     size;

    err = c1_record_type2len(C1_TYPE_TXN, C1_VERSION, &size);
    if (ev(err))
        return err;
    size *= 2;

    io = c1->c1_io;

    mutex_lock(&io->c1io_space_mtx);
    q = list_first_entry_or_null(&io->c1io_qfree, typeof(*q), c1q_list);
    if (ev(!q)) {
        mutex_unlock(&io->c1io_space_mtx);

        q = calloc(1, sizeof(*q));
        if (ev(!q))
            return merr(ENOMEM);

        mutex_lock(&io->c1io_space_mtx);
        list_add(&q->c1q_list, &io->c1io_qfree);
    }

    list_del(&q->c1q_list);

    txn = &q->c1q_txnbuf;
    txn->c1t_kvseqno = C1_INVALID_SEQNO;
    txn->c1t_txnid = txnid;
    txn->c1t_cmd = C1_TYPE_TXN_ABORT;
    txn->c1t_flag = C1_INGEST_ASYNC;

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = 0;
    q->c1q_txn = txn;
    q->c1q_iter = NULL;
    q->c1q_idx = 0;

    cki.ck_kvsz = size;

    err = c1_io_get_tree(c1, &cki, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (!err) {
        txn->c1t_segno = q->c1q_tree->c1t_seqno;
        txn->c1t_gen = q->c1q_tree->c1t_gen;
    }
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(err || io->c1io_err)) {
        c1_io_queue_free(io, q);
        return err ?: io->c1io_err;
    }

    q->c1q_stime = perfc_lat_start(&io->c1io_pcset);
    worker = &io->c1io_slave[q->c1q_idx];

    mutex_lock(&worker->c1w_mtx);
    list_add_tail(&q->c1q_list, &worker->c1w_list);
    atomic_inc(&io->c1io_pending_reqs);
    cv_signal(&worker->c1w_cv);
    mutex_unlock(&worker->c1w_mtx);

    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);
    perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_TXABT);

    return 0;
}

merr_t
c1_io_kvset_builder_get(struct c1 *c1, u64 gen, struct kvset_builder ***c1bldrout)
{
    struct c1_io *io = c1->c1_io;

    if (unlikely(!c1_vbldr(c1))) {
        *c1bldrout = NULL;
        return 0;
    }

    assert(io);
    assert(io->c1io_bldr);

    return c1_kvset_vbuilder_acquire(io->c1io_bldr, gen, c1bldrout);
}

void
c1_io_kvset_builder_put(struct c1 *c1, u64 gen)
{
    struct c1_io *io = c1->c1_io;

    if (ev(!c1_vbldr(c1)))
        return;

    assert(io);
    assert(io->c1io_bldr);

    c1_kvset_vbuilder_release(io->c1io_bldr, gen);
}

void
c1_io_kvset_builder_release(struct c1 *c1, struct c1_kvset_builder_elem *elem)
{
    struct c1_io *io = c1->c1_io;

    if (unlikely(!c1_vbldr(c1)))
        return;

    assert(io);
    assert(io->c1io_bldr);

    c1_kvset_builder_elem_put(io->c1io_bldr, elem);
}

void
c1_io_rec_perf(struct c1_io *io, struct c1_io_queue *q, u64 start, merr_t err)
{
    if (PERFC_ISON(&io->c1io_pcset) && (err == 0)) {
        perfc_rec_lat(&io->c1io_pcset, PERFC_LT_C1_IOTOT, q->c1q_stime);
        perfc_rec_lat(&io->c1io_pcset, PERFC_LT_C1_IOPRO, start);
    }
}

BullseyeCoverageRestore
