/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/kvb_builder.h>
#include <hse_util/barrier.h>
#include <hse_ikvdb/throttle.h>

#include "c1_private.h"
#include "c1_io_internal.h"
#include "c1_omf_internal.h"

struct c1_ioarg;
struct c1_ioslave;

#define C1LOG_TIME (600UL * NSEC_PER_SEC)

struct c1_io {
    struct c1_thread **      c1io_thr;
    struct perfc_set         c1io_pcset;
    struct c1_tree *         c1io_tree;
    merr_t                   c1io_err;
    atomic_t                 c1io_wakeup;
    int                      c1io_threads;
    atomic_t                 c1io_start;
    atomic_t                 c1io_stop;
    atomic_t                 c1io_stop_slave;
    u64                      c1io_dtimens;
    struct list_head         c1io_list;
    struct mutex             c1io_space_mtx;
    struct mutex             c1io_sleep_mtx;
    struct mutex             c1io_queue_mtx;
    atomic64_t               c1io_queued_reqs;
    atomic64_t               c1io_pending_reqs;
    atomic64_t               c1io_log_time;
    struct cv                c1io_cv;
    struct c1_kvset_builder *c1io_bldr;
    struct c1_ioarg *        c1io_arg;
    struct c1_ioslave *      c1io_slave;
    u32                      c1io_kvbmetasz;
    u32                      c1io_kmetasz;
    u32                      c1io_vmetasz;
};

struct c1_ioslave {
    struct list_head c1io_slave_list;
    struct mutex     c1io_slave_mtx;
    struct cv        c1io_slave_cv;
};

struct c1_ioarg {
    int           c1ioa_idx;
    struct c1_io *c1ioa_io;
};

/* c1q_txn and c1q_iter can never be set at the same time. c1q_txn is set
 * only by the c1_io_txn_* APIs.
 */
struct c1_io_queue {
    struct list_head         c1q_list;
    struct c1_tree *         c1q_tree;
    struct kvb_builder_iter *c1q_iter;
    struct c1_ttxn *         c1q_txn;
    u64                      c1q_txnid;
    u64                      c1q_mutation;
    u64                      c1q_stime;
    int                      c1q_idx;
    int                      c1q_sync;
    struct mutex             c1q_mtx;
    struct cv                c1q_cv;
};

merr_t
c1_io_create(struct c1 *c1, u64 dtime, const char *mpname, int threads)
{
    struct c1_thread **thr = NULL;
    struct c1_io *     io;
    merr_t             err;
    int                i;
    struct c1_ioarg *  arg;
    int                slavethreads = threads;
    struct c1_ioslave *slave;

    arg = malloc_array(threads, sizeof(*arg));
    if (!arg)
        return merr(ev(ENOMEM));

    io = malloc(sizeof(*io));
    if (!io) {
        free(arg);
        return merr(ev(ENOMEM));
    }

    memset(io, 0, sizeof(*io));
    io->c1io_arg = arg;

    err = c1_kvset_builder_create(c1_c0sk_get(c1), &io->c1io_bldr);
    if (ev(err)) {
        free(arg);
        free(io);
        return err;
    }

    /* Increment by 1 to include the master thread. */
    ++threads;

    thr = malloc_array(threads, sizeof(*thr));
    if (!thr) {
        free(arg);
        c1_kvset_builder_destroy(io->c1io_bldr);
        free(io);
        return merr(ev(ENOMEM));
    }

    io->c1io_slave = malloc_array(slavethreads, sizeof(*io->c1io_slave));
    if (!io->c1io_slave) {
        free(arg);
        c1_kvset_builder_destroy(io->c1io_bldr);
        free(io);
        free(thr);
        return merr(ev(ENOMEM));
    }

    memset(thr, 0, threads * sizeof(*thr));

    c1_perfc_io_alloc(&io->c1io_pcset, mpname);

    /* Setting up structure per-thread structure for slave threads
     */
    for (i = 0; i < slavethreads; i++) {
        arg[i].c1ioa_idx = i;
        arg[i].c1ioa_io = io;
    }

    io->c1io_dtimens = dtime * 1000UL * 1000;
    io->c1io_threads = threads;
    io->c1io_thr = thr;
    io->c1io_err = 0;
    io->c1io_tree = NULL;
    atomic_set(&io->c1io_start, 0);
    atomic_set(&io->c1io_stop, 0);
    atomic_set(&io->c1io_stop_slave, 0);
    atomic_set(&io->c1io_wakeup, 1);
    atomic64_set(&io->c1io_queued_reqs, 0);
    atomic64_set(&io->c1io_pending_reqs, 0);
    atomic64_set(&io->c1io_log_time, get_time_ns() + C1LOG_TIME);

    err = c1_record_type2len(C1_TYPE_KVT, C1_VERSION, &io->c1io_kmetasz);
    if (ev(err))
        goto err_exit;

    err = c1_record_type2len(C1_TYPE_VT, C1_VERSION, &io->c1io_vmetasz);
    if (ev(err))
        goto err_exit;

    err = c1_record_type2len(C1_TYPE_KVB, C1_VERSION, &io->c1io_kvbmetasz);
    if (ev(err))
        goto err_exit;

    /* [HSE_REVISIT] Successive code changes made the scope of master
     * thread to be very shallow. Consider removing it entirely in
     * a future revision.
     */
    err = c1_thread_create("c1iomaster", c1_io_thread_master, io, &thr[0]);
    if (ev(err))
        goto err_exit;

    /*  The structures are initiatized if master thread is created. The
     *  thread however is executed only after c1_thread_run below. This
     *  order helps in the cleanups.
     */
    INIT_LIST_HEAD(&io->c1io_list);
    mutex_init(&io->c1io_space_mtx);
    mutex_init(&io->c1io_sleep_mtx);
    mutex_init(&io->c1io_queue_mtx);
    cv_init(&io->c1io_cv, "c1io_master_cv");

    for (i = 1; i < threads; i++) {
        err = c1_thread_create("c1ioslave", c1_io_thread_slave, &arg[i - 1], &thr[i]);
        if (ev(err))
            goto err_exit;

        /* Initialize per-slave structure after successful
         * thread creation
         */
        slave = &io->c1io_slave[i - 1];
        INIT_LIST_HEAD(&slave->c1io_slave_list);
        mutex_init(&slave->c1io_slave_mtx);
        cv_init(&slave->c1io_slave_cv, "c1io_slave_cv");
    }

    /* Barrier for per-thread structures before spawing master
     * and slave threads.
     */
    smp_mb();

    atomic_set(&io->c1io_start, 1);

    for (i = 0; i < threads; i++)
        c1_thread_run(thr[i]);

    c1->c1_io = io;

    return 0;

err_exit:
    /* Need to stop threads if they are spawned and then kill them.
     */
    atomic_inc(&io->c1io_stop);
    c1_io_shutdown_threads(io);

    c1_perfc_io_free(&io->c1io_pcset);

    c1_kvset_builder_destroy(io->c1io_bldr);

    free(io->c1io_slave);
    free(io->c1io_arg);
    free(io);
    free(thr);

    return err;
}

void
c1_io_destroy(struct c1 *c1)
{
    struct c1_io *io = c1->c1_io;

    assert(!atomic_read(&io->c1io_stop));
    atomic_inc(&io->c1io_stop);

    /* Stop master and slave threads
     */
    c1_io_shutdown_threads(io);

    c1_kvset_builder_destroy(io->c1io_bldr);

    free(io->c1io_thr);
    free(io->c1io_slave);
    free(io->c1io_arg);

    c1_perfc_io_free(&io->c1io_pcset);
    free(io);
}

void
c1_io_thread_master(void *arg)
{
    struct c1_io *      io = arg;
    struct list_head    list;
    bool                need_lock;
    u64                 queued_reqs;
    struct c1_io_queue *q;
    struct c1_io_queue *qtmp;
    struct c1_ioslave * slave;

    assert(io);

    /* Barrier for ensuring per-thread structures are initialized
     * by the parent thread.
     */
    smp_mb();

    assert(atomic_read(&io->c1io_start) == 1);

    hse_log(HSE_DEBUG "c1 io thread starts");

    while (1) {
        INIT_LIST_HEAD(&list);

        need_lock = true;
        if (!atomic64_read(&io->c1io_queued_reqs)) {
            mutex_lock(&io->c1io_queue_mtx);

            need_lock = false;

            if (list_empty(&io->c1io_list)) {
                if (atomic_read(&io->c1io_stop)) {
                    mutex_unlock(&io->c1io_queue_mtx);
                    hse_log(HSE_DEBUG "c1 io thread stops");
                    return;
                }

                mutex_lock(&io->c1io_sleep_mtx);
                atomic_set(&io->c1io_wakeup, 1);
                mutex_unlock(&io->c1io_queue_mtx);

                cv_wait(&io->c1io_cv, &io->c1io_sleep_mtx);

                mutex_unlock(&io->c1io_sleep_mtx);
                need_lock = true;
            }
        }

        if (need_lock)
            mutex_lock(&io->c1io_queue_mtx);

        atomic_set(&io->c1io_wakeup, 0);

        if (!list_empty(&io->c1io_list)) {
            queued_reqs = atomic64_read(&io->c1io_queued_reqs);

            list_splice_tail(&io->c1io_list, &list);
            INIT_LIST_HEAD(&io->c1io_list);

            atomic64_add(queued_reqs, &io->c1io_pending_reqs);
            atomic64_sub(queued_reqs, &io->c1io_queued_reqs);
        }

        mutex_unlock(&io->c1io_queue_mtx);

        /* Take out each request and queue them to per-slave list
         */
        list_for_each_entry_safe (q, qtmp, &list, c1q_list) {
            u8 idx;

            idx = q->c1q_idx;
            assert(idx < (io->c1io_threads - 1));
            list_del_init(&q->c1q_list);

            slave = &io->c1io_slave[idx];

            mutex_lock(&slave->c1io_slave_mtx);
            list_add_tail(&q->c1q_list, &slave->c1io_slave_list);
            cv_signal(&slave->c1io_slave_cv);
            mutex_unlock(&slave->c1io_slave_mtx);
        }
    }
}

void
c1_io_thread_slave(void *arg)
{
    struct c1_ioarg *        ioarg;
    struct c1_io *           io;
    struct c1_io_queue *     q;
    struct kvb_builder_iter *iter;
    merr_t                   err = 0;
    u64                      start = 0;
    u8                       tidx = 0;
    struct c1_ioslave *      slave;

    assert(arg);
    ioarg = arg;
    io = ioarg->c1ioa_io;
    tidx = ioarg->c1ioa_idx;
    assert(tidx < (io->c1io_threads - 1));

    /* Barrier for ensuring per-thread structures are initialized
     * by the parent thread.
     */
    smp_mb();

    assert(atomic_read(&io->c1io_start) == 1);
    slave = &io->c1io_slave[tidx];

    hse_log(HSE_DEBUG "c1 io thread slave %d starts", tidx);

    while (1) {
        mutex_lock(&slave->c1io_slave_mtx);

        while (list_empty(&slave->c1io_slave_list)) {
            if (atomic_read(&io->c1io_stop_slave)) {
                mutex_unlock(&slave->c1io_slave_mtx);
                hse_log(HSE_DEBUG "c1 io thread slave %d stops", tidx);
                return;
            }

            cv_wait(&slave->c1io_slave_cv, &slave->c1io_slave_mtx);
        }

        q = list_first_entry_or_null(&slave->c1io_slave_list, struct c1_io_queue, c1q_list);
        assert(q);

        list_del(&q->c1q_list);
        err = ev(io->c1io_err);

        mutex_unlock(&slave->c1io_slave_mtx);

        assert(tidx == q->c1q_idx);

        assert(atomic64_read(&io->c1io_pending_reqs) > 0);

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

            atomic64_dec(&io->c1io_pending_reqs);

            c1_io_rec_perf(io, q, start, err);

            free(q->c1q_txn);
            free(q);

            continue;
        }

        iter = q->c1q_iter;
        if (c1_sync_or_flush_command(iter)) {

            mutex_lock(&q->c1q_mtx);
            cv_signal(&q->c1q_cv);
            mutex_unlock(&q->c1q_mtx);
            atomic64_dec(&io->c1io_pending_reqs);
            continue;
        }

        if (!err) {
            c1_io_iter_kvbtxn(io, q, tidx);
            c1_io_rec_perf(io, q, start, err);
        } else {

            c1_io_rec_perf(io, q, start, err);

            iter->put(iter);
        }

        atomic64_dec(&io->c1io_pending_reqs);
        free(q);
    }
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
    io->c1io_tree = tree;

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
    io->c1io_tree = tree;

    return 0;
}

bool
c1_io_pending_reqs(struct c1_io *io)
{
    return (atomic64_read(&io->c1io_queued_reqs) || atomic64_read(&io->c1io_pending_reqs));
}

void
c1_io_wakeup(struct c1_io *io)
{
    if (atomic_read(&io->c1io_wakeup)) {
        mutex_lock(&io->c1io_sleep_mtx);
        cv_signal(&io->c1io_cv);
        mutex_unlock(&io->c1io_sleep_mtx);
    }
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
    struct c1_io_queue q;
    struct c1_io *     io;
    merr_t             err;

    io = c1->c1_io;

    if (sync != C1_INGEST_SYNC)
        return io->c1io_err;

    if (!c1_io_pending_reqs(io)) {
        if (!skip_flush)
            goto log_flush;

        return io->c1io_err;
    }

    INIT_LIST_HEAD(&q.c1q_list);
    q.c1q_sync = sync;
    q.c1q_iter = NULL;
    q.c1q_txn = NULL;
    q.c1q_idx = 0;

    mutex_init(&q.c1q_mtx);
    cv_init(&q.c1q_cv, "c1synccv");

    mutex_lock(&io->c1io_queue_mtx);
    list_add_tail(&q.c1q_list, &io->c1io_list);
    atomic64_inc(&io->c1io_queued_reqs);
    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);

    mutex_lock(&q.c1q_mtx);
    mutex_unlock(&io->c1io_queue_mtx);

    c1_io_wakeup(io);

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
    struct c1_kvset_builder_elem *bldr;
    struct c1_io_queue *          q;
    struct c1_io *                io;
    merr_t                        err;

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
    q = malloc(sizeof(*q));
    if (!q)
        return merr(ev(ENOMEM));

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = sync;
    q->c1q_iter = iter;
    q->c1q_txnid = txnid;
    q->c1q_txn = NULL;
    q->c1q_idx = 0;

    mutex_lock(&io->c1io_space_mtx);

    err = c1_io_get_tree(c1, cki, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (ev(err)) {
        mutex_unlock(&io->c1io_space_mtx);
        free(q);

        if (bldr)
            c1_kvset_builder_elem_put(io->c1io_bldr, bldr);

        iter->kvbi_bldrelm = NULL;
        return err;
    }

    mutex_lock(&io->c1io_queue_mtx);
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(io->c1io_err)) {
        mutex_unlock(&io->c1io_queue_mtx);

        free(q);

        if (bldr)
            c1_kvset_builder_elem_put(io->c1io_bldr, bldr);

        iter->kvbi_bldrelm = NULL;
        return io->c1io_err;
    }

    q->c1q_stime = perfc_lat_start(&io->c1io_pcset);
    list_add_tail(&q->c1q_list, &io->c1io_list);
    atomic64_inc(&io->c1io_queued_reqs);
    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);
    mutex_unlock(&io->c1io_queue_mtx);

    c1_io_wakeup(io);

    return 0;
}

merr_t
c1_io_txn_begin(struct c1 *c1, u64 txnid, struct c1_iterinfo *ci, int sync)
{
    struct c1_io_queue *q;
    struct c1_io *      io;
    merr_t              err;
    struct c1_ttxn *    txn;

    txn = malloc(sizeof(*txn));
    if (!txn)
        return merr(ev(ENOMEM));

    io = c1->c1_io;
    q = malloc(sizeof(*q));
    if (!q) {
        free(txn);
        return merr(ev(ENOMEM));
    }

    txn->c1t_kvseqno = C1_INVALID_SEQNO;
    txn->c1t_txnid = txnid;
    txn->c1t_cmd = C1_TYPE_TXN_BEGIN;
    txn->c1t_flag = sync;

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = sync;
    q->c1q_txn = txn;
    q->c1q_iter = NULL;
    q->c1q_idx = 0;

    mutex_lock(&io->c1io_space_mtx);

    err = c1_io_get_tree_txn(c1, ci, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (ev(err)) {
        mutex_unlock(&io->c1io_space_mtx);
        goto err_exit;
    }

    txn->c1t_segno = q->c1q_tree->c1t_seqno;
    txn->c1t_gen = q->c1q_tree->c1t_gen;

    mutex_lock(&io->c1io_queue_mtx);
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(io->c1io_err)) {
        mutex_unlock(&io->c1io_queue_mtx);
        err = io->c1io_err;
        goto err_exit;
    }

    list_add_tail(&q->c1q_list, &io->c1io_list);
    atomic64_inc(&io->c1io_queued_reqs);
    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);
    perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_TXBEG);
    mutex_unlock(&io->c1io_queue_mtx);

    c1_io_wakeup(io);

    return 0;

err_exit:
    free(txn);
    free(q);

    return err;
}

merr_t
c1_io_txn_commit(struct c1 *c1, u64 txnid, u64 seqno, int sync)
{
    struct c1_io_queue *q;
    struct c1_io *      io;
    merr_t              err;
    u32                 size;
    struct c1_ttxn *    txn;
    struct c1_tree *    tree;
    struct c1_kvinfo    cki = {};

    err = c1_record_type2len(C1_TYPE_TXN, C1_VERSION, &size);
    if (ev(err))
        return err;
    size *= 2;

    txn = malloc(sizeof(*txn));
    if (!txn)
        return merr(ev(ENOMEM));

    io = c1->c1_io;
    q = malloc(sizeof(*q));
    if (!q) {
        free(txn);
        return merr(ev(ENOMEM));
    }

    txn->c1t_kvseqno = seqno;
    txn->c1t_txnid = txnid;
    txn->c1t_cmd = C1_TYPE_TXN_COMMIT;
    txn->c1t_flag = sync;

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = sync;
    q->c1q_txn = txn;
    q->c1q_iter = NULL;
    q->c1q_idx = 0;

    mutex_lock(&io->c1io_space_mtx);
    cki.ck_kvsz = size;

    err = c1_io_get_tree(c1, &cki, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (ev(err)) {
        mutex_unlock(&io->c1io_space_mtx);
        free(txn);
        free(q);
        return err;
    }
    tree = q->c1q_tree;

    txn->c1t_segno = q->c1q_tree->c1t_seqno;
    txn->c1t_gen = q->c1q_tree->c1t_gen;

    mutex_lock(&io->c1io_queue_mtx);
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(io->c1io_err)) {
        mutex_unlock(&io->c1io_queue_mtx);

        free(txn);
        free(q);
        return io->c1io_err;
    }

    q->c1q_stime = perfc_lat_start(&io->c1io_pcset);
    list_add_tail(&q->c1q_list, &io->c1io_list);
    atomic64_inc(&io->c1io_queued_reqs);
    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);
    perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_TXCOM);
    mutex_unlock(&io->c1io_queue_mtx);

    c1_io_wakeup(io);

    err = c1_issue_sync(c1, sync, true);
    if (ev(err))
        return err;

    /* Now that the current mutation set is committed, refresh the current tree's space usage */
    c1_tree_refresh_space(tree);

    return 0;
}

void
c1_io_shutdown_threads(struct c1_io *io)
{
    struct c1_ioslave *slave;
    int                i;

    /* If there is no master thread, there will be no slaves either.
     */
    if (!io->c1io_thr || !io->c1io_thr[0])
        return;

    assert(io->c1io_slave);

    /* Stop master thread
     */
    mutex_lock(&io->c1io_sleep_mtx);
    cv_broadcast(&io->c1io_cv);
    mutex_unlock(&io->c1io_sleep_mtx);
    c1_thread_destroy(io->c1io_thr[0]);

    /* Master thread is stopped. It must have transferred the last
     * request (if any) to slaves' queue. This will avoid a case
     * where the slaves are stopped with master having pending
     * requests in its queue.
     */
    atomic_inc(&io->c1io_stop_slave);

    /* Stop slave threads
     */
    for (i = 1; i < io->c1io_threads; i++) {
        if (io->c1io_thr[i]) {
            slave = &io->c1io_slave[i - 1];
            mutex_lock(&slave->c1io_slave_mtx);
            cv_signal(&slave->c1io_slave_cv);
            mutex_unlock(&slave->c1io_slave_mtx);
        }
    }

    for (i = 1; i < io->c1io_threads; i++) {
        if (io->c1io_thr[i]) {
            slave = &io->c1io_slave[i - 1];
            c1_thread_destroy(io->c1io_thr[i]);
            mutex_destroy(&slave->c1io_slave_mtx);
            cv_destroy(&slave->c1io_slave_cv);
        }
    }

    mutex_destroy(&io->c1io_space_mtx);
    mutex_destroy(&io->c1io_sleep_mtx);
    mutex_destroy(&io->c1io_queue_mtx);
    cv_destroy(&io->c1io_cv);
}

BullseyeCoverageSaveOff
merr_t
c1_io_txn_abort(struct c1 *c1, u64 txnid)
{
    struct c1_io_queue *q;
    struct c1_io *      io;
    merr_t              err;
    u32                 size;
    struct c1_ttxn *    txn;
    struct c1_kvinfo    cki = {};

    err = c1_record_type2len(C1_TYPE_TXN, C1_VERSION, &size);
    if (ev(err))
        return err;
    size *= 2;

    txn = malloc(sizeof(*txn));
    if (!txn)
        return merr(ev(ENOMEM));

    io = c1->c1_io;
    q = malloc(sizeof(*q));
    if (!q) {
        free(txn);
        return merr(ev(ENOMEM));
    }

    txn->c1t_kvseqno = C1_INVALID_SEQNO;
    txn->c1t_txnid = txnid;
    txn->c1t_cmd = C1_TYPE_TXN_ABORT;
    txn->c1t_flag = C1_INGEST_ASYNC;

    INIT_LIST_HEAD(&q->c1q_list);
    q->c1q_sync = 0;
    q->c1q_txn = txn;
    q->c1q_iter = NULL;
    q->c1q_idx = 0;

    mutex_lock(&io->c1io_space_mtx);
    cki.ck_kvsz = size;

    err = c1_io_get_tree(c1, &cki, &q->c1q_tree, &q->c1q_idx, &q->c1q_mutation);
    if (ev(err)) {
        mutex_unlock(&io->c1io_space_mtx);

        free(txn);
        free(q);
        return err;
    }

    txn->c1t_segno = q->c1q_tree->c1t_seqno;
    txn->c1t_gen = q->c1q_tree->c1t_gen;

    mutex_lock(&io->c1io_queue_mtx);
    mutex_unlock(&io->c1io_space_mtx);

    if (ev(io->c1io_err)) {
        mutex_unlock(&io->c1io_queue_mtx);

        free(txn);
        free(q);
        return io->c1io_err;
    }

    q->c1q_stime = perfc_lat_start(&io->c1io_pcset);
    list_add_tail(&q->c1q_list, &io->c1io_list);
    atomic64_inc(&io->c1io_queued_reqs);
    perfc_inc(&io->c1io_pcset, PERFC_RA_C1_IOQUE);
    perfc_inc(&c1->c1_pcset_op, PERFC_RA_C1_TXABT);
    mutex_unlock(&io->c1io_queue_mtx);

    c1_io_wakeup(io);

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
