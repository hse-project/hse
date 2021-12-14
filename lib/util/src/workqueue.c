/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/assert.h>
#include <hse_util/mutex.h>
#include <hse_util/condvar.h>
#include <hse_util/minmax.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/hse_gparams.h>

#include <signal.h>
#include <pthread.h>

/**
 * struct wq_priv - worker thread private data
 * @wqp_barid:  ID of most recently processed barrier
 * @wqp_wq:     workqueue ptr
 * @wqp_tid:    pthread thread ID
 */
struct wq_priv {
    uint      wqp_barid;
    void     *wqp_wq;
    pthread_t wqp_tid;
};

/**
 * struct wq_barrier - Barrier work item for flush_workqueue()
 */
struct wq_barrier {
    struct work_struct wqb_work;
    uint               wqb_visitors;
    uint               wqb_barid;
};

/**
 * struct workqueue_struct - per-workqueue private data
 * @wq_lock:        lock to protect workqueue data
 * @wq_pending:     list of work to be dispatched ASAP
 * @wq_running:     workqueue is able to dispatch requests
 * @wq_growing:     workqueue is spawning worker threads
 * @wq_refcnt:      references held by long-lived threads and delayed work
 * @wq_tdcnt:       current number of worker threads
 * @wq_tdmax:       maximum number of worker threads
 * @wq_tdmin:       minimum number of worker threads
 * @wq_barid:       barrier ID generator
 * @wq_tcdelay:     delay in milliseconds between thread-create operations
 * @wq_barrier:     condvar where all threads wait for barrier completion
 * @wq_idle:        condvar where idle worker threads wait
 * @wq_delayed:     list of work to be dispatched in the future
 * @wq_grow:        timer for grow callback
 * @wq_name:        workqueue name (see pthread_setname_np())
 * @wq_priv:        flexible array of worker thread private data structs
 */
struct workqueue_struct {
    struct mutex      wq_lock;
    struct list_head  wq_pending;
    bool              wq_running;
    bool              wq_growing;
    int               wq_refcnt;
    int               wq_tdcnt;
    int               wq_tdmax;
    int               wq_tdmin;
    uint              wq_barid;
    uint              wq_tcdelay;
    struct cv         wq_barrier;
    struct cv         wq_idle;
    struct list_head  wq_delayed;
    struct timer_list wq_grow;
    char              wq_name[16];
    struct wq_priv    wq_priv[];
};

static void
dump_workqueue_locked(struct workqueue_struct *wq);

static void *
worker_thread(void *arg);

static HSE_ALWAYS_INLINE struct work_struct *
workqueue_first(struct workqueue_struct *wq)
{
    return list_first_entry_or_null(&wq->wq_pending, struct work_struct, entry);
}

static void
grow_workqueue_cb(ulong arg)
{
    struct workqueue_struct *wq = (void *)arg;
    struct wq_priv *priv = NULL;
    int rc, i;

    mutex_lock(&wq->wq_lock);
    for (i = 0; i < wq->wq_tdmax; ++i) {
        priv = wq->wq_priv + (wq->wq_tdcnt + i) % wq->wq_tdmax;
        if (!priv->wqp_wq)
            break;
    }

    assert(priv && i < wq->wq_tdmax);

    priv->wqp_wq = wq;
    ++wq->wq_refcnt;
    ++wq->wq_tdcnt;
    mutex_unlock(&wq->wq_lock);

    rc = pthread_create(&priv->wqp_tid, NULL, worker_thread, priv);
    if (rc) {
        merr_t err = merr(rc);

        log_warnx("growing failed (%s %d/%d%d): @@e",
                  err, wq->wq_name, wq->wq_tdcnt, wq->wq_tdmin, wq->wq_tdmax);
    }

    mutex_lock(&wq->wq_lock);
    if (rc) {
        struct work_struct *first = workqueue_first(wq);

        /* If there is a flush in progress then we must awaken all
         * visitors so that each can re-evaluate the barrier state.
         */
        if (first && !first->func)
            cv_broadcast(&wq->wq_barrier);

        priv->wqp_wq = NULL;
        --wq->wq_refcnt;
        --wq->wq_tdcnt;
    }

    /* Keep growing if there's pending work and room to grow (might create
     * more threads than are strictly needed depending upon scheduling).
     */
    wq->wq_growing = workqueue_first(wq) && (wq->wq_tdcnt < wq->wq_tdmax);
    if (wq->wq_growing) {
        wq->wq_grow.expires = jiffies + wq->wq_tcdelay;
        add_timer(&wq->wq_grow);
        ++wq->wq_refcnt;
    }

    /* Release the reference acquired by queue_work().
     */
    --wq->wq_refcnt;
    mutex_unlock(&wq->wq_lock);
}


struct workqueue_struct *
alloc_workqueue(const char *fmt, unsigned int flags, int min_active, int max_active, ...)
{
    struct workqueue_struct *wq;

    va_list args;
    size_t  wqsz;
    int     i;

    max_active = max_active ?: WQ_DFL_ACTIVE;
    max_active = clamp_t(int, max_active, 1, WQ_MAX_ACTIVE);
    min_active = clamp_t(int, min_active, 0, max_active);

    wqsz = sizeof(*wq) + max_active * sizeof(wq->wq_priv[0]);

    wq = aligned_alloc(HSE_ACP_LINESIZE, roundup(wqsz, HSE_ACP_LINESIZE));
    if (ev(!wq))
        return NULL;

    memset(wq, 0, wqsz);
    va_start(args, max_active);
    vsnprintf(wq->wq_name, sizeof(wq->wq_name), fmt ? fmt : "workqueue", args);
    va_end(args);

    mutex_init_adaptive(&wq->wq_lock);
    cv_init(&wq->wq_idle, "wq_idle");
    cv_init(&wq->wq_barrier, "wq_barrier");

    INIT_LIST_HEAD(&wq->wq_pending);
    INIT_LIST_HEAD(&wq->wq_delayed);

    setup_timer(&wq->wq_grow, grow_workqueue_cb, wq);
    wq->wq_tcdelay = msecs_to_jiffies(1000);

    /* refcnt, tdmin, and tdmax are carefully managed to ensure
     * grow_workqueue_cb() doesn't call add_timer() and to prevent
     * threads entering worker_thread() from exiting until after
     * we have spawned the minimum number of worker threads.
     */
    wq->wq_refcnt = min_active;
    wq->wq_tdmin = max_active;
    wq->wq_running = true;

    for (i = 0; i < min_active; ++i) {
        wq->wq_growing = true;
        wq->wq_tdmax = i + 1;
        grow_workqueue_cb((ulong)wq);
    }

    mutex_lock(&wq->wq_lock);
    assert(!wq->wq_growing);

    if (wq->wq_tdcnt < min_active) {
        mutex_unlock(&wq->wq_lock);
        destroy_workqueue(wq);
        return NULL;
    }

    wq->wq_tdmin = min_active;
    wq->wq_tdmax = max_active;
    mutex_unlock(&wq->wq_lock);

    return wq;
}

void
destroy_workqueue(struct workqueue_struct *wq)
{
    int rc;

    if (ev(!wq))
        return;

    mutex_lock(&wq->wq_lock);
    cv_broadcast(&wq->wq_idle);
    wq->wq_running = false;
    wq->wq_tcdelay = 10;

    /* Wait for all pending and delayed work to complete and all worker
     * threads to exit.  Caller should cancel all delayed work before
     * calling this function to avoid interminable hangs...
     */
    while (wq->wq_refcnt > 0) {
        rc = cv_timedwait(&wq->wq_idle, &wq->wq_lock, 10000);
        if (rc)
            dump_workqueue_locked(wq);
    }

    assert(list_empty(&wq->wq_pending));
    assert(list_empty(&wq->wq_delayed));
    assert(wq->wq_tdcnt == 0);
    assert(!wq->wq_growing);
    mutex_unlock(&wq->wq_lock);

    cv_destroy(&wq->wq_barrier);
    cv_destroy(&wq->wq_idle);
    mutex_destroy(&wq->wq_lock);

    free(wq);
}

static HSE_ALWAYS_INLINE bool
work_pending(const struct work_struct *work)
{
    return !list_empty(&work->entry);
}

static bool
queue_work_locked(struct workqueue_struct *wq, struct work_struct *work)
{
    bool enqueued;

    enqueued = !work_pending(work);
    if (enqueued) {
        list_add_tail(&work->entry, &wq->wq_pending);

        /* Try to spawn a new worker thread if there was work pending
         * when we arrived or we have no worker threads.
         */
        if ((workqueue_first(wq) != work && wq->wq_tdcnt < wq->wq_tdmax) || wq->wq_tdcnt < 1) {
            if (!wq->wq_growing) {
                wq->wq_grow.expires = jiffies + 1;
                add_timer(&wq->wq_grow);
                wq->wq_growing = true;
                wq->wq_refcnt++;
            }
        }

    }

    return enqueued;
}

/**
 * flush_workqueue() - enqueue a barrier and wait for it to complete
 * @wq:     ptr to workqueue
 *
 * Append a barrier work item to the pending list to prevent work
 * appended after the barrier from being dispatched until all work
 * ahead of the barrier has completed.
 */
void
flush_workqueue(struct workqueue_struct *wq)
{
    struct wq_barrier barrier;
    bool              enqueued;

    if (ev(!wq))
        return;

    INIT_WORK(&barrier.wqb_work, NULL);

    mutex_lock(&wq->wq_lock);
    ++wq->wq_refcnt;

    enqueued = queue_work_locked(wq, &barrier.wqb_work);
    if (enqueued) {
        barrier.wqb_barid = ++wq->wq_barid;
        barrier.wqb_visitors = 0;

        cv_broadcast(&wq->wq_idle);

        /* Wait for all workers to visit the barrier.
         */
        while (barrier.wqb_visitors < UINT_MAX)
            cv_wait(&wq->wq_barrier, &wq->wq_lock);
    }

    --wq->wq_refcnt;
    mutex_unlock(&wq->wq_lock);
}

/**
 * worker_thread() - thread pool worker main function
 * @arg:   ptr to thread private structure
 *
 * This is the workqueue pending list processing loop.  All worker threads
 * stay in this function repeatedly dispatching work until the workqueue
 * is shut down.  At shutdown time, no threads are allowed to exit until
 * the pending list is empty.
 *
 * Note that this is the only function in which work items are removed
 * from the pending list.
 */
static void *
worker_thread(void *arg)
{
    struct wq_priv *         priv = arg;
    struct workqueue_struct *wq = priv->wqp_wq;
    sigset_t                 sigset;

    sigfillset(&sigset);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    pthread_setname_np(pthread_self(), wq->wq_name);
    pthread_detach(pthread_self());

    mutex_lock(&wq->wq_lock);

    while (1) {
        struct wq_barrier *barrier;
        struct work_struct *work;

        work = workqueue_first(wq);
        if (!work) {
            bool extra = wq->wq_tdcnt > wq->wq_tdmin;
            static thread_local int timedout = 0;

            if (!wq->wq_running || (timedout && extra))
                break;

            /* Sleep a short time if there are extra workers.  If we time out
             * and still have extra workers after draining the pending queue
             * then exit (above).  Otherwise, sleep here until signaled.
             */
            timedout = cv_timedwait(&wq->wq_idle, &wq->wq_lock, extra ? 10000 : -1);
            continue;
        }

        if (work->func) {
            list_del_init(&work->entry);
            mutex_unlock(&wq->wq_lock);

            work->func(work);

            mutex_lock(&wq->wq_lock);
            continue;
        }

        barrier = container_of(work, struct wq_barrier, wqb_work);

        /* Increment the barrier visitor count once for each
         * thread's first visit to the barrier.
         */
        if (priv->wqp_barid != barrier->wqb_barid) {
            priv->wqp_barid = barrier->wqb_barid;
            ++barrier->wqb_visitors;
        }

        /* Wait until all worker threads have visited this barrier.
         */
        if (barrier->wqb_visitors < wq->wq_tdcnt) {
            cv_wait(&wq->wq_barrier, &wq->wq_lock);
            continue;
        }

        /* All threads have visited this barrier, so remove
         * it and proceed with the next pending work item.
         */
        barrier->wqb_visitors = UINT_MAX;
        list_del_init(&work->entry);
        cv_broadcast(&wq->wq_barrier);
    }

    --wq->wq_refcnt;
    --wq->wq_tdcnt;
    priv->wqp_wq = NULL;
    cv_signal(&wq->wq_idle);
    mutex_unlock(&wq->wq_lock);

    return NULL;
}

/*
 * Add work to a workqueue.  Return false if work was already on a
 * queue, true otherwise.
 */
bool
queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
    bool enqueued;

    assert(work->func);

    mutex_lock(&wq->wq_lock);
    enqueued = queue_work_locked(wq, work);
    if (enqueued)
        cv_signal(&wq->wq_idle);
    mutex_unlock(&wq->wq_lock);

    return enqueued;
}

/* delayed_work_timer_fn() - delayed work timer callback
 * @data:   ptr to the delayed work given via queue_delayed_work()
 *
 * This callback is run for each delayed work item whose delay
 * has expired.
 */
void
delayed_work_timer_fn(unsigned long data)
{
    struct workqueue_struct *wq;
    struct delayed_work *    dwork;
    bool                     enqueued;
    bool                     pending;

    dwork = (struct delayed_work *)data;
    wq = dwork->wq;

    mutex_lock(&wq->wq_lock);
    pending = work_pending(&dwork->work);
    if (pending) {
        list_del_init(&dwork->work.entry);

        enqueued = queue_work_locked(dwork->wq, &dwork->work);
        if (enqueued)
            cv_signal(&wq->wq_idle);

        assert(enqueued);
        --wq->wq_refcnt;
    }

    assert(pending);
    mutex_unlock(&wq->wq_lock);
}

bool
queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *dwork, unsigned long delay)
{
    bool pending;
    u64  expires;

    assert(dwork->timer.function == delayed_work_timer_fn);
    assert(dwork->timer.data == (ulong)dwork);
    assert(dwork->work.func);

    expires = nsecs_to_jiffies(get_time_ns()) + delay;

    mutex_lock(&wq->wq_lock);
    pending = work_pending(&dwork->work);
    if (!pending) {
        list_add_tail(&dwork->work.entry, &wq->wq_delayed);
        dwork->timer.expires = expires;
        dwork->wq = wq;
        ++wq->wq_refcnt;
    }
    mutex_unlock(&wq->wq_lock);

    /* For simplicity, we deviate from the Linux implementation here
     * in that we always schedule a timer, even if delay is zero.
     */
    if (!pending)
        add_timer(&dwork->timer);

    return !pending;
}

bool
cancel_delayed_work(struct delayed_work *dwork)
{
    struct workqueue_struct *wq = dwork->wq;
    bool                     pending;

    mutex_lock(&wq->wq_lock);
    pending = work_pending(&dwork->work);
    if (pending) {
        pending = del_timer(&dwork->timer);
        if (pending) {
            list_del_init(&dwork->work.entry);
            --wq->wq_refcnt;
        }
    }
    mutex_unlock(&wq->wq_lock);

    return pending;
}

/**
 * dump_workqueue_locked() - dump all workqueue thread state and work items
 * @wq:     ptr to workqueue
 *
 * You can call this from gdb if the system gets wedged.  Find a stack
 * frame with a valid workqueue ptr and run:
 *
 *   (gdb) call dump_workqueue_locked(wq)
 */
static void
dump_workqueue_locked(struct workqueue_struct *wq)
{
    struct delayed_work *d;
    struct work_struct *w;
    int i, n;

    log_warn("%s %p: pid %d, refcnt %d, tdcnt %d, tdmin %d, tdmax %d, growing %d",
             wq->wq_name, wq, getpid(), wq->wq_refcnt,
             wq->wq_tdcnt, wq->wq_tdmin, wq->wq_tdmax,
             wq->wq_growing);

    for (i = 0; i < wq->wq_tdmax; ++i) {
        struct wq_priv *priv = wq->wq_priv + i;

        if (!priv->wqp_wq)
            continue;

        log_warn("%s %p: %3u, barid %u, tid %lx",
                 wq->wq_name, wq, i, priv->wqp_barid, priv->wqp_tid);
    }

    i = 0;
    list_for_each_entry(w, &wq->wq_pending, entry) {
        struct wq_barrier *b;
        char buf[128];

        n = snprintf(buf, sizeof(buf), "  work %3d %p", i++, w);

        if (!w->func) {
            b = container_of(w, struct wq_barrier, wqb_work);

            snprintf(buf + n, sizeof(buf) - n,
                     ", barid %4u, visitors %4d",
                     b->wqb_barid,
                     b->wqb_visitors);
        }

        log_warn("%s %p: %s", wq->wq_name, wq, buf);
    }

    i = 0;
    list_for_each_entry(d, &wq->wq_delayed, work.entry) {
        log_warn("%s %p: dwork %3d %p, expires in %lu jiffies",
                 wq->wq_name, wq, i++, d, (ulong)d->timer.expires - jiffies);
    }
}

void
dump_workqueue(struct workqueue_struct *wq)
{
    if (!wq)
        return;

    mutex_lock(&wq->wq_lock);
    dump_workqueue_locked(wq);
    mutex_unlock(&wq->wq_lock);
}
