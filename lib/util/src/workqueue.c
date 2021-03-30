/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/assert.h>
#include <hse_util/mutex.h>
#include <hse_util/condvar.h>
#include <hse_util/minmax.h>
#include <hse_util/page.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>

#include <signal.h>
#include <pthread.h>

/**
 * struct wq_priv - worker thread private data
 * @wqp_barid:  ID of most recently processed barrier
 * @wqp_id:     logical thread ID
 * @wqp_tid:    pthread thread ID
 */
struct wq_priv {
    uint      wqp_barid;
    uint      wqp_id;
    pthread_t wqp_tid;
};

/**
 * struct workqueue_struct - per-workqueue private data
 * @wq_lock:        lock to protect workqueue data
 * @wq_pending:     list of work to be dispatched ASAP
 * @wq_shutdown:    workqueue is shutting down if true
 * @wq_tdcnt:       current number of worker threads
 * @wq_idle:        condvar where idle worker threads wait
 * @wq_barrier:     condvar where all threads wait for barrier completion
 * @wq_refcnt:      number of threads with long term references on workqueue
 * @wq_barid:       barrier ID generator
 * @wq_tdmax:       max number of worker threads
 * @wq_delayed:     list of work to be dispatched in the future
 * @wq_name:        workqueue name (see pthread_setname_np())
 * @wq_base:        base of workqueue memory allocation for free()
 * @wq_priv:        flexible array of worker thread private data structs
 */
struct workqueue_struct {
    struct mutex     wq_lock;
    struct list_head wq_pending;
    bool             wq_shutdown;
    int              wq_tdcnt;
    struct cv        wq_idle;
    struct cv        wq_barrier;
    int              wq_refcnt;
    uint             wq_barid;
    int              wq_tdmax;
    struct list_head wq_delayed;
    char             wq_name[16];
    void *           wq_base;
    struct wq_priv   wq_priv[];
};

static void
workqueue_dump(struct workqueue_struct *wq);
static void
flush_barrier(struct work_struct *work);
static void *
worker_thread(void *arg);

struct workqueue_struct *
alloc_workqueue(const char *fmt, unsigned int flags, int max_active, ...)
{
    struct workqueue_struct *wq;

    void *  base;
    va_list args;
    size_t  wqsz;
    int     i, rc;

    max_active = max_active ?: WQ_DFL_ACTIVE;
    max_active = max_t(int, max_active, 1);
    max_active = min_t(int, max_active, WQ_MAX_ACTIVE);

    wqsz = sizeof(*wq) + max_active * sizeof(wq->wq_priv[0]);

    base = calloc(1, wqsz + 64);
    if (ev(!base))
        return NULL;

    wq = PTR_ALIGN(base, 64);
    wq->wq_base = base;

    va_start(args, max_active);
    vsnprintf(wq->wq_name, sizeof(wq->wq_name), fmt ? fmt : "workqueue", args);
    va_end(args);

    mutex_init_adaptive(&wq->wq_lock);
    cv_init(&wq->wq_idle, "wq_idle");
    cv_init(&wq->wq_barrier, "wq_barrier");

    INIT_LIST_HEAD(&wq->wq_pending);
    INIT_LIST_HEAD(&wq->wq_delayed);

    wq->wq_tdmax = max_active;
    wq->wq_tdcnt = max_active;
    wq->wq_refcnt = max_active;

    for (i = 0; i < wq->wq_tdmax; i++) {
        struct wq_priv *priv = wq->wq_priv + i;

        priv->wqp_id = i;

        rc = pthread_create(&priv->wqp_tid, NULL, worker_thread, priv);
        if (ev(rc)) {
            wq->wq_tdcnt = i;
            wq->wq_refcnt = i;
            destroy_workqueue(wq);
            return NULL;
        }

        pthread_detach(priv->wqp_tid);
    }

    return wq;
}

void
destroy_workqueue(struct workqueue_struct *wq)
{
    if (ev(!wq))
        return;

    mutex_lock(&wq->wq_lock);
    if (!list_empty(&wq->wq_delayed)) {
        hse_log(HSE_ERR "%s: delayed work pending:", __func__);
        workqueue_dump(wq);
        mutex_unlock(&wq->wq_lock);
        return;
    }

    /* Signal shutdown to worker threads, then wait for all threads
     * who have a reference on the workqueue to each drop their ref.
     */
    wq->wq_shutdown = 1;
    cv_broadcast(&wq->wq_idle);

    while (wq->wq_refcnt > 0)
        cv_timedwait(&wq->wq_idle, &wq->wq_lock, 1);

    assert(list_empty(&wq->wq_pending));
    assert(list_empty(&wq->wq_delayed));
    assert(wq->wq_tdcnt == 0);
    mutex_unlock(&wq->wq_lock);

    cv_destroy(&wq->wq_barrier);
    cv_destroy(&wq->wq_idle);
    mutex_destroy(&wq->wq_lock);

    free(wq->wq_base);
}

static HSE_ALWAYS_INLINE bool
work_pending(const struct work_struct *work)
{
    return !list_empty(&work->entry);
}

static HSE_ALWAYS_INLINE struct work_struct *
workqueue_first(struct workqueue_struct *wq)
{
    return list_first_entry_or_null(&wq->wq_pending, struct work_struct, entry);
}

#pragma push_macro("queue_work_locked")
#undef queue_work_locked

MTF_STATIC
bool
queue_work_locked(struct workqueue_struct *wq, struct work_struct *work)
{
    bool enqueued;

    assert(wq->wq_tdcnt > 0);

    enqueued = !work_pending(work);
    if (enqueued)
        list_add_tail(&work->entry, &wq->wq_pending);

    return enqueued;
}

#pragma pop_macro("queue_work_locked")

/**
 * flush_barrier() - sentinel function used to discern barrier work items
 * @work:   not used
 *
 * This function is never called.  It is only used to provide a unique
 * address to differentiate barrier from non-barrier work items.
 */
static void
flush_barrier(struct work_struct *work)
{
    abort();
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

    INIT_WORK(&barrier.wqb_work, flush_barrier);

    mutex_lock(&wq->wq_lock);
    ++wq->wq_refcnt;

    enqueued = queue_work_locked(wq, &barrier.wqb_work);
    if (enqueued) {
        barrier.wqb_barid = ++wq->wq_barid;
        barrier.wqb_visitors = 0;

        /* Awaken just one idle worker, the first visitor
         * will awaken all remaining idle workers.
         */
        cv_signal(&wq->wq_idle);

        while (barrier.wqb_visitors < wq->wq_tdcnt)
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
    struct workqueue_struct *wq;
    struct work_struct *     work;
    struct wq_barrier *      barrier;
    sigset_t                 set;

    /* background threads should not be handling signals */
    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    wq = container_of(priv, struct workqueue_struct, wq_priv[priv->wqp_id]);

    pthread_setname_np(priv->wqp_tid, wq->wq_name);

    mutex_lock(&wq->wq_lock);

    while (1) {
        work = workqueue_first(wq);
        if (!work) {
            if (wq->wq_shutdown)
                break;

            cv_wait(&wq->wq_idle, &wq->wq_lock);
            continue;
        }

        if (work->func != flush_barrier) {
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
            if (barrier->wqb_visitors++ == 0)
                cv_broadcast(&wq->wq_idle);
        }

        /* Wait until all worker threads have visited this barrier.
         */
        if (barrier->wqb_visitors < wq->wq_tdcnt) {
            cv_wait(&wq->wq_barrier, &wq->wq_lock);
            continue;
        }

        /* All threads have visited this barrier, so remove it
         * and continue with next pending work item.
         */
        list_del_init(&work->entry);
        cv_broadcast(&wq->wq_barrier);
    }

    --wq->wq_tdcnt;
    --wq->wq_refcnt;
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
    }

    assert(pending);
    mutex_unlock(&wq->wq_lock);
}

bool
queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *dwork, unsigned long delay)
{
    bool pending;
    u64  expires;

    /* Linux uses WARN_ON_ONCE() for these checks rather than assert().
     */
    assert(dwork->timer.function == delayed_work_timer_fn);
    assert(dwork->timer.data == (ulong)dwork);

    expires = nsecs_to_jiffies(get_time_ns()) + delay;

    mutex_lock(&wq->wq_lock);
    pending = work_pending(&dwork->work);
    if (!pending) {
        list_add_tail(&dwork->work.entry, &wq->wq_delayed);
        dwork->timer.expires = expires;
        dwork->wq = wq;
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
        if (pending)
            list_del_init(&dwork->work.entry);
    }
    mutex_unlock(&wq->wq_lock);

    return pending;
}

/**
 * workqueue_dump() - dump all workqueue thread state and work items
 * @wq:     ptr to workqueue
 *
 * You can call this from gdb if the system gets wedged.  Find a stack
 * frame with a valid workqueue ptr and run:
 *
 *   (gdb) call workqueue_dump(wq)
 */
static void
workqueue_dump(struct workqueue_struct *wq)
{
    struct delayed_work *d;
    struct work_struct * w;
    struct wq_barrier *  b;
    char                 buf[128];
    int                  i, n;

    hse_log(
        HSE_ERR "%s(%p) name %s, refcnt %d, tdcnt %u, tdmax %u",
        __func__,
        wq,
        wq->wq_name,
        wq->wq_refcnt,
        wq->wq_tdcnt,
        wq->wq_tdmax);

    for (i = 0; i < wq->wq_tdmax; ++i) {
        struct wq_priv *priv = wq->wq_priv + i;

        snprintf(
            buf,
            sizeof(buf),
            "thread %3u, tid %8lx, barid %u",
            priv->wqp_id,
            priv->wqp_tid,
            priv->wqp_barid);

        hse_log(HSE_ERR "%s(%p) %s", __func__, wq, buf);
    }

    i = 0;
    list_for_each_entry (w, &wq->wq_pending, entry) {
        n = snprintf(buf, sizeof(buf), "  work %3d %p", i++, w);

        if (w->func == flush_barrier) {
            b = container_of(w, struct wq_barrier, wqb_work);

            snprintf(
                buf + n,
                sizeof(buf) - n,
                ", barid %4u, visitors %4d",
                b->wqb_barid,
                b->wqb_visitors);
        }

        hse_log(HSE_ERR "%s(%p) %s", __func__, wq, buf);
    }

    i = 0;
    list_for_each_entry (d, &wq->wq_delayed, work.entry) {
        n = snprintf(
            buf, sizeof(buf), " dwork %3d %p, expires %lu", i++, d, (ulong)d->timer.expires);

        hse_log(HSE_ERR "%s(%p) %s", __func__, wq, buf);
    }
}

#if HSE_MOCKING
#include "workqueue_ut_impl.i"
#endif /* HSE_MOCKING */
