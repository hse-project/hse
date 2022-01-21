/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/assert.h>
#include <hse_util/mutex.h>
#include <hse_util/condvar.h>
#include <hse_util/minmax.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>
#include <hse_util/logging.h>
#include <hse_util/rest_api.h>
#include <hse_util/list.h>
#include <hse_util/atomic.h>

#include <hse_ikvdb/hse_gparams.h>

#include <signal.h>
#include <pthread.h>
#include <syscall.h>

#define WP_LATV_IDX(_wqp) ((_wqp)->wp_calls % NELEM((_wqp)->wp_latv))

/**
 * struct wq_priv - worker thread private data
 * @wp_wq:     Workqueue
 * @wp_tid:    Thread ID of owner thread
 * @wp_barid:  ID of most recently processed barrier
 * @wp_tstart: Thread start time (nsecs)
 * @wp_cstart: Start time of most recent callback (cycles)
 * @wp_calls:  Total number of callbacks dispatched
 * @wp_wmesgp: Address of thread-local wait message ptr
 * @wp_latv:   Vector of most recent callback latencies
 */
struct wq_priv {
    struct list_head  wp_link HSE_ACP_ALIGNED;
    void             *wp_wq;
    pid_t             wp_tid;
    uint              wp_barid;
    ulong             wp_tstart;
    ulong             wp_cstart;
    ulong             wp_calls;
    volatile const char **wp_wmesgp;
    ulong             wp_latv[8] HSE_L1X_ALIGNED;
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
 * @wq_dlycnt:      current number of delayed work requests
 * @wq_tdcnt:       current number of worker threads
 * @wq_tdmax:       maximum number of worker threads
 * @wq_tdmin:       minimum number of worker threads
 * @wq_barid:       barrier ID generator
 * @wq_tcdelay:     delay in milliseconds between thread-create operations
 * @wq_idle:        condvar where idle worker threads wait
 * @wq_barrier:     condvar where all threads wait for barrier completion
 * @wq_delayed:     list of work to be dispatched in the future
 * @wq_grow:        timer for grow callback
 * @wq_name:        workqueue name
 */
struct workqueue_struct {
    struct mutex      wq_lock HSE_ACP_ALIGNED;
    struct list_head  wq_pending;
    bool              wq_running;
    bool              wq_growing;
    int               wq_refcnt;
    int               wq_dlycnt;
    int               wq_tdcnt;
    int               wq_tdmax;
    int               wq_tdmin;
    uint              wq_barid;
    uint              wq_tcdelay;
    struct cv         wq_idle;
    struct cv         wq_barrier;
    struct list_head  wq_delayed;
    struct timer_list wq_grow;
    char              wq_name[16];
};

struct workqueue_globals {
    struct mutex     wg_lock HSE_ACP_ALIGNED;
    struct list_head wg_list;
    atomic_int       wg_refcnt;
};

static struct workqueue_globals wg;
static thread_local struct wq_priv wq_priv_tls;

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
    pthread_t tid;
    int rc;

    rc = pthread_create(&tid, NULL, worker_thread, wq);

    mutex_lock(&wq->wq_lock);
    if (rc) {
        struct work_struct *first = workqueue_first(wq);

        /* If there is a flush in progress then we must awaken all
         * visitors so that each can re-evaluate the barrier state.
         */
        if (first && !first->func)
            cv_broadcast(&wq->wq_barrier);

        /* Drop references acquired by queue_work_locked()
         * or a follow-on grow attempt (below).
         */
        --wq->wq_refcnt;
        --wq->wq_tdcnt;

        ev_warn(1);
    }

    /* Keep growing if there's pending work and room to grow (might create
     * more threads than are strictly needed depending upon scheduling).
     */
    wq->wq_growing = workqueue_first(wq) && (wq->wq_tdcnt < wq->wq_tdmax);
    if (wq->wq_growing) {
        wq->wq_grow.expires = jiffies + wq->wq_tcdelay;
        add_timer(&wq->wq_grow);
        ++wq->wq_refcnt;
        ++wq->wq_tdcnt;
    }
    mutex_unlock(&wq->wq_lock);
}

struct workqueue_struct *
alloc_workqueue(const char *fmt, unsigned int flags, int min_active, int max_active, ...)
{
    struct workqueue_struct *wq;
    pthread_t tid;
    va_list args;
    int rc, i;

    if (atomic_inc_return(&wg.wg_refcnt) == 1) {
        mutex_init(&wg.wg_lock);
        INIT_LIST_HEAD(&wg.wg_list);
    }

    max_active = max_active ?: WQ_DFL_ACTIVE;
    max_active = clamp_t(int, max_active, 1, WQ_MAX_ACTIVE);
    min_active = clamp_t(int, min_active, 0, max_active);

    wq = aligned_alloc(__alignof__(*wq), sizeof(*wq));
    if (ev(!wq))
        return NULL;

    memset(wq, 0, sizeof(*wq));
    va_start(args, max_active);
    vsnprintf(wq->wq_name, sizeof(wq->wq_name), fmt ? fmt : "workqueue", args);
    va_end(args);

    mutex_init_adaptive(&wq->wq_lock);
    cv_init(&wq->wq_idle);
    cv_init(&wq->wq_barrier);

    INIT_LIST_HEAD(&wq->wq_pending);
    INIT_LIST_HEAD(&wq->wq_delayed);

    setup_timer(&wq->wq_grow, grow_workqueue_cb, wq);
    wq->wq_tcdelay = msecs_to_jiffies(1000);

    /* refcnt, tdcnt, tdmin, and tdmax are initialized to prevent
     * threads entering worker_thread() from exiting until after
     * we have spawned the minimum number of worker threads.
     */
    wq->wq_refcnt = min_active;
    wq->wq_tdmax = min_active;
    wq->wq_tdcnt = min_active;
    wq->wq_tdmin = max_active;
    wq->wq_running = true;

    for (i = 0; i < min_active; ++i) {
        rc = pthread_create(&tid, NULL, worker_thread, wq);
        if (rc)
            break;
    }

    mutex_lock(&wq->wq_lock);
    wq->wq_refcnt -= (min_active - i);
    wq->wq_tdcnt -= (min_active - i);

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
    struct wq_priv *priv;
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
        rc = cv_timedwait(&wq->wq_barrier, &wq->wq_lock, 10000, "qdestroy");
        if (rc)
            dump_workqueue_locked(wq);
    }

    assert(list_empty(&wq->wq_pending));
    assert(list_empty(&wq->wq_delayed));
    assert(wq->wq_tdcnt == 0);
    assert(!wq->wq_growing);
    mutex_unlock(&wq->wq_lock);

    /* Wait for all exiting threads to remove themselves from
     * the global priv list (which contains live wq pointers);
     */
    do {
        mutex_lock(&wg.wg_lock);
        list_for_each_entry(priv, &wg.wg_list, wp_link) {
            if (priv->wp_wq == wq)
                break;
        }
        mutex_unlock(&wg.wg_lock);

        if (priv)
            usleep(333);
    } while (priv);

    cv_destroy(&wq->wq_barrier);
    cv_destroy(&wq->wq_idle);
    mutex_destroy(&wq->wq_lock);

    if (atomic_dec_return(&wg.wg_refcnt) == 0) {
        rest_url_deregister("ps");
        mutex_destroy(&wg.wg_lock);
    }

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

        /* Try to spawn a new worker thread if there does not appear
         * to be enough workers to handle the load.
         */
        if (wq->wq_tdcnt < wq->wq_tdmax && wq->wq_idle.cv_waiters == 0) {
            if (!wq->wq_growing) {
                wq->wq_grow.expires = jiffies + 1;
                add_timer(&wq->wq_grow);
                wq->wq_growing = true;
                wq->wq_refcnt++;
                wq->wq_tdcnt++;
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
            cv_wait(&wq->wq_barrier, &wq->wq_lock, "barflush");
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
    struct workqueue_struct *wq = arg;
    struct wq_priv *priv = &wq_priv_tls;
    sigset_t sigset;
    int timedout;

    sigfillset(&sigset);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    pthread_setname_np(pthread_self(), wq->wq_name);
    pthread_detach(pthread_self());

    memset(priv, 0, sizeof(*priv));
    priv->wp_wq = wq;
    priv->wp_tid = syscall(SYS_gettid);
    priv->wp_barid = 0;
    priv->wp_tstart = get_time_ns();
    priv->wp_cstart = get_cycles();
    priv->wp_calls = 0;
    priv->wp_wmesgp = &hse_wmesg_tls;

    mutex_lock(&wg.wg_lock);
    list_add_tail(&priv->wp_link, &wg.wg_list);
    mutex_unlock(&wg.wg_lock);

    mutex_lock(&wq->wq_lock);
    timedout = 0;

    while (1) {
        struct wq_barrier *barrier;
        struct work_struct *work;

        work = workqueue_first(wq);
        if (!work) {
            bool extra = wq->wq_tdcnt > wq->wq_tdmin;

            if (!wq->wq_running || (timedout && extra))
                break;

            /* Sleep a short time if there are extra workers.  If we time out
             * and still have extra workers after draining the pending queue
             * then exit (above).  Otherwise, sleep here until signaled.
             */
            timedout = cv_timedwait(&wq->wq_idle, &wq->wq_lock, extra ? 60000 : -1, "idle");
            continue;
        }

        if (work->func) {
            list_del_init(&work->entry);
            mutex_unlock(&wq->wq_lock);

            priv->wp_cstart = get_cycles();
            priv->wp_calls++;

            work->func(work);

            priv->wp_latv[WP_LATV_IDX(priv)] = (get_cycles() - priv->wp_cstart);
            priv->wp_cstart += priv->wp_latv[WP_LATV_IDX(priv)];

            mutex_lock(&wq->wq_lock);
            continue;
        }

        barrier = container_of(work, struct wq_barrier, wqb_work);

        /* Increment the barrier visitor count once for each
         * thread's first visit to the barrier.
         */
        if (priv->wp_barid != barrier->wqb_barid) {
            priv->wp_barid = barrier->wqb_barid;
            ++barrier->wqb_visitors;
        }

        /* Wait until all worker threads have visited this barrier.
         */
        if (barrier->wqb_visitors < wq->wq_tdcnt) {
            cv_wait(&wq->wq_barrier, &wq->wq_lock, "barwait");
            continue;
        }

        /* All threads have visited this barrier, so remove
         * it and proceed with the next pending work item.
         */
        barrier->wqb_visitors = UINT_MAX;
        list_del_init(&work->entry);
        cv_broadcast(&wq->wq_barrier);
    }

    /* Wake up all threads waiting on wq_barrier so that they
     * can reevaluate the situation.
     */
    cv_broadcast(&wq->wq_barrier);
    --wq->wq_refcnt;
    --wq->wq_tdcnt;
    mutex_unlock(&wq->wq_lock);

    mutex_lock(&wg.wg_lock);
    list_del(&priv->wp_link);
    mutex_unlock(&wg.wg_lock);

    pthread_exit(NULL);
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
        --wq->wq_dlycnt;
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
        ++wq->wq_dlycnt;
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
            --wq->wq_dlycnt;
        }
    }
    mutex_unlock(&wq->wq_lock);

    return pending;
}

void
end_stats_work(void)
{
    struct wq_priv *priv = &wq_priv_tls;

    assert(priv);

    priv->wp_latv[WP_LATV_IDX(priv)] = (get_cycles() - priv->wp_cstart);
    priv->wp_cstart += priv->wp_latv[WP_LATV_IDX(priv)];
}

void
begin_stats_work(void)
{
    struct wq_priv *priv = &wq_priv_tls;

    assert(priv);

    priv->wp_cstart = get_cycles();
    priv->wp_calls++;
}

merr_t
workqueue_rest_get(
    const char       *path,
    struct conn_info *info,
    const char       *url,
    struct kv_iter   *iter,
    void             *context)
{
    static const ulong divtab[] = {
        1, 0, 1, 1, 1e3, 10, 1e6, 10, 1e9, 10, 1e9 * 3600, 2, 1e9 * 86400, 1,
        1e9 * 86400 * 365, 1, 1e9 * 86400 * 365 * 100, 1, ULONG_MAX, 1
    };
    static const char *divsuf = "xx  nsusmss h d y c xx";
    const size_t bufsz = 128 * 128; /* jobs * columns */
    struct wq_priv *priv;
    int dirfd, idx, n;
    size_t buflen;
    char *colv[4] = { "BARID", "CALLS", "TID", "TIME" };
    ulong maxv[4];
    int widthv[4];
    char *buf;

    path = strchr(path, '/');
    if (path)
        ++path;

    buf = malloc(bufsz);
    if (!buf)
        return merr(ENOMEM);

    /* Determine max column widths...
     */
    mutex_lock(&wg.wg_lock);
    memset(maxv, 0, sizeof(maxv));

    list_for_each_entry(priv, &wg.wg_list, wp_link) {
        if (priv->wp_barid > maxv[0])
            maxv[0] = priv->wp_barid;
        if (priv->wp_calls > maxv[1])
            maxv[1] = priv->wp_calls;
        if (priv->wp_tid > maxv[2])
            maxv[2] = priv->wp_tid;
        if (priv->wp_tstart > maxv[3])
            maxv[3] = priv->wp_tstart;
    }
    mutex_unlock(&wg.wg_lock);

    maxv[3] = (get_time_ns() - maxv[3]) / NSEC_PER_SEC;

    for (uint i = 0; i < NELEM(widthv); ++i) {
        widthv[i] = snprintf(NULL, 0, "%lu", maxv[i]);
        widthv[i] = max_t(int, widthv[i], strlen(colv[i]));
    }

    dirfd = open("/proc/self/task", O_DIRECTORY | O_RDONLY);
    buflen = 0;
    idx = 0;

    mutex_lock(&wg.wg_lock);
    list_for_each_entry(priv, &wg.wg_list, wp_link) {
        struct workqueue_struct *wq = priv->wp_wq;
        char *tidstr, *commstr, *statestr, *cpustr;
        char linebuf[1024], fnbuf[32], tmbuf[32];
        const ulong *ldiv = divtab + 2;
        ulong lat = 0, tm;
        ssize_t cc;

        tidstr = commstr = statestr = cpustr = NULL;

        snprintf(fnbuf, sizeof(fnbuf), "%d/stat", priv->wp_tid);

        cc = hse_readfile(dirfd, fnbuf, linebuf, sizeof(linebuf), O_RDONLY);
        if (cc > 0) {
            char *str = linebuf;

            str[cc - 1] = '\000';
            tidstr = strsep(&str, " ");
            commstr = strsep(&str, " ");
            statestr = strsep(&str, " ");

            for (uint i = 0; i < 38 - 3 && *str; /**/)
                i += (*str++ == ' ');
            cpustr = strsep(&str, " ");
        }

        /* Compute the average of the most recent callback latency
         * samples and convert from cycles to usecs.
         */
        if (priv->wp_calls > NELEM(priv->wp_latv)) {
            for (n = 0; n < NELEM(priv->wp_latv); ++n)
                lat += priv->wp_latv[n];
            lat /= NELEM(priv->wp_latv);
            lat = cycles_to_nsecs(lat);
            while (lat >= ldiv[0] * ldiv[1])
                ldiv += 2;
            lat /= ldiv[-2];
        }

        tm = (get_time_ns() - priv->wp_tstart) / NSEC_PER_SEC;
        if (tm >= 3600) {
            n = snprintf(tmbuf, sizeof(tmbuf), "%lu:%02lu:%02lu",
                         tm / 3600, (tm / 60) % 60, tm % 60);
        } else {
            n = snprintf(tmbuf, sizeof(tmbuf), "%lu:%02lu",
                         (tm / 60) % 60, tm % 60);
        }
        if (n > widthv[3])
            widthv[3] = n;

        if (buflen == 0) {
            n = snprintf(buf, bufsz,
                         "%3s %-16s %3s %3s %3s %3s %3s %3s %3s"
                         " %*s %*s %7s %8s %1s %3s"
                         " %*s %*s %-16s\n",
                         "IDX", "WQNAME", "REF", "MIN", "MAX", "CNT", "BSY", "WK", "DWK",
                         widthv[0], colv[0],
                         widthv[1], colv[1],
                         "LATENCY", "WMESG", "S", "CPU",
                         widthv[2], colv[2],
                         widthv[3], colv[3],
                         "TNAME");
            if (n < 1 || n >= bufsz)
                return merr(EINVAL);

            buflen = n;
        }

        n = snprintf(buf + buflen, bufsz - buflen,
                     "%3d %-16s %3d %3d %3d %3d %3d %3d %3d"
                     " %*u %*lu %5lu%2.2s %8.8s %1s %3s"
                     " %*s %*s %-16s\n",
                     idx, wq->wq_name, wq->wq_refcnt,
                     wq->wq_tdmin, wq->wq_tdmax, wq->wq_tdcnt,
                     wq->wq_tdcnt - wq->wq_idle.cv_waiters,
                     wq->wq_refcnt - wq->wq_dlycnt - wq->wq_tdcnt,
                     wq->wq_dlycnt,
                     widthv[0], wq->wq_barid,
                     widthv[1], priv->wp_calls,
                     lat, divsuf + (ldiv - divtab),
                     *priv->wp_wmesgp,
                     statestr ?: "?", cpustr ?: "?",
                     widthv[2], tidstr ?: "?",
                     widthv[3], tmbuf,
                     commstr ?: "?");
        if (n < 1 || n >= bufsz - buflen)
            break;

        /* Filter out lines that do not partially match
         * the user-supplied literal pattern.
         */
        if (path && !strstr(buf + buflen, path))
            continue;

        buflen += n;
        idx++;
    }
    mutex_unlock(&wg.wg_lock);

    rest_write_safe(info->resp_fd, buf, buflen);

    close(dirfd);
    free(buf);

    return 0;
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

    log_warn("%s %p: pid %d, refcnt %d, dlycnt %d tdcnt %d, tdmin %d, tdmax %d, growing %d",
             wq->wq_name, wq, getpid(), wq->wq_refcnt, wq->wq_dlycnt,
             wq->wq_tdcnt, wq->wq_tdmin, wq->wq_tdmax,
             wq->wq_growing);

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
