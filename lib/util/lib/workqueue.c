/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <sys/types.h>
#include <syscall.h>

#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>

#include <hse/logging/logging.h>
#include <hse/rest/headers.h>
#include <hse/rest/method.h>
#include <hse/rest/params.h>
#include <hse/rest/request.h>
#include <hse/rest/response.h>
#include <hse/rest/status.h>

#include <hse/util/platform.h>
#include <hse/util/assert.h>
#include <hse/util/mutex.h>
#include <hse/util/condvar.h>
#include <hse/util/minmax.h>
#include <hse/util/event_counter.h>
#include <hse/util/workqueue.h>
#include <hse/util/list.h>
#include <hse/util/atomic.h>

#include <hse/ikvdb/hse_gparams.h>

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
    const char * volatile *wp_wmesgp;
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
    struct list_head wg_tlist;
    bool             wg_inited;
};

static struct workqueue_globals hse_wg = {
    .wg_lock = { PTHREAD_MUTEX_INITIALIZER }
};

static thread_local struct wq_priv hse_wp_tls;

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
        wq->wq_refcnt += 2;
        wq->wq_tdcnt++;
    }

    /* Drop our "growing callback" reference.
     */
    --wq->wq_refcnt;
    mutex_unlock(&wq->wq_lock);
}

struct workqueue_struct *
valloc_workqueue(
    const char *const fmt,
    const unsigned int flags,
    int min_active,
    int max_active,
    va_list ap)
{
    int rc, i;
    pthread_t tid;
    struct workqueue_struct *wq;

    mutex_lock(&hse_wg.wg_lock);
    if (!hse_wg.wg_inited) {
        INIT_LIST_HEAD(&hse_wg.wg_tlist);
        hse_wg.wg_inited = true;
    }
    mutex_unlock(&hse_wg.wg_lock);

    max_active = max_active ? max_active : WQ_DFL_ACTIVE;
    max_active = clamp_t(int, max_active, 1, WQ_MAX_ACTIVE);
    min_active = clamp_t(int, min_active, 0, max_active);

    wq = aligned_alloc(__alignof__(*wq), sizeof(*wq));
    if (ev(!wq))
        return NULL;

    memset(wq, 0, sizeof(*wq));
    vsnprintf(wq->wq_name, sizeof(wq->wq_name), fmt, ap);

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

struct workqueue_struct *
alloc_workqueue(
    const char *const fmt,
    const unsigned int flags,
    const int min_active,
    const int max_active,
    ...)
{
    va_list ap;
    struct workqueue_struct *wq;

    va_start(ap, max_active);
    wq = valloc_workqueue(fmt ? fmt : "workqueue", flags, min_active, max_active, ap);
    va_end(ap);

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
        mutex_lock(&hse_wg.wg_lock);
        list_for_each_entry(priv, &hse_wg.wg_tlist, wp_link) {
            if (priv->wp_wq == wq)
                break;
        }
        mutex_unlock(&hse_wg.wg_lock);

        if (priv)
            usleep(333);
    } while (priv);

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

        /* Try to spawn a new worker thread if there does not appear
         * to be enough workers to handle the load.  Acquire a ref
         * for the grow callback and a birth ref for the new thread.
         */
        if (wq->wq_tdcnt < wq->wq_tdmax && wq->wq_idle.cv_waiters == 0) {
            if (!wq->wq_growing) {
                wq->wq_grow.expires = jiffies + 1;
                add_timer(&wq->wq_grow);
                wq->wq_growing = true;
                wq->wq_refcnt += 2;
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
    struct wq_priv *priv = &hse_wp_tls;
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

    mutex_lock(&hse_wg.wg_lock);
    list_add_tail(&priv->wp_link, &hse_wg.wg_tlist);
    mutex_unlock(&hse_wg.wg_lock);

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

    mutex_lock(&hse_wg.wg_lock);
    list_del(&priv->wp_link);
    mutex_unlock(&hse_wg.wg_lock);

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
    uint64_t expires;

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
    struct wq_priv *priv = &hse_wp_tls;

    assert(priv);

    priv->wp_latv[WP_LATV_IDX(priv)] = (get_cycles() - priv->wp_cstart);
    priv->wp_cstart += priv->wp_latv[WP_LATV_IDX(priv)];
}

void
begin_stats_work(void)
{
    struct wq_priv *priv = &hse_wp_tls;

    assert(priv);

    priv->wp_cstart = get_cycles();
    priv->wp_calls++;
}

enum rest_status
rest_get_workqueues(
    const struct rest_request *const req,
    struct rest_response *const resp,
    void *const arg)
{
    static const ulong divtab[] = {
        1, 0, 1, 1, 1e3, 10, 1e6, 10, 1e9, 10, 1e9 * 3600, 2, 1e9 * 86400, 1,
        1e9 * 86400 * 365, 1, 1e9 * 86400 * 365 * 100, 1, ULONG_MAX, 1
    };

    char *data;
    merr_t err;
    int proc_fd;
    bool pretty;
    cJSON *root = NULL;
    struct wq_priv *priv;
    const ulong *divisor = divtab + 2;
    enum rest_status status = REST_STATUS_OK;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (ev(err))
        return rest_response_perror(resp, REST_STATUS_BAD_REQUEST,
            "The 'pretty' query parameter must be a boolean", merr(EINVAL));

    root = cJSON_CreateArray();
    if (ev(!root))
        return rest_response_perror(resp, REST_STATUS_SERVICE_UNAVAILABLE, "Out of memory",
            merr(ENOMEM));

    proc_fd = open("/proc/self/task", O_DIRECTORY | O_RDONLY);
    if (ev(proc_fd == -1)) {
        status = rest_response_perror(resp, REST_STATUS_SERVICE_UNAVAILABLE, "Out of memory",
            merr(ENOMEM));
        goto out;
    }

    mutex_lock(&hse_wg.wg_lock);

    list_for_each_entry(priv, &hse_wg.wg_tlist, wp_link) {
        bool bad;
        char *str;
        ssize_t n;
        uint64_t tm;
        char tm_buf[32];
        char file_buf[64];
        cJSON *elem = NULL;
        char line_buf[1024];
        unsigned long latency = 0;
        char *tid, *comm, *state, *processor;
        struct workqueue_struct *wq = priv->wp_wq;

        snprintf(file_buf, sizeof(file_buf), "%d/stat", priv->wp_tid);

        n = hse_readfile(proc_fd, file_buf, line_buf, sizeof(line_buf), O_RDONLY);
        if (n < 0) {
            status = rest_response_perror(resp, REST_STATUS_INTERNAL_SERVER_ERROR,
                "Failed to read the proc filesystem", merr(errno));
            break;
        }

        str = line_buf;
        str[n - 1] = '\000';

        /* Refer to /proc/[pid]/stat in proc(5) for parsing information. */
        tid = strsep(&str, " ");
        comm = strsep(&str, " ");
        state = strsep(&str, " ");

        for (uint i = 0; i < 38 - 3 && *str; /**/)
            i += (*str++ == ' ');
        processor = strsep(&str, " ");

        /* Compute the average of the most recent callback latency samples and
         * convert from cycles to usecs.
         */
        if (priv->wp_calls > NELEM(priv->wp_latv)) {
            for (size_t i = 0; i < NELEM(priv->wp_latv); i++)
                latency += priv->wp_latv[i];

            latency /= NELEM(priv->wp_latv);
            latency = cycles_to_nsecs(latency);
            while (latency >= divisor[0] * divisor[1])
                divisor += 2;
            latency /= divisor[-2];
        }

        tm = (get_time_ns() - priv->wp_tstart) / NSEC_PER_SEC;
        if (tm >= 3600) {
            snprintf(tm_buf, sizeof(tm_buf), "%lu:%02lu:%02lu", tm / 3600, (tm / 60) % 60, tm % 60);
        } else {
            snprintf(tm_buf, sizeof(tm_buf), "%lu:%02lu", tm / 3600, (tm / 60) % 60);
        }

        elem = cJSON_CreateObject();
        if (ev(!elem)) {
            status = rest_response_perror(resp, REST_STATUS_SERVICE_UNAVAILABLE, "Out of memory",
                merr(ENOMEM));
            break;
        }

        if (ev(!cJSON_AddItemToArray(root, elem))) {
            status = rest_response_perror(resp, REST_STATUS_SERVICE_UNAVAILABLE, "Out of memory",
                merr(ENOMEM));
            break;
        }

        bad = !cJSON_AddStringToObject(elem, "name", wq->wq_name);
        bad |= !cJSON_AddNumberToObject(elem, "references", wq->wq_refcnt);
        bad |= !cJSON_AddNumberToObject(elem, "minimum_threads", wq->wq_tdmin);
        bad |= !cJSON_AddNumberToObject(elem, "maximum_threads", wq->wq_tdmax);
        bad |= !cJSON_AddNumberToObject(elem, "current_threads", wq->wq_tdcnt);
        bad |= !cJSON_AddNumberToObject(elem, "busy", wq->wq_idle.cv_waiters);
        bad |= !cJSON_AddNumberToObject(elem, "working", wq->wq_refcnt - wq->wq_dlycnt
            - wq->wq_tdcnt);
        bad |= !cJSON_AddNumberToObject(elem, "delayed", wq->wq_dlycnt);
        bad |= !cJSON_AddNumberToObject(elem, "barrier_id", wq->wq_barid);
        bad |= !cJSON_AddNumberToObject(elem, "calls", priv->wp_calls);
        bad |= !cJSON_AddNumberToObject(elem, "latency_ns", latency);
        bad |= !cJSON_AddStringToObject(elem, "wmesg", *priv->wp_wmesgp);
        bad |= !cJSON_AddStringToObject(elem, "state", state);
        bad |= !cJSON_AddNumberToObject(elem, "processor", atoi(processor));
        bad |= !cJSON_AddStringToObject(elem, "time", tm_buf);
        bad |= !cJSON_AddNumberToObject(elem, "thread_id", atoi(tid));
        bad |= !cJSON_AddStringToObject(elem, "thread_name", comm);

        if (ev(bad)) {
            status = rest_response_perror(resp, REST_STATUS_SERVICE_UNAVAILABLE, "Out of memory",
                merr(ENOMEM));
            break;
        }
    }

    mutex_unlock(&hse_wg.wg_lock);
    close(proc_fd);

    if (status == REST_STATUS_OK) {
        data = (pretty ? cJSON_Print : cJSON_PrintUnformatted)(root);
        if (ev(!data)) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            goto out;
        }

        fputs(data, resp->rr_stream);
        cJSON_free(data);

        rest_headers_set(resp->rr_headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON);
    }

out:
    cJSON_Delete(root);

    return status;
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
