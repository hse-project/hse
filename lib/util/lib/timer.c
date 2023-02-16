/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <sys/prctl.h>
#include <sys/resource.h>

#include <hse/logging/logging.h>
#include <hse/util/condvar.h>
#include <hse/util/event_counter.h>
#include <hse/util/platform.h>
#include <hse/util/spinlock.h>
#include <hse/util/timer.h>
#include <hse/util/workqueue.h>

static volatile bool timer_running HSE_READ_MOSTLY;
static struct workqueue_struct *timer_wq HSE_READ_MOSTLY;

static spinlock_t timer_xlock;
static struct list_head timer_list;

static struct work_struct timer_jclock_work;
static struct work_struct timer_dispatch_work;

unsigned long timer_slack HSE_READ_MOSTLY;

struct timer_jclock timer_jclock;

static ulong hse_timer_cb_next;
static ulong hse_timer_cb_period;
static void *hse_timer_cb_arg;
static hse_timer_cb_func_t *hse_timer_cb_func;

static HSE_ALWAYS_INLINE void
timer_lock(void)
{
    spin_lock(&timer_xlock);
}

static HSE_ALWAYS_INLINE void
timer_unlock(void)
{
    spin_unlock(&timer_xlock);
}

static HSE_ALWAYS_INLINE struct timer_list *
timer_first(void)
{
    return list_first_entry_or_null(&timer_list, struct timer_list, entry);
}

static void
timer_jclock_cb(struct work_struct *work)
{
    ulong tune_next = 0;
    int prio;

    pthread_setname_np(pthread_self(), "hse_jclock");

    /* Try to increase this thread's scheduling priority to
     * improve timekeeping and dispatch of expired timers.
     */
    errno = 0;
    prio = getpriority(PRIO_PROCESS, 0);
    if (!(prio == -1 && errno))
        setpriority(PRIO_PROCESS, 0, prio - 1);

    /* Disable tuning if get_cycles() is based upon get_time_ns().
     */
    if (hse_tsc_freq == 1000000000ul)
        tune_next = ULONG_MAX;

    while (timer_running) {
        hse_timer_cb_func_t *cb_func;
        struct timer_list *first;
        unsigned long now, jnow;
        struct timespec ts;
        __uint128_t freq;
        void *cb_arg;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

        jnow = nsecs_to_jiffies(now);
        timer_jclock.jc_jiffies = jnow;
        timer_jclock.jc_jclock_ns = now;

        /* Periodically refine hse_tsc_freq until it converges
         * on the measured value.
         */
        if (jnow >= tune_next) {
            atomic_thread_fence(memory_order_seq_cst);

            freq = get_cycles() - timer_jclock.jc_cstart;
            freq = (freq * NSEC_PER_SEC) / (now - timer_jclock.jc_tstart);

            freq = (hse_tsc_freq * 127 + freq) / 128;
            if (freq != hse_tsc_freq) {
                hse_tsc_mult = (NSEC_PER_SEC << HSE_TSC_SHIFT) / freq;
                hse_tsc_freq = freq;
                tune_next = nsecs_to_jiffies(now + NSEC_PER_SEC / 100);
            } else {
                tune_next = nsecs_to_jiffies(now + NSEC_PER_SEC);
            }
        }

        timer_lock();
        first = timer_first();
        if (first && first->expires >= jnow)
            first = NULL;

        if (jnow >= hse_timer_cb_next) {
            hse_timer_cb_next = nsecs_to_jiffies(now + hse_timer_cb_period);
            cb_func = hse_timer_cb_func;
            cb_arg = hse_timer_cb_arg;
        } else {
            cb_func = NULL;
        }
        timer_unlock();

        if (first)
            queue_work(timer_wq, &timer_dispatch_work);

        if (cb_func)
            cb_func(cb_arg);

        ts.tv_sec = 0;
        ts.tv_nsec = roundup(now, NSEC_PER_JIFFY) - now;

        end_stats_work();
        hse_nanosleep(&ts, NULL, "jclkslp");
        begin_stats_work();
    }
}

static void
timer_dispatch_cb(struct work_struct *work)
{
    void (*func)(ulong data);
    ulong data;

    while (1) {
        struct timer_list *t;

        timer_lock();
        t = timer_first();
        if (!t || t->expires > jiffies) {
            timer_unlock();
            break;
        }

        list_del_init(&t->entry);

        func = t->function;
        data = t->data;
        timer_unlock();

        func(data);
    }
}

static HSE_ALWAYS_INLINE int
timer_pending(const struct timer_list *timer)
{
    return !list_empty(&timer->entry);
}

void
add_timer(struct timer_list *timer)
{
    struct list_head *prev = &timer_list;
    struct timer_list *t;

    /* Insert the new timer in time-to-expire sorted order.
     */
    timer_lock();
    if (timer_pending(timer)) {
        assert(!timer_pending(timer)); /* Linux calls BUG_ON() */
        list_del_init(&timer->entry);
    }

    list_for_each_entry(t, &timer_list, entry) {
        if (t->expires > timer->expires)
            break;
        prev = &t->entry;
    }

    list_add(&timer->entry, prev);
    timer_unlock();
}

int
del_timer(struct timer_list *timer)
{
    bool pending;

    timer_lock();
    pending = timer_pending(timer);
    if (pending)
        list_del_init(&timer->entry);
    timer_unlock();

    return pending;
}

void
hse_timer_cb_register(hse_timer_cb_func_t *func, void *arg, ulong period_ms)
{
    assert(func);

    timer_lock();
    assert(!hse_timer_cb_func);

    hse_timer_cb_arg = arg;
    hse_timer_cb_func = func;
    hse_timer_cb_period = period_ms * 1000000;
    hse_timer_cb_next = nsecs_to_jiffies(get_time_ns() + hse_timer_cb_period);
    timer_unlock();
}

void
hse_timer_cb_unregister(void)
{
    timer_lock();
    hse_timer_cb_arg = NULL;
    hse_timer_cb_func = NULL;
    hse_timer_cb_period = 0;
    hse_timer_cb_next = ULONG_MAX;
    timer_unlock();

    /* Wait for at least one tick of the jiffy clock to ensure that
     * the previously registered hse_timer_cb_func() isn't running
     * and can no longer be invoked.
     */
    for (ulong j = jiffies; jiffies == j; /* do nothing */)
        usleep(1000);
}

merr_t
hse_timer_init(void)
{
    int rc;

    if (timer_wq)
        return 0;

    spin_lock_init(&timer_xlock);
    INIT_LIST_HEAD(&timer_list);
    INIT_WORK(&timer_jclock_work, timer_jclock_cb);
    INIT_WORK(&timer_dispatch_work, timer_dispatch_cb);
    hse_timer_cb_next = ULONG_MAX;

    /* Try to obtain cstart and tstart close in time to improve
     * the accuracy of our measured TSC frequency.
     */
    for (uint i = 0; i < 8; ++i) {
        timer_jclock.jc_cstart = get_cycles();
        atomic_thread_fence(memory_order_seq_cst);
        timer_jclock.jc_tstart = get_time_ns();

        if (get_cycles() - timer_jclock.jc_cstart < 1024)
            break;

        ev_warn(1);
    }

    timer_jclock.jc_jclock_ns = timer_jclock.jc_tstart;
    timer_jclock.jc_jiffies = nsecs_to_jiffies(timer_jclock.jc_jclock_ns);

    rc = prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);
    timer_slack = (rc == -1) ? 50000 : rc;

    /* We need at least three threads:
     *   1) one to run the jiffy clock
     *   2) one to dispatch expired dwork
     *   3) one to prune the cursor cache
     */
    timer_wq = alloc_workqueue("hse_timer", 0, 3, 3);
    if (!timer_wq) {
        log_err("unable to alloc timer workqueue");
        return merr(ENOMEM);
    }

    /* Start the jiffy clock...
     */
    timer_running = true;
    queue_work(timer_wq, &timer_jclock_work);

    return 0;
}

void
hse_timer_fini(void)
{
    if (!timer_wq)
        return;

    /* There shouldn't be any pending timers, but if there
     * are we'll log a message and force them to expire.
     */
    while (1) {
        struct timer_list *first;

        timer_lock();
        first = timer_first();
        if (first) {
            log_err(
                "timer %p abandoned, func %p, data %lu, expires in %lu jiffies\n", first,
                first->function, first->data, first->expires - jiffies);
            first->expires = jiffies;
            assert(0);
        }
        timer_unlock();

        if (!first)
            break;

        usleep(USEC_PER_SEC);
    }

    timer_running = false;
    destroy_workqueue(timer_wq);
    timer_wq = NULL;
}
