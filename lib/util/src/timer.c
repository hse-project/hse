/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/workqueue.h>
#include <hse_util/spinlock.h>
#include <hse_util/logging.h>
#include <hse_util/timer.h>
#include <hse_util/condvar.h>

#include <sys/prctl.h>
#include <sys/resource.h>

static volatile bool timer_running HSE_READ_MOSTLY;
static struct workqueue_struct *timer_wq HSE_READ_MOSTLY;

static spinlock_t timer_xlock;
static struct list_head timer_list;

static struct work_struct timer_jclock_work;
static struct work_struct timer_dispatch_work;

unsigned long timer_slack HSE_READ_MOSTLY;

struct timer_jclock timer_jclock;


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
    int prio;

    pthread_setname_np(pthread_self(), "hse_jclock");

    /* Try to increase this thread's scheduling priority to
     * improve timekeeping and dispatch of expired timers.
     */
    errno = 0;
    prio = getpriority(PRIO_PROCESS, 0);
    if (!(prio == -1 && errno))
        setpriority(PRIO_PROCESS, 0, prio - 1);

    while (timer_running) {
        struct timer_list *first;
        unsigned long now, jnow;
        struct timespec ts;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

        jnow = nsecs_to_jiffies(now);
        atomic_set(&timer_jclock.jc_jiffies, jnow);
        atomic_set(&timer_jclock.jc_jclock_ns, now);

        timer_lock();
        first = timer_first();
        if (first && first->expires > jnow)
            first = NULL;
        timer_unlock();

        if (first)
            queue_work(timer_wq, &timer_dispatch_work);

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
    struct list_head * prev = &timer_list;
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

    /* Start the jiffy clock and wait for it initialize jiffies.
     */
    timer_running = true;
    queue_work(timer_wq, &timer_jclock_work);

    while (!jiffies)
        usleep(333);

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
            log_err("timer %p abandoned, func %p, data %lu, expires in %lu jiffies\n",
                    first, first->function, first->data, first->expires - jiffies);
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
