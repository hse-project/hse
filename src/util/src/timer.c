/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/timer.h>

#include <hse_util/platform.h>
#include <hse_util/workqueue.h>

#include <pthread.h>

__aligned(64) static spinlock_t timer_xlock;
static struct list_head timer_list;
volatile bool           timer_running;
volatile unsigned long  jiffies;

__aligned(64) static struct workqueue_struct *timer_wq;
static struct work_struct timer_dispatch_work;
static struct work_struct timer_jclock_work;

static __always_inline void
timer_lock(void)
{
    spin_lock(&timer_xlock);
}

static __always_inline void
timer_unlock(void)
{
    spin_unlock(&timer_xlock);
}

static __always_inline struct timer_list *
timer_first(void)
{
    return list_first_entry_or_null(&timer_list, struct timer_list, entry);
}

static void
timer_jclock_cb(struct work_struct *work)
{
    struct timer_list *first;
    struct timespec    req;
    sigset_t           set;
    u64                last;

    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, 0);

    last = get_time_ns();
    jiffies = nsecs_to_jiffies(last - (last % NSEC_PER_JIFFY));

    while (timer_running) {
        u64 now = get_time_ns();
        u64 incr = 1;

        /* Always increment jiffies by one for each clock tick
         * (even if the clock went backward).  Catch up if we
         * we slept longer than one jiffie.
         */
        if (now > last && now > last + NSEC_PER_JIFFY)
            incr = nsecs_to_jiffies(now - last) - 1;
        last = now;

        timer_lock();
        jiffies += incr;

        first = timer_first();
        if (first && first->expires > jiffies)
            first = NULL;
        timer_unlock();

        if (first)
            queue_work(timer_wq, &timer_dispatch_work);

        /* Sleep for the remainder of the current jiffy in attempt
         * to align our jiffies update with the leading edge of
         * the system clock.
         */
        req.tv_nsec = NSEC_PER_JIFFY - (now % NSEC_PER_JIFFY);
        req.tv_sec = 0;

        nanosleep(&req, NULL);
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

static __always_inline int
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

    list_for_each_entry (t, &timer_list, entry) {
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
    if (timer_wq)
        return 0;

    spin_lock_init(&timer_xlock);
    INIT_LIST_HEAD(&timer_list);
    INIT_WORK(&timer_jclock_work, timer_jclock_cb);
    INIT_WORK(&timer_dispatch_work, timer_dispatch_cb);

    timer_wq = alloc_workqueue("timer_wq", 0, 2);
    if (!timer_wq) {
        hse_log(HSE_ERR "%s: alloc_workqueue failed", __func__);
        return merr(ENOMEM);
    }

    timer_running = true;
    queue_work(timer_wq, &timer_jclock_work);

    return 0;
}

void
hse_timer_fini(void)
{
    struct timer_list *t, *next;
    ulong              n;

    if (!timer_wq)
        return;

    timer_running = false;
    destroy_workqueue(timer_wq);
    timer_wq = NULL;

    n = nsecs_to_jiffies(get_time_ns());

    if ((n > jiffies && n > jiffies + HZ) || (n < jiffies && jiffies > n + HZ))
        hse_log(HSE_ERR "%s: HZ %d, jiffies drift > HZ: %lu != %lu", __func__, HZ, jiffies, n);

    /* It's an iffy proposition touching the entries on the timer
     * list as their memory may have been freed and reused.
     */
    timer_lock();
    list_for_each_entry_safe (t, next, &timer_list, entry) {
        hse_log(HSE_ERR "%s: timer %p abandoned, expires %lu\n", __func__, t, t->expires);
    }
    timer_unlock();
}
