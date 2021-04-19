/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/timer.h>

#include <hse_util/platform.h>
#include <hse_util/workqueue.h>

#include <pthread.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>

static volatile bool timer_running;
static struct list_head timer_list;
static spinlock_t timer_xlock HSE_ALIGNED(64);

static struct work_struct timer_jclock_work;
static struct work_struct timer_dispatch_work;
static struct workqueue_struct *timer_wq HSE_ALIGNED(64);

unsigned long timer_nslpmin HSE_READ_MOSTLY;
unsigned long timer_slack HSE_READ_MOSTLY;
unsigned long tsc_freq HSE_READ_MOSTLY;
unsigned long tsc_mult HSE_READ_MOSTLY;
unsigned int tsc_shift HSE_READ_MOSTLY;

struct timer_jclock timer_jclock;

__attribute__((__noinline__))
u64
timer_calibrate_nsleep(void)
{
    struct timespec req = {.tv_nsec = 1 };

    clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL);

    return get_cycles();
}

__attribute__((__noinline__))
u64
timer_calibrate_gtns(void)
{
    get_time_ns();

    return get_cycles();
}

__attribute__((__noinline__))
u64
timer_calibrate_gc(void)
{
    return get_cycles();
}

__attribute__((__noinline__))
u64
timer_calibrate_loop(int itermax, u64 (*func)(void), u64 *minresp)
{
    u64 mincycles, minres;
    int i, j;

    mincycles = U64_MAX;
    minres = U64_MAX;

    usleep(1000);

    for (i = 0; i < 3; ++i) {
        u64 cycles, last, res;

        cycles = get_cycles();
        last = 0;

        for (j = 0; j < itermax; ++j) {
            res = func();
            if (res - last < minres)
                minres = res - last;
            last = res;
        }

        cycles = get_cycles() - cycles;
        if (cycles < mincycles)
            mincycles = cycles;
    }

    *minresp = minres;

    return mincycles;
}

/**
 * timer_calibrate() - Determine TSC frequency and cost of various facilities
 */
static void
timer_calibrate(ulong delay)
{
    static ulong cps_start, nsecs_start;
    ulong cyc_loop, cyc_gc, cyc_gtns, cyc_nsleep, gc, gtns;
    ulong cps, nsecs, diff;
    int imax = 32768, rc;

    if (!cps_start) {
        cps_start = get_cycles();
        nsecs_start = get_time_ns();
    }

    cps = cps_start;
    nsecs = nsecs_start;

    /* First we measure a few functions that we call a lot in order
     * to get an idea of how much they cost.  Results are likely to
     * vary due to how busy the machine, turbo capabilities, ...
     */
    cyc_loop = timer_calibrate_loop(imax, timer_calibrate_gc, &gc);
    cyc_gc = cyc_loop / imax;

    cyc_gtns = timer_calibrate_loop(imax, timer_calibrate_gtns, &gtns);
    cyc_gtns = (cyc_gtns - cyc_loop) / imax;

    cyc_nsleep = timer_calibrate_loop(64, timer_calibrate_nsleep, &diff);
    cyc_nsleep = (cyc_nsleep - ((cyc_loop * 64) / imax)) / 64;

    usleep(delay);

    /* Compute TSC frequency.  Scale down measurements if the sample
     * period was too long and would cause an overflow.
     */
    nsecs = get_time_ns() - nsecs;
    cps = get_cycles() - cps;

    while (cps > ULONG_MAX / NSEC_PER_SEC) {
        cps >>= 1;
        nsecs >>= 1;
    }
    cps = (cps * NSEC_PER_SEC) / nsecs;

    tsc_freq = cps;
    tsc_shift = 21;
    tsc_mult = (NSEC_PER_SEC << tsc_shift) / tsc_freq;

    timer_nslpmin = cycles_to_nsecs(cyc_nsleep);

    /* If our measured value of nslpmin is high, it's probably because
     * high resolution timers are not enabled.  But it might be due to
     * the machine being really busy, so cap it to a reasonable amount.
     */
    rc = prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);

    timer_slack = (rc == -1) ? timer_nslpmin : rc;
    if (timer_nslpmin > timer_slack * 2)
        timer_nslpmin = timer_slack;

    hse_log(HSE_NOTICE
            "%s: get_cycles %lu/%lucy %lu/%luns, get_time_ns %lu/%lucy %lu/%luns, c/s %lu, timerslack %lu/%lu",
            __func__, cyc_gc, gc, cycles_to_nsecs(cyc_gc), cycles_to_nsecs(gc),
            cyc_gtns, gtns - gc, cycles_to_nsecs(cyc_gtns), cycles_to_nsecs(gtns - gc),
            cps, timer_nslpmin, timer_slack);
}

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
    struct timer_list recalibrate, *first;
    sigset_t set;

    /* Attempt to increase this thread's scheduling priority to ensure
     * more accurate timekeeping and dispatch of expired timers.
     */
    if (__linux__) {
        int prio;

        errno = 0;
        prio = getpriority(PRIO_PROCESS, 0);
        if (!(prio == -1 && errno))
            setpriority(PRIO_PROCESS, 0, prio - 1);
    }

    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, 0);

    /* Recalibrate the TSC after one second for a much more accurate measurement.
     */
    setup_timer(&recalibrate, timer_calibrate, 1);
    recalibrate.expires = nsecs_to_jiffies(get_time_ns() + NSEC_PER_SEC);
    add_timer(&recalibrate);

    while (timer_running) {
        struct timespec ts;
        unsigned long now, jnow;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        now = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

        jnow = nsecs_to_jiffies(now);
        atomic64_set(&timer_jclock.jc_jiffies, jnow);
        atomic64_set(&timer_jclock.jc_jclock_ns, now);

        timer_lock();
        first = timer_first();
        if (first && first->expires > jnow)
            first = NULL;
        timer_unlock();

        if (first)
            queue_work(timer_wq, &timer_dispatch_work);

        ts.tv_sec = 0;
        ts.tv_nsec = roundup(now, NSEC_PER_JIFFY) - now;

        clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
    }

    del_timer(&recalibrate);
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

    /* Take an initial quick measurement of the TSC so as not to hold
     * up short lived program invocations.  We'll take a more accurate
     * measurement a few seconds after the timer starts.
     */
    timer_calibrate(10000);

    /* We need three threads:
     *   1) one for the jclock
     *   2) one to dispatch expired timers
     *   3) one to prune the cursor cache
     */
    timer_wq = alloc_workqueue("timer_wq", 0, 3);
    if (!timer_wq) {
        hse_log(HSE_ERR "%s: alloc_workqueue failed", __func__);
        return merr(ENOMEM);
    }

    timer_running = true;
    queue_work(timer_wq, &timer_jclock_work);

    while (!jiffies)
        usleep(3000);

    return 0;
}

void
hse_timer_fini(void)
{
    struct timer_list *t, *next;

    if (!timer_wq)
        return;

    timer_running = false;
    destroy_workqueue(timer_wq);
    timer_wq = NULL;

    /* It's an iffy proposition touching the entries on the timer
     * list as their memory may have been freed and reused.
     */
    timer_lock();
    list_for_each_entry_safe (t, next, &timer_list, entry) {
        hse_log(HSE_ERR "%s: timer %p abandoned, expires %lu\n", __func__, t, t->expires);
    }
    timer_unlock();
}
