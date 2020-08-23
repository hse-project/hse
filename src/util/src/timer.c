/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/timer.h>

#include <hse_util/platform.h>
#include <hse_util/workqueue.h>

#include <pthread.h>
#include <sys/prctl.h>

static volatile bool timer_running;
static struct list_head timer_list;
static spinlock_t timer_xlock __aligned(64);

static struct work_struct timer_jclock_work;
static struct work_struct timer_dispatch_work;
static struct workqueue_struct *timer_wq __aligned(64);

unsigned long timer_nslpmin __read_mostly;
unsigned long timer_slack __read_mostly;
unsigned long tsc_freq __read_mostly;
unsigned long tsc_mult __read_mostly;
unsigned int tsc_shift __read_mostly;

struct timer_jclock timer_jclock;

/**
 * timer_calibrate() - measure overhead of calling nanosleep()
 */
static void
timer_calibrate(void)
{
    long cpgc, cpgtns, gtns, cps;
    long start, i, last = 0;
    long imax = 1024;
    int rc;

    /* Measure cycles per call of get_cycles() (cpgc), and cycles
     * per call of get_time_ns() (cpgtns).  Keep trying until we
     * have two successive samples within 3% of each other over
     * a 10ms period.
     */
    while (1) {
        struct timespec req = {.tv_nsec = MSEC_PER_SEC * 10 };

        start = get_cycles();
        for (i = 0; i < imax * 128; ++i)
            cpgc = get_cycles();
        cpgc = (cpgc - start) / (imax * 128);

        start = get_cycles();
        for (i = 0; i < imax * 128; ++i)
            gtns = get_time_ns();
        cpgtns = (get_cycles() - start) / (imax * 128);

        if (last > (cpgtns * 97) / 100 && last < (cpgtns * 103) / 100)
            break;

        last = last ? 0 : cpgtns;

        clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL);
    }

    /* Measure nsecs per call of get_time_ns() and compute CPU freq.
     */
    usleep(1000);
    cps = get_cycles();
    start = get_time_ns();
    for (i = 0; i < imax * 128; ++i)
        gtns = get_time_ns();
    cps = get_cycles() - cps;
    cps = (cps - cpgc - cpgtns) * NSEC_PER_SEC / (gtns - start);
    gtns = (gtns - start) / (imax * 128);

    /* Measure the fixed overhead of calling nanosleep().  Typically
     * this is roughly 50us (i.e., each request takes at least 50us
     * longer than the requested sleep time).
     */
    while (1) {
        struct timespec req = {.tv_nsec = 100 };
        int             rc = 0;

        start = get_time_ns();
        for (i = 0; i < imax; ++i)
            rc |= clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL);

        timer_nslpmin = (get_time_ns() - start - gtns) / imax;
        if (!rc)
            break;
    }

    /* If our measured value of nslpmin is high, it's probably because
     * high resolution timers are not enabled.  But it might be due to
     * the machine being really busy, so cap it to a reasonable amount.
     */
    rc = prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0);

    timer_slack = (rc == -1) ? timer_nslpmin : rc;
    if (timer_nslpmin > timer_slack * 2)
        timer_nslpmin = timer_slack;

#if __amd64__
    tsc_freq = cps;
    tsc_shift = 21;
    tsc_mult = (NSEC_PER_SEC << tsc_shift) / tsc_freq;
#else
    /* Default implementation of get_cycles() use clock_gettime().
     */
    tsc_freq = NSEC_PER_SEC;
    tsc_shift = 0;
    tsc_mult = 1;
#endif

    hse_log(HSE_NOTICE
            "%s: c/gc %ld, c/gtns %ld, c/s %ld, gtns %ld ns, nslpmin %lu ns, timerslack %lu",
            __func__, cpgc, cpgtns, cps, gtns, timer_nslpmin, timer_slack);

    if (1) {
        uint cpu;

        usleep(1000);
        cps = get_cycles();
        start = get_time_ns();
        for (i = 0; i < imax * 128; ++i)
            cpu = raw_smp_processor_id();
        cps = get_cycles() - cps;
        hse_log(HSE_NOTICE "%s: cpu %u, %lu, %lu",
                __func__, cpu, cps / i, cycles_to_nsecs(cps) / i);
    }
}

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
    struct timer_list  *first;
    sigset_t            set;

    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, 0);

    timer_calibrate();

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
