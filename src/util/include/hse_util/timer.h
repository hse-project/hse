/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TIMER_H
#define HSE_PLATFORM_TIMER_H

/**
 * This file and its source code peer reproduces the kernel's basic
 * timer functionality, i.e.:
 * - add_timer
 * - del_timer
 * - init_timer
 */

#include <hse_util/hse_err.h>
#include <hse_util/time.h>
#include <hse_util/list.h>

merr_t hse_timer_init(void);
void hse_timer_fini(void);

#define HSE_HZ  1000

#define MAX_JIFFY_OFFSET    ((LONG_MAX >> 1) - 1)
#define USEC_PER_JIFFY      (USEC_PER_SEC / HSE_HZ)
#define NSEC_PER_JIFFY      (NSEC_PER_SEC / HSE_HZ)

struct timer_list {
    struct list_head entry;
    unsigned long    expires;

    void (*function)(unsigned long);
    unsigned long data;
};

/* jiffies is updated HSE_HZ times per second and reflects
 * the time of CLOCK_MONOTONIC divided by HSE_HZ.
 *
 * jclock_ns is updated HSE_HZ times per second and reflects
 * the time of CLOCK_MONOTONIC in nanoseconds.
 *
 * timer_slack is the timer thread's TIMERSLACK (see prctl(2)).
 *
 * timer_nslpmin is the timer thread's measured timer slack
 * of clock_nanosleep().
 *
 * tsc_freq is the measured frequency of the time stamp counter.
 */
extern volatile unsigned long jiffies;
extern volatile unsigned long jclock_ns;
extern unsigned long timer_nslpmin;
extern unsigned long timer_slack;
extern unsigned long tsc_freq;

static __always_inline unsigned long
msecs_to_jiffies(const unsigned int m)
{
    if ((int)m < 0)
        return MAX_JIFFY_OFFSET;

    return (m + (MSEC_PER_SEC / HSE_HZ) - 1) / (MSEC_PER_SEC / HSE_HZ);
}

static __always_inline unsigned long
usecs_to_jiffies(const unsigned int m)
{
    if ((int)m < 0)
        return MAX_JIFFY_OFFSET;

    return (m + (USEC_PER_SEC / HSE_HZ) - 1) / (USEC_PER_SEC / HSE_HZ);
}

static __always_inline unsigned long
nsecs_to_jiffies(const u64 m)
{
    return (m + (NSEC_PER_SEC / HSE_HZ) - 1) / (NSEC_PER_SEC / HSE_HZ);
}

#define init_timer(_timer) INIT_LIST_HEAD(&(_timer)->entry)

#define setup_timer(_timer, _func, _data) \
    do {                                  \
        init_timer((_timer));             \
        (_timer)->function = (_func);     \
        (_timer)->data = (ulong)(_data);  \
    } while (0)

/**
 * add_timer() - Put an initialized timer on the active list
 * @timer, struct timer_list *, timer to be added to the active list.
 */
void
add_timer(struct timer_list *timer);

/**
 * del_timer() - Take a timer off of the active list
 * @timer, struct timer_list *, timer to be removed from the active list
 *
 * Return: 0 if the timer was not on the active list, 1 otherwise.
 */
int
del_timer(struct timer_list *timer);

#endif /* HSE_PLATFORM_TIMER_H */
