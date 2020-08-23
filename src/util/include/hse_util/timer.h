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

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/hse_err.h>
#include <hse_util/time.h>
#include <hse_util/list.h>

#define HSE_HZ  1000

#define MAX_JIFFY_OFFSET    ((LONG_MAX >> 1) - 1)
#define USEC_PER_JIFFY      (USEC_PER_SEC / HSE_HZ)
#define NSEC_PER_JIFFY      (NSEC_PER_SEC / HSE_HZ)

struct timer_jclock {
    atomic64_t  jc_jclock_ns;
    atomic64_t  jc_jiffies;
} __aligned(SMP_CACHE_BYTES);

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
 *
 * tsc_mult and tsc_shift are employed by cycles_to_nsecs() to very
 * quickly convert from cycles to nanoseconds by avoiding division.
 *
 * tsc_shift determines the number of significant digits in the conversion
 * as performed by cycles_to_nsecs().
 *
 * tsc_mult represents nanoseconds-per-cycle multiplied by 2^tsc_shift to
 * scale it up to an integer with a reasonable number of significant digits.
 * Conversion from cycles to nanoseconds then requires only a multiplication
 * by tsc_mult and a division by 2^tsc_shift (i.e., the division reduces to
 * a simple shift by tsc_shift).  The multiplication by tsc_mult therefore
 * limits the magnitude of the value that can be converted to 2^(64 - tsc_shift))
 * in order to avoid overflow.  For example, given a TSC frequency of 2.6GHz,
 * the range of cycles_to_nsecs() is limited to 2^43, or about 3383 seconds,
 * which should be good enough for typical latency measurement purposes.
 * To convert values larger than 2^43 simply divide by tsc_freq, which is
 * slower but will not overflow.
 */
extern struct timer_jclock timer_jclock;

#define jclock_ns   atomic64_read(&timer_jclock.jc_jclock_ns)
#define jiffies     atomic64_read(&timer_jclock.jc_jiffies)

extern unsigned long timer_nslpmin;
extern unsigned long timer_slack;
extern unsigned long tsc_freq;
extern unsigned long tsc_mult;
extern unsigned int tsc_shift;

static __always_inline u64
cycles_to_nsecs(u64 cycles)
{
    /* To avoid overflow cycles is limited to 2^(64 - tsc_shift)
     * (see note in timer.h regarding tsc_mult and tsc_shift).
     */
    return (cycles * tsc_mult) >> tsc_shift;
}

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

merr_t hse_timer_init(void);
void hse_timer_fini(void);

#endif /* HSE_PLATFORM_TIMER_H */
