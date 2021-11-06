/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_EVENT_TIMER_H
#define HSE_PLATFORM_EVENT_TIMER_H

#include <hse_util/arch.h>
#include <hse_util/compiler.h>
#include <hse_util/atomic.h>

/*
 * EVENT_TIMER is intended to provide an opaque, convenient, accurate,
 * low-overhead mechanism to allow for multiple independent
 * event timers with nanosecond resolution.
 *
 * The reporting function provides min, max, mean and stddev.
 * [HSE_REVISIT] Add user-defined quantiles, see P2 paper.
 *
 * Typical use is envisioned as:
 *
 * #include <hse_util/event_timer.h>
 * #define USE_EVENT_TIMER // or set via cc -DUSE_EVENT_TIMER=1
 * main() {
 *   EVENT_TIMER(foo);
 *   EVENT_INIT(foo);
 *   for (...) {
 *      EVENT_START(foo);
 *      foo();
 *      EVENT_SAMPLE(foo);
 *   }
 *   EVENT_REPORT(foo, "speed of foo");
 * }
 *
 * Or for multi-threaded sampling:
 *
 * thread_func(Widget *obj) {
 *      EVENT_WRAP(obj->tfoo,
 *              foo(1, 2, 3);
 *      );
 * }
 */

struct event_timer {
    unsigned long t1, t2;
    unsigned long min, max;
    unsigned long mode, mcnt;
    unsigned long n;
    atomic_int    busy;
    double        om, m, os, s;
    char          buf[128];
};

void
event_sample_ts(struct event_timer *, unsigned long, unsigned long);
void
event_sample(struct event_timer *, unsigned long);
void
event_report(struct event_timer *, const char *);

#ifdef USE_EVENT_TIMER

#define EVENT_TIMER(t) struct event_timer(t)
#define EVENT_INIT(t)               \
    do {                            \
        memset(&(t), 0, sizeof(t)); \
        (t).min = (ulong)-1;        \
    } while (0)

#define EVENT_WRAP(t, stmts)                        \
    do {                                            \
        unsigned long __t1 = get_time_ns();         \
        stmts;                                      \
        event_sample_ts(&(t), __t1, get_time_ns()); \
    } while (0)
#define EVENT_WRAP_PTR(p, stmts) EVENT_WRAP(*(struct event_timer *)p, stmts)

#define EVENT_START_TS(t1) unsigned long t1 = get_time_ns()
#define EVENT_SAMPLE_TS(t1, t) event_sample_ts(&(t), (t1), get_time_ns())

#define EVENT_START(t) ((t).t1 = get_time_ns())
#define EVENT_SAMPLE(t) event_sample(&(t), get_time_ns())
#define EVENT_REPORT(t, w) event_report(&(t), w)

#define EVENT_PRINT(t, w)        \
    do {                         \
        event_report(&(t), w);   \
        printf("%s\n", (t).buf); \
    } while (0)

#else

#define EVENT_WRAP(t, stmts) stmts
#define EVENT_WRAP_PTR(t, stmts) stmts
#define EVENT_START_TS(t1)
#define EVENT_SAMPLE_TS(t1, t)

#define EVENT_TIMER(t)
#define EVENT_INIT(t)
#define EVENT_START(t)
#define EVENT_SAMPLE(t)
#define EVENT_REPORT(t, w)
#define EVENT_PRINT(t, w)

#endif

#endif
