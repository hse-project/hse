/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#define USE_EVENT_TIMER
#include <hse_util/arch.h>
#include <hse_util/event_timer.h>

#include <math.h>
#include <sched.h>

void
event_sample(struct event_timer *t, unsigned long t2)
{
    event_sample_ts(t, t->t1, t2);
}

void
event_sample_ts(struct event_timer *t, unsigned long t1, unsigned long t2)
{
    unsigned long d;
    int           loop = 0;

    /* non-deterministic in tests -- do not count for coverage */
    /* GCOV_EXCL_START */
    /* prevent simultaneous updates */
    while (!atomic_cas(&t->busy, 0, 1)) {
        cpu_relax();
        ++t->t1;
        if (++loop > 1000)
            sched_yield();
    }

    if (t2 < t1) {
        atomic_cas(&t->busy, 1, 0);
        return;
    }
    /* GCOV_EXCL_STOP */

    ++t->n;
    d = t2 - t1;
    t->min = d < t->min ? d : t->min;
    t->max = d > t->max ? d : t->max;

    /* this is the 1982 majority algorithm from Fischer & Salzberg */
    {
        unsigned long e = d / 100; /* within 1% */

        if (d >= t->mode - e && d <= t->mode + e)
            ++t->mcnt;
        else if (t->mcnt == 0)
            t->mode = d;
        else
            --t->mcnt;
    }

    /* this online algorithm from
     * http://www.johndcook.com/blog/standard_deviation/
     */
    if (t->n == 1) {
        t->om = t->m = d;
        t->s = 0;
    } else {
        t->m = t->om + (d - t->om) / t->n;
        t->s = t->os + (d - t->om) * (d - t->m);
        t->om = t->m;
        t->os = t->s;
    }

    atomic_cas(&t->busy, 1, 0);
}

/* https://en.wikipedia.org/wiki/Fast_inverse_square_root */
/* https://en.wikipedia.org/wiki/Methods_of_computing_square_roots */
static float
invsqrt(float x)
{
    float xhalf = 0.5f * x;
    union {
        float x;
        int   i;
    } u;
    u.x = x;
    u.i = 0x5f3759df - (u.i >> 1);
    u.x = u.x * (1.5f - xhalf * u.x * u.x);
    return u.x;
}

void
event_report(struct event_timer *t, const char *what)
{
    struct event_timer copy = *t;
    double             var = copy.s / ((copy.n - 1) ?: 1);
    double             stddev = 1 / invsqrt(var);

    if (copy.n < 2)
        snprintf(
            t->buf,
            sizeof(t->buf),
            "%s: (ns) cnt %ld max %ld",
            what,
            (ulong)copy.n,
            (ulong)copy.max);
    else
        snprintf(
            t->buf,
            sizeof(t->buf),
            "%s: (ns) cnt %ld min %ld mode %ld max %ld mean %.1f std %g",
            what,
            (ulong)copy.n,
            (ulong)copy.min,
            (ulong)copy.mode,
            (ulong)copy.max,
            copy.m,
            stddev);
}
